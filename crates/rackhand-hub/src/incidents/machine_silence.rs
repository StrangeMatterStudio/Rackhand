//! Machine silence (7.6.3): an enrolled probe machine that hasn't reported for 60 s (at least 4 intervals) is silent;
//! the first report resolves it. A machine whose policy expects it offline gets one info event instead (E38).

use rackhand_detect::rules::Severity;
use rackhand_detect::silence::{Context, Subject, silence};

use super::conditions::CondKey;
use super::{Incidents, IncidentsError};
use crate::ingest::{Event, Severity as EventSeverity};

impl Incidents {
    /// When the hub started: no silence for its first 3 minutes (E44).
    pub fn set_started(&self, started_ms: i64) {
        self.eval().started_ms = started_ms;
    }

    pub(crate) async fn evaluate_silence(&self, now_ms: i64) -> Result<(), IncidentsError> {
        let machines: Vec<(String, bool, Option<i64>)> = self.inner.db.readers().with(|c| {
            let mut s = c.prepare(
                "SELECT m.id, coalesce(p.expected_offline, 0) != 0, m.enrolled_at FROM machines m
                 LEFT JOIN policies p ON p.id = m.policy_id WHERE m.state = 'enrolled' AND m.driver IS NULL",
            )?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
        })?;
        let started = self.eval().started_ms;
        let ctx = Context { now_ms, hub_started_ms: started, in_maintenance: false, reboot_job_waiting: false };
        for (machine, expected_offline, enrolled_at) in machines {
            let ingest = &self.inner.ingest;
            // in the start grace the rule says nothing, which for a machine that hasn't reported since the start isn't
            // the machine being back: an incident open across a restart stays until its first report
            if ingest.last_seen(&machine).is_none() && now_ms - started < rackhand_detect::silence::HUB_START_GRACE_MS {
                continue;
            }
            // never heard from since the hub started: counted from the start (or enrollment, if later)
            let last = ingest.last_seen(&machine).unwrap_or(enrolled_at.unwrap_or(started).max(started));
            let interval_s = (ingest.interval_ms(&machine) / 1000).max(1) as u32;
            let severity = silence(&Subject::Machine { interval_s, expected_offline }, last, &ctx);
            if expected_offline {
                let newly = severity.is_some() && self.eval().asleep.insert(machine.clone());
                if severity.is_none() {
                    self.eval().asleep.remove(&machine);
                }
                if newly {
                    let data = serde_json::json!({ "last_report_ms": last });
                    let event = Event {
                        at_ms: now_ms,
                        ..Event::machine(&machine, "machine.silent", EventSeverity::Info, data)
                    };
                    if let Err(e) = ingest.raise_event(event).await {
                        tracing::warn!(error = %e, "raising machine.silent");
                    }
                }
                continue;
            }
            let severity = severity.filter(|s| *s != Severity::Info);
            let key = CondKey::new(&machine, "machine.silent", "{}");
            self.condition(key, severity, 1, "No report from the machine", now_ms).await?;
        }
        Ok(())
    }
}
