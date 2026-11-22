//! Machine silence (7.6.3): an enrolled probe machine that hasn't reported for 60 s (at least 4 intervals) is silent;
//! the first report resolves it. A machine whose policy expects it offline gets one info event instead (E38).
//!
//! An agentless machine (a driver and no probe) is silent after 2 failed polls in a row and critical after 5, counted
//! from the stored poll results, so a restart doesn't start the count again; its next good poll resolves it. A
//! machine with both, such as a Proxmox host whose API was added, is silent by its probe's reports.
//!
//! In a maintenance window, and while a job is rebooting the machine, nothing new is said about a machine that isn't
//! reporting: no incident opens, and one already open stays as it is until the machine reports.

use std::sync::Arc;

use rackhand_detect::rules::Severity;
use rackhand_detect::silence::{Context, Subject, silence};

use super::conditions::CondKey;
use super::{Incidents, IncidentsError};
use crate::ingest::{Event, Severity as EventSeverity};

/// When a machine's silence is expected, from the systems that know (the Scheduler and Actions).
pub trait Quiet: Send + Sync + std::fmt::Debug {
    /// A maintenance window covers the machine.
    fn in_maintenance(&self, machine: &str, tags: &[String], now_ms: i64) -> bool;
    /// A job that reboots the machine is running and its wait step hasn't ended.
    fn awaiting_reboot(&self, machine: &str) -> bool;
}

impl Incidents {
    /// What says when a machine's silence is expected; until it is set, never.
    pub fn set_quiet(&self, quiet: Arc<dyn Quiet>) {
        if self.inner.quiet.set(quiet).is_err() {
            tracing::warn!("incidents: the quiet source is already set");
        }
    }

    /// Whether the silence `ctx` would raise is suppressed for the machine (7.6.3).
    fn suppressed(&self, subject: &Subject, last_ms: i64, machine: &str, tags: &str, ctx: &Context) -> bool {
        let Some(quiet) = self.inner.quiet.get() else { return false };
        let tags: Vec<String> = serde_json::from_str(tags).unwrap_or_default();
        let ctx = Context {
            in_maintenance: quiet.in_maintenance(machine, &tags, ctx.now_ms),
            reboot_job_waiting: quiet.awaiting_reboot(machine),
            ..*ctx
        };
        silence(subject, last_ms, &ctx).is_none()
    }

    /// When the hub started: no silence for its first 3 minutes (E44).
    pub fn set_started(&self, started_ms: i64) {
        self.eval().started_ms = started_ms;
    }

    pub(crate) async fn evaluate_silence(&self, now_ms: i64) -> Result<(), IncidentsError> {
        let machines: Vec<(String, bool, Option<i64>, String)> = self.inner.db.readers().with(|c| {
            let mut s = c.prepare(
                "SELECT m.id, coalesce(p.expected_offline, 0) != 0, m.enrolled_at, m.tags FROM machines m
                 LEFT JOIN policies p ON p.id = m.policy_id
                 WHERE m.state = 'enrolled' AND (m.driver IS NULL OR m.probe_endpoint_id IS NOT NULL)",
            )?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect()
        })?;
        let started = self.eval().started_ms;
        let ctx = Context { now_ms, hub_started_ms: started, in_maintenance: false, reboot_job_waiting: false };
        for (machine, expected_offline, enrolled_at, tags) in machines {
            let ingest = &self.inner.ingest;
            // in the start grace the rule says nothing, which for a machine that hasn't reported since the start isn't
            // the machine being back: an incident open across a restart stays until its first report
            if ingest.last_seen(&machine).is_none() && now_ms - started < rackhand_detect::silence::HUB_START_GRACE_MS {
                continue;
            }
            // never heard from since the hub started: counted from the start (or enrollment, if later)
            let last = ingest.last_seen(&machine).unwrap_or(enrolled_at.unwrap_or(started).max(started));
            let interval_s = (ingest.interval_ms(&machine) / 1000).max(1) as u32;
            let subject = Subject::Machine { interval_s, expected_offline };
            let severity = silence(&subject, last, &ctx);
            if severity.is_some() && self.suppressed(&subject, last, &machine, &tags, &ctx) {
                continue;
            }
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
        self.evaluate_agentless_silence(&ctx).await
    }

    async fn evaluate_agentless_silence(&self, ctx: &Context) -> Result<(), IncidentsError> {
        // in the start grace the rule says nothing, which isn't the appliance answering again: an open incident stays
        if ctx.now_ms - ctx.hub_started_ms < rackhand_detect::silence::HUB_START_GRACE_MS {
            return Ok(());
        }
        let machines: Vec<(String, String)> = self.inner.db.readers().with(|c| {
            let mut s = c.prepare(
                "SELECT id, tags FROM machines
                 WHERE state = 'enrolled' AND driver IS NOT NULL AND probe_endpoint_id IS NULL",
            )?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })?;
        for (machine, tags) in machines {
            let latest: Vec<bool> = self.inner.db.readers().with(|c| {
                let mut s =
                    c.prepare("SELECT ok FROM check_results WHERE check_id = ?1 ORDER BY at_ms DESC LIMIT 5")?;
                s.query_map([crate::checks::agentless::check_id(&machine)], |r| r.get::<_, i64>(0).map(|v| v != 0))?
                    .collect()
            })?;
            let failed_polls = latest.iter().take_while(|ok| !**ok).count() as u32;
            let subject = Subject::Agentless { failed_polls };
            let severity = silence(&subject, ctx.now_ms, ctx);
            if severity.is_some() && self.suppressed(&subject, ctx.now_ms, &machine, &tags, ctx) {
                continue;
            }
            let key = CondKey::new(&machine, "machine.silent", "{}");
            self.condition(key, severity, 1, "No answer from the machine's API", ctx.now_ms).await?;
        }
        Ok(())
    }
}
