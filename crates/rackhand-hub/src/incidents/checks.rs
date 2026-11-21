//! Check incidents (7.6.1, 7.6.2): a check failing 2 runs in a row warns and 4 is critical, and 2 good runs in a row
//! resolve it; a TLS check's certificate with 14 days left warns and 3 is critical. Both come from what is stored (the
//! latest results, the latest `check.cert_days` point), so a restart doesn't start a count again, and an evaluation
//! between two runs changes nothing. A check that belongs to no machine has its incidents without one.

use rackhand_detect::counted::check_failing;
use rackhand_detect::forecast::cert_expiry;
use rackhand_detect::rules::Severity;
use rackhand_store::series::chunk::Tier;

use super::conditions::CondKey;
use super::{Incidents, IncidentsError};
use crate::checks::HUB_MACHINE;

const DAY_MS: i64 = 86_400_000;

struct Check {
    id: String,
    kind: String,
    interval_s: i64,
    machine: Option<String>,
}

impl Incidents {
    pub(crate) async fn evaluate_checks(&self, now_ms: i64) -> Result<(), IncidentsError> {
        let checks: Vec<Check> = self.inner.db.readers().with(|c| {
            let mut s = c.prepare("SELECT id, kind, interval_s, machine_id FROM checks ORDER BY id")?;
            s.query_map([], |r| {
                Ok(Check { id: r.get(0)?, kind: r.get(1)?, interval_s: r.get(2)?, machine: r.get(3)? })
            })?
            .collect()
        })?;
        for check in checks {
            let labels = serde_json::json!({ "check": check.id }).to_string();
            let machine = check.machine.clone().unwrap_or_default();
            let failing = CondKey::new(&machine, "check.failing", &labels);
            let severity = if check.interval_s == 0 { None } else { self.failing_now(&check.id, &failing)? };
            self.condition(failing, severity, 1, &format!("Check {} failing", check.id), now_ms).await?;
            if check.kind == "tls" {
                let key = CondKey::new(&machine, "cert.expiry", &labels);
                let (severity, days) =
                    if check.interval_s == 0 { (None, None) } else { self.cert_now(&check, &labels, &key, now_ms)? };
                let title = format!("Certificate of {} expires in {} days", check.id, days.unwrap_or(0));
                self.condition(key, severity, 1, &title, now_ms).await?;
            }
        }
        Ok(())
    }

    /// The check's severity from its latest runs: failures in a row give it; with none, an open incident stays until
    /// 2 good runs in a row.
    fn failing_now(&self, check: &str, key: &CondKey) -> Result<Option<Severity>, IncidentsError> {
        let latest: Vec<bool> = self.inner.db.readers().with(|c| {
            let mut s = c.prepare("SELECT ok FROM check_results WHERE check_id = ?1 ORDER BY at_ms DESC LIMIT 4")?;
            s.query_map([check], |r| r.get::<_, i64>(0).map(|v| v != 0))?.collect()
        })?;
        let failures = latest.iter().take_while(|ok| !**ok).count() as u32;
        let goods = latest.iter().take_while(|ok| **ok).count();
        let held = self.held(key);
        Ok(match failures {
            0 if goods >= 2 || held.is_none() => None,
            0 => held,
            n => check_failing(n).max(held),
        })
    }

    /// The certificate's severity from the latest `check.cert_days` reading of the last two intervals (none yet: an
    /// open incident stays).
    fn cert_now(
        &self,
        check: &Check,
        labels: &str,
        key: &CondKey,
        now_ms: i64,
    ) -> Result<(Option<Severity>, Option<i64>), IncidentsError> {
        let series_machine = check.machine.as_deref().unwrap_or(HUB_MACHINE);
        let since = now_ms - 2 * check.interval_s * 1000 - 60_000;
        let points = self
            .inner
            .ingest
            .tier_series(series_machine, "check.cert_days", labels, Tier::Raw, since, now_ms)
            .map_err(|e| IncidentsError::Ingest(e.to_string()))?;
        let Some((at, values)) = points.last() else { return Ok((self.held(key), None)) };
        let days = values.first().copied().unwrap_or(0.0) as i64;
        Ok((cert_expiry(at + days * DAY_MS, *at), Some(days)))
    }
}
