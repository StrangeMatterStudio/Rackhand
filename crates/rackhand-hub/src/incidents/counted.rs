//! Counted rules (7.6.1): watched services not active, container restarts and pending security updates, from the
//! machine's live reports.

use rackhand_detect::counted::{container_restarts, security_updates, service_not_active};

use super::conditions::CondKey;
use super::{Incidents, IncidentsError};

fn labels(key: &str, value: &str) -> String {
    serde_json::json!({ key: value }).to_string()
}

impl Incidents {
    /// The severity of the incident open for `key`. The report counts and the first-seen times are in memory, so after
    /// a restart they start again: while the condition is still there, an incident open across the restart keeps at
    /// least its severity rather than reading the short count as the condition clearing.
    fn held(&self, key: &CondKey) -> Option<rackhand_detect::rules::Severity> {
        self.eval().conditions.get(key).and_then(|s| s.active)
    }

    pub(crate) async fn evaluate_counted(&self, now_ms: i64) -> Result<(), IncidentsError> {
        for machine in self.inner.ingest.machines() {
            let c = self.inner.ingest.counted(&machine);
            let mut seen = Vec::new();
            for (service, n) in &c.services_down {
                let key = CondKey::new(&machine, "service.not_active", &labels("service", service));
                seen.push(key.clone());
                let severity = service_not_active(*n).max(self.held(&key));
                self.condition(key, severity, 1, &format!("{service} not active"), now_ms).await?;
            }
            for key in self.stale_conditions(&machine, "service.not_active", &seen) {
                self.condition(key, None, 1, "", now_ms).await?;
            }
            for (container, (_, restarts)) in &c.restarts {
                let key = CondKey::new(&machine, "container.restarts", &labels("container", container));
                let title = format!("{container} keeps restarting");
                self.condition(key, container_restarts(restarts, now_ms), 1, &title, now_ms).await?;
            }
            let key = CondKey::new(&machine, "updates.security", "{}");
            let mut severity = security_updates(c.security_since, now_ms);
            if c.security_since.is_some() {
                severity = severity.max(self.held(&key));
            }
            self.condition(key, severity, 1, "Security updates pending", now_ms).await?;
        }
        Ok(())
    }
}
