//! Reconciliation (7.3.8): on start and every minute, an incident in `automation` or `assistant` whose job has
//! finished is advanced as if `JobFinished` had arrived, since a crash can lose queued bus messages.

use super::lifecycle::{State, by_id};
use super::{Incidents, IncidentsError};

impl Incidents {
    /// Advances every incident whose job finished without the incident hearing of it; returns how many.
    pub async fn reconcile(&self, now_ms: i64) -> Result<usize, IncidentsError> {
        let finished: Vec<(String, String, String)> = self.inner.db.readers().with(|c| {
            let mut s = c.prepare(
                "SELECT i.id, j.id, j.state FROM incidents i JOIN jobs j ON j.incident_id = i.id
                 WHERE i.state IN ('automation', 'assistant')
                   AND j.state IN ('succeeded', 'failed', 'interrupted', 'cancelled', 'timed_out')
                   AND NOT EXISTS (SELECT 1 FROM incident_events e WHERE e.incident_id = i.id
                                   AND e.kind = 'job_finished' AND json_extract(e.data, '$.job_id') = j.id)
                 ORDER BY j.ended_at",
            )?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
        })?;
        for (incident, job, outcome) in &finished {
            self.job_finished(incident, job, outcome, now_ms).await?;
        }
        Ok(finished.len())
    }

    /// A finished job of an incident. A success waits for the condition to clear (routing on after a while is T57's);
    /// anything else goes to a person until playbook routing exists (T57, T78).
    pub async fn job_finished(
        &self,
        incident: &str,
        job: &str,
        outcome: &str,
        now_ms: i64,
    ) -> Result<(), IncidentsError> {
        let mut inc = by_id(&self.inner.db, incident)?;
        if outcome != "succeeded" {
            inc.state = State::Human;
        }
        let data = serde_json::json!({ "job_id": job, "outcome": outcome, "state": inc.state.as_str() });
        self.write(&inc, "job_finished", data, now_ms).await
    }
}
