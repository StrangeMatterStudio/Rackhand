//! What a quarantine does to a machine's state (7.5.6): `quarantine` and `quarantine-release` jobs move it, and while it is
//! anything but `none` or `pending`, only those two runbooks may run on it (so Incidents, the dashboard, the Scheduler and
//! an assistant's job are all stopped here, not only the MCP gate).
//!
//! - `quarantine` starts: `applying`; its end: `active`, or `failed` with a critical event (which opens a critical incident).
//! - `quarantine-release` starts: `releasing`; its end: `none`, or back to `active` with a critical event.
//!
//! A job that never got the machine (busy, or refused) changes nothing.

use rackhand_store::ids::now_ms;
use rackhand_store::{RegistryChange, Row, RowUpdate, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;

use super::{Actions, ActionsError};
use crate::bus::JobOutcome;
use crate::policy::quarantine::{State, Trigger, next};

pub const QUARANTINE: &str = "quarantine";
pub const RELEASE: &str = "quarantine-release";

/// Whether a runbook may run on a machine in this state.
pub fn allowed(runbook: &str, state: State) -> bool {
    match state {
        State::None | State::Pending => true,
        // a failed quarantine is tried again, with an approval; its release comes after it has applied
        State::Failed => runbook == QUARANTINE,
        State::Active => runbook == RELEASE,
        State::Applying | State::Releasing => false,
    }
}

impl Actions {
    /// The machine's quarantine state.
    pub(super) fn quarantine_state(&self, machine: &str) -> Result<State, ActionsError> {
        let found: Option<String> = self.inner.db.readers().with(|c| {
            c.query_row("SELECT quarantine FROM machines WHERE id = ?1", [machine], |r| r.get(0)).optional()
        })?;
        Ok(found.as_deref().and_then(State::parse).unwrap_or(State::None))
    }

    async fn set_quarantine(
        &self,
        machine: &str,
        from: State,
        to: State,
        job: &str,
        actor: &str,
    ) -> Result<(), ActionsError> {
        let set = Row::from([("quarantine", Value::Text(to.as_str().into()))]);
        let update = RowUpdate { table: "machines", key: ("id", Value::Text(machine.into())), set };
        let change = RegistryChange { updates: vec![update], ..Default::default() };
        self.inner.db.writer().send(WriteCmd::RegistryChange(change)).await?;
        self.audit(
            actor,
            "quarantine.state",
            machine,
            serde_json::json!({ "from": from.as_str(), "to": to.as_str(), "job": job }),
        )
        .await;
        Ok(())
    }

    async fn quarantine_event(&self, machine: &str, kind: &str, severity: &str, job: &str) -> Result<(), ActionsError> {
        let event: Row = [
            ("id", Value::Text(ulid::Ulid::new().to_string())),
            ("machine_id", Value::Text(machine.into())),
            ("at_ms", Value::Integer(now_ms())),
            ("kind", Value::Text(kind.into())),
            ("severity", Value::Text(severity.into())),
            ("subject", Value::Text(job.into())),
            ("data", Value::Text(serde_json::json!({ "job": job }).to_string())),
            ("job_id", Value::Text(job.into())),
        ]
        .into_iter()
        .collect();
        self.inner.db.writer().send(WriteCmd::PutEvents(vec![event])).await?;
        Ok(())
    }

    /// A quarantine job has the machine: it is `applying`, or `releasing`.
    pub(super) async fn quarantine_begin(
        &self,
        runbook: &str,
        machine: &str,
        state: State,
        job: &str,
        actor: &str,
    ) -> Result<(), ActionsError> {
        let to = match runbook {
            QUARANTINE => match state {
                State::None => next(state, Trigger::FindingAutoRule),
                State::Pending => next(state, Trigger::Approved),
                State::Failed => next(state, Trigger::RetryApproved),
                _ => None,
            },
            RELEASE => next(state, Trigger::ReleaseApproved),
            _ => None,
        };
        match to {
            Some(to) => self.set_quarantine(machine, state, to, job, actor).await,
            None => Ok(()),
        }
    }

    /// A quarantine job has ended.
    pub(super) async fn quarantine_end(
        &self,
        runbook: &str,
        machine: &str,
        job: &str,
        outcome: JobOutcome,
        actor: &str,
    ) -> Result<(), ActionsError> {
        let ok = outcome == JobOutcome::Succeeded;
        let (trigger, from) = match (runbook, ok) {
            (QUARANTINE, true) => (Trigger::Done, State::Applying),
            (QUARANTINE, false) => (Trigger::StepFailed, State::Applying),
            (RELEASE, true) => (Trigger::Released, State::Releasing),
            (RELEASE, false) => (Trigger::ReleaseFailed, State::Releasing),
            _ => return Ok(()),
        };
        // only a job that began moved the machine; anything else ended without the state having changed
        if self.quarantine_state(machine)? != from {
            return Ok(());
        }
        let Some(to) = next(from, trigger) else { return Ok(()) };
        self.set_quarantine(machine, from, to, job, actor).await?;
        let (kind, severity) = match (runbook, ok) {
            (QUARANTINE, true) => ("quarantine.active", "info"),
            (QUARANTINE, false) => ("quarantine.failed", "critical"),
            (_, true) => ("quarantine.released", "info"),
            (_, false) => ("quarantine.release_failed", "critical"),
        };
        self.quarantine_event(machine, kind, severity, job).await
    }
}
