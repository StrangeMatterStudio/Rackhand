//! Jobs a stopped hub left behind (7.5.3 step 8, 7.3.7, E14, E44), each looked at once when the hub starts, before
//! anything starts new jobs:
//!
//! - one marked with a `resumable_step` goes on there: its machine was being rebooted with the hub on it, and the job
//!   waits for that restart first, as it was waiting when the hub went down;
//! - one in a detached step is picked up by polling the step on its machine (nothing is started again), its result
//!   recorded, and the job goes on after it;
//! - every other running job, and every running assistant job, ends `interrupted`, with a warning event that opens an
//!   incident on its machine. Jobs that never started (queued, waiting for an approval) are left alone.

use std::collections::BTreeMap;

use rackhand_runbook::runbook::StepKind;
use rackhand_store::{Row, WriteCmd};
use rusqlite::types::Value;

use super::coordinator::{StepEnd, substitute_argv, with_params};
use super::runner::{StepCtx, StepOutcome, StepResult};
use super::{Actions, ActionsError, DEFAULT_STEP_TIMEOUT, JobKind, StartJob, jobs};
use crate::bus::JobOutcome;

/// What a stopped hub left of a job.
struct Left {
    id: String,
    kind: String,
    start: StartJob,
    /// The step a reboot left to resume at.
    resumable: Option<String>,
}

/// What a restarted hub does with a job.
enum Plan {
    /// Wait for the restart of the machine the job rebooted, then go on at this step.
    Reboot(String),
    /// Poll the detached step at this index, then go on after it.
    Detached(usize),
    Interrupt,
}

/// The reason a job the restart interrupted ends with.
pub const HUB_RESTARTED: &str = "hub_restarted";

impl Actions {
    /// Takes up the jobs that can go on, and returns how many; called once, before anything starts new jobs.
    pub async fn resume(&self) -> Result<usize, ActionsError> {
        let left: Vec<Left> = self.inner.db.readers().with(|c| {
            let mut s = c.prepare(
                "SELECT id, kind, name, rev, target, params, requested_by, resumable_step FROM jobs
                 WHERE state = 'running' ORDER BY started_at",
            )?;
            s.query_map([], |r| {
                let params: String = r.get(5)?;
                let kind: String = r.get(1)?;
                Ok(Left {
                    id: r.get(0)?,
                    start: StartJob {
                        kind: if kind == "assistant" { JobKind::Assistant } else { JobKind::Runbook },
                        name: r.get(2)?,
                        rev: r.get(3)?,
                        machine_id: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                        params: serde_json::from_str::<BTreeMap<String, String>>(&params).unwrap_or_default(),
                        requested_by: r.get(6)?,
                        incident_id: None,
                        approval_id: None,
                    },
                    kind,
                    resumable: r.get(7)?,
                })
            })?
            .collect()
        })?;
        let mut taken = 0;
        for job in left {
            if !self.inner.resumed.lock().unwrap_or_else(|e| e.into_inner()).insert(job.id.clone()) {
                continue;
            }
            match self.plan(&job) {
                Plan::Interrupt => {
                    if let Err(e) = self.interrupt(&job).await {
                        tracing::error!(error = %e, job = %job.id, "interrupting a job");
                    }
                }
                plan => {
                    taken += 1;
                    self.spawn_resumed(job, plan);
                }
            }
        }
        Ok(taken)
    }

    fn plan(&self, job: &Left) -> Plan {
        if job.kind != "runbook" || job.start.machine_id.is_empty() {
            return Plan::Interrupt;
        }
        if let Some(step) = &job.resumable {
            return Plan::Reboot(step.clone());
        }
        let Ok((_, runbook)) = self.runbook(&job.start) else { return Plan::Interrupt };
        let running: Option<String> = self
            .inner
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT step_id FROM job_steps WHERE job_id = ?1 AND state = 'running' ORDER BY started_at DESC LIMIT 1",
                    [&job.id],
                    |r| r.get(0),
                )
            })
            .ok();
        let at = running.and_then(|id| runbook.steps.iter().position(|s| s.id == id && s.detached));
        at.map_or(Plan::Interrupt, Plan::Detached)
    }

    fn spawn_resumed(&self, job: Left, plan: Plan) {
        let actions = self.clone();
        let machine = job.start.machine_id.clone();
        // expected to be silent from now on, not only once the task runs
        let hold = actions.inner.reboots.hold_machine(&machine);
        tokio::spawn(async move {
            tracing::info!(job = %job.id, "resuming a job");
            let result = match plan {
                Plan::Reboot(step) => actions.resume_reboot(&job, &step, hold).await,
                Plan::Detached(at) => actions.resume_detached(&job, at, hold).await,
                Plan::Interrupt => return,
            };
            let (outcome, reason) = result.unwrap_or_else(|e| {
                tracing::error!(error = %e, job = %job.id, "resuming a job");
                (JobOutcome::Failed, Some("store_error".to_string()))
            });
            if let Err(e) = actions.finish(&job.id, &job.start.requested_by, outcome, reason.as_deref()).await {
                tracing::error!(error = %e, job = %job.id, "finishing a resumed job");
            }
        });
    }

    /// The job ends `interrupted`; its running step with it, and a warning event on its machine says so.
    async fn interrupt(&self, job: &Left) -> Result<(), ActionsError> {
        let db = &self.inner.db;
        let running: Vec<String> = db.readers().with(|c| {
            let mut s = c.prepare("SELECT step_id FROM job_steps WHERE job_id = ?1 AND state = 'running'")?;
            s.query_map([&job.id], |r| r.get(0))?.collect()
        })?;
        for step in running {
            let end = StepEnd {
                state: "interrupted",
                exit_code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                now_ms: now_ms(),
            };
            jobs::step_finished(db, &job.id, &step, end).await?;
        }
        let machine = (!job.start.machine_id.is_empty()).then(|| job.start.machine_id.clone());
        let event: Row = [
            ("id", Value::Text(ulid::Ulid::new().to_string())),
            ("machine_id", machine.map_or(Value::Null, Value::Text)),
            ("at_ms", Value::Integer(now_ms())),
            ("kind", Value::Text("job.interrupted".into())),
            ("severity", Value::Text("warning".into())),
            ("subject", Value::Text(job.start.name.clone())),
            ("data", Value::Text(serde_json::json!({ "job": job.id, "name": job.start.name }).to_string())),
            ("job_id", Value::Text(job.id.clone())),
        ]
        .into_iter()
        .collect();
        db.writer().send(WriteCmd::PutEvents(vec![event])).await?;
        self.finish(&job.id, &job.start.requested_by, JobOutcome::Interrupted, Some(HUB_RESTARTED)).await?;
        // a quarantine the restart cut short is failed, so the machine isn't left applying for good
        self.quarantine_end(
            &job.start.name,
            &job.start.machine_id,
            &job.id,
            JobOutcome::Interrupted,
            &job.start.requested_by,
        )
        .await
    }

    async fn resume_detached(
        &self,
        job: &Left,
        at: usize,
        hold: super::reboots::Awaiting,
    ) -> Result<(JobOutcome, Option<String>), ActionsError> {
        let machine = self.machine(&job.start.machine_id)?;
        let (_, runbook) = self.runbook(&job.start)?;
        let Some(guard) = self.inner.locks.acquire(&machine.id, self.lock_wait).await else {
            return Ok((JobOutcome::Failed, Some("machine_busy".into())));
        };
        let step = with_params(&runbook.steps[at], &job.start.params);
        let argv = step.cmd.as_deref().map(|c| substitute_argv(c, &job.start.params));
        let timeout = step.timeout_s().map_or(DEFAULT_STEP_TIMEOUT, std::time::Duration::from_secs);
        let ctx = StepCtx {
            job_id: job.id.clone(),
            machine_id: machine.id.clone(),
            machine_kind: machine.kind.clone(),
            address: machine.address.clone(),
            identity: runbook.identity,
            timeout,
        };
        let result = match tokio::time::timeout(timeout, self.inner.runner.adopt(&ctx, &step, argv.as_deref())).await {
            Ok(r) => r,
            Err(_) => StepResult::failed("timeout"),
        };
        if result.outcome == StepOutcome::Failed("adopt_unavailable".into()) {
            drop(guard);
            drop(hold);
            self.interrupt(job).await?;
            return Ok((JobOutcome::Interrupted, Some(HUB_RESTARTED.into())));
        }
        let failed = match &result.outcome {
            StepOutcome::Succeeded => None,
            StepOutcome::Failed(reason) => Some(reason.clone()),
        };
        self.record_step(&job.id, &step.id, result).await?;
        if let Some(reason) = failed {
            return Ok((JobOutcome::Failed, Some(reason)));
        }
        drop(hold);
        self.run_steps_from(at + 1, &job.id, &machine, &runbook, &job.start.params, guard, None).await
    }

    async fn resume_reboot(
        &self,
        job: &Left,
        resume_at: &str,
        hold: super::reboots::Awaiting,
    ) -> Result<(JobOutcome, Option<String>), ActionsError> {
        let failed = |why: &str| Ok((JobOutcome::Failed, Some(why.to_string())));
        let machine = self.machine(&job.start.machine_id)?;
        let (_, runbook) = self.runbook(&job.start)?;
        let Some(at) = runbook.steps.iter().position(|s| s.id == resume_at) else { return failed("resume_step_gone") };
        let Some(guard) = self.inner.locks.acquire(&machine.id, self.lock_wait).await else {
            return failed("machine_busy");
        };
        // the reboot the job was waiting for, not yet recorded as over
        if let Some(reboot) = runbook.steps[..at].iter().rev().find(|s| s.kind == StepKind::RebootIfRequired) {
            let started: Option<(String, i64)> = self
                .inner
                .db
                .readers()
                .with(|c| {
                    c.query_row(
                        "SELECT state, started_at FROM job_steps WHERE job_id = ?1 AND step_id = ?2",
                        [&job.id, &reboot.id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                })
                .ok();
            if let Some((state, since_ms)) = started.filter(|(state, _)| state == "running") {
                tracing::debug!(%state, since_ms, "waiting for the machine's restart");
                let timeout = reboot.timeout_s().map_or(DEFAULT_STEP_TIMEOUT, std::time::Duration::from_secs);
                let ctx = StepCtx {
                    job_id: job.id.clone(),
                    machine_id: machine.id.clone(),
                    machine_kind: machine.kind.clone(),
                    address: machine.address.clone(),
                    identity: runbook.identity,
                    timeout,
                };
                let back = match tokio::time::timeout(timeout, self.inner.runner.rebooted(&ctx, since_ms)).await {
                    Ok(back) => back,
                    Err(_) => StepResult::failed("timeout"),
                };
                let mut result = StepResult { command: None, exit_code: None, ..back };
                if result.stdout.is_empty() {
                    result.stdout = b"{\"reboot\":\"scheduled\"}\n".to_vec();
                }
                let outcome = result.outcome.clone();
                self.record_step(&job.id, &reboot.id, result).await?;
                if let StepOutcome::Failed(reason) = outcome {
                    return Ok((JobOutcome::Failed, Some(reason)));
                }
            }
        }
        drop(hold);
        self.run_steps_from(at, &job.id, &machine, &runbook, &job.start.params, guard, None).await
    }
}

fn now_ms() -> i64 {
    rackhand_store::ids::now_ms()
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
