//! Jobs a stopped hub left behind (7.5.3 step 8, E14): one marked with a `resumable_step` goes on there. Its machine was
//! being rebooted with the hub on it; the job waits for that restart first, as it was waiting when the hub went down.
//! (Detached steps and the jobs that can't go on: T65.)

use std::collections::BTreeMap;

use rackhand_runbook::runbook::StepKind;

use super::runner::{StepCtx, StepOutcome, StepResult};
use super::{Actions, ActionsError, DEFAULT_STEP_TIMEOUT, JobKind, StartJob};
use crate::bus::JobOutcome;

struct Left {
    id: String,
    start: StartJob,
    step: String,
}

impl Actions {
    /// Takes up the jobs that can go on, and returns how many; called once, before anything starts new jobs.
    pub async fn resume(&self) -> Result<usize, ActionsError> {
        let left: Vec<Left> = self.inner.db.readers().with(|c| {
            let mut s = c.prepare(
                "SELECT id, name, rev, target, params, requested_by, resumable_step FROM jobs
                 WHERE state = 'running' AND kind = 'runbook' AND resumable_step IS NOT NULL AND target IS NOT NULL",
            )?;
            s.query_map([], |r| {
                let params: String = r.get(4)?;
                Ok(Left {
                    id: r.get(0)?,
                    start: StartJob {
                        kind: JobKind::Runbook,
                        name: r.get(1)?,
                        rev: r.get(2)?,
                        machine_id: r.get(3)?,
                        params: serde_json::from_str::<BTreeMap<String, String>>(&params).unwrap_or_default(),
                        requested_by: r.get(5)?,
                        incident_id: None,
                        approval_id: None,
                    },
                    step: r.get(6)?,
                })
            })?
            .collect()
        })?;
        let mut taken = 0;
        for job in left {
            if !self.inner.resumed.lock().unwrap_or_else(|e| e.into_inner()).insert(job.id.clone()) {
                continue;
            }
            taken += 1;
            let actions = self.clone();
            let machine = job.start.machine_id.clone();
            // expected to be silent from now on, not only once the task runs
            let hold = actions.inner.reboots.hold_machine(&machine);
            tokio::spawn(async move {
                tracing::info!(job = %job.id, step = %job.step, "resuming a job");
                let (outcome, reason) = match actions.resume_one(&job, hold).await {
                    Ok(end) => end,
                    Err(e) => {
                        tracing::error!(error = %e, job = %job.id, "resuming a job");
                        (JobOutcome::Failed, Some("store_error".to_string()))
                    }
                };
                if let Err(e) = actions.finish(&job.id, &job.start.requested_by, outcome, reason.as_deref()).await {
                    tracing::error!(error = %e, job = %job.id, "finishing a resumed job");
                }
            });
        }
        Ok(taken)
    }

    async fn resume_one(
        &self,
        job: &Left,
        hold: super::reboots::Awaiting,
    ) -> Result<(JobOutcome, Option<String>), ActionsError> {
        let failed = |why: &str| Ok((JobOutcome::Failed, Some(why.to_string())));
        let machine = self.machine(&job.start.machine_id)?;
        let (_, runbook) = self.runbook(&job.start)?;
        let Some(at) = runbook.steps.iter().position(|s| s.id == job.step) else { return failed("resume_step_gone") };
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
