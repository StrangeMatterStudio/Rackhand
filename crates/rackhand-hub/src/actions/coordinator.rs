//! Running a job: resolve the runbook and machine, take the machine, use the approval, then run each step in order,
//! recording it before it runs (9) and enforcing its timeout. A detached step that passes its timeout isn't killed
//! (E55): the job ends `timed_out` and the machine stays locked until the step's result is recorded.
//!
//! A reboot step that was scheduled (7.5.3 steps 7 and 8) may take the hub down with its machine: the job is marked to go
//! on at the verify step before anything waits, and `resume` (in `recovery`) goes on there in the hub that comes back.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rackhand_runbook::params::check_value;
use rackhand_runbook::runbook::{Identity, Runbook, Step, StepKind};
use rackhand_store::ids::{new_id, now_ms};
use rusqlite::OptionalExtension;

pub(super) use super::jobs::StepEnd;
use super::jobs::{self, NewJob};
use super::locks::MachineGuard;
use super::runner::{StepCtx, StepOutcome, StepResult, StepRunner, display};
use super::{Actions, ActionsError, DEFAULT_STEP_TIMEOUT, JobKind, JobResult, StartJob, quarantining};
use crate::bus::JobOutcome;
use crate::library::items::{Kind, Library};
use crate::policy::approvals::{ApprovalRequest, Approvals, approval_hash};
use crate::policy::quarantine::State;

pub(super) struct Machine {
    pub(super) id: String,
    pub(super) kind: String,
    pub(super) access: String,
    pub(super) address: Option<String>,
    pub(super) quarantine: String,
}

impl Machine {
    pub(super) fn monitor_only(&self) -> bool {
        self.access == "monitor"
    }
}

/// Whole-argument substitution (7.3.7): an argument that is exactly `{{name}}` becomes the value.
pub(super) fn substitute_argv(cmd: &[String], params: &BTreeMap<String, String>) -> Vec<String> {
    cmd.iter()
        .map(|a| {
            let name = a.trim().strip_prefix("{{").and_then(|r| r.strip_suffix("}}")).map(str::trim);
            match name.and_then(|n| params.get(n)) {
                Some(v) => v.clone(),
                None => a.clone(),
            }
        })
        .collect()
}

/// Text substitution for checks, calls and messages (`containers_running:{{project}}`).
fn substitute_text(text: &str, params: &BTreeMap<String, String>) -> String {
    let mut out = text.to_string();
    for (k, v) in params {
        for pattern in [format!("{{{{{k}}}}}"), format!("{{{{ {k} }}}}")] {
            out = out.replace(&pattern, v);
        }
    }
    out
}

pub(crate) fn with_params(step: &Step, params: &BTreeMap<String, String>) -> Step {
    let mut s = step.clone();
    s.checks = s.checks.map(|c| c.iter().map(|x| substitute_text(x, params)).collect());
    s.call = s.call.map(|c| substitute_text(&c, params));
    s.message = s.message.map(|m| substitute_text(&m, params));
    s.source = s.source.map(|m| substitute_text(&m, params));
    s.dest = s.dest.map(|m| substitute_text(&m, params));
    s
}
enum StepEndState {
    Done(StepResult),
    TimedOut,
}

impl Actions {
    pub(super) fn machine(&self, id: &str) -> Result<Machine, ActionsError> {
        self.inner
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT id, kind, access, address, quarantine FROM machines WHERE id = ?1", [id], |r| {
                    Ok(Machine {
                        id: r.get(0)?,
                        kind: r.get(1)?,
                        access: r.get(2)?,
                        address: r.get(3)?,
                        quarantine: r.get(4)?,
                    })
                })
                .optional()
            })?
            .ok_or(ActionsError::UnknownMachine)
    }

    pub(super) fn runbook(&self, start: &StartJob) -> Result<(i64, Runbook), ActionsError> {
        let db = &self.inner.db;
        let store = |e: crate::library::items::SaveError| ActionsError::Store(e.to_string());
        let (rev, source) = match start.rev {
            Some(rev) => (rev, Library::revision_in(db, Kind::Runbook, &start.name, rev).map_err(store)?),
            None => match Library::current_in(db, Kind::Runbook, &start.name).map_err(store)? {
                Some((rev, s)) => (rev, Some(s)),
                None => (0, None),
            },
        };
        let source = source.ok_or(ActionsError::UnknownRunbook)?;
        let runbook = Runbook::parse(&source).map_err(|e| ActionsError::InvalidRunbook(e.to_string()))?;
        Ok((rev, runbook))
    }

    pub(super) async fn audit(&self, actor: &str, action: &str, target: &str, data: serde_json::Value) {
        // The audit row follows the change it records; a failed append is logged by the writer and doesn't undo it.
        let _ = self.inner.audit.append(actor, action, Some(target), &data.to_string()).await;
    }

    /// Runs a runbook job to its end. `Err` means no job was created (an unknown machine or runbook, bad parameters, an
    /// approval that doesn't hold); every other end is a job row with its outcome, `JobFinished` and audit rows. A job
    /// that waited the full lock wait for a busy machine ends `failed` with `machine_busy` (AC50). Returns once the job's
    /// outcome is recorded; a detached step that timed out may hold the machine in the background until its own result
    /// is recorded (E55).
    pub async fn run(&self, start: StartJob) -> Result<JobResult, ActionsError> {
        let machine = self.machine(&start.machine_id)?;
        let (rev, runbook) = self.runbook(&start)?;
        check_params(&runbook, &start.params)?;
        // A quarantined machine runs nothing but its release, whoever asks (7.5.6)
        if !quarantining::allowed(&start.name, State::parse(&machine.quarantine).unwrap_or(State::None)) {
            return Err(ActionsError::Quarantined);
        }
        // The approval is checked now and used only once the machine is ours: a busy machine doesn't spend it.
        let approval = start.approval_id.as_ref().map(|id| {
            let request = ApprovalRequest {
                requester: start.requested_by.clone(),
                tool: "run_runbook".into(),
                target: Some(machine.id.clone()),
                args: serde_json::json!({ "name": start.name, "params": start.params }),
                runbook_rev: Some(rev),
                risk: runbook.risk,
                step_up: false,
                reason: String::new(),
            };
            (id.clone(), approval_hash(&request))
        });
        let approvals = Approvals::new(self.inner.db.clone());
        if let Some((id, hash)) = &approval {
            approvals.check(id, &start.requested_by, hash, now_ms()).map_err(ActionsError::Approval)?;
        }
        let job_id = new_id().to_string();
        let params = serde_json::to_string(&start.params).unwrap_or_else(|_| "{}".into());
        let refused_for_disk = self.gate.as_ref().is_some_and(|g| !g.accepting_jobs());
        let guard = if refused_for_disk { None } else { self.inner.locks.acquire(&machine.id, self.lock_wait).await };
        let row = |state| NewJob {
            id: &job_id,
            kind: JobKind::Runbook.as_str(),
            name: &start.name,
            rev: Some(rev),
            target: Some(&machine.id),
            params: &params,
            requested_by: &start.requested_by,
            incident_id: start.incident_id.as_deref(),
            approval_id: start.approval_id.as_deref(),
            state,
            now_ms: now_ms(),
        };
        let Some(guard) = guard else {
            jobs::create(&self.inner.db, &row("queued")).await?;
            // the hub's disk is nearly full (E32), or another job held the machine for the whole wait
            let reason = Some(if refused_for_disk { "disk_low" } else { "machine_busy" }.to_string());
            self.finish(&job_id, &start.requested_by, JobOutcome::Failed, reason.as_deref()).await?;
            return Ok(JobResult { job_id, outcome: JobOutcome::Failed, reason });
        };
        // the state may have changed while this job waited for the machine
        let q_state = self.quarantine_state(&machine.id)?;
        if !quarantining::allowed(&start.name, q_state) {
            return Err(ActionsError::Quarantined);
        }
        if let Some((id, hash)) = &approval {
            // Used now, once; another call may have used it while this one waited.
            approvals.use_approval(id, &start.requested_by, hash, now_ms()).await.map_err(ActionsError::Approval)?;
            self.audit(&start.requested_by, "approval.used", id, serde_json::json!({ "runbook": start.name })).await;
        }
        jobs::create(&self.inner.db, &row("running")).await?;
        self.audit(
            &start.requested_by,
            "job.started",
            &job_id,
            serde_json::json!({ "runbook": start.name, "rev": rev, "machine": machine.id }),
        )
        .await;
        self.quarantine_begin(&start.name, &machine.id, q_state, &job_id, &start.requested_by).await?;
        let (outcome, reason) = match self.run_steps(&job_id, &machine, &runbook, &start.params, guard).await {
            Ok(end) => end,
            Err(e) => {
                // A step row couldn't be written: the job still ends, so nothing waits on it forever.
                let _ = self.finish(&job_id, &start.requested_by, JobOutcome::Failed, Some("store_error")).await;
                let _ = self
                    .quarantine_end(&start.name, &machine.id, &job_id, JobOutcome::Failed, &start.requested_by)
                    .await;
                return Err(e);
            }
        };
        self.finish(&job_id, &start.requested_by, outcome, reason.as_deref()).await?;
        self.quarantine_end(&start.name, &machine.id, &job_id, outcome, &start.requested_by).await?;
        Ok(JobResult { job_id, outcome, reason })
    }

    pub(super) async fn finish(
        &self,
        job_id: &str,
        actor: &str,
        outcome: JobOutcome,
        reason: Option<&str>,
    ) -> Result<(), ActionsError> {
        jobs::finish(&self.inner.db, job_id, outcome, reason, now_ms()).await?;
        self.audit(
            actor,
            "job.finished",
            job_id,
            serde_json::json!({ "outcome": jobs::state_name(outcome), "reason": reason }),
        )
        .await;
        if let Ok(id) = ulid::Ulid::from_string(job_id) {
            self.inner.bus.publish_job_finished(id.to_bytes(), outcome);
        }
        Ok(())
    }

    async fn run_steps(
        &self,
        job_id: &str,
        machine: &Machine,
        runbook: &Runbook,
        params: &BTreeMap<String, String>,
        guard: MachineGuard,
    ) -> Result<(JobOutcome, Option<String>), ActionsError> {
        let awaiting = self.inner.reboots.hold(&machine.id, runbook);
        self.run_steps_from(0, job_id, machine, runbook, params, guard, awaiting).await
    }

    /// The steps from the `from`th on; `awaiting` is the hold on the machine's expected silence, if it has one.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn run_steps_from(
        &self,
        from: usize,
        job_id: &str,
        machine: &Machine,
        runbook: &Runbook,
        params: &BTreeMap<String, String>,
        guard: MachineGuard,
        mut awaiting: Option<super::reboots::Awaiting>,
    ) -> Result<(JobOutcome, Option<String>), ActionsError> {
        let db = &self.inner.db;
        for (i, step) in runbook.steps.iter().enumerate().skip(from) {
            let started_ms = now_ms();
            let step = with_params(step, params);
            let argv = step.cmd.as_deref().map(|c| substitute_argv(c, params));
            let command = argv.as_deref().map(display);
            jobs::step_started(db, job_id, &step.id, command.as_deref(), now_ms()).await?;
            if machine.monitor_only() && step.needs_account() {
                let end = StepEnd {
                    state: "failed",
                    exit_code: None,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    now_ms: now_ms(),
                };
                jobs::step_finished(db, job_id, &step.id, end).await?;
                return Ok((JobOutcome::Failed, Some("monitor_only".into())));
            }
            let timeout = step.timeout_s().map_or(DEFAULT_STEP_TIMEOUT, Duration::from_secs);
            let ctx = StepCtx {
                job_id: job_id.into(),
                machine_id: machine.id.clone(),
                machine_kind: machine.kind.clone(),
                address: machine.address.clone(),
                identity: runbook.identity,
                timeout,
            };
            let attempts = if step.idempotent { step.retries + 1 } else { 1 };
            let mut last = None;
            for _ in 0..attempts {
                let handle = spawn_step(self.inner.runner.clone(), ctx.clone(), step.clone(), argv.clone());
                match wait_step(handle, timeout, step.detached).await {
                    (StepEndState::Done(result), _) => {
                        let ok = result.outcome == StepOutcome::Succeeded;
                        last = Some(result);
                        if ok {
                            break;
                        }
                    }
                    (StepEndState::TimedOut, Some(rest)) => {
                        // Detached: not killed. The job ends now; the machine stays ours until the result is in.
                        let actions = self.clone();
                        let (job, step_id) = (job_id.to_string(), step.id.clone());
                        tokio::spawn(async move {
                            let result = match rest.await {
                                Ok(r) => r,
                                Err(e) if e.is_panic() => StepResult::failed("executor_crashed"),
                                Err(_) => StepResult::failed("cancelled"),
                            };
                            let _ = actions.record_step(&job, &step_id, result).await;
                            drop(guard);
                        });
                        return Ok((JobOutcome::TimedOut, Some("timeout".into())));
                    }
                    (StepEndState::TimedOut, None) => {
                        let end = StepEnd {
                            state: "timed_out",
                            exit_code: None,
                            stdout: Vec::new(),
                            stderr: Vec::new(),
                            now_ms: now_ms(),
                        };
                        jobs::step_finished(db, job_id, &step.id, end).await?;
                        return Ok((JobOutcome::TimedOut, Some("timeout".into())));
                    }
                }
            }
            let mut result = last.unwrap_or_else(|| StepResult::failed("not_run"));
            if step.kind == StepKind::RebootIfRequired && scheduled(&result) {
                if let Some(next) = resume_step(runbook, i) {
                    jobs::resume_at(db, job_id, &next).await?;
                }
                let back = match tokio::time::timeout(timeout, self.inner.runner.rebooted(&ctx, started_ms)).await {
                    Ok(back) => back.outcome,
                    Err(_) => StepOutcome::Failed("timeout".into()),
                };
                result.outcome = back;
            }
            let failed = match &result.outcome {
                StepOutcome::Succeeded => None,
                StepOutcome::Failed(reason) => Some(reason.clone()),
            };
            self.record_step(job_id, &step.id, result).await?;
            if awaiting.as_ref().is_some_and(|a| a.wait == Some(i)) {
                awaiting = None;
            }
            if let Some(reason) = failed {
                return Ok((JobOutcome::Failed, Some(reason)));
            }
        }
        drop(guard);
        Ok((JobOutcome::Succeeded, None))
    }

    pub(super) async fn record_step(
        &self,
        job_id: &str,
        step_id: &str,
        result: StepResult,
    ) -> Result<(), ActionsError> {
        let state = if result.outcome == StepOutcome::Succeeded { "succeeded" } else { "failed" };
        let end = StepEnd {
            state,
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
            now_ms: now_ms(),
        };
        Ok(jobs::step_finished(&self.inner.db, job_id, step_id, end).await?)
    }

    /// Opens an assistant job (the playbook session is its body; 7.3.10). Its `exec` calls take the machine one at a
    /// time like any other job.
    pub async fn open_assistant_job(
        &self,
        playbook: &str,
        requested_by: &str,
        incident_id: Option<&str>,
    ) -> Result<String, ActionsError> {
        let job_id = new_id().to_string();
        jobs::create(
            &self.inner.db,
            &NewJob {
                id: &job_id,
                kind: JobKind::Assistant.as_str(),
                name: playbook,
                rev: None,
                target: None,
                params: "{}",
                requested_by,
                incident_id,
                approval_id: None,
                state: "running",
                now_ms: now_ms(),
            },
        )
        .await?;
        self.audit(requested_by, "job.started", &job_id, serde_json::json!({ "playbook": playbook })).await;
        Ok(job_id)
    }

    /// Assistant jobs whose token's deadline passed more than `grace_ms` ago and that nobody has ended: the operator never
    /// reported, so they end `timed_out`. Returns how many it ended.
    pub async fn sweep_assistant_jobs(&self, now_ms: i64, grace_ms: i64) -> Result<usize, ActionsError> {
        let stale: Vec<String> = self.inner.db.readers().with(|c| {
            let mut s = c.prepare(
                "SELECT j.id FROM jobs j JOIN job_tokens t ON t.job_id = j.id
                 WHERE j.kind = 'assistant' AND j.state = 'running' AND t.expires_at + ?1 < ?2",
            )?;
            s.query_map(rusqlite::params![grace_ms, now_ms], |r| r.get(0))?.collect()
        })?;
        for id in &stale {
            self.finish(id, "hub", JobOutcome::TimedOut, Some("timed_out")).await?;
        }
        Ok(stale.len())
    }

    /// One assistant transcript event (7.3.5): Actions stores them, as it owns `assistant_transcripts`.
    pub async fn append_transcript(
        &self,
        job_id: &str,
        seq: i64,
        at_ms: i64,
        kind: &str,
        text: &str,
    ) -> Result<(), ActionsError> {
        let row: rackhand_store::Row = [
            ("job_id", rusqlite::types::Value::Text(job_id.into())),
            ("seq", rusqlite::types::Value::Integer(seq)),
            ("at_ms", rusqlite::types::Value::Integer(at_ms)),
            ("kind", rusqlite::types::Value::Text(kind.into())),
            ("text", rusqlite::types::Value::Text(text.into())),
        ]
        .into_iter()
        .collect();
        self.inner.db.writer().send(rackhand_store::WriteCmd::AppendTranscript(row)).await?;
        Ok(())
    }

    /// The assistant ends its job (`finish_job`): `resolved` succeeds, anything else fails with that outcome. Its
    /// token stops working, since a token only works while its job runs.
    pub async fn finish_assistant(&self, job_id: &str, outcome: &str, summary: &str) -> Result<(), ActionsError> {
        let running: Option<i64> = self.inner.db.readers().with(|c| {
            c.query_row(
                "SELECT 1 FROM jobs WHERE id = ?1 AND kind = 'assistant' AND state = 'running'",
                [job_id],
                |r| r.get(0),
            )
            .optional()
        })?;
        if running.is_none() {
            return Err(ActionsError::UnknownJob);
        }
        let result = if outcome == "resolved" { JobOutcome::Succeeded } else { JobOutcome::Failed };
        self.audit(
            &format!("job:{job_id}"),
            "job.summary",
            job_id,
            serde_json::json!({ "outcome": outcome, "summary": summary }),
        )
        .await;
        self.finish(job_id, &format!("job:{job_id}"), result, Some(outcome)).await
    }

    /// An assistant `exec` on a machine (7.3.7): the command string as-is, as the assistant identity, recorded as a step
    /// of its job. It waits for the machine like a job does.
    pub async fn exec(
        &self,
        job_id: &str,
        machine_id: &str,
        command: &str,
        timeout: Duration,
    ) -> Result<StepResult, ActionsError> {
        let machine = self.machine(machine_id)?;
        let open: Option<i64> = self.inner.db.readers().with(|c| {
            c.query_row(
                "SELECT 1 FROM jobs WHERE id = ?1 AND kind = 'assistant' AND state = 'running'",
                [job_id],
                |r| r.get(0),
            )
            .optional()
        })?;
        if open.is_none() {
            return Err(ActionsError::UnknownJob);
        }
        if machine.monitor_only() {
            return Err(ActionsError::MonitorOnly);
        }
        let guard = self.inner.locks.acquire(&machine.id, self.lock_wait).await.ok_or(ActionsError::MachineBusy)?;
        // Unique per call: one assistant job may run execs on several machines at once.
        let step_id = format!("exec-{}", new_id().to_string().to_ascii_lowercase());
        jobs::step_started(&self.inner.db, job_id, &step_id, Some(command), now_ms()).await?;
        self.audit(&format!("job:{job_id}"), "assistant.exec", &machine.id, serde_json::json!({ "command": command }))
            .await;
        let ctx = StepCtx {
            job_id: job_id.into(),
            machine_id: machine.id.clone(),
            machine_kind: machine.kind.clone(),
            address: machine.address.clone(),
            identity: Identity::Assistant,
            timeout,
        };
        let runner = self.inner.runner.clone();
        let cmd = command.to_string();
        let handle = tokio::spawn(async move { runner.exec(&ctx, &cmd).await });
        let result = match wait_step(handle, timeout, false).await {
            (StepEndState::Done(r), _) => r,
            (StepEndState::TimedOut, _) => StepResult::failed("timeout"),
        };
        self.record_step(job_id, &step_id, result.clone()).await?;
        drop(guard);
        Ok(result)
    }
}

/// A reboot step's command only set the reboot's time.
fn scheduled(result: &StepResult) -> bool {
    result.outcome == StepOutcome::Succeeded
        && serde_json::from_slice::<serde_json::Value>(&result.stdout).is_ok_and(|v| v["reboot"] == "scheduled")
}

/// Where a restarted hub goes on after the reboot step `reboot`: the next verify step, or the next step at all.
fn resume_step(runbook: &Runbook, reboot: usize) -> Option<String> {
    let rest = runbook.steps.get(reboot + 1..)?;
    rest.iter().find(|s| s.kind == StepKind::Verify).or(rest.first()).map(|s| s.id.clone())
}

fn spawn_step(
    runner: Arc<dyn StepRunner>,
    ctx: StepCtx,
    step: Step,
    argv: Option<Vec<String>>,
) -> tokio::task::JoinHandle<StepResult> {
    tokio::spawn(async move { runner.run(&ctx, &step, argv.as_deref()).await })
}

/// Waits for a step up to its timeout. A plain step is stopped at the timeout; a detached one keeps running and is
/// handed back so its result can still be recorded.
async fn wait_step(
    mut handle: tokio::task::JoinHandle<StepResult>,
    timeout: Duration,
    detached: bool,
) -> (StepEndState, Option<tokio::task::JoinHandle<StepResult>>) {
    match tokio::time::timeout(timeout, &mut handle).await {
        Ok(Ok(result)) => (StepEndState::Done(result), None),
        // A crash inside the step is a crash of the job; its step row stays `running` for recovery (E44).
        Ok(Err(e)) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Ok(Err(_)) => (StepEndState::Done(StepResult::failed("cancelled")), None),
        Err(_) if detached => (StepEndState::TimedOut, Some(handle)),
        Err(_) => {
            handle.abort();
            (StepEndState::TimedOut, None)
        }
    }
}

/// Every declared parameter is given and valid, and nothing undeclared is.
fn check_params(runbook: &Runbook, params: &BTreeMap<String, String>) -> Result<(), ActionsError> {
    if let Some(extra) = params.keys().find(|k| !runbook.params.contains_key(*k)) {
        return Err(ActionsError::InvalidParam(extra.clone(), "not a parameter of the runbook".into()));
    }
    for (name, param) in &runbook.params {
        let value = params.get(name).ok_or_else(|| ActionsError::InvalidParam(name.clone(), "missing".into()))?;
        check_value(param, value).map_err(|e| ActionsError::InvalidParam(name.clone(), e.to_string()))?;
    }
    Ok(())
}
