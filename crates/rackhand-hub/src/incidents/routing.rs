//! Routing an incident to a runbook (7.5.2, 7.6.8): the most specific automatic runbook for its kind starts through
//! `StartJob` as the policy allows (level 0 tells a person, level 1 waits for an approval, 2 and 3 run). A job that
//! succeeds isn't the end: the incident waits 10 minutes for its condition to clear, then goes on as if the job had
//! failed. Automatic starts are limited per incident (across reopens) in any 24 hours; past the limit a person gets the
//! incident with "attempt limit reached". Playbooks after a failed runbook come with T78; until then a person does.
//!
//! What happened is kept in the incident's events (`runbook.started`, `runbook.succeeded`), so the limits and the wait
//! survive a restart.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use rackhand_detect::rules::Severity;
use rackhand_runbook::runbook::{Identity, Runbook, StepKind};
use rackhand_store::Db;
use rusqlite::OptionalExtension;

use super::lifecycle::{IncidentRow, Opening, State, by_id};
use super::{Incidents, IncidentsError, notes};
use crate::actions::StartJob;
use crate::bus::{BusEvent, Delivery, JobOutcome, Subscription};
use crate::library::items::{Kind, Library};
use crate::policy::approvals::{ApprovalRequest, Approvals};
use crate::policy::decide::{Access, Action, Decision, Deny, Request, Requester, Target, decide};

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// How long a succeeded job's incident waits for its condition to clear (7.8.1).
pub const CLEAR_WAIT_MS: i64 = 10 * 60_000;
/// Automatic runbook starts per incident in any 24 hours (7.8.1).
pub const MAX_AUTOMATIC_STARTS: i64 = 2;
const ATTEMPT_WINDOW_MS: i64 = 24 * 3_600_000;
/// An approval routing asks for, as an MCP call's (7.6.8).
const APPROVAL_TTL_MS: i64 = 60 * 60_000;
const BY: &str = "rackhand";
const STARTED: &str = "runbook.started";
const SUCCEEDED: &str = "runbook.succeeded";
const TICK: Duration = Duration::from_secs(30);

/// Starts a job; the future ends when the job does. `Err` means no job was started (the job's end otherwise comes as
/// `JobFinished`).
pub trait JobStarter: Send + Sync + std::fmt::Debug {
    fn start(&self, job: StartJob) -> BoxFuture<Result<(), String>>;
}

/// What a runbook's targets are matched against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineFacts {
    pub name: String,
    pub kind: String,
    pub tags: Vec<String>,
    pub roles: Vec<String>,
}

/// How specifically a runbook targets the machine: 0 by name, 1 by one of its tags or roles, 2 by its kind, 3 a
/// general runbook (no targets); none when its targets leave the machine out.
fn specificity(rb: &Runbook, m: &MachineFacts) -> Option<u8> {
    let t = &rb.targets;
    if t.machines.contains(&m.name) {
        return Some(0);
    }
    if t.tags.iter().any(|x| m.tags.contains(x)) || t.roles.iter().any(|x| m.roles.contains(x)) {
        return Some(1);
    }
    if t.kinds.contains(&m.kind) {
        return Some(2);
    }
    (t.machines.is_empty() && t.tags.is_empty() && t.roles.is_empty() && t.kinds.is_empty()).then_some(3)
}

/// The runbook that starts for an incident of `kind` on the machine: automatic triggers for that kind, the most
/// specific match, ties to the name that sorts first (7.5.2).
pub fn choose<'a>(runbooks: &'a [Runbook], kind: &str, m: &MachineFacts) -> Option<&'a Runbook> {
    runbooks
        .iter()
        .filter(|r| r.triggers.as_ref().is_some_and(|t| t.auto && t.incident_kinds.iter().any(|k| k == kind)))
        .filter_map(|r| specificity(r, m).map(|s| (s, r)))
        .min_by(|(a, ra), (b, rb)| a.cmp(b).then_with(|| ra.name.cmp(&rb.name)))
        .map(|(_, r)| r)
}

#[derive(Debug, Clone)]
pub struct Routing {
    incidents: Incidents,
    starter: Arc<dyn JobStarter>,
}

struct Machine {
    facts: MachineFacts,
    access: Access,
}

fn json_list(text: &str) -> Vec<String> {
    serde_json::from_str(text).unwrap_or_default()
}

fn requester(incident_id: &str) -> String {
    format!("incident:{incident_id}")
}

impl Routing {
    pub fn new(incidents: Incidents, starter: Arc<dyn JobStarter>) -> Routing {
        Routing { incidents, starter }
    }

    fn db(&self) -> &Db {
        &self.incidents.inner.db
    }

    fn machine(&self, id: &str) -> Result<Option<Machine>, IncidentsError> {
        let found = self.db().readers().with(|c| {
            c.query_row("SELECT name, kind, tags, roles, access FROM machines WHERE id = ?1", [id], |r| {
                let (tags, roles, access): (String, String, String) = (r.get(2)?, r.get(3)?, r.get(4)?);
                Ok(Machine {
                    facts: MachineFacts {
                        name: r.get(0)?,
                        kind: r.get(1)?,
                        tags: json_list(&tags),
                        roles: json_list(&roles),
                    },
                    access: if access == "monitor" { Access::Monitor } else { Access::Managed },
                })
            })
            .optional()
        })?;
        Ok(found)
    }

    fn runbooks(&self) -> Vec<Runbook> {
        Library::all_current(self.db())
            .unwrap_or_default()
            .into_iter()
            .filter(|(kind, _, _)| *kind == Kind::Runbook)
            .filter_map(|(_, _, text)| Runbook::parse(&text).ok())
            .collect()
    }

    /// Automatic starts for the incident in the 24 hours before `now_ms`, across its reopens.
    fn attempts(&self, incident_id: &str, now_ms: i64) -> Result<i64, IncidentsError> {
        Ok(self.db().readers().with(|c| {
            c.query_row(
                "SELECT count(*) FROM incident_events WHERE incident_id = ?1 AND kind = ?2 AND at_ms > ?3",
                rusqlite::params![incident_id, STARTED, now_ms - ATTEMPT_WINDOW_MS],
                |r| r.get(0),
            )
        })?)
    }

    async fn note(&self, incident_id: &str, text: &str, now_ms: i64) {
        if let Err(e) = notes::add_note(self.db(), incident_id, text, BY, now_ms).await {
            tracing::warn!(error = %e, incident = incident_id, "routing note");
        }
    }

    /// A person takes it from here, told why.
    async fn to_person(&self, incident_id: &str, why: &str, now_ms: i64) -> Result<(), IncidentsError> {
        self.note(incident_id, why, now_ms).await;
        self.incidents.set_state(incident_id, State::Human, now_ms).await
    }

    async fn mark(
        &self,
        inc: &IncidentRow,
        kind: &str,
        data: serde_json::Value,
        now_ms: i64,
    ) -> Result<(), IncidentsError> {
        self.incidents.write(inc, kind, data, now_ms).await
    }

    /// Routes an open incident: a runbook if one matches and the policy allows, else a person.
    pub async fn route(&self, incident_id: &str, now_ms: i64) -> Result<(), IncidentsError> {
        let inc = by_id(self.db(), incident_id)?;
        if inc.state != State::Open {
            return Ok(());
        }
        let machine = match &inc.machine_id {
            Some(id) => self.machine(id)?,
            None => None,
        };
        let (Some(machine_id), Some(machine)) = (inc.machine_id.clone(), machine) else {
            return self.incidents.set_state(incident_id, State::Human, now_ms).await;
        };
        let runbooks = self.runbooks();
        let Some(rb) = choose(&runbooks, &inc.kind, &machine.facts) else {
            return self.incidents.set_state(incident_id, State::Human, now_ms).await;
        };
        if self.attempts(incident_id, now_ms)? >= MAX_AUTOMATIC_STARTS {
            let why = format!(
                "attempt limit reached: runbook `{}` started {MAX_AUTOMATIC_STARTS} times for this incident in 24 hours",
                rb.name
            );
            return self.to_person(incident_id, &why, now_ms).await;
        }
        let rev = Library::current_in(self.db(), Kind::Runbook, &rb.name).ok().flatten().map(|(rev, _)| rev);
        let needs_account = rb.steps.iter().any(|s| matches!(s.kind, StepKind::Ssh | StepKind::Transfer));
        let commands: Vec<String> = if rb.identity == Identity::Assistant {
            rb.steps.iter().filter_map(|s| s.cmd.as_ref()).map(|c| c.join(" ")).collect()
        } else {
            Vec::new()
        };
        let commands: Vec<&str> = commands.iter().map(String::as_str).collect();
        let roles: Vec<&str> = machine.facts.roles.iter().map(String::as_str).collect();
        let tags: Vec<&str> = machine.facts.tags.iter().map(String::as_str).collect();
        let request = Request {
            requester: Requester::Local,
            action: Action::Runbook { risk: rb.risk, level: rb.autonomy, needs_account, assistant_commands: &commands },
            target: Target { access: machine.access, roles: &roles, tags: &tags },
            peer_auto: false,
            auto_rollback: false,
        };
        let mut job = StartJob::runbook(&rb.name, &machine_id, &requester(incident_id));
        job.rev = rev;
        job.incident_id = Some(incident_id.to_string());
        match decide(&request) {
            Decision::Allow => self.start(inc, job, now_ms).await,
            Decision::NeedsApproval { risk, step_up } => {
                let approval = ApprovalRequest {
                    requester: job.requested_by.clone(),
                    tool: "run_runbook".into(),
                    target: Some(machine_id.clone()),
                    args: serde_json::json!({ "name": job.name, "params": job.params }),
                    runbook_rev: rev,
                    risk,
                    step_up,
                    reason: format!("incident: {}", inc.title),
                };
                let id = match Approvals::new(self.incidents.inner.db.clone())
                    .create(&approval, now_ms, APPROVAL_TTL_MS)
                    .await
                {
                    Ok(id) => id,
                    Err(e) => {
                        return self
                            .to_person(
                                incident_id,
                                &format!("runbook `{}` couldn't ask for an approval: {e}", rb.name),
                                now_ms,
                            )
                            .await;
                    }
                };
                let mut inc = inc;
                inc.state = State::Automation;
                self.mark(&inc, "runbook.approval", serde_json::json!({ "runbook": rb.name, "approval": id }), now_ms)
                    .await?;
                self.note(incident_id, &format!("runbook `{}` waits for an approval", rb.name), now_ms).await;
                Ok(())
            }
            Decision::Deny(Deny::TellOnly) => {
                let why = format!("level 0: runbook `{}` would run ({}); nothing was run", rb.name, rb.description);
                self.to_person(incident_id, &why, now_ms).await
            }
            Decision::Deny(deny) => {
                let why = match deny {
                    Deny::MonitorOnly => "the machine is at access level monitor",
                    _ => "the policy doesn't allow it",
                };
                self.to_person(incident_id, &format!("runbook `{}` can't run: {why}", rb.name), now_ms).await
            }
        }
    }

    /// Records the start and asks for the job; a start that fails goes to a person.
    async fn start(&self, mut inc: IncidentRow, job: StartJob, now_ms: i64) -> Result<(), IncidentsError> {
        inc.state = State::Automation;
        let data = serde_json::json!({ "runbook": job.name, "approval": job.approval_id });
        self.mark(&inc, STARTED, data, now_ms).await?;
        let (name, id) = (job.name.clone(), inc.id.clone());
        let pending = self.starter.start(job);
        let this = self.clone();
        tokio::spawn(async move {
            if let Err(e) = pending.await {
                let now = rackhand_store::ids::now_ms();
                let _ = this.to_person(&id, &format!("runbook `{name}` didn't start: {e}"), now).await;
            }
        });
        Ok(())
    }

    /// A job ended. One routing started moves its incident on; any job that timed out opens an incident on its
    /// machine (E55).
    pub async fn job_finished(&self, job_id: &str, outcome: JobOutcome, now_ms: i64) -> Result<(), IncidentsError> {
        type JobRow = (String, Option<String>, String, Option<String>);
        let row: Option<JobRow> = self.db().readers().with(|c| {
            c.query_row("SELECT name, target, requested_by, incident_id FROM jobs WHERE id = ?1", [job_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .optional()
        })?;
        let Some((name, target, requested_by, incident_id)) = row else { return Ok(()) };
        if outcome == JobOutcome::TimedOut {
            if let Some(machine) = &target {
                let o = Opening {
                    machine_id: Some(machine.clone()),
                    rule_id: None,
                    dedupe_key: format!("{machine}:job.timed_out:{job_id}"),
                    kind: "job.timed_out".into(),
                    severity: Severity::Warning,
                    title: format!("Job {name} timed out"),
                };
                self.incidents.open(o, now_ms).await?;
            }
        }
        let Some(incident_id) = incident_id.filter(|i| requested_by == requester(i)) else { return Ok(()) };
        let inc = by_id(self.db(), &incident_id)?;
        if inc.state == State::Resolved {
            return Ok(());
        }
        if outcome == JobOutcome::Succeeded {
            return self.mark(&inc, SUCCEEDED, serde_json::json!({ "runbook": name, "job": job_id }), now_ms).await;
        }
        let ended = match outcome {
            JobOutcome::TimedOut => "timed out",
            JobOutcome::Cancelled => "was cancelled",
            JobOutcome::Interrupted => "was interrupted",
            _ => "failed",
        };
        self.to_person(&incident_id, &format!("runbook `{name}` {ended} (job {job_id})"), now_ms).await
    }

    fn recorded_outcome(&self, job_id: &str) -> Option<JobOutcome> {
        let state: Option<String> = self
            .db()
            .readers()
            .with(|c| c.query_row("SELECT state FROM jobs WHERE id = ?1", [job_id], |r| r.get(0)).optional())
            .ok()
            .flatten();
        match state.as_deref()? {
            "succeeded" => Some(JobOutcome::Succeeded),
            "failed" => Some(JobOutcome::Failed),
            "cancelled" => Some(JobOutcome::Cancelled),
            "timed_out" => Some(JobOutcome::TimedOut),
            "interrupted" => Some(JobOutcome::Interrupted),
            _ => None,
        }
    }

    /// A person decided an approval routing asked for: approved, the job starts with it; rejected, a person has it.
    pub async fn approval_decided(&self, approval_id: &str, approved: bool, now_ms: i64) -> Result<(), IncidentsError> {
        type ApprovalRow = (String, Option<String>, String, Option<i64>);
        let row: Option<ApprovalRow> = self.db().readers().with(|c| {
            c.query_row(
                "SELECT requested_by, target, args, runbook_rev FROM approvals WHERE id = ?1",
                [approval_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
        })?;
        let Some((requested_by, Some(machine), args, rev)) = row else { return Ok(()) };
        let Some(incident_id) = requested_by.strip_prefix("incident:") else { return Ok(()) };
        let inc = by_id(self.db(), incident_id)?;
        if inc.state == State::Resolved {
            return Ok(());
        }
        let args: serde_json::Value = serde_json::from_str(&args).unwrap_or_default();
        let name = args["name"].as_str().unwrap_or_default().to_string();
        if !approved {
            return self
                .to_person(incident_id, &format!("the approval to run runbook `{name}` was rejected"), now_ms)
                .await;
        }
        let mut job = StartJob::runbook(&name, &machine, &requested_by);
        job.rev = rev;
        job.incident_id = Some(incident_id.to_string());
        job.approval_id = Some(approval_id.to_string());
        self.start(inc, job, now_ms).await
    }

    /// Incidents whose runbook succeeded but whose condition hasn't cleared in 10 minutes go on as failed.
    pub async fn tick(&self, now_ms: i64) -> Result<(), IncidentsError> {
        let waiting: Vec<(String, String)> = self.db().readers().with(|c| {
            let mut s = c.prepare(
                "SELECT i.id, coalesce(json_extract(e.data, '$.runbook'), '') FROM incidents i
                 JOIN incident_events e ON e.incident_id = i.id
                 WHERE i.state = 'automation' AND e.kind = ?1 AND e.at_ms <= ?2
                   AND NOT EXISTS (SELECT 1 FROM incident_events s WHERE s.incident_id = i.id AND s.kind = ?3
                                   AND s.at_ms > e.at_ms)",
            )?;
            s.query_map(rusqlite::params![SUCCEEDED, now_ms - CLEAR_WAIT_MS, STARTED], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect()
        })?;
        for (id, runbook) in waiting {
            let why = format!("the condition persists 10 minutes after runbook `{runbook}` succeeded");
            self.to_person(&id, &why, now_ms).await?;
        }
        Ok(())
    }

    /// Runs until the bus is gone: routes opened and reopened incidents, follows the jobs and approvals routing asked
    /// for, and checks the waits every 30 s.
    pub fn spawn(self, mut sub: Subscription) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(TICK);
            loop {
                tokio::select! {
                    delivery = sub.recv() => {
                        let Some(delivery) = delivery else { return };
                        let now = rackhand_store::ids::now_ms();
                        let result = match delivery {
                            Delivery::Event(BusEvent::IncidentChanged { id }) => {
                                self.route(&ulid::Ulid::from_bytes(id).to_string(), now).await
                            }
                            Delivery::Event(BusEvent::JobFinished { job, outcome }) => {
                                self.job_finished(&ulid::Ulid::from_bytes(job).to_string(), outcome, now).await
                            }
                            Delivery::Event(BusEvent::ApprovalDecided { id, approved }) => {
                                self.approval_decided(&ulid::Ulid::from_bytes(id).to_string(), approved, now).await
                            }
                            _ => Ok(()),
                        };
                        if let Err(e) = result {
                            tracing::warn!(error = %e, "routing");
                        }
                    }
                    _ = tick.tick() => {
                        let now = rackhand_store::ids::now_ms();
                        // jobs whose JobFinished didn't fit the queue: their outcome is in their row
                        for job in sub.take_missed_jobs() {
                            let id = ulid::Ulid::from_bytes(job).to_string();
                            if let Some(outcome) = self.recorded_outcome(&id) {
                                let _ = self.job_finished(&id, outcome, now).await;
                            }
                        }
                        if let Err(e) = self.tick(now).await {
                            tracing::warn!(error = %e, "routing waits");
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
#[path = "routing_tests.rs"]
mod tests;
