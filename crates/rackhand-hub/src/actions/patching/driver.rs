//! The window driver (7.5.3 steps 2 and 3): told which windows are open, it selects their machines (`select`), asks for
//! the approvals approve-only machines need, starts each machine's patch runbook at its turn, and tries offline machines
//! again. A machine is tried once per window; a hub that restarts during a window leaves out the machines that had a
//! job in it.
//!
//! An approval binds the runbook's current revision (Actions checks it when the job starts). It can be decided until
//! the end of the next window: given while its window is open it starts the job, and given later it carries to the
//! next window, which doesn't ask again (D89).
//!
//! A machine that never reported after its patch's reboot is rolled back to the snapshot the job took under D45
//! (`rollback`), by the `rollback` runbook; the machine stays the window's until that ends.
//!
//! Until their runbooks exist, roles `hypervisor` and `hub` (T60) and kind `windows` (T90) are left out.

use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rackhand_runbook::runbook::{Risk, Runbook};
use rackhand_store::Db;
use rusqlite::OptionalExtension;
use tokio::sync::Mutex;

use super::rollback::{Failure, rolls_back};
pub use super::select::Window;
use super::select::{Candidate, DEFAULT_PER_SITE, Order, Others, PatchMode, Run};
use crate::actions::{Actions, ActionsError, JobResult, StartJob};
use crate::policy::approvals::{ApprovalRequest, Approvals};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Who a patch job is requested by.
pub const REQUESTER: &str = "schedule:patch";

/// What the driver asks about machines.
pub trait World: Send + Sync {
    fn online(&self, id: &str, now_ms: i64) -> bool;
    /// Updates pending: security ones, and all.
    fn pending(&self, id: &str) -> (u32, u32);
    fn in_maintenance(&self, id: &str, tags: &[String], now_ms: i64) -> bool;
}

/// Runs a job to its end.
pub trait Jobs: Send + Sync {
    fn run(&self, job: StartJob) -> BoxFuture<'static, Result<JobResult, ActionsError>>;
}

impl Jobs for Actions {
    fn run(&self, job: StartJob) -> BoxFuture<'static, Result<JobResult, ActionsError>> {
        let actions = self.clone();
        Box::pin(async move { Actions::run(&actions, job).await })
    }
}

/// A policy's window open at a site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenWindow {
    pub policy: String,
    pub site: String,
    pub window: Window,
    pub starts_ms: i64,
    pub ends_ms: i64,
    /// When the window after this one ends: how long an approval can be decided.
    pub next_ends_ms: i64,
}

impl OpenWindow {
    fn same(&self, o: &OpenWindow) -> bool {
        self.policy == o.policy && self.site == o.site && self.window == o.window && self.starts_ms == o.starts_ms
    }
}

struct Active {
    open: OpenWindow,
    run: Run,
    machines: BTreeMap<String, Selected>,
}

struct Selected {
    runbook: &'static str,
    /// Its policy asks for approval.
    ask: bool,
    tags: Vec<String>,
}

#[derive(Default)]
struct State {
    runs: Vec<Active>,
    inflight: HashSet<String>,
}

pub struct Driver {
    db: Arc<Db>,
    world: Arc<dyn World>,
    jobs: Arc<dyn Jobs>,
    state: Mutex<State>,
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Driver").finish_non_exhaustive()
    }
}

/// The patch runbook of a machine, if there is one for it.
fn runbook_for(kind: &str, roles: &[String]) -> Option<&'static str> {
    if roles.iter().any(|r| r == "hypervisor" || r == "hub") {
        return None;
    }
    match kind {
        "linux" => Some("patch-debian"),
        "alpine" => Some("patch-alpine"),
        _ => None,
    }
}

/// The approval a machine's patch job needs, as Actions checks it.
pub fn request(name: &str, machine: &str, rev: i64, risk: Risk) -> ApprovalRequest {
    ApprovalRequest {
        requester: REQUESTER.into(),
        tool: "run_runbook".into(),
        target: Some(machine.into()),
        args: serde_json::json!({ "name": name, "params": {} }),
        runbook_rev: Some(rev),
        risk,
        step_up: false,
        reason: "updates are pending and the machine's policy asks before patching".into(),
    }
}

impl Driver {
    pub fn new(db: Arc<Db>, world: Arc<dyn World>, jobs: Arc<dyn Jobs>) -> Arc<Driver> {
        Arc::new(Driver { db, world, jobs, state: Mutex::default() })
    }

    /// Whether a patch job the driver started on the machine hasn't ended.
    pub async fn busy(&self, machine: &str) -> bool {
        self.state.lock().await.inflight.contains(machine)
    }

    fn runbook(&self, name: &str) -> Option<(i64, Risk)> {
        let (rev, text): (i64, String) = self
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT i.rev, r.content FROM library_items i
                     JOIN library_revisions r ON r.kind = i.kind AND r.name = i.name AND r.rev = i.rev
                     WHERE i.kind = 'runbook' AND i.name = ?1",
                    [name],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
            })
            .ok()
            .flatten()?;
        Runbook::parse(&text).ok().map(|r| (rev, r.risk))
    }

    /// The machine's newest approval for this runbook revision that can still be decided or used, with its state.
    fn approval(&self, runbook: &str, machine: &str, rev: i64, now_ms: i64) -> Option<(String, String)> {
        self.db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT id, state FROM approvals WHERE requested_by = ?1 AND target = ?2 AND runbook_rev = ?3
                       AND json_extract(args, '$.name') = ?4 AND expires_at > ?5 AND state != 'used'
                     ORDER BY id DESC LIMIT 1",
                    rusqlite::params![REQUESTER, machine, rev, runbook, now_ms],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
            })
            .ok()
            .flatten()
    }

    fn approved(&self, runbook: &str, machine: &str, now_ms: i64) -> Option<String> {
        let (rev, _) = self.runbook(runbook)?;
        self.approval(runbook, machine, rev, now_ms).filter(|(_, state)| state == "approved").map(|(id, _)| id)
    }

    /// The window's machines, leaving out those with no patch runbook and those already tried in it.
    fn select(&self, open: &OpenWindow, now_ms: i64) -> rusqlite::Result<Active> {
        type Row = (String, String, String, String, String, String, String);
        let rows: Vec<Row> = self.db.readers().with(|c| {
            let mut s = c.prepare(
                "SELECT m.id, m.kind, m.access, m.roles, m.tags, m.quarantine, p.patch
                 FROM machines m JOIN policies p ON p.id = m.policy_id
                 WHERE m.policy_id = ?1 AND m.site_id = ?2 AND m.state = 'enrolled'
                   AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.target = m.id AND j.requested_by = ?3
                                   AND coalesce(j.started_at, j.ended_at) >= ?4)
                 ORDER BY m.name",
            )?;
            s.query_map(rusqlite::params![open.policy, open.site, REQUESTER, open.starts_ms], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
            })?
            .collect()
        })?;
        let mut machines = BTreeMap::new();
        let mut candidates = Vec::new();
        for (id, kind, access, roles, tags, quarantine, patch) in rows {
            let roles: Vec<String> = serde_json::from_str(&roles).unwrap_or_default();
            let tags: Vec<String> = serde_json::from_str(&tags).unwrap_or_default();
            let Some(runbook) = runbook_for(&kind, &roles) else { continue };
            let patch = PatchMode::parse(&patch);
            let (pending_security, pending_total) = self.world.pending(&id);
            let ask = patch == PatchMode::ApproveOnly;
            candidates.push(Candidate {
                approved: ask && self.approved(runbook, &id, now_ms).is_some(),
                site: open.site.clone(),
                kind,
                roles,
                managed: access == "managed",
                patch,
                pending_security,
                pending_total,
                in_maintenance: self.world.in_maintenance(&id, &tags, now_ms),
                quarantined: quarantine != "none",
                id: id.clone(),
            });
            machines.insert(id, Selected { runbook, ask, tags });
        }
        let run = Run::new(open.window, open.starts_ms, open.ends_ms, candidates, DEFAULT_PER_SITE);
        Ok(Active { open: open.clone(), run, machines })
    }

    /// Takes up newly open windows and does what each run asks for now.
    pub async fn tick(self: &Arc<Driver>, open: Vec<OpenWindow>, now_ms: i64) {
        let mut state = self.state.lock().await;
        state.runs.retain(|a| !a.run.ended(now_ms) || !a.run.running_by_site().is_empty());
        for w in open {
            if state.runs.iter().any(|a| a.open.same(&w)) {
                continue;
            }
            match self.select(&w, now_ms) {
                Ok(active) => state.runs.push(active),
                Err(e) => tracing::warn!(error = %e, policy = %w.policy, "patch window selection"),
            }
        }
        for i in 0..state.runs.len() {
            let a = &mut state.runs[i];
            for id in a.run.waiting_approval() {
                if let Some(m) = a.machines.get(&id) {
                    if self.approved(m.runbook, &id, now_ms).is_some() {
                        a.run.approved(&id, now_ms);
                    }
                }
            }
            let mut others = Others::default();
            for (_, o) in state.runs.iter().enumerate().filter(|(j, _)| *j != i) {
                for (site, n) in o.run.running_by_site() {
                    *others.running.entry(site).or_default() += n;
                }
                if !o.run.ended(now_ms) {
                    others.waiting.extend(o.run.waiting_sites());
                }
            }
            // A machine whose maintenance window started since the selection waits as an offline one does (AC20).
            let world = self.world.clone();
            let Active { run, machines, .. } = &mut state.runs[i];
            let available = |id: &str| {
                world.online(id, now_ms) && !machines.get(id).is_some_and(|m| world.in_maintenance(id, &m.tags, now_ms))
            };
            let orders = run.step_with(now_ms, available, &others);
            for order in orders {
                match order {
                    Order::AskApproval { id, .. } => {
                        let a = &state.runs[i];
                        if let Some(m) = a.machines.get(&id) {
                            self.ask(m.runbook, &id, &a.open, now_ms).await;
                        }
                    }
                    Order::Start(id) => self.start(&mut state, i, id, now_ms),
                }
            }
        }
    }

    /// Asks for a machine's approval, unless one can still be decided or was rejected in this window.
    async fn ask(&self, runbook: &str, machine: &str, open: &OpenWindow, now_ms: i64) {
        let Some((rev, risk)) = self.runbook(runbook) else {
            tracing::warn!(%runbook, "patch window: no such runbook");
            return;
        };
        if let Some((id, state)) = self.approval(runbook, machine, rev, now_ms) {
            let asked_ms = id.parse::<ulid::Ulid>().map_or(0, |u| u.timestamp_ms() as i64);
            if state != "rejected" || asked_ms >= open.starts_ms {
                return;
            }
        }
        let made = Approvals::new(self.db.clone())
            .create(&request(runbook, machine, rev, risk), now_ms, open.next_ends_ms - now_ms)
            .await;
        if let Err(e) = made {
            tracing::warn!(error = %e, %machine, "patch approval");
        }
    }

    /// D45: whether the machine's failed patch is rolled back.
    fn must_roll_back(&self, machine: &str, result: &JobResult) -> bool {
        let no_report_after_reboot = result.outcome != crate::bus::JobOutcome::Succeeded
            && result.reason.as_deref() == Some(crate::actions::patching::NO_REPORT_AFTER_REBOOT);
        if !no_report_after_reboot {
            return false;
        }
        let policy: Option<(bool, bool)> = self
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT p.auto_rollback, EXISTS (SELECT 1 FROM json_each(m.roles) WHERE value = 'hub')
                     FROM machines m JOIN policies p ON p.id = m.policy_id WHERE m.id = ?1",
                    [machine],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
            })
            .ok()
            .flatten();
        let Some((auto_rollback, hub)) = policy else { return false };
        let outputs: Vec<Vec<u8>> = self
            .db
            .readers()
            .with(|c| {
                let mut s = c.prepare("SELECT stdout FROM job_steps WHERE job_id = ?1 AND stdout IS NOT NULL")?;
                s.query_map([&result.job_id], |r| r.get(0))?.collect()
            })
            .unwrap_or_default();
        let snapshot_taken = outputs
            .iter()
            .filter_map(|o| serde_json::from_slice::<serde_json::Value>(o).ok())
            .any(|v| v["snapshot"].is_string());
        rolls_back(&Failure { no_report_after_reboot, auto_rollback, hub, snapshot_taken })
    }

    fn start(self: &Arc<Driver>, state: &mut State, run: usize, machine: String, now_ms: i64) {
        let a = &mut state.runs[run];
        let Some((runbook, ask)) = a.machines.get(&machine).map(|m| (m.runbook, m.ask)) else { return };
        // another window's run has it already
        if !state.inflight.insert(machine.clone()) {
            a.run.finished(&machine);
            return;
        }
        let mut job = StartJob::runbook(runbook, &machine, REQUESTER);
        if ask {
            job.approval_id = self.approved(runbook, &machine, now_ms);
            if job.approval_id.is_none() {
                state.inflight.remove(&machine);
                a.run.finished(&machine);
                return;
            }
        }
        let (driver, window) = (self.clone(), a.open.clone());
        let running = self.jobs.run(job);
        tokio::spawn(async move {
            let result = running.await;
            match &result {
                Err(e) => tracing::warn!(error = %e, %machine, "patch job not started"),
                Ok(r) if driver.must_roll_back(&machine, r) => {
                    let mut back = StartJob::runbook("rollback", &machine, REQUESTER);
                    back.params.insert("job".into(), r.job_id.clone());
                    match driver.jobs.run(back).await {
                        Ok(b) => tracing::warn!(%machine, outcome = ?b.outcome, "rolled back after a failed patch"),
                        Err(e) => tracing::error!(error = %e, %machine, "rollback not started"),
                    }
                }
                Ok(_) => {}
            }
            let mut state = driver.state.lock().await;
            state.inflight.remove(&machine);
            if let Some(a) = state.runs.iter_mut().find(|a| a.open.same(&window)) {
                a.run.finished(&machine);
            }
        });
    }
}

#[cfg(test)]
#[path = "driver_tests.rs"]
mod tests;
