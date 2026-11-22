//! The single coordinator for every job (7.2, Actions; 7.3.7; FR-12). Actions owns `jobs`, `job_steps` and
//! `assistant_transcripts`, runs one job per machine at a time (a second waits up to 60 s, then fails `machine_busy`),
//! records each step before it runs, and publishes `JobFinished` on the Bus.

mod coordinator;
pub mod diagnostics;
pub mod jobs;
mod locks;
pub mod patching;
mod reboots;
mod recovery;
pub mod runner;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rackhand_store::Db;

use crate::audit::Audit;
use crate::bus::{Bus, JobOutcome};
use crate::policy::approvals::ApprovalError;
use runner::StepRunner;

/// How long a job waits for its machine (AC50).
pub const DEFAULT_LOCK_WAIT: Duration = Duration::from_secs(60);
/// A step without its own `timeout`.
pub const DEFAULT_STEP_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    Runbook,
    Assistant,
}

impl JobKind {
    fn as_str(self) -> &'static str {
        match self {
            JobKind::Runbook => "runbook",
            JobKind::Assistant => "assistant",
        }
    }
}

/// A request to run a runbook on a machine, from a person, a schedule, Incidents or the assistant (7.3.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartJob {
    pub kind: JobKind,
    pub name: String,
    /// The runbook revision; the current one when `None`.
    pub rev: Option<i64>,
    pub machine_id: String,
    pub params: BTreeMap<String, String>,
    /// `user:<name>`, `job:<id>`, `schedule:<kind>`, ... as the audit log names actors.
    pub requested_by: String,
    pub incident_id: Option<String>,
    /// An approval for exactly this call; it is used up when the job starts.
    pub approval_id: Option<String>,
}

impl StartJob {
    /// A runbook job on a machine at the runbook's current revision, with no parameters.
    pub fn runbook(name: &str, machine_id: &str, requested_by: &str) -> StartJob {
        StartJob {
            kind: JobKind::Runbook,
            name: name.into(),
            rev: None,
            machine_id: machine_id.into(),
            params: BTreeMap::new(),
            requested_by: requested_by.into(),
            incident_id: None,
            approval_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobResult {
    pub job_id: String,
    pub outcome: JobOutcome,
    /// Why it didn't succeed: `monitor_only`, `timeout`, `exit_code 3`, ...
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActionsError {
    #[error("machine_busy: another job holds the machine")]
    MachineBusy,
    #[error("monitor_only: the machine is at access level monitor")]
    MonitorOnly,
    #[error("no such machine")]
    UnknownMachine,
    #[error("no such runbook or revision")]
    UnknownRunbook,
    #[error("no such job")]
    UnknownJob,
    #[error("no such diagnostic")]
    UnknownDiagnostic,
    #[error("not available yet: {0}")]
    Unsupported(String),
    #[error("the runbook doesn't validate: {0}")]
    InvalidRunbook(String),
    #[error("parameter `{0}`: {1}")]
    InvalidParam(String, String),
    #[error("{0}")]
    Approval(ApprovalError),
    #[error("store: {0}")]
    Store(String),
}

impl From<rackhand_store::StoreError> for ActionsError {
    fn from(e: rackhand_store::StoreError) -> Self {
        ActionsError::Store(e.to_string())
    }
}

impl From<rusqlite::Error> for ActionsError {
    fn from(e: rusqlite::Error) -> Self {
        ActionsError::Store(e.to_string())
    }
}

/// Whether new jobs may start (E32: not while the hub's disk is nearly full).
pub trait JobGate: Send + Sync + std::fmt::Debug {
    fn accepting_jobs(&self) -> bool;
}

impl JobGate for crate::ingest::Ingest {
    fn accepting_jobs(&self) -> bool {
        crate::ingest::Ingest::accepting_jobs(self)
    }
}

struct Inner {
    db: Arc<Db>,
    audit: Audit,
    bus: Bus,
    runner: Arc<dyn StepRunner>,
    locks: locks::MachineLocks,
    reboots: reboots::Reboots,
    /// The jobs of a stopped hub this one took up.
    resumed: std::sync::Mutex<std::collections::HashSet<String>>,
}

#[derive(Clone)]
pub struct Actions {
    inner: Arc<Inner>,
    lock_wait: Duration,
    gate: Option<Arc<dyn JobGate>>,
}

impl std::fmt::Debug for Actions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Actions").field("lock_wait", &self.lock_wait).finish_non_exhaustive()
    }
}

impl Actions {
    pub fn new(db: Arc<Db>, audit: Audit, bus: Bus, runner: Arc<dyn StepRunner>) -> Actions {
        Actions {
            inner: Arc::new(Inner {
                db,
                audit,
                bus,
                runner,
                locks: Default::default(),
                reboots: Default::default(),
                resumed: Default::default(),
            }),
            lock_wait: DEFAULT_LOCK_WAIT,
            gate: None,
        }
    }

    /// The same Actions with another wait for a busy machine (tests).
    pub fn with_lock_wait(mut self, wait: Duration) -> Actions {
        self.lock_wait = wait;
        self
    }

    /// Whether a job that reboots the machine is running and its wait step hasn't ended: the machine's silence is
    /// expected (7.6.3).
    pub fn awaiting_reboot(&self, machine_id: &str) -> bool {
        self.inner.reboots.awaiting(machine_id)
    }

    /// What says whether new jobs may start (Ingest, from the hub's free disk).
    pub fn with_gate(mut self, gate: Arc<dyn JobGate>) -> Actions {
        self.gate = Some(gate);
        self
    }
}

#[cfg(test)]
mod tests;
