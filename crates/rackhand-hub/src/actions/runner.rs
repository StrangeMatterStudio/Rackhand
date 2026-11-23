//! The interface between Actions and whatever runs a step (the Executor, or a fake in tests).

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use rackhand_runbook::runbook::{Identity, Step};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What a step runs against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepCtx {
    pub job_id: String,
    pub machine_id: String,
    pub machine_kind: String,
    pub address: Option<String>,
    pub identity: Identity,
    /// The step's timeout. Actions enforces it; a runner may use it to size its own waits.
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    Succeeded,
    /// The step failed; the text is the job's reason (`exit_code 3`, `machine_unreachable`, ...).
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepResult {
    pub outcome: StepOutcome,
    /// The command as shown in the job log, if the step ran one.
    pub command: Option<String>,
    pub exit_code: Option<i64>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl StepResult {
    pub fn failed(reason: impl Into<String>) -> StepResult {
        StepResult {
            outcome: StepOutcome::Failed(reason.into()),
            command: None,
            exit_code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }
}

/// How the job log shows an argument list: plain words as they are, anything else POSIX-quoted.
pub fn display(argv: &[String]) -> String {
    let plain = |a: &str| !a.is_empty() && a.bytes().all(|b| b.is_ascii_alphanumeric() || b"_./:=@%+,-".contains(&b));
    argv.iter().map(|a| if plain(a) { a.clone() } else { crate::ssh::quote::quote(a) }).collect::<Vec<_>>().join(" ")
}

pub trait StepRunner: Send + Sync {
    /// Runs one runbook step. `argv` is the `ssh` step's argument array with parameters substituted.
    fn run<'a>(&'a self, ctx: &'a StepCtx, step: &'a Step, argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult>;

    /// Waits until a machine whose reboot step was scheduled (its output's `reboot` is `scheduled`) has started again and
    /// reported, since `since_ms`.
    fn rebooted<'a>(&'a self, _ctx: &'a StepCtx, _since_ms: i64) -> BoxFuture<'a, StepResult> {
        Box::pin(async { StepResult::failed("reboot_if_required_unavailable") })
    }

    /// Takes up a detached step a stopped hub left running on its machine: polls it to its end without starting it again
    /// (7.3.7, E44). A runner that can't says `adopt_unavailable`, and the job is interrupted.
    fn adopt<'a>(
        &'a self,
        _ctx: &'a StepCtx,
        _step: &'a Step,
        _argv: Option<&'a [String]>,
    ) -> BoxFuture<'a, StepResult> {
        Box::pin(async { StepResult::failed("adopt_unavailable") })
    }

    /// Runs an assistant `exec` command string as-is (7.3.7).
    fn exec<'a>(&'a self, _ctx: &'a StepCtx, _command: &'a str) -> BoxFuture<'a, StepResult> {
        Box::pin(async { StepResult::failed("exec_unavailable") })
    }
}
