//! Runs runbook steps for Actions (7.2, Executor; 7.3.7). `ssh` steps go over the SSH system as the runbook's
//! identity, plain or detached; the other step kinds are passed to the systems that own them (`other`), which later
//! steps of the plan provide.

pub mod commands;
mod detached;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rackhand_runbook::runbook::{Identity as RunbookIdentity, Step, StepKind};

use crate::actions::runner::{BoxFuture, StepCtx, StepOutcome, StepResult, StepRunner, display};
use crate::ssh::client::{Output, SshError, run};
use crate::ssh::hostkeys::HostKeys;
use crate::ssh::keys::{Identity, load_or_create};
use crate::ssh::quote;
use crate::vault::Vault;

pub use detached::POLL;

/// Step kinds whose systems aren't wired to the Executor yet fail with `<kind>_unavailable`.
#[derive(Debug, Default)]
pub struct Unavailable;

fn kind_name(kind: StepKind) -> &'static str {
    match kind {
        StepKind::Ssh => "ssh",
        StepKind::Snapshot => "snapshot",
        StepKind::Rollback => "rollback",
        StepKind::RebootIfRequired => "reboot_if_required",
        StepKind::WaitReport => "wait_report",
        StepKind::Verify => "verify",
        StepKind::ProbeCheck => "probe_check",
        StepKind::Api => "api",
        StepKind::Transfer => "transfer",
        StepKind::Tunnel => "tunnel",
        StepKind::Notify => "notify",
    }
}

impl StepRunner for Unavailable {
    fn run<'a>(&'a self, _ctx: &'a StepCtx, step: &'a Step, _argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async move { StepResult::failed(format!("{}_unavailable", kind_name(step.kind))) })
    }
}

/// The runner for each step kind other than `ssh`, by the system that owns it; any other kind is unavailable.
#[derive(Default)]
pub struct ByKind(Vec<(StepKind, Arc<dyn StepRunner>)>);

impl std::fmt::Debug for ByKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.iter().map(|(k, _)| kind_name(*k))).finish()
    }
}

impl ByKind {
    pub fn with(mut self, kind: StepKind, runner: Arc<dyn StepRunner>) -> ByKind {
        self.0.push((kind, runner));
        self
    }
}

impl StepRunner for ByKind {
    fn run<'a>(&'a self, ctx: &'a StepCtx, step: &'a Step, argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        match self.0.iter().find(|(k, _)| *k == step.kind) {
            Some((_, runner)) => runner.run(ctx, step, argv),
            None => Unavailable.run(ctx, step, argv),
        }
    }
}

pub struct Executor {
    vault: Arc<Vault>,
    host_keys: Arc<HostKeys>,
    other: Arc<dyn StepRunner>,
    poll: Duration,
    port: u16,
}

impl std::fmt::Debug for Executor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Executor").field("poll", &self.poll).field("port", &self.port).finish_non_exhaustive()
    }
}

fn ssh_failure(e: &SshError) -> &'static str {
    match e {
        SshError::HostKeyNotPinned => "host_key_not_pinned",
        SshError::HostKeyChanged => "host_key_changed",
        SshError::AuthRefused(_) => "auth_refused",
        SshError::Transport(_) => "machine_unreachable",
        SshError::Timeout => "timeout",
    }
}

fn from_output(command: String, out: Output) -> StepResult {
    let exit_code = out.exit_code.map(i64::from);
    let outcome = match exit_code {
        Some(0) => StepOutcome::Succeeded,
        Some(n) => StepOutcome::Failed(format!("exit_code {n}")),
        None => StepOutcome::Failed("no_exit_status".into()),
    };
    StepResult { outcome, command: Some(command), exit_code, stdout: out.stdout, stderr: out.stderr }
}

impl Executor {
    pub fn new(vault: Arc<Vault>, host_keys: Arc<HostKeys>) -> Executor {
        Executor { vault, host_keys, other: Arc::new(Unavailable), poll: POLL, port: 22 }
    }

    /// The runner for step kinds other than `ssh`.
    pub fn with_other(mut self, other: Arc<dyn StepRunner>) -> Executor {
        self.other = other;
        self
    }

    pub fn with_poll(mut self, poll: Duration) -> Executor {
        self.poll = poll;
        self
    }

    fn addr(&self, ctx: &StepCtx) -> Option<SocketAddr> {
        let a = ctx.address.as_deref()?;
        a.parse::<SocketAddr>().ok().or_else(|| a.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, self.port)))
    }

    /// One command over SSH, already quoted.
    async fn ssh(&self, ctx: &StepCtx, id: Identity, line: &str, timeout: Duration) -> Result<Output, SshError> {
        let addr = self.addr(ctx).ok_or_else(|| SshError::Transport("the machine has no address".into()))?;
        let key = load_or_create(&self.vault, id).await.map_err(|e| SshError::Transport(e.to_string()))?;
        run(addr, &ctx.machine_id, self.host_keys.clone(), id, &key, line, timeout).await
    }

    async fn plain(&self, ctx: &StepCtx, id: Identity, argv: &[String]) -> StepResult {
        let command = display(argv);
        // Actions enforces the step's timeout and drops the connection, which doesn't stop a command without a
        // terminal; `timeout` on the machine stops it (and its process group) at the same moment.
        let line = format!("timeout -k 5 {} {}", ctx.timeout.as_secs().max(1), quote::join(argv));
        match self.ssh(ctx, id, &line, ctx.timeout + Duration::from_secs(5)).await {
            Ok(out) => from_output(command, out),
            Err(e) => StepResult { command: Some(command), ..StepResult::failed(ssh_failure(&e)) },
        }
    }

    async fn detached(&self, ctx: &StepCtx, step: &Step, argv: &[String]) -> StepResult {
        let command = display(argv);
        let job_ref = format!("{}/{}", ctx.job_id, step.id);
        let Some(start) = detached::start_argv(&job_ref, argv) else {
            return StepResult { command: Some(command), ..StepResult::failed("detached_needs_wrapper") };
        };
        let id = Identity::Automation;
        let limit = Duration::from_secs(60);
        match self.ssh(ctx, id, &quote::join(&start), limit).await {
            Ok(out) if out.exit_code == Some(0) => {}
            Ok(out) => {
                let mut r = from_output(command, out);
                if r.outcome == StepOutcome::Succeeded {
                    r.outcome = StepOutcome::Failed("no_exit_status".into());
                }
                return r;
            }
            Err(e) => return StepResult { command: Some(command), ..StepResult::failed(ssh_failure(&e)) },
        }
        let mut collected = detached::Collected::default();
        let end = loop {
            tokio::time::sleep(self.poll).await;
            let line = quote::join(&detached::status_argv(&job_ref, collected.offset));
            // A dropped connection or a restarting sshd: poll again (E54).
            let Ok(out) = self.ssh(ctx, id, &line, limit).await else { continue };
            // The wrapper refused the poll (126) or sudo failed: that won't change by asking again.
            if let Some(code) = out.exit_code.filter(|c| *c != 0) {
                break (StepOutcome::Failed(format!("job_status exit {code}")), None);
            }
            let Ok(status) = serde_json::from_slice::<detached::Status>(&out.stdout) else { continue };
            collected.add(&status);
            if let Some(end) = detached::outcome(&status) {
                break end;
            }
        };
        let _ = self.ssh(ctx, id, &quote::join(&detached::clean_argv(&job_ref)), limit).await;
        detached::result(command, collected, end)
    }
}

fn identity(i: RunbookIdentity) -> Identity {
    match i {
        RunbookIdentity::Automation => Identity::Automation,
        RunbookIdentity::Assistant => Identity::Assistant,
    }
}

impl StepRunner for Executor {
    fn run<'a>(&'a self, ctx: &'a StepCtx, step: &'a Step, argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            match (step.kind, argv) {
                (StepKind::Ssh, Some(argv)) if step.detached => self.detached(ctx, step, argv).await,
                (StepKind::Ssh, Some(argv)) => self.plain(ctx, identity(ctx.identity), argv).await,
                // `windows_script` steps go through the dispatcher (T90).
                (StepKind::Ssh, None) => StepResult::failed("windows_unavailable"),
                _ => self.other.run(ctx, step, argv).await,
            }
        })
    }

    fn exec<'a>(&'a self, ctx: &'a StepCtx, command: &'a str) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            match self.ssh(ctx, Identity::Assistant, command, ctx.timeout + Duration::from_secs(5)).await {
                Ok(out) => from_output(command.to_string(), out),
                Err(e) => StepResult { command: Some(command.to_string()), ..StepResult::failed(ssh_failure(&e)) },
            }
        })
    }
}
