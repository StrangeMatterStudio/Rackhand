//! Runs runbook steps for Actions (7.2, Executor; 7.3.7). `ssh` steps go over the SSH system as the runbook's
//! identity, plain or detached; the other step kinds are passed to the systems that own them (`other`), which later
//! steps of the plan provide.

pub mod commands;
mod detached;
mod hub;
pub mod quarantine;
mod reboot;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rackhand_runbook::runbook::{Identity as RunbookIdentity, Step, StepKind};

use crate::actions::runner::{BoxFuture, StepCtx, StepOutcome, StepResult, StepRunner, display};
use crate::ssh::client::{Output, SshError, run_with_input};
use crate::ssh::hostkeys::HostKeys;
use crate::ssh::keys::{Identity, load_for};
use crate::ssh::quote;
use crate::vault::Vault;

pub mod transfer_step;
pub mod tunnel_step;
pub use detached::POLL;
pub use hub::{GuestEnrollment, GuestHost, HubSide};
pub use reboot::{NO_REPORT, RebootFacts};

/// Reaches a remote-mode machine's SSH server for the hub's own commands (7.3.7): a loopback address whose connections each
/// go through a tunnel to the machine's probe. `None` for a machine that isn't in remote mode.
pub trait RemoteReach: Send + Sync {
    fn reach<'a>(&'a self, machine_id: &'a str) -> Option<BoxFuture<'a, Result<SocketAddr, String>>>;
}

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
        StepKind::Hub => "hub",
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
    reboot: Option<(Arc<dyn RebootFacts>, Duration)>,
    hub: Option<Arc<dyn HubSide>>,
    /// How a remote-mode machine's SSH server is reached (through its probe).
    remote: Option<Arc<dyn RemoteReach>>,
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
        Executor {
            vault,
            host_keys,
            other: Arc::new(Unavailable),
            reboot: None,
            hub: None,
            remote: None,
            poll: POLL,
            port: 22,
        }
    }

    /// Runs `reboot_if_required` steps; a rebooted machine has `wait` to report again.
    pub fn with_reboot(mut self, facts: Arc<dyn RebootFacts>, wait: Duration) -> Executor {
        self.reboot = Some((facts, wait));
        self
    }

    /// What `hub` steps ask of the hub itself.
    pub fn with_hub(mut self, hub: Arc<dyn HubSide>) -> Executor {
        self.hub = Some(hub);
        self
    }

    /// How machines in remote mode are reached: through a tunnel to their probe (7.3.7).
    pub fn with_remote(mut self, remote: Arc<dyn RemoteReach>) -> Executor {
        self.remote = Some(remote);
        self
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
        self.ssh_with(ctx, id, line, None, timeout).await
    }

    /// The same, with `input` on the command's standard input.
    async fn ssh_input(
        &self,
        ctx: &StepCtx,
        id: Identity,
        line: &str,
        input: &[u8],
        timeout: Duration,
    ) -> Result<Output, SshError> {
        self.ssh_with(ctx, id, line, Some(input), timeout).await
    }

    async fn ssh_with(
        &self,
        ctx: &StepCtx,
        id: Identity,
        line: &str,
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Output, SshError> {
        let key = load_for(&self.vault, id, &ctx.machine_id).await.map_err(|e| SshError::Transport(e.to_string()))?;
        self.ssh_key(ctx, id, &key, line, input, timeout).await
    }

    /// The same, with this key rather than the machine's current one.
    async fn ssh_key(
        &self,
        ctx: &StepCtx,
        id: Identity,
        key: &russh::keys::PrivateKey,
        line: &str,
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Output, SshError> {
        let through_probe = self.remote.as_ref().and_then(|r| r.reach(&ctx.machine_id));
        let addr = match through_probe {
            Some(reach) => reach.await.map_err(SshError::Transport)?,
            None => self.addr(ctx).ok_or_else(|| SshError::Transport("the machine has no address".into()))?,
        };
        run_with_input(addr, &ctx.machine_id, self.host_keys.clone(), id, key, line, input, timeout).await
    }

    /// A command started on the machine whose input and output the caller drives (7.3.11): how a transfer writes a file and a
    /// backup stream goes in and out. `line` is already quoted.
    pub async fn stream(
        &self,
        ctx: &StepCtx,
        id: Identity,
        line: &str,
        timeout: Duration,
    ) -> Result<crate::ssh::client::Exec, SshError> {
        let key = load_for(&self.vault, id, &ctx.machine_id).await.map_err(|e| SshError::Transport(e.to_string()))?;
        let through_probe = self.remote.as_ref().and_then(|r| r.reach(&ctx.machine_id));
        let addr = match through_probe {
            Some(reach) => reach.await.map_err(SshError::Transport)?,
            None => self.addr(ctx).ok_or_else(|| SshError::Transport("the machine has no address".into()))?,
        };
        crate::ssh::client::start(addr, &ctx.machine_id, self.host_keys.clone(), id, &key, line, timeout).await
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
            // The session ended without the start's exit status (SSH cut as it answered, E54): the unit may well be
            // running. The machine's job files say whether it started; only if it didn't does the step fail.
            Ok(out) if out.exit_code.is_none() => {
                if !self.started(ctx, id, &job_ref, limit).await {
                    return from_output(command, out);
                }
            }
            Ok(out) => {
                let mut r = from_output(command, out);
                if r.outcome == StepOutcome::Succeeded {
                    r.outcome = StepOutcome::Failed("no_exit_status".into());
                }
                return r;
            }
            Err(e) => return StepResult { command: Some(command), ..StepResult::failed(ssh_failure(&e)) },
        }
        self.poll_detached(ctx, command, &job_ref).await
    }

    /// Polls a detached step on the machine to its end, collecting its output; then cleans it up. Used after starting
    /// it and, after a hub restart, in place of starting it again (T65).
    async fn poll_detached(&self, ctx: &StepCtx, command: String, job_ref: &str) -> StepResult {
        let id = Identity::Automation;
        let limit = Duration::from_secs(60);
        let job_ref = job_ref.to_string();
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

impl Executor {
    /// Whether a detached step whose start lost its answer was started: asks `job-status` until the machine answers
    /// (within `limit`); `unknown` means the start never reached the wrapper.
    async fn started(&self, ctx: &StepCtx, id: Identity, job_ref: &str, limit: Duration) -> bool {
        let line = quote::join(&detached::status_argv(job_ref, 0));
        let deadline = tokio::time::Instant::now() + limit;
        while tokio::time::Instant::now() < deadline {
            if let Ok(out) = self.ssh(ctx, id, &line, limit).await {
                if out.exit_code == Some(0) {
                    if let Ok(status) = serde_json::from_slice::<detached::Status>(&out.stdout) {
                        return status.state != "unknown";
                    }
                }
            }
            tokio::time::sleep(self.poll).await;
        }
        false
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
                (StepKind::Hub, _) => self.hub_step(ctx, step).await,
                (StepKind::RebootIfRequired, _) if self.reboot.is_some() => {
                    self.reboot_if_required(ctx, step.always).await
                }
                _ => self.other.run(ctx, step, argv).await,
            }
        })
    }

    fn rebooted<'a>(&'a self, ctx: &'a StepCtx, since_ms: i64) -> BoxFuture<'a, StepResult> {
        Box::pin(self.scheduled_reboot(ctx, since_ms))
    }

    fn adopt<'a>(&'a self, ctx: &'a StepCtx, step: &'a Step, argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            match (step.kind, argv) {
                (StepKind::Ssh, Some(argv)) if step.detached => {
                    let job_ref = format!("{}/{}", ctx.job_id, step.id);
                    self.poll_detached(ctx, display(argv), &job_ref).await
                }
                _ => StepResult::failed("adopt_unavailable"),
            }
        })
    }

    /// The assistant's command string, run by `sh -c` under `timeout` so it stops on the machine at its timeout as a
    /// runbook step does (D33, owner review); the job log shows the line that ran.
    fn exec<'a>(&'a self, ctx: &'a StepCtx, command: &'a str) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            let line = exec_line(command, ctx.timeout);
            match self.ssh(ctx, Identity::Assistant, &line, ctx.timeout + Duration::from_secs(5)).await {
                Ok(out) => from_output(line, out),
                Err(e) => StepResult { command: Some(line), ..StepResult::failed(ssh_failure(&e)) },
            }
        })
    }
}

/// The line an assistant `exec` runs as on the machine: its command by `sh -c`, under `timeout` (D33, owner review).
pub fn exec_line(command: &str, timeout: Duration) -> String {
    format!("timeout -k 5 {} sh -c {}", timeout.as_secs().max(1), quote::quote(command))
}

#[cfg(test)]
mod tests;
