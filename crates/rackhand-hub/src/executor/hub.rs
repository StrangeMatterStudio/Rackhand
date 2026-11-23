//! `hub` steps (7.8.7): what the hub does itself, from the fixed list in `rackhand_runbook::runbook::HUB_CALLS`.
//!
//! - `send_commands`: the hub's current command list, signed with its node key, through the machine's wrapper
//!   (`run install-commands`, which checks the signature against the hub pinned on the machine, the version and the expiry).
//! - `rotate_keys`: the machine gets a key of its own for the automation user. The hub makes it, has the machine take it
//!   beside the old one (`run install-keys`, a payload signed with the node key), logs in with it, keeps it, and has the
//!   machine drop the old one, which it then finds refused. Stopped halfway, the same key is taken up again.
//! - `provision_machine`, `send_guest`, `bind_guest`, `await_machine`: the hub's side of `provision-vm` and
//!   `provision-lxc` (T64): the guest's machine and token; the hypervisor's wrapper giving the guest its enrollment
//!   (`run install-guest`, a payload signed with the node key); the guest's binding; and waiting for it to enroll.
//! - `quarantine_isolate`, `quarantine_snapshot`, `quarantine_release`: `quarantine` and `quarantine-release` (7.5.6), in
//!   `quarantine.rs`.
//! - `revoke`: waits until the machine refuses the hub's key (its accounts are gone, which is how the hub knows an
//!   uninstall happened), then revokes the machine. A machine at access level `monitor` has no such account: it is
//!   revoked at once.

use rackhand_runbook::runbook::Step;
use rackhand_runbook::templates::WRAPPER;
use rackhand_store::ids::now_ms;
use russh::keys::PrivateKey;

use super::{Executor, from_output, ssh_failure};
use crate::actions::runner::{BoxFuture, StepCtx, StepOutcome, StepResult};
use crate::ssh::client::SshError;
use crate::ssh::keys::{Identity, commit_next, load_for, next_for};

/// How a guest being provisioned finds the installer: its address and arguments, with the guest's one-time token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestEnrollment {
    pub script_url: String,
    pub args: Vec<String>,
    /// The installer is fetched from the hub's own certificate (the offline variant).
    pub self_signed: bool,
}

fn not_provisioning<'a, T: Send + 'a>() -> BoxFuture<'a, Result<T, String>> {
    Box::pin(async { Err("provisioning_unavailable".to_string()) })
}

/// What the hub knows that a `hub` step needs, which the Executor doesn't.
pub trait HubSide: Send + Sync {
    /// Makes the machine named `name` on the hypervisor's site, pending, and its token, for the job's guest.
    fn provision_machine<'a>(
        &'a self,
        _job: &'a str,
        _host: &'a str,
        _name: &'a str,
    ) -> BoxFuture<'a, Result<(), String>> {
        not_provisioning()
    }
    /// The installer's address and arguments for the guest this job is making.
    fn guest_enrollment(&self, _job: &str) -> Option<GuestEnrollment> {
        None
    }
    /// The protobuf bytes of a guest request with this JSON `body`, signed with the node key.
    fn signed_guest(&self, _now_ms: i64, _body: &[u8]) -> Vec<u8> {
        Vec::new()
    }
    /// Binds the machine `name` to the guest the job made, confirmed.
    fn bind_guest<'a>(
        &'a self,
        _job: &'a str,
        _host: &'a str,
        _name: &'a str,
        _kind: &'a str,
        _vmid: u64,
    ) -> BoxFuture<'a, Result<(), String>> {
        not_provisioning()
    }
    /// Whether the machine `name` on the hypervisor's site has enrolled.
    fn machine_enrolled(&self, _host: &str, _name: &str) -> bool {
        false
    }
    /// The protobuf bytes of the signed command list for the runbooks enabled now, versioned by `now_ms` as the list in a
    /// join is, so that the machine finds it newer.
    fn signed_commands(&self, now_ms: i64) -> Vec<u8>;
    /// The protobuf bytes of a key update with this JSON `body` (the machine's helper and wrapper say what it may hold),
    /// signed with the node key and versioned by `now_ms`.
    fn signed_keys(&self, now_ms: i64, body: &[u8]) -> Vec<u8>;
    /// The addresses the machine takes the hub's SSH from.
    fn ssh_from(&self, machine: &str) -> Vec<String>;
    /// Whether the machine has the hub's accounts (access level `managed`).
    fn managed(&self, machine: &str) -> bool;
    /// Revokes the machine: it is marked and its probe is no longer admitted.
    fn revoke<'a>(&'a self, machine: &'a str) -> BoxFuture<'a, Result<(), String>>;
    /// The hub's addresses as `ip:port`, the one path out of a quarantined machine (7.5.6).
    fn quarantine_addrs(&self) -> Vec<String> {
        Vec::new()
    }
    /// A firewall operation of the hypervisor on the machine's guest (`firewall_isolate`, `firewall_release`), only when the
    /// machine's binding to it is confirmed; `not_a_proxmox_guest` when the machine isn't one.
    fn guest_firewall<'a>(
        &'a self,
        _machine: &'a str,
        _op: &'a str,
        _args: serde_json::Value,
        _timeout: std::time::Duration,
    ) -> BoxFuture<'a, Result<serde_json::Value, String>> {
        Box::pin(async { Err("not_a_proxmox_guest".to_string()) })
    }
    /// A snapshot of the machine's guest called `name`.
    fn guest_snapshot<'a>(
        &'a self,
        _machine: &'a str,
        _name: &'a str,
        _timeout: std::time::Duration,
    ) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async { Err("not_a_proxmox_guest".to_string()) })
    }
    /// What the machine's quarantine recorded when it isolated the machine, and that hasn't been released: `{method,
    /// enforced, saved, applied}`.
    fn quarantine_record(&self, _machine: &str) -> Option<serde_json::Value> {
        None
    }
}

/// How long a rotation's login and key updates may take each.
const ROTATE_STEP: std::time::Duration = std::time::Duration::from_secs(30);

impl Executor {
    pub(super) async fn hub_step(&self, ctx: &StepCtx, step: &Step) -> StepResult {
        let Some(hub) = &self.hub else { return StepResult::failed("hub_unavailable") };
        let call = step.call.as_deref().unwrap_or("");
        let (name, args) = rackhand_runbook::runbook::call_parts(call);
        let arg = |key: &str| args.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
        match step.call.is_some().then_some(name) {
            Some("provision_machine") => {
                let Some(guest) = arg("name") else { return StepResult::failed("no_name") };
                match hub.provision_machine(&ctx.job_id, &ctx.machine_id, guest).await {
                    Ok(()) => {
                        succeeded_text(format!("made the machine {guest}, pending, with a token for its installer\n"))
                    }
                    Err(e) => StepResult::failed(e),
                }
            }
            Some("send_guest") => self.send_guest(ctx, hub.as_ref(), arg("kind"), arg("vmid")).await,
            Some("bind_guest") => {
                let (Some(guest), Some(kind), Some(vmid)) =
                    (arg("name"), arg("kind"), arg("vmid").and_then(|v| v.parse().ok()))
                else {
                    return StepResult::failed("bind_needs_name_kind_vmid");
                };
                match hub.bind_guest(&ctx.job_id, &ctx.machine_id, guest, kind, vmid).await {
                    Ok(()) => succeeded_text(format!("bound {guest} to {kind} {vmid}\n")),
                    Err(e) => StepResult::failed(e),
                }
            }
            Some("await_machine") => {
                let Some(guest) = arg("name") else { return StepResult::failed("no_name") };
                let deadline = tokio::time::Instant::now() + ctx.timeout;
                loop {
                    if hub.machine_enrolled(&ctx.machine_id, guest) {
                        return succeeded_text(format!("{guest} has enrolled\n"));
                    }
                    if tokio::time::Instant::now() >= deadline {
                        return StepResult::failed("machine_not_enrolled");
                    }
                    tokio::time::sleep(AWAIT_EVERY.min(ctx.timeout)).await;
                }
            }
            Some("send_commands") => {
                let payload = hub.signed_commands(now_ms());
                let command = format!("sudo {WRAPPER} install-commands");
                match self.ssh_input(ctx, Identity::Automation, &command, &payload, ctx.timeout).await {
                    Ok(out) => from_output(command, out),
                    Err(e) => StepResult { command: Some(command), ..StepResult::failed(ssh_failure(&e)) },
                }
            }
            Some("rotate_keys") => self.rotate_keys(ctx, hub.as_ref()).await,
            Some("revoke") => self.revoke_machine(ctx, hub.as_ref()).await,
            Some("quarantine_isolate") => self.quarantine_isolate(ctx, hub.as_ref()).await,
            Some("quarantine_snapshot") => self.quarantine_snapshot(ctx, hub.as_ref()).await,
            Some("quarantine_release") => self.quarantine_release(ctx, hub.as_ref()).await,
            Some(other) => StepResult::failed(format!("hub_call_unavailable:{other}")),
            None => StepResult::failed("no_call"),
        }
    }
}

/// How often `await_machine` looks.
const AWAIT_EVERY: std::time::Duration = std::time::Duration::from_secs(2);

pub(super) fn succeeded_text(out: String) -> StepResult {
    StepResult { outcome: StepOutcome::Succeeded, stdout: out.into_bytes(), ..StepResult::failed("") }
}

impl Executor {
    /// `send_guest`: the hypervisor's wrapper gives the guest its enrollment (a VM's user data, or the installer run in
    /// the container); the step's output is what the wrapper answered, a VM's `cicustom` value.
    async fn send_guest(&self, ctx: &StepCtx, hub: &dyn HubSide, kind: Option<&str>, vmid: Option<&str>) -> StepResult {
        let (Some(kind), Some(vmid)) = (kind, vmid.and_then(|v| v.parse::<u64>().ok())) else {
            return StepResult::failed("send_guest_needs_kind_and_vmid");
        };
        let Some(enrollment) = hub.guest_enrollment(&ctx.job_id) else {
            return StepResult::failed("no_provisioned_machine");
        };
        let body = serde_json::json!({
            "kind": kind, "vmid": vmid, "script_url": enrollment.script_url, "args": enrollment.args,
            "self_signed": enrollment.self_signed,
        });
        let payload = hub.signed_guest(now_ms(), body.to_string().as_bytes());
        let command = format!("sudo {WRAPPER} install-guest");
        match self.ssh_input(ctx, Identity::Automation, &command, &payload, ctx.timeout).await {
            Ok(out) => from_output(command, out),
            Err(e) => StepResult { command: Some(command), ..StepResult::failed(ssh_failure(&e)) },
        }
    }
}

fn text(e: impl std::fmt::Display) -> StepResult {
    StepResult::failed(format!("keys: {e}"))
}

fn fingerprint(key: &PrivateKey) -> String {
    key.public_key().fingerprint(russh::keys::ssh_key::HashAlg::Sha256).to_string()
}

impl Executor {
    /// Has the machine take `keys` for the automation user, logging in with `with`; `Err` is the step's result.
    async fn install_keys(
        &self,
        ctx: &StepCtx,
        hub: &dyn HubSide,
        with: &PrivateKey,
        keys: &[&PrivateKey],
        version_ms: i64,
    ) -> Result<(), StepResult> {
        let id = Identity::Automation;
        let public: Result<Vec<String>, _> = keys.iter().map(|k| k.public_key().to_openssh()).collect();
        let public = public.map_err(text)?;
        let body = serde_json::json!({ "from": hub.ssh_from(&ctx.machine_id), "keys": { id.user(): public } });
        let payload = hub.signed_keys(version_ms, body.to_string().as_bytes());
        let command = format!("sudo {WRAPPER} install-keys");
        match self.ssh_key(ctx, id, with, &command, Some(&payload), ROTATE_STEP).await {
            Ok(out) if out.exit_code == Some(0) => Ok(()),
            Ok(out) => Err(from_output(command, out)),
            Err(e) => Err(StepResult { command: Some(command), ..StepResult::failed(ssh_failure(&e)) }),
        }
    }

    async fn rotate_keys(&self, ctx: &StepCtx, hub: &dyn HubSide) -> StepResult {
        let id = Identity::Automation;
        let machine = &ctx.machine_id;
        let current = match load_for(&self.vault, id, machine).await {
            Ok(k) => k,
            Err(e) => return text(e),
        };
        let next = match next_for(&self.vault, id, machine).await {
            Ok(k) => k,
            Err(e) => return text(e),
        };
        // 1. the machine takes the new key beside the old one
        let first = now_ms();
        if let Err(failed) = self.install_keys(ctx, hub, &current, &[&current, &next], first).await {
            return failed;
        }
        // 2. the new key works
        match self.ssh_key(ctx, id, &next, "id -un", None, ROTATE_STEP).await {
            Ok(out) if out.exit_code == Some(0) => {}
            Ok(out) => return StepResult { stderr: out.stderr, ..StepResult::failed("new_key_refused") },
            Err(SshError::AuthRefused(_)) => return StepResult::failed("new_key_refused"),
            Err(e) => return StepResult::failed(ssh_failure(&e)),
        }
        // 3. the hub keeps it; from here the machine's key is the new one
        if let Err(e) = commit_next(&self.vault, id, machine).await {
            return text(e);
        }
        // 4. the machine drops the old one
        if let Err(mut failed) = self.install_keys(ctx, hub, &next, &[&next], now_ms().max(first + 1)).await {
            failed.outcome = crate::actions::runner::StepOutcome::Failed("old_key_not_removed".into());
            return failed;
        }
        // 5. and refuses it
        match self.ssh_key(ctx, id, &current, "id -un", None, ROTATE_STEP).await {
            Err(SshError::AuthRefused(_)) => {}
            Ok(_) => return StepResult::failed("old_key_still_accepted"),
            Err(e) => return StepResult::failed(ssh_failure(&e)),
        }
        let mut out = serde_json::json!({
            "rotated": id.user(),
            "fingerprint": fingerprint(&next),
            "previous": fingerprint(&current),
        })
        .to_string()
        .into_bytes();
        out.push(b'\n');
        StepResult {
            outcome: crate::actions::runner::StepOutcome::Succeeded,
            command: Some(format!("sudo {WRAPPER} install-keys")),
            exit_code: Some(0),
            stdout: out,
            stderr: Vec::new(),
        }
    }
}

/// How often a machine is asked whether it still takes the hub's key.
const GONE_POLL: std::time::Duration = std::time::Duration::from_secs(2);

impl Executor {
    async fn revoke_machine(&self, ctx: &StepCtx, hub: &dyn HubSide) -> StepResult {
        let mut proof = "the machine has no hub accounts to check".to_string();
        if hub.managed(&ctx.machine_id) {
            let id = Identity::Automation;
            let key = match load_for(&self.vault, id, &ctx.machine_id).await {
                Ok(k) => k,
                Err(e) => return text(e),
            };
            // time left for the revoke itself
            let deadline = tokio::time::Instant::now() + ctx.timeout.saturating_sub(std::time::Duration::from_secs(10));
            let mut last: String;
            loop {
                match self.ssh_key(ctx, id, &key, "id -un", None, ROTATE_STEP).await {
                    Err(SshError::AuthRefused(_)) => break,
                    Ok(_) => last = "machine_still_enrolled".into(),
                    Err(e) => last = ssh_failure(&e).into(),
                }
                if tokio::time::Instant::now() >= deadline {
                    return StepResult::failed(last);
                }
                tokio::time::sleep(GONE_POLL).await;
            }
            proof = "the machine refuses the hub's key".to_string();
        }
        if let Err(e) = hub.revoke(&ctx.machine_id).await {
            return StepResult::failed(format!("revoke: {e}"));
        }
        let mut out = serde_json::json!({ "revoked": true, "after": proof }).to_string().into_bytes();
        out.push(b'\n');
        StepResult { outcome: StepOutcome::Succeeded, command: None, exit_code: None, stdout: out, stderr: Vec::new() }
    }
}
