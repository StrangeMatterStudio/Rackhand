//! `reboot_if_required` steps (7.8.7, 7.5.3). The machine is asked at that moment whether it wants a reboot
//! (`/run/reboot-required`): its reports carry the flag from a refresh up to 6 hours old, from before the updates this
//! job installed. A hypervisor has no such flag: it wants one when its newest installed kernel isn't the one it runs,
//! unless a kernel is pinned. A machine whose policy doesn't have `auto_reboot`, and a hypervisor whose job has no
//! approved high-risk approval (E13), is left running and the job goes on. Otherwise
//! `/sbin/reboot` goes through the wrapper, and the step ends once the machine has started again and reported.

use std::sync::Arc;
use std::time::Duration;

use rackhand_runbook::templates::{REBOOT, WRAPPER};
use rackhand_store::ids::now_ms;
use serde_json::json;

use super::{Executor, ssh_failure};
use crate::actions::runner::{StepCtx, StepOutcome, StepResult};
use crate::ssh::keys::Identity;

/// The step's reason when the machine didn't report again after its reboot (E11, D45).
pub const NO_REPORT: &str = crate::actions::patching::NO_REPORT_AFTER_REBOOT;

const FLAG: &str = "test -e /run/reboot-required || test -e /var/run/reboot-required";
/// The same, or a newer kernel than the running one is installed and none is pinned.
const FLAG_OR_KERNEL: &str = "if test -e /run/reboot-required || test -e /var/run/reboot-required; then exit 0; fi; \
    n=$(ls /boot/vmlinuz-* 2>/dev/null | sed 's,.*/vmlinuz-,,' | sort -V | tail -n 1); \
    if [ -e /etc/kernel/proxmox-boot-pin ] || [ -z \"$n\" ] || [ \"$n\" = \"$(uname -r)\" ]; then exit 1; fi; exit 0";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// A machine going down may still report for this long.
const SHUTDOWN_MS: i64 = 120_000;
const POLL: Duration = Duration::from_secs(1);

/// What the step asks about its machine.
pub trait RebootFacts: Send + Sync {
    /// The machine's policy lets it be rebooted.
    fn auto_reboot(&self, machine: &str) -> bool;
    /// The job was approved to reboot a machine that is never rebooted automatically.
    fn approved(&self, _job: &str) -> bool {
        false
    }
    /// The machine is asked about its kernels too.
    fn compares_kernels(&self, _machine: &str) -> bool {
        false
    }
    /// The machine has started again, and reported, since `since_ms`.
    fn back_since(&self, machine: &str, since_ms: i64) -> bool;
    /// The machine has reported since `since_ms`, started again or not.
    fn reported_since(&self, machine: &str, since_ms: i64) -> bool;
}

fn ended(reboot: &str, command: Option<String>, outcome: StepOutcome) -> StepResult {
    let mut stdout = json!({ "reboot": reboot }).to_string().into_bytes();
    stdout.push(b'\n');
    StepResult { outcome, command, exit_code: None, stdout, stderr: Vec::new() }
}

impl Executor {
    pub(super) async fn reboot_if_required(&self, ctx: &StepCtx) -> StepResult {
        let Some((facts, wait)) = self.reboot.as_ref().map(|(f, w)| (Arc::clone(f), *w)) else {
            return StepResult::failed("reboot_if_required_unavailable");
        };
        let flag = if facts.compares_kernels(&ctx.machine_id) { FLAG_OR_KERNEL } else { FLAG };
        let required = match self.ssh(ctx, Identity::Automation, flag, COMMAND_TIMEOUT).await {
            Ok(out) if out.exit_code == Some(0) => true,
            Ok(out) if out.exit_code == Some(1) => false,
            Ok(out) => {
                let reason = out.exit_code.map_or("no_exit_status".into(), |c| format!("exit_code {c}"));
                return StepResult { command: Some(flag.into()), stderr: out.stderr, ..StepResult::failed(reason) };
            }
            Err(e) => return StepResult { command: Some(flag.into()), ..StepResult::failed(ssh_failure(&e)) },
        };
        if !required {
            return ended("not_required", None, StepOutcome::Succeeded);
        }
        if !facts.auto_reboot(&ctx.machine_id) && !facts.approved(&ctx.job_id) {
            return ended("required_not_allowed", None, StepOutcome::Succeeded);
        }
        let command = format!("sudo {WRAPPER} {REBOOT}");
        let since = now_ms();
        match self.ssh(ctx, Identity::Automation, &command, COMMAND_TIMEOUT).await {
            Ok(out) if out.exit_code.is_some_and(|c| c != 0) => {
                let reason = out.exit_code.map_or_else(String::new, |c| format!("exit_code {c}"));
                return StepResult { command: Some(command), stderr: out.stderr, ..StepResult::failed(reason) };
            }
            // It was refused before it could run: the machine hasn't rebooted.
            Err(e) if matches!(ssh_failure(&e), "auth_refused" | "host_key_changed" | "host_key_not_pinned") => {
                return StepResult { command: Some(command), ..StepResult::failed(ssh_failure(&e)) };
            }
            // A machine going down cuts the session, with or without an exit status.
            Ok(_) | Err(_) => {}
        }
        let deadline = tokio::time::Instant::now() + wait;
        while !facts.back_since(&ctx.machine_id, since) {
            if tokio::time::Instant::now() >= deadline {
                // A machine that goes on reporting hasn't started again (the command may never have run): that isn't
                // the silence after a reboot that rolls a guest back (D45).
                let reason = if facts.reported_since(&ctx.machine_id, since + SHUTDOWN_MS) {
                    "did_not_reboot"
                } else {
                    NO_REPORT
                };
                return ended("done", Some(command), StepOutcome::Failed(reason.into()));
            }
            tokio::time::sleep(POLL.min(wait / 4)).await;
        }
        ended("done", Some(command), StepOutcome::Succeeded)
    }
}
