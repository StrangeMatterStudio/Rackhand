//! `hub` steps (7.8.7): what the hub does itself, from the fixed list in `rackhand_runbook::runbook::HUB_CALLS`.
//!
//! - `send_commands`: the hub's current command list, signed with its node key, through the machine's wrapper
//!   (`run install-commands`, which checks the signature against the hub pinned on the machine, the version and the expiry).

use rackhand_runbook::runbook::Step;
use rackhand_runbook::templates::WRAPPER;
use rackhand_store::ids::now_ms;

use super::{Executor, from_output, ssh_failure};
use crate::actions::runner::{StepCtx, StepResult};
use crate::ssh::keys::Identity;

/// What the hub knows that a `hub` step needs, which the Executor doesn't.
pub trait HubSide: Send + Sync {
    /// The protobuf bytes of the signed command list for the runbooks enabled now, versioned by `now_ms` as the list in a
    /// join is, so that the machine finds it newer.
    fn signed_commands(&self, now_ms: i64) -> Vec<u8>;
}

impl Executor {
    pub(super) async fn hub_step(&self, ctx: &StepCtx, step: &Step) -> StepResult {
        let Some(hub) = &self.hub else { return StepResult::failed("hub_unavailable") };
        match step.call.as_deref() {
            Some("send_commands") => {
                let payload = hub.signed_commands(now_ms());
                let command = format!("sudo {WRAPPER} install-commands");
                match self.ssh_input(ctx, Identity::Automation, &command, &payload, ctx.timeout).await {
                    Ok(out) => from_output(command, out),
                    Err(e) => StepResult { command: Some(command), ..StepResult::failed(ssh_failure(&e)) },
                }
            }
            Some(other) => StepResult::failed(format!("hub_call_unavailable:{other}")),
            None => StepResult::failed("no_call"),
        }
    }
}
