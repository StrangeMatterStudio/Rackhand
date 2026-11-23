//! The `hub` calls of `quarantine` and `quarantine-release` (7.5.6, D104): isolating a machine, the forensic snapshot after
//! it, and putting the machine back.
//!
//! - A guest on Proxmox is isolated from its hypervisor: the datacenter firewall must be on (`pve_firewall_off` otherwise,
//!   and nothing is changed), the guest's whole firewall configuration is saved, and the guest's firewall then allows only
//!   DHCP, the guest's QUIC connection to the hub, and the hub's SSH and ping. The step's output is the record release
//!   needs: `{method, enforced, saved, applied}`.
//! - Any other managed Linux machine loads the wrapper's `quarantine on` table over SSH, which is advisory against an
//!   attacker with root on the machine; its record says so.
//!
//! A retry after a failed quarantine takes up the record an earlier attempt made rather than saving the isolated
//! configuration as if it were the original.

use std::net::SocketAddr;

use rackhand_runbook::templates::WRAPPER;
use serde_json::{Value, json};

use super::hub::{HubSide, succeeded_text};
use super::{Executor, from_output, ssh_failure};
use crate::actions::runner::{StepCtx, StepOutcome, StepResult};
use crate::ssh::keys::Identity;
use crate::ssh::quote::quote;

/// What the hub says when the machine isn't a Proxmox guest.
pub const NOT_A_GUEST: &str = "not_a_proxmox_guest";

/// A failure with a code the job shows (`pve_firewall_off`, `quarantine_config_changed`, ...) and the full text in the
/// step's error output.
fn failure(text: String) -> StepResult {
    let code = text.split(':').next().unwrap_or("");
    let is_code = !code.is_empty() && code.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    StepResult {
        stderr: text.clone().into_bytes(),
        ..StepResult::failed(if is_code { code.to_string() } else { text })
    }
}

fn record_text(record: &Value) -> StepResult {
    succeeded_text(format!("{record}\n"))
}

/// The hub's addresses that share the port most of them have, for a firewall rule per address and one port.
fn addresses_and_port(addrs: &[String]) -> Option<(Vec<String>, u16)> {
    let socks: Vec<SocketAddr> = addrs.iter().filter_map(|a| a.parse().ok()).collect();
    let port = socks.iter().map(|s| s.port()).max_by_key(|p| socks.iter().filter(|s| s.port() == *p).count())?;
    let mut ips: Vec<String> = socks.iter().filter(|s| s.port() == port).map(|s| s.ip().to_string()).collect();
    ips.sort();
    ips.dedup();
    Some((ips, port))
}

impl Executor {
    pub(super) async fn quarantine_isolate(&self, ctx: &StepCtx, hub: &dyn HubSide) -> StepResult {
        let addrs = hub.quarantine_addrs();
        let Some((ips, port)) = addresses_and_port(&addrs) else { return StepResult::failed("hub_addresses_unknown") };
        // an earlier attempt isolated the guest and then failed: its record is the original configuration
        if let Some(mut earlier) = hub.quarantine_record(&ctx.machine_id).filter(|r| r["method"] == "proxmox") {
            earlier["reused"] = json!(true);
            return record_text(&earlier);
        }
        let args = json!({ "hub_addrs": ips, "hub_port": port });
        match hub.guest_firewall(&ctx.machine_id, "firewall_isolate", args, ctx.timeout).await {
            Ok(out) => record_text(&json!({
                "method": "proxmox",
                "enforced": true,
                "saved": out["saved"],
                "applied": out["applied"],
                // the API can't flush connection tracking; the hypervisor's own enrollment does (D112)
                "conntrack": "not_flushed",
            })),
            Err(e) if e == NOT_A_GUEST => self.isolate_in_guest(ctx, hub, &addrs).await,
            Err(e) => failure(e),
        }
    }

    async fn isolate_in_guest(&self, ctx: &StepCtx, hub: &dyn HubSide, addrs: &[String]) -> StepResult {
        if !matches!(ctx.machine_kind.as_str(), "linux" | "alpine") {
            return StepResult::failed("in_guest_quarantine_unsupported");
        }
        if !hub.managed(&ctx.machine_id) {
            // a monitor machine has no account: only its hypervisor can cut it off
            return StepResult::failed("monitor_machine_needs_hypervisor");
        }
        let words: Vec<String> = addrs.iter().filter(|a| a.parse::<SocketAddr>().is_ok()).map(|a| quote(a)).collect();
        let command = format!("sudo {WRAPPER} quarantine on {}", words.join(" "));
        let out = match self.ssh(ctx, Identity::Automation, &command, ctx.timeout).await {
            Ok(out) => out,
            Err(e) => return StepResult { command: Some(command), ..StepResult::failed(ssh_failure(&e)) },
        };
        let said = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let mut result = from_output(command, out);
        if result.outcome == StepOutcome::Succeeded {
            result.stdout =
                format!("{}\n", json!({ "method": "in_guest", "enforced": false, "said": said })).into_bytes();
        }
        result
    }

    pub(super) async fn quarantine_snapshot(&self, ctx: &StepCtx, hub: &dyn HubSide) -> StepResult {
        let Some(record) = hub.quarantine_record(&ctx.machine_id) else {
            return StepResult::failed("no_quarantine_record");
        };
        if record["method"] != "proxmox" {
            return succeeded_text(
                json!({ "snapshot": null, "note": "not a Proxmox guest: no forensic snapshot" }).to_string() + "\n",
            );
        }
        let name = format!("rackhand-quarantine-{}", jiff::Timestamp::now().strftime("%Y%m%d-%H%M%S"));
        match hub.guest_snapshot(&ctx.machine_id, &name, ctx.timeout).await {
            Ok(()) => succeeded_text(json!({ "snapshot": name }).to_string() + "\n"),
            Err(e) => failure(e),
        }
    }

    pub(super) async fn quarantine_release(&self, ctx: &StepCtx, hub: &dyn HubSide) -> StepResult {
        let Some(record) = hub.quarantine_record(&ctx.machine_id) else {
            return StepResult::failed("no_quarantine_record");
        };
        if record["method"] == "proxmox" {
            let args = json!({ "saved": record["saved"], "applied": record["applied"] });
            return match hub.guest_firewall(&ctx.machine_id, "firewall_release", args, ctx.timeout).await {
                Ok(_) => succeeded_text(json!({ "released": true, "method": "proxmox" }).to_string() + "\n"),
                Err(e) => failure(e),
            };
        }
        if !hub.managed(&ctx.machine_id) {
            return StepResult::failed("monitor_machine_needs_hypervisor");
        }
        let command = format!("sudo {WRAPPER} quarantine off");
        match self.ssh(ctx, Identity::Automation, &command, ctx.timeout).await {
            Ok(out) => {
                let mut result = from_output(command, out);
                if result.outcome == StepOutcome::Succeeded {
                    result.stdout = format!("{}\n", json!({ "released": true, "method": "in_guest" })).into_bytes();
                }
                result
            }
            Err(e) => StepResult { command: Some(command), ..StepResult::failed(ssh_failure(&e)) },
        }
    }
}
