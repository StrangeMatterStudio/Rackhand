//! The risk of assistant commands (7.6.8, 7.3.7).

use rackhand_runbook::runbook::Risk;

use super::exec_patterns::needs_step_up;

/// Roles where any assistant `exec` is high risk.
const HIGH_RISK_ROLES: [&str; 3] = ["operator", "relay", "hypervisor"];

/// An assistant `exec` is normal risk on ordinary machines, and high on the roles above or for a step-up pattern.
pub fn exec_risk(roles: &[&str], command: &str) -> Risk {
    if roles.iter().any(|r| HIGH_RISK_ROLES.contains(r)) || needs_step_up(command) { Risk::High } else { Risk::Normal }
}

/// Diagnostics whose output can hold secrets: a personal key needs an approval for them (7.3.6).
pub const SENSITIVE_DIAGNOSTICS: [&str; 2] = ["journal", "docker_logs"];
