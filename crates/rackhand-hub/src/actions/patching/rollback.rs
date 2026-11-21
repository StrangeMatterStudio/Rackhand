//! Rollback and the patching defaults (7.5.3 steps 6 and 9). A failed patch is rolled back by the hub only when the
//! machine never reported in the 15 minutes after its reboot, the policy has `auto_rollback`, the machine isn't the
//! hub, and the job took a snapshot (D45, an allowed automatic high-risk action). Otherwise the incident routes on.

/// How a patch failed, for the rollback decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    /// No report in the 15 minutes after the reboot.
    pub no_report_after_reboot: bool,
    pub auto_rollback: bool,
    /// The machine has role `hub`.
    pub hub: bool,
    pub snapshot_taken: bool,
}

pub fn rolls_back(f: &Failure) -> bool {
    f.no_report_after_reboot && f.auto_rollback && !f.hub && f.snapshot_taken
}

/// The policy defaults for a machine (7.5.3 step 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Defaults {
    pub snapshot_required: bool,
    pub auto_rollback: bool,
    pub auto_reboot: bool,
}

pub fn defaults(kind: &str, roles: &[&str]) -> Defaults {
    let no_reboot = kind == "windows" || roles.iter().any(|r| matches!(*r, "desktop" | "hypervisor" | "hub"));
    Defaults { snapshot_required: true, auto_rollback: false, auto_reboot: !no_reboot }
}

#[cfg(test)]
#[path = "rollback_tests.rs"]
mod tests;
