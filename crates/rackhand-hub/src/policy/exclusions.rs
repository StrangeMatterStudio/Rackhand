//! Machines that are never quarantined (7.5.6, D57): roles `hub`, `operator`, `relay`, `hypervisor`, and the tag
//! `no-quarantine`. The exclusion is checked before any rule.

const NEVER_QUARANTINED_ROLES: [&str; 4] = ["hub", "operator", "relay", "hypervisor"];
const NO_QUARANTINE_TAG: &str = "no-quarantine";

pub fn quarantine_excluded(roles: &[&str], tags: &[&str]) -> bool {
    roles.iter().any(|r| NEVER_QUARANTINED_ROLES.contains(r)) || tags.contains(&NO_QUARANTINE_TAG)
}
