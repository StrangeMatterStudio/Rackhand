//! The built-in runbooks (7.8.7) shipped in the binary. The hub seeds them into the Library at start (origin
//! `builtin`), where an admin can read and edit them like any runbook.

const RUNBOOKS: &[(&str, &str)] = &[
    ("patch-debian", include_str!("../builtin/patch-debian.toml")),
    ("patch-alpine", include_str!("../builtin/patch-alpine.toml")),
    ("patch-proxmox-host", include_str!("../builtin/patch-proxmox-host.toml")),
    ("patch-hub-host", include_str!("../builtin/patch-hub-host.toml")),
    ("reboot-host", include_str!("../builtin/reboot-host.toml")),
    ("rollback", include_str!("../builtin/rollback.toml")),
    ("sudoers-refresh", include_str!("../builtin/sudoers-refresh.toml")),
    ("keys-rotate", include_str!("../builtin/keys-rotate.toml")),
    ("unenroll", include_str!("../builtin/unenroll.toml")),
    ("reboot", include_str!("../builtin/reboot.toml")),
    ("snapshot", include_str!("../builtin/snapshot.toml")),
    ("service-restart", include_str!("../builtin/service-restart.toml")),
    ("compose-restart", include_str!("../builtin/compose-restart.toml")),
    ("compose-update", include_str!("../builtin/compose-update.toml")),
    ("provision-vm", include_str!("../builtin/provision-vm.toml")),
    ("provision-lxc", include_str!("../builtin/provision-lxc.toml")),
    ("quarantine", include_str!("../builtin/quarantine.toml")),
    ("quarantine-release", include_str!("../builtin/quarantine-release.toml")),
    ("conntrack-flush", include_str!("../builtin/conntrack-flush.toml")),
];

const PLAYBOOKS: &[(&str, &str)] = &[
    ("patch-failure", include_str!("../builtin/playbooks/patch-failure.md")),
    ("service-down", include_str!("../builtin/playbooks/service-down.md")),
    ("disk-filling", include_str!("../builtin/playbooks/disk-filling.md")),
    ("security-finding", include_str!("../builtin/playbooks/security-finding.md")),
    ("machine-silent", include_str!("../builtin/playbooks/machine-silent.md")),
    ("backup-stale", include_str!("../builtin/playbooks/backup-stale.md")),
    ("guided-install", include_str!("../builtin/playbooks/guided-install.md")),
];

/// Every built-in playbook (7.8.8), as `(name, content)`.
pub fn playbooks() -> &'static [(&'static str, &'static str)] {
    PLAYBOOKS
}

/// Every built-in runbook, as `(name, content)`.
pub fn runbooks() -> &'static [(&'static str, &'static str)] {
    RUNBOOKS
}

/// One built-in runbook's content.
pub fn runbook(name: &str) -> Option<&'static str> {
    RUNBOOKS.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
}
