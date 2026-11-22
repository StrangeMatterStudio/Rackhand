//! The built-in runbooks (7.8.7) shipped in the binary. The hub seeds them into the Library at start (origin
//! `builtin`), where an admin can read and edit them like any runbook.

const RUNBOOKS: &[(&str, &str)] = &[
    ("patch-debian", include_str!("../builtin/patch-debian.toml")),
    ("patch-alpine", include_str!("../builtin/patch-alpine.toml")),
    ("patch-proxmox-host", include_str!("../builtin/patch-proxmox-host.toml")),
    ("patch-hub-host", include_str!("../builtin/patch-hub-host.toml")),
    ("rollback", include_str!("../builtin/rollback.toml")),
];

/// Every built-in runbook, as `(name, content)`.
pub fn runbooks() -> &'static [(&'static str, &'static str)] {
    RUNBOOKS
}

/// One built-in runbook's content.
pub fn runbook(name: &str) -> Option<&'static str> {
    RUNBOOKS.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
}
