//! What a hypervisor-side action may do to a guest (7.3.12, D93, E50): only to the guest an admin confirmed as the
//! machine's. A binding that is proposed, or `mismatch` after a probe reported another guest's MAC, is refused before
//! any call to the hypervisor's API, so a probe that lies about which guest it is can't point a snapshot, a rollback,
//! a firewall change or a power action at another one.

/// The kinds of hypervisor-side action on a guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestAction {
    Snapshot,
    Rollback,
    /// Reading and restoring the guest's firewall, and isolating it and releasing it (quarantine, 7.5.6).
    Firewall,
    Power,
}

impl GuestAction {
    /// The driver operations the action may use; any other is refused.
    pub fn ops(self) -> &'static [&'static str] {
        match self {
            GuestAction::Snapshot => &["snapshot", "snapshot_room", "snapshots", "delete_snapshot"],
            GuestAction::Rollback => &["rollback"],
            GuestAction::Firewall => &["firewall_read", "firewall_restore", "firewall_isolate", "firewall_release"],
            GuestAction::Power => &["power"],
        }
    }
}

/// Why a guest isn't acted on, or `None` when its binding is confirmed.
pub fn refusal(binding_state: &str) -> Option<&'static str> {
    match binding_state {
        "confirmed" => None,
        "mismatch" => Some("guest_binding_mismatch"),
        _ => Some("guest_binding_unconfirmed"),
    }
}
