//! The path to a peer, as the dashboard shows it (7.3.4, 7.7.1, E26, E29): direct, through a relay, or unreachable with the
//! reason in words. Two hubs behind NATs that can't be punched through need a relay; saying so is the point of the last case.

use iroh::endpoint::Connection;
use rackhand_net::paths::{self, PathKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStatus {
    Direct,
    Relayed,
    Unreachable,
}

/// What the page says about one peer's path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPath {
    pub status: PathStatus,
    /// The short label: `direct`, `via relay` or `unreachable: no path`.
    pub label: &'static str,
    /// What it means and what to do about it, when there is something to say.
    pub detail: Option<String>,
}

impl PeerPath {
    /// The path a connection uses now. `relays_configured` is whether this hub has a relay to use.
    pub fn of(conn: &Connection, relays_configured: bool) -> PeerPath {
        PeerPath::from_kind(paths::kind(conn), relays_configured)
    }

    pub fn from_kind(kind: PathKind, relays_configured: bool) -> PeerPath {
        match kind {
            PathKind::Direct => PeerPath { status: PathStatus::Direct, label: "direct", detail: None },
            PathKind::Relay => PeerPath {
                status: PathStatus::Relayed,
                label: "via relay",
                detail: Some(
                    "Traffic goes through a relay, which is slower. Bulk transfers and backups wait for a direct path \
                     unless the job allows a relay. Two hubs behind typical home or office NATs may stay on the relay \
                     unless one of them has a port forwarded."
                        .into(),
                ),
            },
            PathKind::None => PeerPath::unreachable(relays_configured),
        }
    }

    /// A peer that couldn't be reached at all.
    pub fn unreachable(relays_configured: bool) -> PeerPath {
        let detail = if relays_configured {
            "No path to this peer, even through the relay. Check that the relay is running and that this hub's relay key \
             is accepted, and that the peer is online."
        } else {
            "No path to this peer: the hubs couldn't reach each other directly, and no relay is configured. When both \
             hubs are behind NATs a relay is needed. Add one under Peers and relays."
        };
        PeerPath { status: PathStatus::Unreachable, label: "unreachable: no path", detail: Some(detail.into()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_direct_path_needs_no_explanation() {
        let p = PeerPath::from_kind(PathKind::Direct, false);
        assert_eq!((p.status, p.label, p.detail), (PathStatus::Direct, "direct", None));
    }

    #[test]
    fn a_relayed_path_says_bulk_transfers_wait() {
        let p = PeerPath::from_kind(PathKind::Relay, true);
        assert_eq!((p.status, p.label), (PathStatus::Relayed, "via relay"));
        let detail = p.detail.expect("an explanation");
        assert!(detail.contains("Bulk transfers and backups wait for a direct path"), "{detail}");
    }

    #[test]
    fn hard_nat_no_relay_unreachable_with_explanation() {
        let p = PeerPath::from_kind(PathKind::None, false);
        assert_eq!((p.status, p.label), (PathStatus::Unreachable, "unreachable: no path"));
        let detail = p.detail.expect("an explanation");
        assert!(detail.contains("a relay is needed") && detail.contains("Add one under Peers and relays"), "{detail}");
        // with a relay configured the advice is about the relay, not about adding one
        let with = PeerPath::unreachable(true).detail.expect("an explanation");
        assert!(with.contains("even through the relay") && !with.contains("Add one"), "{with}");
    }
}
