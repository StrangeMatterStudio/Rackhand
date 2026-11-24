//! Peer watch (7.5.5, 7.6.3, E25, AC9): a peer is silent after 2 minutes without a summary (a warning) and down after 10
//! (critical). Several healthy hubs may see the same peer down; only the one whose site name sorts first calls out (the others
//! write what they saw and nothing more). A peer that is heard from again resolves its incidents.

use rackhand_proto::peer::SiteSummary;

use super::election::{self, Candidate};
use super::{PeerRow, Peers};
use crate::incidents::Incidents;

/// Silent after this long without a summary.
pub const SILENT_AFTER_MS: i64 = 2 * 60_000;
/// Down after this long.
pub const DOWN_AFTER_MS: i64 = 10 * 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Ok,
    Silent,
    Down,
}

/// How a peer looks that was last heard from `age_ms` ago.
pub fn state(age_ms: i64) -> PeerState {
    if age_ms >= DOWN_AFTER_MS {
        PeerState::Down
    } else if age_ms >= SILENT_AFTER_MS {
        PeerState::Silent
    } else {
        PeerState::Ok
    }
}

fn well(summary: &SiteSummary) -> bool {
    summary.hub_health.as_ref().is_some_and(|h| h.db_ok && h.notifiers_ok && h.self_check_ok)
}

impl Peers {
    /// When a peer was last heard from: its latest summary, or when it was linked if it never sent one.
    pub fn last_heard(&self, peer: &PeerRow) -> i64 {
        let heard = self.latest_summary(&peer.id).map(|(at, _)| at);
        heard.or_else(|| self.one("SELECT added_at FROM peers WHERE id = ?1", [&peer.id])).unwrap_or(0)
    }

    /// The state of every linked peer now.
    pub fn states(&self, now_ms: i64) -> Vec<(PeerRow, PeerState, i64)> {
        self.peers()
            .into_iter()
            .map(|p| {
                let last = self.last_heard(&p);
                let s = state(now_ms - last);
                (p, s, last)
            })
            .collect()
    }

    /// The other hubs, for the election about `down`: lately heard, well, and not hearing `down` either.
    fn candidates(&self, down: &PeerRow, now_ms: i64) -> Vec<Candidate> {
        self.peers()
            .into_iter()
            .filter(|p| p.id != down.id)
            .map(|p| {
                let latest = self.latest_summary(&p.id).filter(|(at, _)| now_ms - at < SILENT_AFTER_MS);
                let healthy = latest.as_ref().is_some_and(|(_, s)| well(s));
                let sees_down = latest.as_ref().is_some_and(|(_, s)| {
                    s.peers_seen
                        .iter()
                        .find(|seen| seen.site == down.site)
                        .is_none_or(|seen| now_ms - seen.last_heard_ms >= DOWN_AFTER_MS)
                });
                Candidate { site: p.site, healthy, sees_down }
            })
            .collect()
    }

    fn i_am_well(&self) -> bool {
        self.inner.health.lock().ok().and_then(|h| h.clone()).is_none_or(|h| h.notifiers_ok() && h.self_check_ok())
    }

    /// One look at every peer: incidents for the silent and the down, with the callout only from the elected hub.
    pub async fn watch(&self, incidents: &Incidents, now_ms: i64) {
        for (peer, state, last) in self.states(now_ms) {
            let result = match state {
                PeerState::Ok => incidents.peer_well(&peer.site, now_ms).await,
                PeerState::Silent => incidents.peer_unwell(&peer.site, false, last, now_ms).await,
                PeerState::Down => {
                    let me = self.site();
                    if election::elected(me, self.i_am_well(), &self.candidates(&peer, now_ms)) {
                        incidents.peer_unwell(&peer.site, true, last, now_ms).await
                    } else {
                        // another hub calls out; this one only writes down what it saw
                        let data = serde_json::json!({ "peer": peer.site, "since_ms": last }).to_string();
                        let _ = self.inner.audit.append("peer watch", "peer.down_seen", Some(&peer.id), &data).await;
                        Ok(())
                    }
                }
            };
            if let Err(e) = result {
                tracing::warn!(error = %e, peer = %peer.site, "peer watch");
            }
        }
    }

    /// Every 30 seconds until the hub stops: the watch and, for a hub with no peers, the dead-man URL.
    pub fn spawn_watch(
        self,
        incidents: Incidents,
        deadman_url: std::sync::Arc<dyn Fn() -> Option<String> + Send + Sync>,
        ping: std::sync::Arc<dyn super::deadman::Ping>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(super::SUMMARY_EVERY);
            let mut dead = super::deadman::Deadman::default();
            loop {
                tick.tick().await;
                let now = rackhand_store::ids::now_ms();
                self.watch(&incidents, now).await;
                let url = deadman_url();
                dead.tick(now, url.as_deref(), !self.peers().is_empty(), ping.as_ref()).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_is_silent_after_2_minutes_and_down_after_10() {
        let min = 60_000;
        assert_eq!(state(0), PeerState::Ok);
        assert_eq!(state(2 * min - 1), PeerState::Ok);
        assert_eq!(state(2 * min), PeerState::Silent);
        assert_eq!(state(10 * min - 1), PeerState::Silent);
        assert_eq!(state(10 * min), PeerState::Down);
    }
}
