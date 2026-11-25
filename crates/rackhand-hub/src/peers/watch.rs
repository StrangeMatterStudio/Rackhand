//! Peer watch (7.5.5, 7.6.3, E25, AC9): a peer is silent after the larger of 2 minutes and 3 summary intervals without a
//! summary (a warning, 7.8.1) and down after 10 minutes (critical). Several healthy hubs may see the same peer down; only the
//! one whose site name sorts first calls out (the others write what they saw and nothing more). A peer that is heard from
//! again resolves its incidents.

use rackhand_proto::peer::SiteSummary;

use super::election::{self, Candidate};
use super::{PeerRow, Peers};
use crate::incidents::Incidents;

/// Down after this long. (Silent comes first: after the larger of 2 minutes and 3 summary intervals, 7.8.1.)
pub const DOWN_AFTER_MS: i64 = 10 * 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Ok,
    Silent,
    Down,
}

/// How a peer looks that was last heard from `age_ms` ago, silent after `silent_after_ms`.
pub fn state(age_ms: i64, silent_after_ms: i64) -> PeerState {
    if age_ms >= DOWN_AFTER_MS {
        PeerState::Down
    } else if age_ms >= silent_after_ms {
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
        let silent = self.silent_after_ms();
        self.peers()
            .into_iter()
            .map(|p| {
                let last = self.last_heard(&p);
                let s = state(now_ms - last, silent);
                (p, s, last)
            })
            .collect()
    }

    /// The other hubs, for the election about `down`: lately heard, well, and not hearing `down` either.
    fn candidates(&self, down: &PeerRow, now_ms: i64) -> Vec<Candidate> {
        let silent = self.silent_after_ms();
        self.peers()
            .into_iter()
            .filter(|p| p.id != down.id)
            .map(|p| {
                let latest = self.latest_summary(&p.id).filter(|(at, _)| now_ms - at < silent);
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

    /// When a peer is silent: after the larger of 2 minutes and 3 of the summary intervals this hub's settings give
    /// (7.8.1).
    pub fn silent_after_ms(&self) -> i64 {
        crate::library::config::hub_or_default(&self.inner.db).peers.silent_after_ms()
    }

    /// The summary interval of the settings (7.8.1), read each time.
    pub(super) fn summary_every(&self) -> std::time::Duration {
        crate::library::config::hub_or_default(&self.inner.db).peers.summary_every()
    }

    /// Every summary interval until the hub stops: the watch and, for a hub with no peers, the dead-man URL.
    pub fn spawn_watch(
        self,
        incidents: Incidents,
        deadman_url: std::sync::Arc<dyn Fn() -> Option<String> + Send + Sync>,
        ping: std::sync::Arc<dyn super::deadman::Ping>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut dead = super::deadman::Deadman::default();
            loop {
                let now = rackhand_store::ids::now_ms();
                self.watch(&incidents, now).await;
                let url = deadman_url();
                dead.tick(now, url.as_deref(), !self.peers().is_empty(), ping.as_ref()).await;
                tokio::time::sleep(self.summary_every()).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::config::PeerSettings;

    #[test]
    fn a_peer_is_silent_after_2_minutes_and_down_after_10() {
        let min = 60_000;
        let silent = PeerSettings::default().silent_after_ms();
        assert_eq!(state(0, silent), PeerState::Ok);
        assert_eq!(state(2 * min - 1, silent), PeerState::Ok);
        assert_eq!(state(2 * min, silent), PeerState::Silent);
        assert_eq!(state(10 * min - 1, silent), PeerState::Silent);
        assert_eq!(state(10 * min, silent), PeerState::Down);
    }

    /// 7.8.1: silent after the larger of 2 minutes and 3 summary intervals.
    #[test]
    fn the_silent_warning_follows_3_summary_intervals() {
        let min = 60_000;
        let every = |s: u32| PeerSettings { summary_interval_s: s }.silent_after_ms();
        assert_eq!((every(10), every(30), every(40)), (2 * min, 2 * min, 2 * min), "2 minutes at least");
        assert_eq!(every(60), 3 * min);
        assert_eq!(state(3 * min - 1, every(60)), PeerState::Ok, "a peer that sends every minute");
        assert_eq!(state(3 * min, every(60)), PeerState::Silent);
    }
}
