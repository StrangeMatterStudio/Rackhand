//! What the dashboard asks of the peers system (7.7.1): a request for a peer's machine, a join, an unlink and how a peer is
//! reached. `Peers` is the real one; the page tests give a fake that records what was asked.

use std::time::Duration;

use rackhand_proto::peer::{ActionRequest, ActionRequestStatus};

use super::Peers;
use super::path_status::PeerPath;
use crate::actions::runner::BoxFuture;

/// How long the dashboard waits for a peer to say what became of a request.
const FIRST_STATUS: Duration = Duration::from_secs(15);

pub trait PeerReach: Send + Sync {
    /// Asks the peer to run something; the first status it gives (usually that it needs an approval there).
    fn request<'a>(
        &'a self,
        peer_id: &'a str,
        request: &'a ActionRequest,
    ) -> BoxFuture<'a, Result<ActionRequestStatus, String>>;

    /// Joins the hub an invite names; the site it is.
    fn join<'a>(&'a self, invite: &'a str, by: &'a str) -> BoxFuture<'a, Result<String, String>>;

    /// Tells the peer and removes it from this hub.
    fn unlink<'a>(&'a self, peer_id: &'a str, by: &'a str) -> BoxFuture<'a, Result<(), String>>;

    /// The path this hub uses to the peer now.
    fn path(&self, peer_id: &str) -> PeerPath;
}

impl PeerReach for Peers {
    fn request<'a>(
        &'a self,
        peer_id: &'a str,
        request: &'a ActionRequest,
    ) -> BoxFuture<'a, Result<ActionRequestStatus, String>> {
        Box::pin(async move {
            let peer = self.peers().into_iter().find(|p| p.id == peer_id).ok_or("no such peer")?;
            let mut statuses = self.link(&peer).await?.request(request).await?;
            tokio::time::timeout(FIRST_STATUS, statuses.next())
                .await
                .map_err(|_| format!("{} didn't answer", peer.site))?
                .ok_or_else(|| format!("{} closed the request without an answer", peer.site))
        })
    }

    fn join<'a>(&'a self, invite: &'a str, by: &'a str) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async move { Peers::join(self, invite, by).await.map(|p| p.site) })
    }

    fn unlink<'a>(&'a self, peer_id: &'a str, by: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let peer = self.peers().into_iter().find(|p| p.id == peer_id).ok_or("no such peer")?;
            // the peer is told when it can be; either way this hub forgets it
            if let Ok(link) = self.link(&peer).await {
                let _ = link.unlink(&format!("unlinked by {by}")).await;
            }
            self.remove_peer(&peer, by, "unlinked on the dashboard").await.map_err(|e| e.to_string())
        })
    }

    fn path(&self, peer_id: &str) -> PeerPath {
        let relays = self.network().is_ok_and(|n| !n.relays().is_empty());
        match self.alive(peer_id) {
            Some(conn) => PeerPath::of(&conn, relays),
            None => PeerPath::unreachable(relays),
        }
    }
}
