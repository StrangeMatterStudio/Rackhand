//! Peer links, summaries, queries, request forwarding and unlinking (7.3.4, FR-18, D30, D32, D69).
//!
//! Two linked hubs keep one connection on `rackhand/peer/1`. Every stream starts with one byte that says what it is, then
//! length-prefixed protobuf frames:
//!
//! | first byte | stream | frames |
//! | --- | --- | --- |
//! | 0 | unidirectional, once per connection | `PeerHello` |
//! | 1 | unidirectional, every 30 s | `SiteSummary` |
//! | 2 | bidirectional, one query | `PeerQuery`, then `PeerAnswer` (a job log in chunks) |
//! | 3 | bidirectional, one request | `ActionRequest`, then `ActionRequestStatus` each time it changes until it is final |
//! | 4 | unidirectional | `PeerUnlink` |
//!
//! A peer is a pair: A linked to B and B linked to C doesn't link A and C. The owning hub decides what a peer may ask: a
//! query allow-list per peer (`JobLog` off by default, and sensitive diagnostics' output is never sent), at most 10 queries a
//! second, and an action request is like a local request at level 1: it always needs an approval on the owning hub unless the
//! target's policy says `peer_requests = "auto"` for a runbook that isn't high risk. `requested_by` is information.

pub mod deadman;
pub mod election;
mod link;
mod links;
pub mod path_status;
mod queries;
mod reach;
pub mod relay_lists;
mod requests;
mod summary;
pub mod tunnel;
mod unlink;
mod watch;
mod wire;
pub mod xfer;
pub mod xfer_machine;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use iroh::endpoint::Connection;
use rackhand_store::Db;
use rusqlite::OptionalExtension;

use crate::actions::Actions;
use crate::audit::Audit;
use crate::ingest::Ingest;

pub use link::{PeerLink, Statuses};
pub use reach::PeerReach;
pub use summary::HubHealthSource;
pub use watch::{DOWN_AFTER_MS, PeerState, state};

/// Queries a peer may make in a second.
pub const QUERIES_PER_SECOND: usize = 10;

pub(crate) mod kind {
    pub const HELLO: u8 = 0;
    pub const SUMMARY: u8 = 1;
    pub const QUERY: u8 = 2;
    pub const REQUEST: u8 = 3;
    pub const UNLINK: u8 = 4;
}

/// A linked peer, as the owning hub knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRow {
    pub id: String,
    pub site: String,
    pub endpoint_id: String,
    pub allowed: Vec<String>,
    /// The peer's direct addresses and relays, from its ticket and its join.
    pub addrs: Vec<String>,
    pub relays: Vec<String>,
    /// What this hub keeps for the peer's backups, in bytes (0: none).
    pub quota_bytes: u64,
}

struct Inner {
    db: Arc<Db>,
    audit: Audit,
    actions: Actions,
    ingest: Ingest,
    /// This hub's own site name and version.
    site: String,
    version: String,
    health: Mutex<Option<Arc<dyn HubHealthSource>>>,
    /// Admission, so that an unlinked peer is refused at once.
    registry: Mutex<Option<Arc<crate::registry::Registry>>>,
    /// Query times per peer, for the rate limit.
    queries: Mutex<HashMap<String, VecDeque<Instant>>>,
    /// The hub's endpoint, to dial peers and join (links.rs).
    network: Mutex<Option<Arc<tunnel::Network>>>,
    /// The live connection to each peer, by peer id: the one it opened or the one this hub dialed.
    live: Mutex<HashMap<String, Connection>>,
}

#[derive(Clone)]
pub struct Peers {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Peers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Peers")
    }
}

impl Peers {
    pub fn new(db: Arc<Db>, audit: Audit, actions: Actions, ingest: Ingest, site: &str, version: &str) -> Peers {
        Peers {
            inner: Arc::new(Inner {
                db,
                audit,
                actions,
                ingest,
                site: site.to_string(),
                version: version.to_string(),
                health: Mutex::new(None),
                registry: Mutex::new(None),
                queries: Mutex::new(HashMap::new()),
                network: Mutex::new(None),
                live: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Where the summary's hub health comes from (the operators online, the self-check); `ok` values without it.
    pub fn with_health(self, source: Arc<dyn HubHealthSource>) -> Peers {
        *self.inner.health.lock().unwrap_or_else(|e| e.into_inner()) = Some(source);
        self
    }

    /// Admission, so that unlinking a peer closes its next connection with `0x13`.
    pub fn with_registry(self, registry: Arc<crate::registry::Registry>) -> Peers {
        *self.inner.registry.lock().unwrap_or_else(|e| e.into_inner()) = Some(registry);
        self
    }

    pub fn site(&self) -> &str {
        &self.inner.site
    }

    /// The linked peers, not revoked.
    pub fn peers(&self) -> Vec<PeerRow> {
        self.inner
            .db
            .readers()
            .with(|c| {
                let mut s = c.prepare(
                    "SELECT id, site, endpoint_id, allowed_queries, addrs, relays, backup_quota_bytes FROM peers
                     WHERE revoked_at IS NULL ORDER BY site",
                )?;
                s.query_map([], |r| {
                    let (allowed, addrs, relays): (String, String, String) = (r.get(3)?, r.get(4)?, r.get(5)?);
                    let quota: i64 = r.get(6)?;
                    Ok(PeerRow {
                        id: r.get(0)?,
                        site: r.get(1)?,
                        endpoint_id: r.get(2)?,
                        allowed: serde_json::from_str(&allowed).unwrap_or_default(),
                        addrs: serde_json::from_str(&addrs).unwrap_or_default(),
                        relays: serde_json::from_str(&relays).unwrap_or_default(),
                        quota_bytes: u64::try_from(quota).unwrap_or(0),
                    })
                })?
                .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn peer_by_endpoint(&self, endpoint_id: &str) -> Option<PeerRow> {
        self.peers().into_iter().find(|p| p.endpoint_id == endpoint_id)
    }

    /// The router handler for `rackhand/peer/1`.
    pub fn handler(&self) -> rackhand_net::router::Handler {
        let peers = self.clone();
        rackhand_net::router::handler(move |conn: Connection| {
            let peers = peers.clone();
            async move { peers.serve(conn).await }
        })
    }

    async fn serve(&self, conn: Connection) {
        let id = conn.remote_id().to_string();
        let Some(peer) = self.peer_by_endpoint(&id) else {
            rackhand_net::close(&conn, rackhand_proto::close::CloseCode::Revoked);
            return;
        };
        let _ = self.touch(&peer.id);
        self.keep(&peer.id, &conn);
        self.accept_streams(&id, &conn).await;
        self.forget(&peer.id, &conn);
    }

    async fn accept_streams(&self, id: &str, conn: &Connection) {
        loop {
            tokio::select! {
                uni = conn.accept_uni() => {
                    let Ok(recv) = uni else { return };
                    let (peers, id) = (self.clone(), id.to_string());
                    // the peer as it is now: the admin may have changed what it may ask, or removed it
                    tokio::spawn(async move {
                        if let Some(peer) = peers.peer_by_endpoint(&id) {
                            peers.on_uni(&peer, recv).await;
                        }
                    });
                }
                bi = conn.accept_bi() => {
                    let Ok((send, recv)) = bi else { return };
                    let (peers, id) = (self.clone(), id.to_string());
                    tokio::spawn(async move {
                        if let Some(peer) = peers.peer_by_endpoint(&id) {
                            peers.on_bi(&peer, send, recv).await;
                        }
                    });
                }
            }
        }
    }

    fn touch(&self, _peer_id: &str) -> Result<(), rusqlite::Error> {
        // the time is for the dashboard and the watch (T81); it is written with the summary, not on every stream
        Ok(())
    }

    async fn on_uni(&self, peer: &PeerRow, mut recv: iroh::endpoint::RecvStream) {
        let Some(first) = wire::read_kind(&mut recv).await else { return };
        match first {
            kind::HELLO => {
                if let Some(hello) = wire::read::<rackhand_proto::peer::PeerHello>(&mut recv).await {
                    if hello.site != peer.site {
                        tracing::warn!(peer = %peer.site, said = %hello.site, "a peer's hello names another site");
                    }
                }
            }
            kind::SUMMARY => {
                if let Some(summary) = wire::read::<rackhand_proto::peer::SiteSummary>(&mut recv).await {
                    self.store_summary(peer, &summary).await;
                }
            }
            kind::UNLINK => {
                let reason = wire::read::<rackhand_proto::peer::PeerUnlink>(&mut recv).await.map(|u| u.reason);
                self.unlinked_by(peer, reason.as_deref().unwrap_or("")).await;
            }
            _ => {}
        }
    }

    async fn on_bi(&self, peer: &PeerRow, mut send: iroh::endpoint::SendStream, mut recv: iroh::endpoint::RecvStream) {
        let Some(first) = wire::read_kind(&mut recv).await else { return };
        match first {
            kind::QUERY => {
                let Some(query) = wire::read::<rackhand_proto::peer::PeerQuery>(&mut recv).await else { return };
                self.answer(peer, query, &mut send).await;
            }
            kind::REQUEST => {
                let Some(request) = wire::read::<rackhand_proto::peer::ActionRequest>(&mut recv).await else { return };
                self.on_request(peer, request, &mut send).await;
            }
            _ => {}
        }
        let _ = send.finish();
    }

    fn one<T>(&self, sql: &str, params: impl rusqlite::Params) -> Option<T>
    where
        T: rusqlite::types::FromSql,
    {
        self.inner.db.readers().with(|c| c.query_row(sql, params, |r| r.get(0)).optional()).ok().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_kinds_are_distinct() {
        let all = [kind::HELLO, kind::SUMMARY, kind::QUERY, kind::REQUEST, kind::UNLINK];
        let mut sorted = all;
        sorted.sort_unstable();
        assert!(sorted.windows(2).all(|w| w[0] != w[1]));
    }
}
