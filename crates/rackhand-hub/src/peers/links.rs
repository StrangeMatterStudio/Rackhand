//! Making and keeping a link (7.3.4, 7.3.1, D158): the join one hub makes with the other's invite, the connection each keeps to
//! the other, and the summary each pushes every 30 seconds. A hub reaches a peer on the connection the peer opened if there is
//! one, and otherwise dials its endpoint id with the addresses and relays it was given; a hub behind a NAT is reached because
//! it dialed first.

use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::{EndpointAddr, EndpointId, TransportAddr};
use rackhand_net::ticket::Ticket;
use rackhand_proto::common::{RelayUrl, SemVer};
use rackhand_proto::frame;
use rackhand_proto::join::join_request::Kind as Req;
use rackhand_proto::join::join_response::Kind as Resp;
use rackhand_proto::join::{JoinError, JoinRequest, JoinResponse, PeerJoin};
use rackhand_proto::peer::PeerHello;
use rackhand_store::ids::now_ms;
use rackhand_store::{RegistryChange, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use super::tunnel::Network;
use super::{PeerLink, PeerRow, Peers};
use crate::registry::peers::valid_site_name;
use crate::registry::tokens::TokenKind;

/// How long a dial or a join may take before the peer counts as unreachable.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

fn json_list(items: &[String]) -> String {
    serde_json::to_string(items).unwrap_or_else(|_| "[]".into())
}

impl Peers {
    /// The hub's endpoint, for dialing peers and joining; bound after the endpoint exists.
    pub fn with_network(self, network: std::sync::Arc<Network>) -> Peers {
        *self.inner.network.lock().unwrap_or_else(|e| e.into_inner()) = Some(network);
        self
    }

    pub(super) fn network(&self) -> Result<std::sync::Arc<Network>, String> {
        self.inner
            .network
            .lock()
            .ok()
            .and_then(|n| n.clone())
            .filter(|n| n.endpoint().is_some())
            .ok_or_else(|| "this hub has no network yet".to_string())
    }

    /// Remembers a live connection to a peer: the one it opened, or the one this hub dialed.
    pub(super) fn keep(&self, peer_id: &str, conn: &Connection) {
        self.inner.live.lock().unwrap_or_else(|e| e.into_inner()).insert(peer_id.to_string(), conn.clone());
    }

    /// Forgets the connection when it is the one that ended (a newer one may have replaced it).
    pub(super) fn forget(&self, peer_id: &str, conn: &Connection) {
        let mut live = self.inner.live.lock().unwrap_or_else(|e| e.into_inner());
        if live.get(peer_id).is_some_and(|c| c.stable_id() == conn.stable_id()) {
            live.remove(peer_id);
        }
    }

    pub(super) fn alive(&self, peer_id: &str) -> Option<Connection> {
        let live = self.inner.live.lock().unwrap_or_else(|e| e.into_inner());
        live.get(peer_id).filter(|c| c.close_reason().is_none()).cloned()
    }

    fn hello(&self, network: &Network) -> PeerHello {
        PeerHello {
            site: self.inner.site.clone(),
            hub_version: Some(SemVer { version: self.inner.version.clone() }),
            relays: network.relays().iter().map(|r| RelayUrl { url: r.to_string() }).collect(),
        }
    }

    /// The connection to a peer: the live one, or a new one dialed with what is known of it.
    async fn connection(&self, peer: &PeerRow) -> Result<Connection, String> {
        if let Some(conn) = self.alive(&peer.id) {
            return Ok(conn);
        }
        let network = self.network()?;
        let endpoint = network.endpoint().ok_or("this hub has no network yet")?;
        let id: EndpointId =
            peer.endpoint_id.parse().map_err(|_| "the peer's endpoint id is unreadable".to_string())?;
        let mut addr = EndpointAddr::new(id);
        for a in peer.addrs.iter().filter_map(|a| a.parse().ok()) {
            addr.addrs.insert(TransportAddr::Ip(a));
        }
        let relays = peer.relays.iter().filter_map(|r| r.parse().ok()).chain(network.relays().iter().cloned());
        for relay in relays {
            addr.addrs.insert(TransportAddr::Relay(relay));
        }
        let conn = tokio::time::timeout(DIAL_TIMEOUT, endpoint.connect(addr, rackhand_proto::alpn::PEER))
            .await
            .map_err(|_| format!("{} didn't answer", peer.site))?
            .map_err(|e| format!("can't reach {}: {e}", peer.site))?;
        self.keep(&peer.id, &conn);
        // what the peer opens toward this hub on the same connection is served like any other
        let (peers, served) = (self.clone(), conn.clone());
        tokio::spawn(async move { peers.serve(served).await });
        let _ = PeerLink::new(conn.clone()).hello(&self.hello(&network)).await;
        Ok(conn)
    }

    /// The asking side of a peer's connection, for the dashboard.
    pub async fn link(&self, peer: &PeerRow) -> Result<PeerLink, String> {
        Ok(PeerLink::new(self.connection(peer).await?))
    }

    /// Sends this hub's summary to every peer now; each result is that peer's site and how it went. A peer that can't be
    /// reached doesn't hold up the others.
    pub async fn push(&self) -> Vec<(String, Result<(), String>)> {
        let summary = self.summary(now_ms());
        let mut tasks = tokio::task::JoinSet::new();
        for peer in self.peers() {
            let (peers, summary) = (self.clone(), summary.clone());
            tasks.spawn(async move {
                let sent = async { peers.link(&peer).await?.send_summary(&summary).await }.await;
                (peer.site, sent)
            });
        }
        let mut results = Vec::new();
        while let Some(done) = tasks.join_next().await {
            if let Ok(r) = done {
                results.push(r);
            }
        }
        results.sort_by(|a, b| a.0.cmp(&b.0));
        results
    }

    /// Every 30 seconds until the hub stops: this hub's summary to each peer.
    pub fn spawn_push(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(super::SUMMARY_EVERY);
            loop {
                tick.tick().await;
                for (site, result) in self.push().await {
                    if let Err(e) = result {
                        tracing::debug!(peer = %site, error = %e, "pushing the summary");
                    }
                }
            }
        })
    }

    /// Joins the hub an invite (`<ticket>#<secret>`, from its Add page) names: it adds this hub as a peer, and this hub adds
    /// it. Both are listed and admitted afterward, and the summaries start at once.
    pub async fn join(&self, invite: &str, by: &str) -> Result<PeerRow, String> {
        let (ticket, secret) = invite
            .trim()
            .split_once('#')
            .filter(|(t, s)| !t.is_empty() && !s.is_empty())
            .ok_or("a peer invite looks like `rackhand1:...#...`")?;
        let ticket = Ticket::parse(ticket)?;
        let network = self.network()?;
        let endpoint = network.endpoint().ok_or("this hub has no network yet")?;
        let request = JoinRequest {
            kind: Some(Req::Peer(PeerJoin {
                invite_secret: secret.to_string(),
                site: self.inner.site.clone(),
                hub_version: Some(SemVer { version: self.inner.version.clone() }),
                relays: network.relays().iter().map(|r| RelayUrl { url: r.to_string() }).collect(),
            })),
        };
        let conn =
            tokio::time::timeout(DIAL_TIMEOUT, endpoint.connect(ticket.endpoint_addr()?, rackhand_proto::alpn::JOIN))
                .await
                .map_err(|_| "the other hub didn't answer".to_string())?
                .map_err(|e| format!("can't reach the other hub: {e}"))?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
        send.write_all(&frame::encode(&request).map_err(|e| e.to_string())?).await.map_err(|e| e.to_string())?;
        send.finish().map_err(|e| e.to_string())?;
        let data = recv.read_to_end(frame::MAX_FRAME + 4).await.map_err(|e| e.to_string())?;
        conn.close(0u32.into(), b"done");
        let body = frame::read_frame(&mut data.as_slice()).map_err(|e| e.to_string())?;
        let joined = match <JoinResponse as prost::Message>::decode(body.as_slice()).map_err(|e| e.to_string())?.kind {
            Some(Resp::Peer(joined)) => joined,
            Some(Resp::Error(f)) => {
                let code = JoinError::try_from(f.code).map(|c| c.as_str_name()).unwrap_or("JOIN_ERROR_UNSPECIFIED");
                return Err(format!("the other hub refused the join ({code}): {}", f.message));
            }
            _ => return Err("the other hub answered something other than a peer join".into()),
        };
        if !valid_site_name(&joined.site) {
            return Err(format!("the other hub's site name `{}` isn't one this hub accepts", joined.site));
        }
        let registry = self.inner.registry.lock().ok().and_then(|r| r.clone()).ok_or("this hub has no registry")?;
        if registry.site_name_known(&joined.site).map_err(|e| e.to_string())? {
            return Err(format!("site `{}` is already known to this hub", joined.site));
        }
        let id = ulid::Ulid::new().to_string();
        let peer_id = EndpointId::from_bytes(&ticket.hub_id).map_err(|e| e.to_string())?;
        let addrs: Vec<String> = ticket.addrs.iter().map(|a| a.to_string()).collect();
        let mut relays: Vec<String> = joined.relays.iter().map(|r| r.url.clone()).collect();
        for r in &ticket.relays {
            if !relays.contains(r) {
                relays.push(r.clone());
            }
        }
        let row: Row = [
            ("id", Value::Text(id.clone())),
            ("site", Value::Text(joined.site.clone())),
            ("endpoint_id", Value::Text(peer_id.to_string())),
            ("added_at", Value::Integer(now_ms())),
            ("addrs", Value::Text(json_list(&addrs))),
            ("relays", Value::Text(json_list(&relays))),
        ]
        .into_iter()
        .collect();
        let change = RegistryChange { writes: vec![RowWrite::insert("peers", row)], ..Default::default() };
        self.inner.db.writer().send(WriteCmd::RegistryChange(change)).await.map_err(|e| e.to_string())?;
        registry.allow(TokenKind::Peer, peer_id);
        let data = serde_json::json!({ "site": joined.site }).to_string();
        let _ = self.inner.audit.append(by, "peer.linked", Some(&id), &data).await;
        let peer = self.peers().into_iter().find(|p| p.id == id).ok_or("the peer was not saved")?;
        let (peers, first) = (self.clone(), peer.clone());
        tokio::spawn(async move {
            if let Ok(link) = peers.link(&first).await {
                let _ = link.send_summary(&peers.summary(now_ms())).await;
            }
        });
        Ok(peer)
    }
}
