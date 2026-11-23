//! The asking side of a peer connection: what a hub does to a peer it is linked to. It is used by the dashboard's peer pages, by
//! the watch (T81) and by the contract tests, over a connection the caller made.

use iroh::endpoint::{Connection, RecvStream};
use rackhand_proto::peer::{
    ActionRequest, ActionRequestStatus, PeerAnswer, PeerHello, PeerQuery, PeerUnlink, SiteSummary, peer_answer,
};

use super::{kind, wire};

#[derive(Debug)]
pub struct PeerLink {
    conn: Connection,
}

/// The statuses of a request, one at a time until the last.
#[derive(Debug)]
pub struct Statuses {
    recv: RecvStream,
    done: bool,
}

impl Statuses {
    /// The next status; `None` after the last one or when the stream breaks.
    pub async fn next(&mut self) -> Option<ActionRequestStatus> {
        if self.done {
            return None;
        }
        let status: ActionRequestStatus = wire::read(&mut self.recv).await?;
        self.done = super::requests::is_final(&status);
        Some(status)
    }
}

impl PeerLink {
    pub fn new(conn: Connection) -> PeerLink {
        PeerLink { conn }
    }

    /// The path this link uses now, as the dashboard shows it.
    pub fn path(&self, relays_configured: bool) -> super::path_status::PeerPath {
        super::path_status::PeerPath::of(&self.conn, relays_configured)
    }

    pub async fn hello(&self, hello: &PeerHello) -> Result<(), String> {
        let mut send = self.conn.open_uni().await.map_err(|e| e.to_string())?;
        wire::write_kind(&mut send, kind::HELLO).await;
        wire::write(&mut send, hello).await;
        send.finish().map_err(|e| e.to_string())
    }

    pub async fn send_summary(&self, summary: &SiteSummary) -> Result<(), String> {
        let mut send = self.conn.open_uni().await.map_err(|e| e.to_string())?;
        wire::write_kind(&mut send, kind::SUMMARY).await;
        wire::write(&mut send, summary).await;
        send.finish().map_err(|e| e.to_string())
    }

    /// One query; a job log comes as its chunks, joined.
    pub async fn query(&self, query: &PeerQuery) -> Result<PeerAnswer, String> {
        let (mut send, mut recv) = self.conn.open_bi().await.map_err(|e| e.to_string())?;
        wire::write_kind(&mut send, kind::QUERY).await;
        wire::write(&mut send, query).await;
        send.finish().map_err(|e| e.to_string())?;
        let first: PeerAnswer = wire::read(&mut recv).await.ok_or("no answer")?;
        let Some(peer_answer::Kind::JobLogChunk(mut chunk)) = first.kind.clone() else { return Ok(first) };
        let mut data = std::mem::take(&mut chunk.data);
        while !chunk.last {
            let next: PeerAnswer = wire::read(&mut recv).await.ok_or("the log was cut off")?;
            let Some(peer_answer::Kind::JobLogChunk(c)) = next.kind else { return Ok(next) };
            data.extend_from_slice(&c.data);
            chunk = c;
        }
        Ok(PeerAnswer {
            kind: Some(peer_answer::Kind::JobLogChunk(rackhand_proto::peer::JobLogChunk { data, last: true })),
        })
    }

    /// Asks the peer to run something; the statuses come as they change.
    pub async fn request(&self, request: &ActionRequest) -> Result<Statuses, String> {
        let (mut send, recv) = self.conn.open_bi().await.map_err(|e| e.to_string())?;
        wire::write_kind(&mut send, kind::REQUEST).await;
        wire::write(&mut send, request).await;
        send.finish().map_err(|e| e.to_string())?;
        Ok(Statuses { recv, done: false })
    }

    pub async fn unlink(&self, reason: &str) -> Result<(), String> {
        let mut send = self.conn.open_uni().await.map_err(|e| e.to_string())?;
        wire::write_kind(&mut send, kind::UNLINK).await;
        wire::write(&mut send, &PeerUnlink { reason: reason.to_string() }).await;
        send.finish().map_err(|e| e.to_string())
    }
}
