//! The receiving side of `rackhand/xfer/1` (7.3.11, FR-19, E30): a file arrives in 1 MiB chunks, each checked against its BLAKE3
//! before it is written, and the sender is told after each one which chunk the hub wants next. What happens to the chunks is
//! the [`Sink`]'s: a file on a machine (written over SSH), a backup kept for a peer, or the input of a backup tool's receiving
//! command. Who may send what, and where it goes, is the [`Opener`]'s.

use std::sync::Arc;

use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use prost::Message;
use rackhand_net::frames;
use rackhand_net::router::{Handler, handler};
use rackhand_net::xfer::{CHUNK, chunks};
use rackhand_proto::tunnel::{XferAnswer, XferChunk, XferDone, XferKind, XferOffer, XferResume, xfer_answer};

use crate::actions::runner::BoxFuture;

/// Where the chunks of one transfer go.
pub trait Sink: Send {
    /// The first chunk the sink doesn't have yet (a file that was cut short has the chunks before it).
    fn resume(&mut self) -> BoxFuture<'_, Result<u64, String>>;
    /// The next chunk, already checked.
    fn write<'a>(&'a mut self, index: u64, data: &'a [u8]) -> BoxFuture<'a, Result<(), String>>;
    /// Every chunk has come: complete the whole and check it against the offer's BLAKE3.
    fn finish(self: Box<Self>) -> BoxFuture<'static, Result<(), String>>;
    /// The transfer broke: keep what was written, for the next attempt.
    fn abandon(self: Box<Self>) -> BoxFuture<'static, ()>;
}

/// Decides whether a caller may send this, and where it goes. An error is the reason the sender is told.
pub trait Opener: Send + Sync {
    fn open<'a>(&'a self, caller: EndpointId, offer: &'a XferOffer) -> BoxFuture<'a, Result<Box<dyn Sink>, String>>;
}

/// Linked peers send backups; everyone else is a person's device sending to a machine.
pub struct ByCaller {
    db: Arc<rackhand_store::Db>,
    peers: Arc<dyn Opener>,
    devices: Arc<dyn Opener>,
}

impl std::fmt::Debug for ByCaller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ByCaller")
    }
}

impl ByCaller {
    pub fn new(db: Arc<rackhand_store::Db>, peers: Arc<dyn Opener>, devices: Arc<dyn Opener>) -> ByCaller {
        ByCaller { db, peers, devices }
    }
}

impl Opener for ByCaller {
    fn open<'a>(&'a self, caller: EndpointId, offer: &'a XferOffer) -> BoxFuture<'a, Result<Box<dyn Sink>, String>> {
        let is_peer = self
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT count(*) FROM peers WHERE endpoint_id = ?1", [caller.to_string()], |r| {
                    r.get::<_, i64>(0)
                })
            })
            .is_ok_and(|n| n > 0);
        // a peer's stream is an action on a machine, judged with the machine's policy; its backup is kept here
        if is_peer && offer.kind != XferKind::Stream as i32 {
            self.peers.open(caller, offer)
        } else {
            self.devices.open(caller, offer)
        }
    }
}

pub struct Xfer {
    opener: Arc<dyn Opener>,
}

impl std::fmt::Debug for Xfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Xfer")
    }
}

fn resume(next_chunk: u64) -> XferAnswer {
    XferAnswer { answer: Some(xfer_answer::Answer::Resume(XferResume { next_chunk })) }
}

fn done(ok: bool, error: &str) -> XferAnswer {
    XferAnswer { answer: Some(xfer_answer::Answer::Done(XferDone { ok, error: error.to_string() })) }
}

async fn say(send: &mut SendStream, answer: XferAnswer) -> bool {
    frames::write_msg(send, &answer).await.is_ok()
}

/// The length chunk `index` of a file of `size` bytes has.
fn chunk_len(size: u64, index: u64) -> usize {
    size.saturating_sub(index * CHUNK as u64).min(CHUNK as u64) as usize
}

impl Xfer {
    pub fn new(opener: Arc<dyn Opener>) -> Arc<Xfer> {
        Arc::new(Xfer { opener })
    }

    /// The router's handler for `rackhand/xfer/1`.
    pub fn handler(self: &Arc<Xfer>) -> Handler {
        let this = self.clone();
        handler(move |conn| {
            let this = this.clone();
            async move { this.serve(conn).await }
        })
    }

    async fn serve(self: Arc<Xfer>, conn: Connection) {
        let caller = conn.remote_id();
        while let Ok((send, recv)) = conn.accept_bi().await {
            tokio::spawn(self.clone().one(caller, send, recv));
        }
    }

    async fn one(self: Arc<Xfer>, caller: EndpointId, mut send: SendStream, mut recv: RecvStream) {
        let Ok(body) = frames::read(&mut recv).await else { return };
        let Ok(offer) = XferOffer::decode(body.as_slice()) else { return };
        let stream = offer.kind == XferKind::Stream as i32;
        if offer.chunk_size as usize != CHUNK || (!stream && offer.kind != XferKind::File as i32) {
            say(&mut send, done(false, "chunks are 1 MiB, and a transfer is a file or a stream")).await;
            return;
        }
        let mut sink = match self.opener.open(caller, &offer).await {
            Ok(sink) => sink,
            Err(why) => {
                say(&mut send, done(false, &why)).await;
                let _ = send.finish();
                return;
            }
        };
        let total = if stream { u64::MAX } else { chunks(offer.size) };
        let mut next = if stream {
            0
        } else {
            match sink.resume().await {
                Ok(n) => n.min(total),
                Err(why) => {
                    say(&mut send, done(false, &why)).await;
                    return;
                }
            }
        };
        if !say(&mut send, resume(next)).await {
            sink.abandon().await;
            return;
        }
        // a file the sink already has all of is only left to complete
        if !stream && next == total {
            let answer = match sink.finish().await {
                Ok(()) => done(true, ""),
                Err(why) => done(false, &why),
            };
            say(&mut send, answer).await;
            let _ = send.finish();
            return;
        }
        loop {
            let Ok(body) = frames::read(&mut recv).await else {
                sink.abandon().await;
                return;
            };
            let Ok(chunk) = XferChunk::decode(body.as_slice()) else {
                sink.abandon().await;
                return;
            };
            let end = stream && chunk.index == next && chunk.data.is_empty();
            let length_ok =
                if stream { chunk.data.len() <= CHUNK } else { chunk.data.len() == chunk_len(offer.size, next) };
            let intact =
                chunk.index == next && length_ok && blake3::hash(&chunk.data).as_bytes().as_slice() == chunk.blake3;
            if !intact {
                // not what was due, or damaged on the way: the sender is told to send this chunk again
                if !say(&mut send, resume(next)).await {
                    sink.abandon().await;
                    return;
                }
                continue;
            }
            if !end && let Err(why) = sink.write(next, &chunk.data).await {
                say(&mut send, done(false, &why)).await;
                return;
            }
            next += 1;
            if end || (!stream && next == total) {
                let answer = match sink.finish().await {
                    Ok(()) => done(true, ""),
                    Err(why) => done(false, &why),
                };
                say(&mut send, answer).await;
                let _ = send.finish();
                return;
            }
            if !say(&mut send, resume(next)).await {
                sink.abandon().await;
                return;
            }
        }
    }
}
