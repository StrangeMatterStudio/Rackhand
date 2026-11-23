//! The `rackhand/xfer/1` contract (7.3.11, FR-19, E29, E30): chunks that are checked and sent again when they aren't right, a
//! transfer that goes on from the last verified chunk, and refusals that say why. The receiving side here is a sink in memory.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::{RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use prost::Message;
use rackhand_hub::actions::runner::BoxFuture;
use rackhand_hub::peers::xfer::{Opener, Sink, Xfer};
use rackhand_net::frames;
use rackhand_net::registry::MemoryRegistry;
use rackhand_net::xfer::{CHUNK, XferError, send_file, send_stream};
use rackhand_proto::alpn;
use rackhand_proto::tunnel::{XferAnswer, XferChunk, XferKind, XferOffer, xfer_answer};

/// What each destination has received: chunk index to data.
type Files = Arc<Mutex<BTreeMap<String, BTreeMap<u64, Vec<u8>>>>>;

#[derive(Default)]
struct Memory {
    files: Files,
    /// Every chunk index written, in order, across all transfers.
    written: Arc<Mutex<Vec<u64>>>,
    /// Streams received, whole.
    streams: Arc<Mutex<Vec<Vec<u8>>>>,
    /// The destinations that are refused, with the reason.
    refused: Mutex<BTreeMap<String, String>>,
    /// Writing this chunk index fails once (the connection or the disk broke).
    fail_at: Mutex<Option<u64>>,
}

struct MemorySink {
    dest: String,
    stream: bool,
    offer_hash: Vec<u8>,
    files: Files,
    written: Arc<Mutex<Vec<u64>>>,
    streams: Arc<Mutex<Vec<Vec<u8>>>>,
    pending: Vec<u8>,
    fail_at: Option<u64>,
}

impl Sink for MemorySink {
    fn resume(&mut self) -> BoxFuture<'_, Result<u64, String>> {
        Box::pin(async move {
            // the chunks the file has, from the first, without a gap
            let files = self.files.lock().unwrap();
            let have = files
                .get(&self.dest)
                .map(|c| {
                    c.keys()
                        .take_while({
                            let mut want = 0;
                            move |k| {
                                let ok = **k == want;
                                want += 1;
                                ok
                            }
                        })
                        .count()
                })
                .unwrap_or(0);
            Ok(have as u64)
        })
    }

    fn write<'a>(&'a mut self, index: u64, data: &'a [u8]) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            if self.fail_at == Some(index) {
                return Err("the disk is full".into());
            }
            self.written.lock().unwrap().push(index);
            if self.stream {
                self.pending.extend_from_slice(data);
            } else {
                self.files.lock().unwrap().entry(self.dest.clone()).or_default().insert(index, data.to_vec());
            }
            Ok(())
        })
    }

    fn finish(self: Box<Self>) -> BoxFuture<'static, Result<(), String>> {
        Box::pin(async move {
            if self.stream {
                self.streams.lock().unwrap().push(self.pending);
                return Ok(());
            }
            let whole: Vec<u8> = self
                .files
                .lock()
                .unwrap()
                .get(&self.dest)
                .map(|c| c.values().flatten().copied().collect())
                .unwrap_or_default();
            if blake3::hash(&whole).as_bytes().as_slice() != self.offer_hash {
                return Err("the file doesn't match its hash".into());
            }
            Ok(())
        })
    }

    fn abandon(self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }
}

impl Opener for Memory {
    fn open<'a>(&'a self, _caller: EndpointId, offer: &'a XferOffer) -> BoxFuture<'a, Result<Box<dyn Sink>, String>> {
        Box::pin(async move {
            if let Some(why) = self.refused.lock().unwrap().get(&offer.dest) {
                return Err(why.clone());
            }
            let fail_at = self.fail_at.lock().unwrap().take();
            Ok(Box::new(MemorySink {
                dest: offer.dest.clone(),
                stream: offer.kind == XferKind::Stream as i32,
                offer_hash: offer.blake3.clone(),
                files: self.files.clone(),
                written: self.written.clone(),
                streams: self.streams.clone(),
                pending: Vec::new(),
                fail_at,
            }) as Box<dyn Sink>)
        })
    }
}

struct Env {
    memory: Arc<Memory>,
    client: Endpoint,
    addr: EndpointAddr,
    dir: std::path::PathBuf,
    _relay: iroh_relay::server::Server,
}

async fn env(name: &str) -> Env {
    let dir = std::env::temp_dir().join(format!("rackhand-xfer-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (relay, relay_url) = rackhand_net::testing::local_relay().await;
    let server = rackhand_net::testing::endpoint(&relay_url, &[alpn::XFER]).await;
    let client = rackhand_net::testing::endpoint(&relay_url, &[]).await;
    let registry = Arc::new(MemoryRegistry::default());
    registry.allow(alpn::XFER, client.id());
    let memory = Arc::new(Memory::default());
    let xfer = Xfer::new(memory.clone());
    let router = rackhand_net::router::Router::new(server.clone(), registry).route(alpn::XFER, xfer.handler());
    tokio::spawn(router.serve());
    let mut addr = server.addr();
    addr.addrs.insert(TransportAddr::Relay(relay_url));
    Env { memory, client, addr, dir, _relay: relay }
}

/// A file of `chunks` chunks and a part of one, with contents that differ from chunk to chunk.
fn file(env: &Env, name: &str, whole_chunks: usize, tail: usize) -> (std::path::PathBuf, Vec<u8>) {
    let data: Vec<u8> = (0..whole_chunks * CHUNK + tail).map(|i| ((i / 4096) % 251) as u8 ^ (i % 7) as u8).collect();
    let path = env.dir.join(name);
    std::fs::write(&path, &data).unwrap();
    (path, data)
}

const MACHINE: [u8; 16] = [3; 16];

async fn raw(env: &Env) -> (SendStream, RecvStream) {
    let conn = env.client.connect(env.addr.clone(), alpn::XFER).await.unwrap();
    let streams = conn.open_bi().await.unwrap();
    std::mem::forget(conn);
    streams
}

async fn answer(recv: &mut RecvStream) -> xfer_answer::Answer {
    let body = tokio::time::timeout(Duration::from_secs(10), frames::read(recv)).await.expect("an answer").unwrap();
    XferAnswer::decode(body.as_slice()).unwrap().answer.unwrap()
}

fn offer_of(data: &[u8], dest: &str) -> XferOffer {
    let hash = blake3::hash(data);
    XferOffer {
        transfer_id: hash.as_bytes()[..16].to_vec(),
        kind: XferKind::File as i32,
        blake3: hash.as_bytes().to_vec(),
        size: data.len() as u64,
        chunk_size: CHUNK as u32,
        target: MACHINE.to_vec(),
        dest: dest.into(),
    }
}

fn resume_of(a: &xfer_answer::Answer) -> Option<u64> {
    match a {
        xfer_answer::Answer::Resume(r) => Some(r.next_chunk),
        xfer_answer::Answer::Done(_) => None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_whole_file_arrives_and_matches() {
    let env = env("whole").await;
    let (path, data) = file(&env, "a.bin", 2, 12_345);
    let conn = env.client.connect(env.addr.clone(), alpn::XFER).await.unwrap();
    let mut seen = Vec::new();
    send_file(&conn, &MACHINE, "/incoming/a.bin", &path, &mut |done, total| seen.push((done, total))).await.unwrap();
    assert_eq!(seen.last(), Some(&(3, 3)), "progress ends with every chunk: {seen:?}");
    let got: Vec<u8> = env.memory.files.lock().unwrap()["/incoming/a.bin"].values().flatten().copied().collect();
    assert_eq!(got, data);
    // an empty file is a transfer of no chunks
    let (empty, _) = file(&env, "empty.bin", 0, 0);
    send_file(&conn, &MACHINE, "/incoming/empty.bin", &empty, &mut |_, _| {}).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn chunk_hash_mismatch_rejected_and_resent() {
    let env = env("corrupt").await;
    let (_, data) = file(&env, "b.bin", 1, 500);
    let offer = offer_of(&data, "/incoming/b.bin");
    let (mut send, mut recv) = raw(&env).await;
    frames::write_msg(&mut send, &offer).await.unwrap();
    assert_eq!(resume_of(&answer(&mut recv).await), Some(0), "a new file starts at the first chunk");
    // chunk 0 with a damaged byte: the hash the sender computed no longer matches
    let good =
        XferChunk { index: 0, blake3: blake3::hash(&data[..CHUNK]).as_bytes().to_vec(), data: data[..CHUNK].to_vec() };
    let mut bad = good.clone();
    bad.data[1000] ^= 0xff;
    frames::write_msg(&mut send, &bad).await.unwrap();
    assert_eq!(resume_of(&answer(&mut recv).await), Some(0), "not accepted: the same chunk is asked for again");
    assert!(env.memory.written.lock().unwrap().is_empty(), "nothing was written for it");
    // a chunk out of order, and one of the wrong length, are asked for again too
    let ahead =
        XferChunk { index: 1, blake3: blake3::hash(&data[CHUNK..]).as_bytes().to_vec(), data: data[CHUNK..].to_vec() };
    frames::write_msg(&mut send, &ahead).await.unwrap();
    assert_eq!(resume_of(&answer(&mut recv).await), Some(0));
    let short =
        XferChunk { index: 0, blake3: blake3::hash(&data[..10]).as_bytes().to_vec(), data: data[..10].to_vec() };
    frames::write_msg(&mut send, &short).await.unwrap();
    assert_eq!(resume_of(&answer(&mut recv).await), Some(0));
    // then the right ones are taken, and the last one's answer is `done`
    frames::write_msg(&mut send, &good).await.unwrap();
    assert_eq!(resume_of(&answer(&mut recv).await), Some(1));
    frames::write_msg(&mut send, &ahead).await.unwrap();
    assert!(matches!(answer(&mut recv).await, xfer_answer::Answer::Done(d) if d.ok));
    assert_eq!(*env.memory.written.lock().unwrap(), vec![0, 1]);
}

#[tokio::test(flavor = "multi_thread")]
async fn resume_from_last_verified_chunk() {
    let env = env("resume").await;
    let (path, data) = file(&env, "c.bin", 4, 77);
    let conn = env.client.connect(env.addr.clone(), alpn::XFER).await.unwrap();
    // the sink breaks at chunk 3: chunks 0 to 2 were taken
    *env.memory.fail_at.lock().unwrap() = Some(3);
    let first = send_file(&conn, &MACHINE, "/incoming/c.bin", &path, &mut |_, _| {}).await;
    assert!(matches!(&first, Err(XferError::Refused(why)) if why.contains("disk is full")), "{first:?}");
    assert_eq!(*env.memory.written.lock().unwrap(), vec![0, 1, 2]);
    // the next attempt, as the same offer, goes on from chunk 3 and sends only the rest
    let mut starts = Vec::new();
    send_file(&conn, &MACHINE, "/incoming/c.bin", &path, &mut |done, _| starts.push(done)).await.unwrap();
    assert_eq!(starts.first(), Some(&3), "the receiver said where to go on: {starts:?}");
    assert_eq!(*env.memory.written.lock().unwrap(), vec![0, 1, 2, 3, 4], "only the missing chunks were sent");
    let got: Vec<u8> = env.memory.files.lock().unwrap()["/incoming/c.bin"].values().flatten().copied().collect();
    assert_eq!(got, data);
    // a file already complete is only finished: nothing is sent again
    send_file(&conn, &MACHINE, "/incoming/c.bin", &path, &mut |_, _| {}).await.unwrap();
    assert_eq!(env.memory.written.lock().unwrap().len(), 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn refusals_say_why_and_a_wrong_whole_file_is_not_accepted() {
    let env = env("refused").await;
    let (path, data) = file(&env, "d.bin", 1, 1);
    let conn = env.client.connect(env.addr.clone(), alpn::XFER).await.unwrap();
    env.memory.refused.lock().unwrap().insert("/etc/passwd".into(), "outside the transfer roots".into());
    let e = send_file(&conn, &MACHINE, "/etc/passwd", &path, &mut |_, _| {}).await.unwrap_err();
    assert_eq!(e, XferError::Refused("outside the transfer roots".into()));
    // chunks that are each fine but don't make the offered file are refused at the end
    let mut offer = offer_of(&data, "/incoming/d.bin");
    offer.blake3 = blake3::hash(b"something else").as_bytes().to_vec();
    let (mut send, mut recv) = raw(&env).await;
    frames::write_msg(&mut send, &offer).await.unwrap();
    assert_eq!(resume_of(&answer(&mut recv).await), Some(0));
    for (i, part) in [&data[..CHUNK], &data[CHUNK..]].into_iter().enumerate() {
        let chunk = XferChunk { index: i as u64, blake3: blake3::hash(part).as_bytes().to_vec(), data: part.to_vec() };
        frames::write_msg(&mut send, &chunk).await.unwrap();
        if i == 0 {
            assert_eq!(resume_of(&answer(&mut recv).await), Some(1));
        }
    }
    assert!(matches!(answer(&mut recv).await, xfer_answer::Answer::Done(d) if !d.ok && d.error.contains("hash")));
    // an offer with another chunk size isn't taken
    let mut odd = offer_of(&data, "/incoming/e.bin");
    odd.chunk_size = 4096;
    let (mut send, mut recv) = raw(&env).await;
    frames::write_msg(&mut send, &odd).await.unwrap();
    assert!(matches!(answer(&mut recv).await, xfer_answer::Answer::Done(d) if !d.ok && d.error.contains("1 MiB")));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_arrives_whole_with_no_resume() {
    let env = env("stream").await;
    let data: Vec<u8> = (0..(2 * CHUNK + 9)).map(|i| (i % 253) as u8).collect();
    let conn = env.client.connect(env.addr.clone(), alpn::XFER).await.unwrap();
    let mut input = std::io::Cursor::new(data.clone());
    let mut reader = tokio::io::BufReader::new(&mut input);
    let sent = send_stream(&conn, &MACHINE, "zfs-recv tank/backup", &mut reader).await.unwrap();
    assert_eq!(sent, data.len() as u64);
    assert_eq!(env.memory.streams.lock().unwrap()[0], data, "the receiving command was given every byte, in order");
    // a stream that has nothing to say is a stream all the same
    let mut none = tokio::io::empty();
    assert_eq!(send_stream(&conn, &MACHINE, "zfs-recv tank/backup", &mut none).await.unwrap(), 0);
    assert_eq!(env.memory.streams.lock().unwrap()[1], Vec::<u8>::new());
}
