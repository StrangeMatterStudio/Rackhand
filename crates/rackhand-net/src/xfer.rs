//! The sending side of `rackhand/xfer/1` (7.3.11, FR-19): a file goes in 1 MiB chunks, each checked with BLAKE3 by the
//! receiver, which says after each one what it wants next. A transfer that breaks starts again where the receiver's verified
//! chunks end (E30), and a chunk that doesn't match is sent again.
//!
//! One stream per transfer: the sender's `XferOffer`, then the receiver's `XferAnswer` (the first chunk it wants, or a refusal),
//! then a `XferChunk` and an `XferAnswer` for each chunk. The answer to the last chunk is `done`. A stream (a backup tool's output)
//! has no size and no resume: its chunks end with an empty one.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use prost::Message;
use rackhand_proto::tunnel::{XferAnswer, XferChunk, XferKind, XferOffer, xfer_answer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt};

use crate::frames;
use crate::paths::{self, PathKind};

/// The chunk size: 1 MiB.
pub const CHUNK: usize = 1 << 20;
/// How many times a chunk is sent again after the receiver refuses it.
pub const RESENDS: usize = 3;
/// How long a transfer that wants a direct path waits before it says so (E29).
pub const DIRECT_WAIT_NOTICE: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XferError {
    /// The receiver turned the offer down, or failed, and said why.
    #[error("{0}")]
    Refused(String),
    #[error("the connection broke: {0}")]
    Broken(String),
    #[error("a chunk was refused {RESENDS} times")]
    Corrupt,
    #[error("{0}")]
    Source(String),
}

fn broken(e: impl std::fmt::Display) -> XferError {
    XferError::Broken(e.to_string())
}

/// What the receiver answered.
async fn answer(recv: &mut RecvStream) -> Result<xfer_answer::Answer, XferError> {
    let body = frames::read(recv).await.map_err(broken)?;
    XferAnswer::decode(body.as_slice()).map_err(broken)?.answer.ok_or_else(|| broken("an empty answer"))
}

fn refusal(done: rackhand_proto::tunnel::XferDone) -> XferError {
    XferError::Refused(if done.error.is_empty() { "the receiver stopped the transfer".into() } else { done.error })
}

/// Where chunks come from.
pub trait Source: Send {
    /// The chunk `index` (a full chunk, or the rest of the file).
    fn chunk<'a>(&'a mut self, index: u64) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;
}

struct FileSource {
    file: tokio::fs::File,
    size: u64,
}

impl Source for FileSource {
    fn chunk<'a>(&'a mut self, index: u64) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            let start = index * CHUNK as u64;
            let len = (self.size.saturating_sub(start)).min(CHUNK as u64) as usize;
            self.file.seek(std::io::SeekFrom::Start(start)).await.map_err(|e| e.to_string())?;
            let mut data = vec![0u8; len];
            self.file.read_exact(&mut data).await.map_err(|e| e.to_string())?;
            Ok(data)
        })
    }
}

/// How many chunks a file of `size` bytes has.
pub fn chunks(size: u64) -> u64 {
    size.div_ceil(CHUNK as u64)
}

fn hash_of(data: &[u8]) -> Vec<u8> {
    blake3::hash(data).as_bytes().to_vec()
}

async fn write(send: &mut SendStream, msg: &impl Message) -> Result<(), XferError> {
    frames::write_msg(send, msg).await.map_err(broken)
}

/// The BLAKE3 of a file, read in the background.
pub async fn hash_file(path: &Path) -> Result<[u8; 32], XferError> {
    let owned = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut hasher = blake3::Hasher::new();
        hasher.update_reader(std::fs::File::open(&owned)?)?;
        Ok::<_, std::io::Error>(*hasher.finalize().as_bytes())
    })
    .await
    .map_err(|e| XferError::Source(e.to_string()))?
    .map_err(|e| XferError::Source(format!("{}: {e}", path.display())))
}

/// Sends the file at `path` to `dest` on the machine `target`. `progress` is told after each chunk the receiver took how many
/// of the file's chunks it has.
pub async fn send_file(
    conn: &Connection,
    target: &[u8],
    dest: &str,
    path: &Path,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<(), XferError> {
    let size =
        tokio::fs::metadata(path).await.map_err(|e| XferError::Source(format!("{}: {e}", path.display())))?.len();
    let hash = hash_file(path).await?;
    let file = tokio::fs::File::open(path).await.map_err(|e| XferError::Source(format!("{}: {e}", path.display())))?;
    let offer = XferOffer {
        // content-addressed: the same file offered again is the same transfer
        transfer_id: hash[..16].to_vec(),
        kind: XferKind::File as i32,
        blake3: hash.to_vec(),
        size,
        chunk_size: CHUNK as u32,
        target: target.to_vec(),
        dest: dest.to_string(),
    };
    send(conn, &offer, &mut FileSource { file, size }, progress).await
}

/// Sends what `source` gives for an offer (a file's chunks, by index).
pub async fn send(
    conn: &Connection,
    offer: &XferOffer,
    source: &mut dyn Source,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<(), XferError> {
    let (mut tx, mut rx) = conn.open_bi().await.map_err(broken)?;
    write(&mut tx, offer).await?;
    let total = chunks(offer.size);
    let mut next = match answer(&mut rx).await? {
        xfer_answer::Answer::Resume(r) => r.next_chunk,
        xfer_answer::Answer::Done(d) if d.ok => return Ok(()),
        xfer_answer::Answer::Done(d) => return Err(refusal(d)),
    };
    progress(next.min(total), total);
    let mut resends = 0;
    while next < total {
        let data = source.chunk(next).await.map_err(XferError::Source)?;
        write(&mut tx, &XferChunk { index: next, blake3: hash_of(&data), data }).await?;
        match answer(&mut rx).await? {
            xfer_answer::Answer::Resume(r) if r.next_chunk == next + 1 => {
                next += 1;
                resends = 0;
                progress(next, total);
            }
            // it didn't match: the receiver wants this one again
            xfer_answer::Answer::Resume(r) if r.next_chunk == next => {
                resends += 1;
                if resends > RESENDS {
                    return Err(XferError::Corrupt);
                }
            }
            xfer_answer::Answer::Resume(r) => {
                return Err(broken(format!("the receiver asked for chunk {}", r.next_chunk)));
            }
            xfer_answer::Answer::Done(d) if d.ok && next + 1 == total => {
                progress(total, total);
                return Ok(());
            }
            xfer_answer::Answer::Done(d) => return Err(refusal(d)),
        }
    }
    // a file of no chunks, or one whose receiver already had every chunk, is finished by the receiver's answer
    match answer(&mut rx).await? {
        xfer_answer::Answer::Done(d) if d.ok => {}
        xfer_answer::Answer::Done(d) => return Err(refusal(d)),
        xfer_answer::Answer::Resume(_) => return Err(broken("an answer after the last chunk")),
    }
    let _ = tx.finish();
    Ok(())
}

/// Sends what `input` gives as a stream (a backup tool's output): no size, no resume, an empty chunk at the end.
pub async fn send_stream(
    conn: &Connection,
    target: &[u8],
    dest: &str,
    input: &mut (dyn AsyncRead + Send + Unpin),
) -> Result<u64, XferError> {
    let (mut tx, mut rx) = conn.open_bi().await.map_err(broken)?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&blake3::hash(format!("{dest}{:?}", std::time::SystemTime::now()).as_bytes()).as_bytes()[..16]);
    let offer = XferOffer {
        transfer_id: id.to_vec(),
        kind: XferKind::Stream as i32,
        blake3: Vec::new(),
        size: 0,
        chunk_size: CHUNK as u32,
        target: target.to_vec(),
        dest: dest.to_string(),
    };
    write(&mut tx, &offer).await?;
    match answer(&mut rx).await? {
        xfer_answer::Answer::Resume(_) => {}
        xfer_answer::Answer::Done(d) => return Err(refusal(d)),
    }
    let (mut index, mut sent) = (0u64, 0u64);
    loop {
        let mut data = vec![0u8; CHUNK];
        let mut filled = 0;
        while filled < CHUNK {
            let n = input.read(&mut data[filled..]).await.map_err(|e| XferError::Source(e.to_string()))?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        data.truncate(filled);
        let last = data.is_empty();
        sent += filled as u64;
        write(&mut tx, &XferChunk { index, blake3: hash_of(&data), data }).await?;
        match answer(&mut rx).await? {
            xfer_answer::Answer::Resume(r) if r.next_chunk == index + 1 && !last => index += 1,
            xfer_answer::Answer::Done(d) if d.ok && last => break,
            xfer_answer::Answer::Done(d) => return Err(refusal(d)),
            xfer_answer::Answer::Resume(_) => return Err(XferError::Corrupt),
        }
    }
    let _ = tx.finish();
    Ok(sent)
}

/// What the waiting for a direct path asks of a connection; a fake in tests.
pub trait Paths: Send + Sync {
    fn kind(&self) -> PathKind;
    /// Returns when the path changes, or after `within`.
    fn changed<'a>(&'a self, within: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

impl Paths for Connection {
    fn kind(&self) -> PathKind {
        paths::kind(self)
    }

    fn changed<'a>(&'a self, within: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let _ = paths::wait_direct(self, within).await;
        })
    }
}

/// Waits for a direct path before a bulk transfer starts (7.3.11, E29), unless the transfer allows a relay. After
/// [`DIRECT_WAIT_NOTICE`] on the relay `notice` is called once (an info event, `bulk_waiting_direct_path`); the wait goes on.
pub async fn wait_for_direct(
    paths: &dyn Paths,
    allow_relay: bool,
    now_ms: &(dyn Fn() -> i64 + Send + Sync),
    notice: &mut (dyn FnMut() + Send),
) {
    if allow_relay {
        return;
    }
    let started = now_ms();
    let mut said = false;
    while paths.kind() != PathKind::Direct {
        if !said && now_ms() - started >= DIRECT_WAIT_NOTICE.as_millis() as i64 {
            said = true;
            notice();
        }
        paths.changed(Duration::from_secs(30)).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// A path that stays on the relay for `until_ms` of fake time, a minute for each wait.
    struct Fake {
        now: Mutex<i64>,
        direct_at_ms: i64,
    }

    impl Paths for Fake {
        fn kind(&self) -> PathKind {
            if *self.now.lock().unwrap() >= self.direct_at_ms { PathKind::Direct } else { PathKind::Relay }
        }

        fn changed<'a>(&'a self, _within: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            *self.now.lock().unwrap() += 60_000;
            Box::pin(async {})
        }
    }

    #[test]
    fn a_file_has_whole_chunks_and_a_last_part() {
        assert_eq!([chunks(0), chunks(1), chunks(CHUNK as u64), chunks(CHUNK as u64 + 1)], [0, 1, 1, 2]);
    }

    #[tokio::test]
    async fn bulk_waits_for_direct_and_raises_info_after_10_min() {
        let paths = Fake { now: Mutex::new(0), direct_at_ms: 15 * 60_000 };
        let notices = Mutex::new(0);
        let clock = || *paths.now.lock().unwrap();
        wait_for_direct(&paths, false, &clock, &mut || *notices.lock().unwrap() += 1).await;
        assert_eq!(*notices.lock().unwrap(), 1, "the info event is raised once, after 10 minutes");
        assert_eq!(*paths.now.lock().unwrap(), 15 * 60_000, "and the wait went on until the path was direct");
        // a path that is direct at once raises nothing; a transfer that allows a relay doesn't wait at all
        let direct = Fake { now: Mutex::new(0), direct_at_ms: 0 };
        wait_for_direct(&direct, false, &|| 0, &mut || panic!("no notice for a direct path")).await;
        let relayed = Fake { now: Mutex::new(0), direct_at_ms: i64::MAX };
        wait_for_direct(&relayed, true, &|| 0, &mut || panic!("no wait when a relay is allowed")).await;
        assert_eq!(*relayed.now.lock().unwrap(), 0);
        // ten minutes less a moment raises nothing yet
        let early = Fake { now: Mutex::new(0), direct_at_ms: 9 * 60_000 };
        wait_for_direct(&early, false, &|| *early.now.lock().unwrap(), &mut || panic!("too early")).await;
    }
}
