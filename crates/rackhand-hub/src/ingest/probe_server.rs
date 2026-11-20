//! The hub side of `rackhand/probe/1` (7.3.2): Hello and Welcome on stream 0, live reports on stream 1, replay
//! batches on stream 2, acks of every committed range, rate limits and close codes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream};
use prost::Message;
use rackhand_net::{close, frames};
use rackhand_proto::close::CloseCode;
use rackhand_proto::common::{ProbeConfig, SemVer};
use rackhand_proto::probe::{
    Ack, EpochRanges, HubToProbe, ProbeToHub, ReplayBatch, Report, SeqRange, Welcome, hub_to_probe, probe_to_hub,
};
use rackhand_store::ids::now_ms;
use tokio::sync::mpsc;

use super::events::{Event, Severity};
use super::{Ingest, Receipt, Stream};

/// Stream 1 allows a report a second with bursts of 10 (7.3.2).
const LIVE_BURST: f64 = 10.0;
const LIVE_PER_SECOND: f64 = 1.0;
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const REPLAY_POLL: Duration = Duration::from_millis(50);

/// Which machine each probe endpoint is enrolled as (the Registry's machines table).
pub trait ProbeDirectory: Send + Sync + std::fmt::Debug {
    fn machine_of(&self, endpoint: &EndpointId) -> Option<[u8; 16]>;
}

#[derive(Clone)]
pub struct ServerSettings {
    pub hub_version: String,
    /// Whether a probe of this version may connect; otherwise the connection closes with `0x12`.
    pub supports: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    pub config: ProbeConfig,
    pub config_rev: u64,
}

impl std::fmt::Debug for ServerSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerSettings")
            .field("hub_version", &self.hub_version)
            .field("config_rev", &self.config_rev)
            .finish()
    }
}

impl Default for ServerSettings {
    fn default() -> ServerSettings {
        ServerSettings {
            hub_version: env!("CARGO_PKG_VERSION").into(),
            supports: Arc::new(|_| true),
            config: ProbeConfig::default(),
            config_rev: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeServer {
    ingest: Ingest,
    directory: Arc<dyn ProbeDirectory>,
    settings: ServerSettings,
}

/// How a connection ends.
enum End {
    Close(CloseCode),
    Gone,
}

impl ProbeServer {
    pub fn new(ingest: Ingest, directory: Arc<dyn ProbeDirectory>, settings: ServerSettings) -> ProbeServer {
        ProbeServer { ingest, directory, settings }
    }

    pub fn handler(&self) -> rackhand_net::router::Handler {
        let this = self.clone();
        rackhand_net::router::handler(move |conn| {
            let this = this.clone();
            async move { this.serve(conn).await }
        })
    }

    pub async fn serve(&self, conn: Connection) {
        if let End::Close(code) = self.session(&conn).await {
            close(&conn, code);
        }
    }

    async fn session(&self, conn: &Connection) -> End {
        let Ok((mut ctrl_send, mut ctrl_recv)) = conn.accept_bi().await else { return End::Gone };
        let hello = match tokio::time::timeout(HELLO_TIMEOUT, frames::read(&mut ctrl_recv)).await {
            Ok(Ok(body)) => match ProbeToHub::decode(body.as_slice()).ok().and_then(|m| m.msg) {
                Some(probe_to_hub::Msg::Hello(h)) => h,
                _ => return End::Close(CloseCode::UnsupportedVersion),
            },
            _ => return End::Gone,
        };
        let claimed: Option<[u8; 16]> = hello.machine_id.as_slice().try_into().ok();
        let enrolled = self.directory.machine_of(&conn.remote_id());
        let (Some(claimed), Some(enrolled)) = (claimed, enrolled) else {
            return End::Close(CloseCode::IdentityMismatch);
        };
        let machine = ulid::Ulid::from_bytes(claimed).to_string();
        if claimed != enrolled {
            let event = Event::machine(
                &machine,
                "probe.identity_conflict",
                Severity::Critical,
                serde_json::json!({
                    "machine_id": machine,
                    "endpoint": conn.remote_id().to_string(),
                    "enrolled_as": ulid::Ulid::from_bytes(enrolled).to_string(),
                }),
            );
            let _ = self.ingest.raise_event(event).await;
            return End::Close(CloseCode::IdentityMismatch);
        }
        let version = hello.probe_version.as_ref().map(|v| v.version.as_str()).unwrap_or_default();
        if !(self.settings.supports)(version) {
            return End::Close(CloseCode::UnsupportedVersion);
        }
        if self.ingest.hello(&machine, hello.epoch, &hello.label_table).await.is_err() {
            return End::Gone;
        }
        let received = self.ingest.received(&machine, hello.epoch);
        let welcome = Welcome {
            hub_version: Some(SemVer { version: self.settings.hub_version.clone() }),
            config: Some(self.settings.config.clone()),
            config_rev: self.settings.config_rev,
            received: (!received.is_empty()).then(|| EpochRanges { epoch: hello.epoch, ranges: seq_ranges(&received) }),
            server_time_ms: now_ms(),
        };
        let welcome = HubToProbe { msg: Some(hub_to_probe::Msg::Welcome(welcome)) };
        if frames::write_msg(&mut ctrl_send, &welcome).await.is_err() {
            return End::Gone;
        }
        // Acks from every stream go out on stream 0 in the order they are produced.
        let (acks, mut ack_rx) = mpsc::channel::<Ack>(256);
        let writer = tokio::spawn(async move {
            while let Some(ack) = ack_rx.recv().await {
                let msg = HubToProbe { msg: Some(hub_to_probe::Msg::Ack(ack)) };
                if frames::write_msg(&mut ctrl_send, &msg).await.is_err() {
                    return;
                }
            }
        });
        let (ends, mut end_rx) = mpsc::channel::<End>(4);
        let control =
            tokio::spawn(control(self.ingest.clone(), machine.clone(), ctrl_recv, acks.clone(), ends.clone()));
        let end = loop {
            tokio::select! {
                end = end_rx.recv() => break end.unwrap_or(End::Gone),
                stream = conn.accept_uni() => {
                    let Ok(mut recv) = stream else { break End::Gone };
                    let mut tag = [0u8; 1];
                    if recv.read_exact(&mut tag).await.is_err() {
                        continue;
                    }
                    let (ingest, machine, acks, ends) = (self.ingest.clone(), machine.clone(), acks.clone(), ends.clone());
                    match tag[0] {
                        rackhand_proto::streams::LIVE => { tokio::spawn(live(ingest, machine, recv, acks, ends)); }
                        rackhand_proto::streams::REPLAY => { tokio::spawn(replay(ingest, machine, recv, acks, ends)); }
                        _ => break End::Close(CloseCode::UnsupportedVersion),
                    }
                }
            }
        };
        control.abort();
        writer.abort();
        end
    }
}

impl Ingest {
    /// Every committed seq range of a machine's epoch.
    pub fn received(&self, machine: &str, epoch: u64) -> Vec<(u64, u64)> {
        self.state().machines.get(machine).and_then(|m| m.received.get(&epoch)).map(|r| r.list()).unwrap_or_default()
    }
}

fn seq_ranges(ranges: &[(u64, u64)]) -> Vec<SeqRange> {
    ranges.iter().map(|&(from, to)| SeqRange { from, to }).collect()
}

async fn ack(ingest: &Ingest, machine: &str, epoch: u64, receipt: Receipt, acks: &mpsc::Sender<Ack>) {
    let ranges = match receipt {
        Receipt::Staged { ranges } => ranges,
        // A resend of committed reports is acked again, so the probe can delete them.
        Receipt::Duplicate => ingest.received(machine, epoch),
    };
    let _ = acks.send(Ack { epoch, ranges: seq_ranges(&ranges) }).await;
}

/// Stream 0 after the Welcome: `DataDropped` from the probe.
async fn control(
    ingest: Ingest,
    machine: String,
    mut recv: RecvStream,
    acks: mpsc::Sender<Ack>,
    ends: mpsc::Sender<End>,
) {
    loop {
        let Ok(body) = frames::read(&mut recv).await else {
            let _ = ends.send(End::Gone).await;
            return;
        };
        if let Some(probe_to_hub::Msg::DataDropped(d)) = ProbeToHub::decode(body.as_slice()).ok().and_then(|m| m.msg) {
            if ingest.dropped(&machine, d.epoch, d.from_seq, d.to_seq).await.is_ok() {
                let ranges = ingest.received(&machine, d.epoch);
                let _ = acks.send(Ack { epoch: d.epoch, ranges: seq_ranges(&ranges) }).await;
            }
        }
    }
}

/// Decompresses a stream 1 or 2 frame body (16 MB at most, else `0x15`).
fn inflate<M: Message + Default>(body: &[u8]) -> Result<M, CloseCode> {
    let bytes = rackhand_proto::zstd::decompress_bounded(body)?;
    M::decode(bytes.as_slice()).map_err(|_| CloseCode::FrameTooLarge)
}

async fn live(ingest: Ingest, machine: String, mut recv: RecvStream, acks: mpsc::Sender<Ack>, ends: mpsc::Sender<End>) {
    let (mut tokens, mut at) = (LIVE_BURST, Instant::now());
    loop {
        let Ok(body) = frames::read(&mut recv).await else { return };
        let now = Instant::now();
        tokens = (tokens + now.duration_since(at).as_secs_f64() * LIVE_PER_SECOND).min(LIVE_BURST);
        at = now;
        if tokens < 1.0 {
            let _ = ends.send(End::Close(CloseCode::RateLimited)).await;
            return;
        }
        tokens -= 1.0;
        let report: Report = match inflate(&body) {
            Ok(r) => r,
            Err(code) => {
                let _ = ends.send(End::Close(code)).await;
                return;
            }
        };
        let epoch = report.epoch;
        match ingest.receive(&machine, Stream::Live, vec![report], body.len(), now_ms()).await {
            Ok(receipt) => ack(&ingest, &machine, epoch, receipt, &acks).await,
            Err(e) => tracing::warn!(%machine, error = %e, "staging a live report failed"),
        }
    }
}

async fn replay(
    ingest: Ingest,
    machine: String,
    mut recv: RecvStream,
    acks: mpsc::Sender<Ack>,
    ends: mpsc::Sender<End>,
) {
    loop {
        // Past the replay limits stream 2 isn't read, so QUIC flow control holds the probe back (7.3.2).
        while !ingest.replay_allowed(&machine, now_ms()) {
            tokio::time::sleep(REPLAY_POLL).await;
        }
        let Ok(body) = frames::read(&mut recv).await else { return };
        let batch: ReplayBatch = match inflate(&body) {
            Ok(b) => b,
            Err(code) => {
                let _ = ends.send(End::Close(code)).await;
                return;
            }
        };
        let Some(epoch) = batch.reports.last().map(|r| r.epoch) else { continue };
        match ingest.receive(&machine, Stream::Replay, batch.reports, body.len(), now_ms()).await {
            Ok(receipt) => ack(&ingest, &machine, epoch, receipt, &acks).await,
            Err(e) => tracing::warn!(%machine, error = %e, "staging a replay batch failed"),
        }
    }
}
