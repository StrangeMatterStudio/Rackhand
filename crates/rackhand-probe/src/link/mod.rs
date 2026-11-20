//! The probe side of `rackhand/probe/1` (7.3.2): Hello and Welcome on stream 0, live reports on stream 1, the backlog
//! on stream 2, acks that delete buffered reports, `DataDropped`, and what each close code means for the probe.

use std::time::Duration;

use iroh::endpoint::{Connection, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use prost::Message;
use rackhand_net::frames;
use rackhand_proto::close::CloseCode;
use rackhand_proto::common::{IfaceInfo, LabelEntry, OsInfo, SemVer};
use rackhand_proto::probe::{
    DataDropped, Hello, HubToProbe, ProbeToHub, ReplayBatch, Report, Welcome, hub_to_probe, probe_to_hub,
};
use tokio::sync::mpsc;

use crate::buffer::epoch::{EpochState, Received};
use crate::buffer::segments::Buffer;

/// A replay batch holds at most 100 reports or 4 MB (7.3.2).
const BATCH_REPORTS: usize = 100;
const BATCH_BYTES: usize = 4 * 1024 * 1024 - 1024;
/// How long to wait for the reason after the hub closes.
const CLOSE_WAIT: Duration = Duration::from_secs(5);

/// Why a connection ended, and so what the probe does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// `0x13`: the machine was removed; the probe stops and exits with code 3.
    Revoked,
    /// `0x12`: this version isn't supported; the probe keeps buffering and retries hourly.
    Unsupported,
    /// `0x11`: another endpoint holds this machine.
    IdentityMismatch,
    /// `0x14`: stream 1 sent faster than a report a second.
    RateLimited,
    /// `0x15`: a frame was over its limits.
    TooLarge,
    /// `0x10`: the hub doesn't know this probe.
    Unknown,
    Timeout,
    Buffer(String),
    Disconnected(String),
}

impl Stop {
    fn from_close(code: CloseCode) -> Stop {
        match code {
            CloseCode::Revoked => Stop::Revoked,
            CloseCode::UnsupportedVersion => Stop::Unsupported,
            CloseCode::IdentityMismatch => Stop::IdentityMismatch,
            CloseCode::RateLimited => Stop::RateLimited,
            CloseCode::FrameTooLarge => Stop::TooLarge,
            CloseCode::UnknownPeer => Stop::Unknown,
        }
    }

    /// The process exit code when the probe must stop for good.
    pub fn exit_code(&self) -> Option<i32> {
        (*self == Stop::Revoked).then_some(3)
    }

    /// When to reconnect: hourly after `0x12`, otherwise exponential from 1 s to 60 s, shortened by up to a quarter
    /// by `jitter` (0 to 1).
    pub fn retry_after(&self, attempt: u32, jitter: f64) -> Duration {
        if *self == Stop::Unsupported {
            return Duration::from_secs(3_600);
        }
        let base = 2f64.powi(attempt.min(6) as i32).min(60.0);
        Duration::from_secs_f64(base - base * jitter.clamp(0.0, 1.0) / 4.0)
    }
}

/// Who the probe is and where its hub is.
#[derive(Debug, Clone)]
pub struct LinkConfig {
    pub hub: EndpointAddr,
    pub machine_id: [u8; 16],
    pub version: String,
    pub os: Option<OsInfo>,
    pub boot_id: String,
    pub capabilities: Vec<i32>,
    pub interfaces: Vec<IfaceInfo>,
}

impl LinkConfig {
    pub fn new(hub: EndpointAddr, machine_id: [u8; 16], version: &str) -> LinkConfig {
        LinkConfig {
            hub,
            machine_id,
            version: version.into(),
            os: None,
            boot_id: String::new(),
            capabilities: Vec::new(),
            interfaces: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct Link {
    endpoint: Endpoint,
    cfg: LinkConfig,
    pub buffer: Buffer,
    epoch: EpochState,
    epoch_changed: bool,
    last_ack: Option<(u64, Vec<(u64, u64)>)>,
}

/// One connection to the hub.
#[derive(Debug)]
pub struct Session {
    conn: Connection,
    ctrl: SendStream,
    live: SendStream,
    incoming: mpsc::Receiver<HubToProbe>,
    pub welcome: Welcome,
    hello_at_ms: i64,
}

async fn stop_of(conn: &Connection) -> Stop {
    match tokio::time::timeout(CLOSE_WAIT, conn.closed()).await {
        Ok(reason) => {
            rackhand_net::close_code(&reason).map(Stop::from_close).unwrap_or(Stop::Disconnected(reason.to_string()))
        }
        Err(_) => Stop::Disconnected("stream ended".into()),
    }
}

impl Link {
    pub fn new(endpoint: Endpoint, cfg: LinkConfig, buffer: Buffer, epoch: EpochState) -> Link {
        Link { endpoint, cfg, buffer, epoch, epoch_changed: false, last_ack: None }
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.epoch()
    }

    pub fn next_seq(&mut self) -> u64 {
        self.epoch.next_seq()
    }

    /// Whether the last Welcome started a new epoch (`probe.epoch_changed`).
    pub fn epoch_changed(&self) -> bool {
        self.epoch_changed
    }

    /// The last `Ack`: its epoch and every committed range.
    pub fn last_ack(&self) -> Option<(u64, Vec<(u64, u64)>)> {
        self.last_ack.clone()
    }

    pub fn set_machine_id(&mut self, machine_id: [u8; 16]) {
        self.cfg.machine_id = machine_id;
    }

    /// Buffers a report without sending it (it goes out on stream 2 after the next Hello).
    pub fn queue(&mut self, report: &Report, now_ms: i64) -> Result<(), Stop> {
        self.buffer
            .append(report.epoch, report.seq, report.sampled_at_ms, &report.encode_to_vec(), now_ms)
            .map_err(|e| Stop::Buffer(e.to_string()))
    }

    /// Connects, sends the Hello with the whole label table of the epoch, and reads the Welcome. When the hub already
    /// holds this epoch's next seq (a rolled-back guest), a new epoch starts at once.
    pub async fn connect(&mut self, label_table: &[LabelEntry], now_ms: i64) -> Result<Session, Stop> {
        let conn = self
            .endpoint
            .connect(self.cfg.hub.clone(), rackhand_proto::alpn::PROBE)
            .await
            .map_err(|e| Stop::Disconnected(e.to_string()))?;
        let Ok((mut ctrl, mut recv)) = conn.open_bi().await else { return Err(stop_of(&conn).await) };
        let hello = Hello {
            probe_version: Some(SemVer { version: self.cfg.version.clone() }),
            machine_id: self.cfg.machine_id.to_vec(),
            epoch: self.epoch.epoch(),
            os: self.cfg.os.clone(),
            boot_id: self.cfg.boot_id.clone(),
            capabilities: self.cfg.capabilities.clone(),
            interfaces: self.cfg.interfaces.clone(),
            label_table: label_table.to_vec(),
        };
        let msg = ProbeToHub { msg: Some(probe_to_hub::Msg::Hello(hello)) };
        if frames::write_msg(&mut ctrl, &msg).await.is_err() {
            return Err(stop_of(&conn).await);
        }
        let welcome = match frames::read(&mut recv).await {
            Ok(body) => match HubToProbe::decode(body.as_slice()).ok().and_then(|m| m.msg) {
                Some(hub_to_probe::Msg::Welcome(w)) => w,
                _ => return Err(Stop::Disconnected("no welcome".into())),
            },
            Err(_) => return Err(stop_of(&conn).await),
        };
        self.epoch_changed = false;
        if let Some(r) = &welcome.received {
            let received = Received { epoch: r.epoch, ranges: r.ranges.iter().map(|s| (s.from, s.to)).collect() };
            self.epoch_changed = self.epoch.on_welcome(&received);
        }
        let Ok(mut live) = conn.open_uni().await else { return Err(stop_of(&conn).await) };
        if live.write_all(&[rackhand_proto::streams::LIVE]).await.is_err() {
            return Err(stop_of(&conn).await);
        }
        let (tx, incoming) = mpsc::channel(256);
        tokio::spawn(async move {
            while let Ok(body) = frames::read(&mut recv).await {
                let Ok(msg) = HubToProbe::decode(body.as_slice()) else { continue };
                if tx.send(msg).await.is_err() {
                    return;
                }
            }
        });
        Ok(Session { conn, ctrl, live, incoming, welcome, hello_at_ms: now_ms })
    }

    /// Buffers a live report, then sends it on stream 1. It stays buffered until an ack covers it.
    pub async fn send_live(&mut self, s: &mut Session, report: Report, now_ms: i64) -> Result<(), Stop> {
        self.queue(&report, now_ms)?;
        s.send_report(&report).await
    }

    /// Sends the backlog (buffered reports sampled before this connection's Hello) on stream 2, in batches; returns
    /// how many reports went out.
    pub async fn replay(&mut self, s: &mut Session) -> Result<usize, Stop> {
        let keys: Vec<(u64, u64)> =
            self.buffer.pending().filter(|r| r.sampled_at_ms < s.hello_at_ms).map(|r| (r.epoch, r.seq)).collect();
        if keys.is_empty() {
            return Ok(0);
        }
        let Ok(mut stream) = s.conn.open_uni().await else { return Err(stop_of(&s.conn).await) };
        if stream.write_all(&[rackhand_proto::streams::REPLAY]).await.is_err() {
            return Err(stop_of(&s.conn).await);
        }
        let mut batch = ReplayBatch::default();
        let mut size = 0;
        for (epoch, seq) in &keys {
            let payload = self.buffer.read(*epoch, *seq).map_err(|e| Stop::Buffer(e.to_string()))?;
            let report = Report::decode(payload.as_slice()).map_err(|e| Stop::Buffer(e.to_string()))?;
            if !batch.reports.is_empty() && (batch.reports.len() == BATCH_REPORTS || size + payload.len() > BATCH_BYTES)
            {
                s.send_batch(&mut stream, &std::mem::take(&mut batch)).await?;
                size = 0;
            }
            size += payload.len();
            batch.reports.push(report);
        }
        s.send_batch(&mut stream, &batch).await?;
        let _ = stream.finish();
        Ok(keys.len())
    }

    /// Reads acks (deleting the buffered reports they cover) until `done` holds for the buffer, the connection ends,
    /// or `timeout` passes.
    pub async fn read_acks(
        &mut self,
        s: &mut Session,
        done: impl Fn(&Buffer) -> bool,
        timeout: Duration,
    ) -> Result<(), Stop> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if done(&self.buffer) {
                return Ok(());
            }
            let msg = match tokio::time::timeout_at(deadline, s.incoming.recv()).await {
                Err(_) => return Err(Stop::Timeout),
                Ok(None) => return Err(stop_of(&s.conn).await),
                Ok(Some(m)) => m,
            };
            if let Some(hub_to_probe::Msg::Ack(ack)) = msg.msg {
                let ranges: Vec<(u64, u64)> = ack.ranges.iter().map(|r| (r.from, r.to)).collect();
                self.buffer.ack(ack.epoch, &ranges).map_err(|e| Stop::Buffer(e.to_string()))?;
                self.last_ack = Some((ack.epoch, ranges));
            }
        }
    }
}

impl Session {
    /// Sends a report on stream 1 without buffering it.
    pub async fn send_report(&mut self, report: &Report) -> Result<(), Stop> {
        let body = rackhand_proto::zstd::compress(&report.encode_to_vec()).map_err(|e| Stop::Buffer(e.to_string()))?;
        self.send_live_frame(&body).await
    }

    /// Sends one already-compressed frame body on stream 1.
    pub async fn send_live_frame(&mut self, body: &[u8]) -> Result<(), Stop> {
        if frames::write(&mut self.live, body).await.is_err() {
            return Err(stop_of(&self.conn).await);
        }
        Ok(())
    }

    async fn send_batch(&mut self, stream: &mut SendStream, batch: &ReplayBatch) -> Result<(), Stop> {
        let body = rackhand_proto::zstd::compress(&batch.encode_to_vec()).map_err(|e| Stop::Buffer(e.to_string()))?;
        if frames::write(stream, &body).await.is_err() {
            return Err(stop_of(&self.conn).await);
        }
        Ok(())
    }

    /// Tells the hub that buffered reports were deleted unsent (buffer full).
    pub async fn data_dropped(&mut self, epoch: u64, from_seq: u64, to_seq: u64) -> Result<(), Stop> {
        let msg = ProbeToHub { msg: Some(probe_to_hub::Msg::DataDropped(DataDropped { epoch, from_seq, to_seq })) };
        if frames::write_msg(&mut self.ctrl, &msg).await.is_err() {
            return Err(stop_of(&self.conn).await);
        }
        Ok(())
    }
}
