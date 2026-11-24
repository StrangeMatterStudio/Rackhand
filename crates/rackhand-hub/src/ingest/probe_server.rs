//! The hub side of `rackhand/probe/1` (7.3.2): Hello and Welcome on stream 0, live reports on stream 1, replay
//! batches on stream 2, acks of every committed range, rate limits and close codes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream};
use prost::Message;
use rackhand_net::{close, frames};
use rackhand_proto::close::CloseCode;
use rackhand_proto::common::{ProbeConfig, SemVer};
use rackhand_proto::probe::{
    Ack, CheckResult, EpochRanges, HubToProbe, ProbeToHub, ReplayBatch, Report, SeqRange, Welcome, hub_to_probe,
    probe_to_hub,
};
use rackhand_store::ids::now_ms;
use std::sync::atomic::{AtomicI64, Ordering};
use tokio::sync::mpsc;

use crate::registry::identity::{Entry, Identities};

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

/// The connected probes' stream 0, for messages the hub starts (`RunCheck`), and the checks waiting for an answer.
#[derive(Debug, Default)]
pub(crate) struct Outbound {
    pub(crate) probes: Mutex<HashMap<String, mpsc::Sender<HubToProbe>>>,
    pub(crate) pending: Mutex<HashMap<String, tokio::sync::oneshot::Sender<CheckResult>>>,
}

impl Outbound {
    fn probes(&self) -> std::sync::MutexGuard<'_, HashMap<String, mpsc::Sender<HubToProbe>>> {
        self.probes.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn pending(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, tokio::sync::oneshot::Sender<CheckResult>>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The machine's stream 0, while its probe is connected.
    pub(crate) fn to(&self, machine: &str) -> Option<mpsc::Sender<HubToProbe>> {
        self.probes().get(machine).filter(|s| !s.is_closed()).cloned()
    }
}

#[derive(Debug, Clone)]
pub struct ProbeServer {
    ingest: Ingest,
    directory: Arc<dyn ProbeDirectory>,
    settings: ServerSettings,
    outbound: Arc<Outbound>,
    /// Which boot of which machine is behind each endpoint id (E6).
    identities: Arc<Identities>,
    /// The hub's addresses and relays now, which every Welcome carries (E35).
    addresses: Arc<Mutex<(Vec<String>, Vec<String>)>>,
    /// Guest binding, given the MACs each Hello reports.
    bindings: Option<Arc<crate::registry::guest_binding::GuestBindings>>,
    /// Told the machine id of each accepted Hello (the hub's SSH test follows a managed machine's first report).
    greeted: Option<tokio::sync::mpsc::UnboundedSender<String>>,
}

/// How a connection ends.
enum End {
    Close(CloseCode),
    Gone,
}

impl ProbeServer {
    pub fn new(ingest: Ingest, directory: Arc<dyn ProbeDirectory>, settings: ServerSettings) -> ProbeServer {
        ProbeServer {
            ingest,
            directory,
            settings,
            outbound: Arc::default(),
            identities: Arc::default(),
            addresses: Arc::default(),
            bindings: None,
            greeted: None,
        }
    }

    /// Gives guest binding the MACs of each probe's interfaces, as its Hello reports them.
    pub fn with_bindings(mut self, bindings: Arc<crate::registry::guest_binding::GuestBindings>) -> ProbeServer {
        self.bindings = Some(bindings);
        self
    }

    /// Tells `greeted` the machine id of each accepted Hello.
    pub fn with_greeted(mut self, greeted: tokio::sync::mpsc::UnboundedSender<String>) -> ProbeServer {
        self.greeted = Some(greeted);
        self
    }

    /// The runner of `probe_check` steps (D115), sending them to the machines' connected probes.
    /// What the hub tells probes now: their `ProbeConfig`.
    pub fn config(&self) -> &ProbeConfig {
        &self.settings.config
    }

    pub fn config_rev(&self) -> u64 {
        self.settings.config_rev
    }

    /// The hub's addresses and relays, for every Welcome after this.
    pub fn set_hub_addresses(&self, addrs: Vec<String>, relays: Vec<String>) {
        *self.addresses.lock().unwrap_or_else(|e| e.into_inner()) = (addrs, relays);
    }

    /// The machines whose probes are connected.
    pub fn connected(&self) -> Vec<String> {
        let mut machines: Vec<String> =
            self.outbound.probes().iter().filter(|(_, s)| !s.is_closed()).map(|(m, _)| m.clone()).collect();
        machines.sort();
        machines
    }

    /// Sends a message on a machine's stream 0; whether its probe is connected.
    pub async fn send_to(&self, machine: &str, msg: HubToProbe) -> bool {
        match self.outbound.to(machine) {
            Some(out) => out.send(msg).await.is_ok(),
            None => false,
        }
    }

    pub fn probe_checks(&self) -> super::probe_checks::ProbeChecks {
        super::probe_checks::ProbeChecks::new(self.outbound.clone())
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
        // one endpoint id from two boots that both report is a clone, and neither is the machine the hub enrolled (E6)
        let identity = match self.identities.enter(conn.remote_id(), &hello.boot_id, now_ms()) {
            Entry::Admitted(session) => session,
            Entry::Conflict => {
                let event = Event::machine(
                    &machine,
                    "probe.identity_conflict",
                    Severity::Critical,
                    serde_json::json!({
                        "machine_id": machine,
                        "endpoint": conn.remote_id().to_string(),
                        "reason": "one endpoint id from two boots; each is refused until one re-enrolls",
                    }),
                );
                let _ = self.ingest.raise_event(event).await;
                return End::Close(CloseCode::IdentityMismatch);
            }
        };
        if self.ingest.hello(&machine, hello.epoch, &hello.label_table).await.is_err() {
            return End::Gone;
        }
        self.ingest.set_capabilities(&machine, &hello.capabilities);
        self.ingest.set_probe_build(&machine, version, hello.os.as_ref().map(|o| o.arch.as_str()).unwrap_or_default());
        if let Some(bindings) = &self.bindings {
            let macs = hello.interfaces.iter().map(|i| i.mac.clone()).collect();
            if let Err(e) = bindings.reported(&machine, macs, now_ms()).await {
                tracing::warn!(error = %e, %machine, "guest binding");
            }
        }
        if let Some(greeted) = &self.greeted {
            let _ = greeted.send(machine.clone());
        }
        let received = self.ingest.received(&machine, hello.epoch);
        let mut config = self.settings.config.clone();
        {
            let (addrs, relays) = self.addresses.lock().unwrap_or_else(|e| e.into_inner()).clone();
            config.hub_addrs = addrs;
            config.hub_relays = relays;
        }
        let welcome = Welcome {
            hub_version: Some(SemVer { version: self.settings.hub_version.clone() }),
            config: Some(config),
            config_rev: self.settings.config_rev,
            received: (!received.is_empty()).then(|| EpochRanges { epoch: hello.epoch, ranges: seq_ranges(&received) }),
            server_time_ms: now_ms(),
        };
        let welcome = HubToProbe { msg: Some(hub_to_probe::Msg::Welcome(welcome)) };
        if frames::write_msg(&mut ctrl_send, &welcome).await.is_err() {
            return End::Gone;
        }
        // Acks from every stream go out on stream 0 in the order they are produced, and so does what the hub starts.
        let (acks, mut ack_rx) = mpsc::channel::<Ack>(256);
        let (out, mut out_rx) = mpsc::channel::<HubToProbe>(16);
        self.outbound.probes().insert(machine.clone(), out.clone());
        let writer = tokio::spawn(async move {
            loop {
                let msg = tokio::select! {
                    ack = ack_rx.recv() => match ack {
                        Some(ack) => HubToProbe { msg: Some(hub_to_probe::Msg::Ack(ack)) },
                        None => return,
                    },
                    msg = out_rx.recv() => match msg {
                        Some(m) => m,
                        None => return,
                    },
                };
                if frames::write_msg(&mut ctrl_send, &msg).await.is_err() {
                    return;
                }
            }
        });
        let (ends, mut end_rx) = mpsc::channel::<End>(4);
        let control = tokio::spawn(control(
            self.ingest.clone(),
            machine.clone(),
            ctrl_recv,
            acks.clone(),
            ends.clone(),
            self.outbound.clone(),
        ));
        let end = loop {
            tokio::select! {
                end = end_rx.recv() => break end.unwrap_or(End::Gone),
                _ = identity.killed() => break End::Close(CloseCode::IdentityMismatch),
                stream = conn.accept_uni() => {
                    let Ok(mut recv) = stream else { break End::Gone };
                    let mut tag = [0u8; 1];
                    if recv.read_exact(&mut tag).await.is_err() {
                        continue;
                    }
                    let (ingest, machine, acks, ends) = (self.ingest.clone(), machine.clone(), acks.clone(), ends.clone());
                    let activity = identity.activity();
                    match tag[0] {
                        rackhand_proto::streams::LIVE => { tokio::spawn(live(ingest, machine, recv, acks, ends, activity)); }
                        rackhand_proto::streams::REPLAY => { tokio::spawn(replay(ingest, machine, recv, acks, ends, activity)); }
                        _ => break End::Close(CloseCode::UnsupportedVersion),
                    }
                }
            }
        };
        control.abort();
        writer.abort();
        // a newer connection of the same machine may have replaced this one
        let mut probes = self.outbound.probes();
        if probes.get(&machine).is_some_and(|s| s.same_channel(&out)) {
            probes.remove(&machine);
        }
        drop(probes);
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
        Receipt::Held => return,
    };
    let _ = acks.send(Ack { epoch, ranges: seq_ranges(&ranges) }).await;
}

/// Stream 0 after the Welcome: `DataDropped` and `CheckResult` from the probe.
async fn control(
    ingest: Ingest,
    machine: String,
    mut recv: RecvStream,
    acks: mpsc::Sender<Ack>,
    ends: mpsc::Sender<End>,
    outbound: Arc<Outbound>,
) {
    loop {
        let Ok(body) = frames::read(&mut recv).await else {
            let _ = ends.send(End::Gone).await;
            return;
        };
        match ProbeToHub::decode(body.as_slice()).ok().and_then(|m| m.msg) {
            Some(probe_to_hub::Msg::DataDropped(d)) => {
                if ingest.dropped(&machine, d.epoch, d.from_seq, d.to_seq).await.is_ok() {
                    let ranges = ingest.received(&machine, d.epoch);
                    let _ = acks.send(Ack { epoch: d.epoch, ranges: seq_ranges(&ranges) }).await;
                }
            }
            Some(probe_to_hub::Msg::CheckResult(r)) => {
                // an answer nobody waits for any more (its step timed out) is dropped
                if let Some(waiting) = outbound.pending().remove(&r.id) {
                    let _ = waiting.send(r);
                }
            }
            _ => {}
        }
    }
}

/// Decompresses a stream 1 or 2 frame body (16 MB at most, else `0x15`).
fn inflate<M: Message + Default>(body: &[u8]) -> Result<M, CloseCode> {
    let bytes = rackhand_proto::zstd::decompress_bounded(body)?;
    M::decode(bytes.as_slice()).map_err(|_| CloseCode::FrameTooLarge)
}

async fn live(
    ingest: Ingest,
    machine: String,
    mut recv: RecvStream,
    acks: mpsc::Sender<Ack>,
    ends: mpsc::Sender<End>,
    activity: Arc<AtomicI64>,
) {
    let (mut tokens, mut at) = (LIVE_BURST, Instant::now());
    loop {
        let Ok(body) = frames::read(&mut recv).await else { return };
        activity.store(now_ms(), Ordering::Relaxed);
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
    activity: Arc<AtomicI64>,
) {
    loop {
        // Past the replay limits stream 2 isn't read, so QUIC flow control holds the probe back (7.3.2).
        while !ingest.replay_allowed(&machine, now_ms()) {
            tokio::time::sleep(REPLAY_POLL).await;
        }
        let Ok(body) = frames::read(&mut recv).await else { return };
        activity.store(now_ms(), Ordering::Relaxed);
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
