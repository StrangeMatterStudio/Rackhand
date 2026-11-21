//! `rackhand-probe run` (7.3.2, FR-1, FR-3): samples at its interval, reports to its hub, buffers across outages and
//! replays the backlog beside live reports, reconnects with backoff, and keeps `probe.state` current.
//!
//! Collection runs on its own task, so a slow hub never delays sampling. Live reports go out as they are made; the
//! backlog goes out on stream 2 from its own task, so live reports never wait on replay or on acks.

use std::collections::BTreeSet;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rackhand_proto::catalogue;
use rackhand_proto::common::{LabelEntry, ProbeConfig};
use rackhand_proto::probe::{ContainerState, ProbeEvent, Report, Sample, UpdateSummary};
use tokio::sync::{mpsc, watch};

use crate::buffer::labels::{LabelSet, LabelTable};
use crate::buffer::segments::Dropped;
use crate::collect::{self, Collection, Host, SelfUse, Snapshot, Stamp};
use crate::helper::client::{HelperClient, HelperData};
use crate::link::{Link, Session, Stop};

/// The probe interval's range (7.8.1).
const MIN_INTERVAL: Duration = Duration::from_secs(5);
const MAX_INTERVAL: Duration = Duration::from_secs(300);
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(15);

/// Time, for the daemon and its tests.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> i64;
    /// A monotonic reading in milliseconds.
    fn mono_ms(&self) -> i64;
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

#[derive(Debug)]
pub struct SystemClock {
    start: Instant,
}

impl Default for SystemClock {
    fn default() -> SystemClock {
        SystemClock { start: Instant::now() }
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
    }
    fn mono_ms(&self) -> i64 {
        self.start.elapsed().as_millis() as i64
    }
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep(d))
    }
}

/// What the collector does each interval.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub interval: Duration,
    pub collect: collect::Config,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { interval: DEFAULT_INTERVAL, collect: collect::Config::default() }
    }
}

impl Settings {
    /// The hub's probe config (from `Welcome` or `ConfigUpdate`); an unset interval keeps the current one.
    pub fn apply(&mut self, cfg: &ProbeConfig) {
        if cfg.interval_s > 0 {
            self.interval = Duration::from_secs(cfg.interval_s.into()).clamp(MIN_INTERVAL, MAX_INTERVAL);
        }
        self.collect.per_core_cpu = cfg.per_core_cpu;
        self.collect.extra_mount_excludes = cfg.extra_mount_excludes.clone();
        self.collect.extra_iface_excludes = cfg.extra_iface_excludes.clone();
        self.collect.watched_services = cfg.watched_services.clone();
    }
}

pub struct Options {
    pub host: Arc<dyn Host + Send + Sync>,
    pub settings: Settings,
    /// Where the label tables live (next to the buffer).
    pub data_dir: PathBuf,
    /// `/run/rackhand-probe/probe.state`, when it should be written.
    pub state_file: Option<PathBuf>,
    pub version: String,
    pub clock: Arc<dyn Clock>,
    /// 0 to 1, for the backoff's jitter.
    pub jitter: Arc<dyn Fn() -> f64 + Send + Sync>,
    /// The root helper, when the machine has one.
    pub helper: Option<HelperClient>,
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options").field("settings", &self.settings).field("data_dir", &self.data_dir).finish()
    }
}

/// A random jitter from the system's random source.
pub fn random_jitter() -> f64 {
    let mut b = [0u8; 4];
    if getrandom::fill(&mut b).is_err() {
        return 0.5;
    }
    f64::from(u32::from_le_bytes(b)) / f64::from(u32::MAX)
}

struct Sampled {
    collection: Collection,
    sampled_at_ms: i64,
    helper: HelperData,
}

/// Aborts the replay task when the session ends.
struct Replaying(tokio::task::JoinHandle<()>);

impl Drop for Replaying {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct Daemon {
    link: Link,
    labels: LabelTable,
    opts: Options,
    settings: watch::Sender<Settings>,
    /// Label ids the hub has for this connection: the Hello's table, then each report's new entries.
    sent: BTreeSet<u32>,
    /// Dropped ranges not yet told to the hub.
    held_drops: Vec<Dropped>,
    attempts: u32,
    /// `helper_version_mismatch` was reported for the current mismatch.
    mismatch_reported: bool,
}

impl std::fmt::Debug for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Daemon").field("epoch", &self.link.epoch()).field("attempts", &self.attempts).finish()
    }
}

impl Daemon {
    pub fn new(link: Link, opts: Options) -> std::io::Result<Daemon> {
        let labels = LabelTable::open(&opts.data_dir, link.epoch())?;
        let (settings, _) = watch::channel(opts.settings.clone());
        Ok(Daemon {
            link,
            labels,
            opts,
            settings,
            sent: BTreeSet::new(),
            held_drops: Vec::new(),
            attempts: 0,
            mismatch_reported: false,
        })
    }

    /// Runs until the hub revokes this probe (exit code 3) or the collector stops (1).
    pub async fn run(mut self) -> i32 {
        let (tx, mut rx) = mpsc::channel(64);
        let (host, clock, helper) = (self.opts.host.clone(), self.opts.clock.clone(), self.opts.helper.clone());
        spawn_collector(host, clock, helper, self.settings.subscribe(), tx);
        loop {
            self.state("connecting", None, None);
            let now = self.opts.clock.now_ms();
            let stop = match self.link.connect(&self.table(), now).await {
                Ok(mut session) => {
                    self.attempts = 0;
                    let stop = self.serve(&mut session, &mut rx).await;
                    if stop == Stop::Disconnected("stopping".into()) {
                        return 1;
                    }
                    stop
                }
                Err(stop) => stop,
            };
            if let Some(code) = stop.exit_code() {
                self.state("stopped", Some(&stop), None);
                return code;
            }
            let wait = stop.retry_after(self.attempts, (self.opts.jitter)());
            self.attempts = self.attempts.saturating_add(1);
            self.state("disconnected", Some(&stop), Some(wait));
            let sleep = self.opts.clock.sleep(wait);
            tokio::pin!(sleep);
            loop {
                tokio::select! {
                    () = &mut sleep => break,
                    sampled = rx.recv() => match sampled {
                        Some(s) => self.keep(&s),
                        None => return 1,
                    },
                }
            }
        }
    }

    /// The whole label table, for the Hello.
    fn table(&self) -> Vec<LabelEntry> {
        self.labels
            .entries()
            .iter()
            .map(|(id, l)| LabelEntry { id: *id, labels: l.clone().into_iter().collect() })
            .collect()
    }

    async fn serve(&mut self, s: &mut Session, rx: &mut mpsc::Receiver<Sampled>) -> Stop {
        if self.link.epoch_changed() {
            // a new epoch has an empty table: the next report defines every label set it uses (7.3.2)
            match LabelTable::open(&self.opts.data_dir, self.link.epoch()) {
                Ok(t) => self.labels = t,
                Err(e) => return Stop::Buffer(e.to_string()),
            }
            self.sent.clear();
        } else {
            self.sent = self.labels.entries().keys().copied().collect();
        }
        if let Some(cfg) = s.welcome.config.clone() {
            self.apply(&cfg);
        }
        self.state("connected", None, None);
        if let Err(stop) = self.send_drops(s).await {
            return stop;
        }
        let (done_tx, mut replayed) = tokio::sync::oneshot::channel();
        let (conn, backlog) = (s.connection(), self.link.backlog(s));
        let _replaying = Replaying(tokio::spawn(async move {
            let _ = done_tx.send(crate::link::replay(conn, backlog).await);
        }));
        let mut replaying = true;
        loop {
            tokio::select! {
                sampled = rx.recv() => {
                    let Some(sampled) = sampled else {
                        s.close();
                        return Stop::Disconnected("stopping".into());
                    };
                    let report = self.report(&sampled);
                    if let Err(stop) = self.link.send_live(s, report, self.opts.clock.now_ms()).await {
                        return stop;
                    }
                    if let Err(stop) = self.send_drops(s).await {
                        return stop;
                    }
                }
                msg = s.next_message() => match msg.and_then(|m| self.link.on_message(m)) {
                    Ok(Some(cfg)) => self.apply(&cfg),
                    Ok(None) => {}
                    Err(stop) => return stop,
                },
                done = &mut replayed, if replaying => {
                    replaying = false;
                    if let Ok(Err(stop)) = done {
                        return stop;
                    }
                }
            }
        }
    }

    fn apply(&mut self, cfg: &ProbeConfig) {
        self.settings.send_modify(|s| s.apply(cfg));
        if cfg.buffer_max_mb > 0 {
            let max = u64::from(cfg.buffer_max_mb.min(64)) * 1024 * 1024;
            if let Err(e) = self.link.buffer.set_max_bytes(max) {
                tracing::warn!(error = %e, "applying the buffer cap");
            }
        }
    }

    /// Buffers a report while there is no connection.
    fn keep(&mut self, sampled: &Sampled) {
        let report = self.report(sampled);
        if let Err(e) = self.link.queue(&report, self.opts.clock.now_ms()) {
            tracing::warn!(error = ?e, "buffering a report");
        }
        let dropped = self.link.buffer.take_dropped();
        self.held_drops.extend(dropped);
    }

    /// Tells the hub about reports deleted unsent; a range stays held until the hub has it.
    async fn send_drops(&mut self, s: &mut Session) -> Result<(), Stop> {
        let dropped = self.link.buffer.take_dropped();
        self.held_drops.extend(dropped);
        while let Some(d) = self.held_drops.first().copied() {
            s.data_dropped(d.epoch, d.from_seq, d.to_seq).await?;
            self.held_drops.remove(0);
        }
        Ok(())
    }

    /// The next report of the epoch, with the label sets the hub doesn't have yet on this connection.
    fn report(&mut self, sampled: &Sampled) -> Report {
        let c = &sampled.collection;
        let (mut vitals, mut label_sets) = (Vec::new(), Vec::new());
        for series in &c.series {
            let Some(metric) = catalogue::by_name(series.metric) else { continue };
            let labels: LabelSet = series.labels.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
            let id = self.labels.id_for(&labels);
            if self.sent.insert(id) {
                label_sets.push(LabelEntry { id, labels: labels.into_iter().collect() });
            }
            vitals.push(Sample { metric: metric.id, labels_id: id, value: series.value });
        }
        let mut events: Vec<ProbeEvent> = c
            .events
            .iter()
            .map(|e| ProbeEvent {
                kind: e.kind.into(),
                at_ms: sampled.sampled_at_ms,
                fields: [("detail".to_string(), e.detail.clone())].into_iter().collect(),
            })
            .collect();
        let h = &sampled.helper;
        match &h.mismatch {
            Some(helper) if !self.mismatch_reported => {
                self.mismatch_reported = true;
                let fields = [("helper".to_string(), helper.clone()), ("probe".to_string(), self.opts.version.clone())];
                events.push(ProbeEvent {
                    kind: "helper_version_mismatch".into(),
                    at_ms: sampled.sampled_at_ms,
                    fields: fields.into_iter().collect(),
                });
            }
            Some(_) => {}
            None => self.mismatch_reported = false,
        }
        let containers = h
            .containers
            .iter()
            .map(|c| ContainerState {
                id: c.id.clone(),
                name: c.name.clone(),
                image: c.image.clone(),
                state: c.state.clone(),
                health: c.health.clone().unwrap_or_default(),
                restart_count: c.restart_count,
                started_at_ms: c.started_at_ms,
            })
            .collect();
        let updates = h.updates.as_ref().map(|u| UpdateSummary {
            pending: u.pending,
            security: u.security,
            reboot_required: u.reboot_required,
            packages: u.packages.clone(),
        });
        Report {
            epoch: self.link.epoch(),
            seq: self.link.next_seq(),
            sampled_at_ms: sampled.sampled_at_ms,
            vitals,
            label_sets,
            services: c.services.clone(),
            containers,
            updates,
            events,
            ..Report::default()
        }
    }

    /// Writes `probe.state` (replaced whole, so a reader never sees half of it).
    fn state(&self, state: &str, stop: Option<&Stop>, retry_in: Option<Duration>) {
        let Some(path) = &self.opts.state_file else { return };
        let value = serde_json::json!({
            "state": state,
            "version": self.opts.version,
            "at_ms": self.opts.clock.now_ms(),
            "reason": stop.map(|s| format!("{s:?}")),
            "retry_in_ms": retry_in.map(|d| d.as_millis() as u64),
            "epoch": self.link.epoch(),
            "buffered": self.link.buffer.pending().count(),
        });
        if let Err(e) = write_atomically(path, value.to_string().as_bytes()) {
            tracing::warn!(error = %e, path = %path.display(), "writing probe.state");
        }
    }
}

pub fn write_atomically(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

/// Samples every interval and hands each collection to the daemon; stops when the daemon goes.
fn spawn_collector(
    host: Arc<dyn Host + Send + Sync>,
    clock: Arc<dyn Clock>,
    helper: Option<HelperClient>,
    settings: watch::Receiver<Settings>,
    tx: mpsc::Sender<Sampled>,
) {
    tokio::spawn(async move {
        let mut prev: Option<Snapshot> = None;
        loop {
            let Settings { interval, collect: cfg } = settings.borrow().clone();
            let at = Stamp { wall_ms: clock.now_ms(), mono_ms: clock.mono_ms() };
            let self_use = SelfUse { rss_bytes: collect::own_rss_bytes(), ..SelfUse::default() };
            let collection = collect::collect_at(host.as_ref(), prev.as_ref(), at, &cfg, self_use);
            prev = Some(collection.snapshot.clone());
            let helper = match &helper {
                Some(h) => h.collect().await,
                None => HelperData::default(),
            };
            if tx.send(Sampled { collection, sampled_at_ms: at.wall_ms, helper }).await.is_err() {
                return;
            }
            clock.sleep(interval).await;
        }
    });
}

/// Where the daemon's files are (7.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub config: PathBuf,
    /// The node key, the buffer and the label tables.
    pub data_dir: PathBuf,
    pub state_file: PathBuf,
    /// A fixture root to collect from instead of the system (tests).
    pub root: Option<PathBuf>,
}

impl Default for Paths {
    fn default() -> Paths {
        Paths {
            config: crate::config::PATH.into(),
            data_dir: "/var/lib/rackhand-probe".into(),
            state_file: "/run/rackhand-probe/probe.state".into(),
            root: None,
        }
    }
}

/// The daemon from its files: the hub and machine from `probe.toml`, the node key and buffer from the data directory.
pub async fn main(paths: Paths) -> Result<i32, String> {
    let cfg = crate::config::ProbeToml::load(&paths.config).map_err(|e| e.to_string())?;
    let machine_id = cfg.machine_id().map_err(|e| e.to_string())?;
    let hub_id =
        iroh::EndpointId::from_bytes(&cfg.hub_key().map_err(|e| e.to_string())?).map_err(|e| format!("hub.id: {e}"))?;
    let mut hub = iroh::EndpointAddr::new(hub_id);
    for a in &cfg.hub.addrs {
        hub.addrs.insert(iroh::TransportAddr::Ip(*a));
    }
    for r in &cfg.hub.relays {
        let url: iroh::RelayUrl = r.parse().map_err(|_| format!("hub.relays: {r} isn't a URL"))?;
        hub.addrs.insert(iroh::TransportAddr::Relay(url));
    }
    std::fs::create_dir_all(&paths.data_dir).map_err(|e| format!("{}: {e}", paths.data_dir.display()))?;
    let key_path = paths.data_dir.join("node.key");
    let key = rackhand_net::key::load_or_create(&key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
    let relays = rackhand_net::relays::RelayConfig { relays: cfg.hub.relays.clone(), ..Default::default() };
    let endpoint_config = rackhand_net::endpoint::EndpointConfig { relays, alpns: Vec::new(), bind: None };
    let endpoint = rackhand_net::endpoint::bind(key, &endpoint_config).await.map_err(|e| e.to_string())?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
    let buffer_dir = paths.data_dir.join("buffer");
    let buffer = crate::buffer::segments::Buffer::open(&buffer_dir, Default::default(), clock.now_ms())
        .map_err(|e| format!("{}: {e}", buffer_dir.display()))?;
    let backlog = buffer.pending().last().map(|r| (r.epoch, r.seq));
    let version = env!("CARGO_PKG_VERSION");
    let link_cfg = crate::link::LinkConfig::new(hub, machine_id, version);
    let link = Link::new(endpoint, link_cfg, buffer, crate::buffer::epoch::EpochState::start(backlog));
    let host: Arc<dyn Host + Send + Sync> = Arc::new(match &paths.root {
        Some(root) => collect::RootHost::new(root.clone()),
        None => collect::RootHost::system(),
    });
    if let Some(dir) = paths.state_file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let opts = Options {
        host,
        settings: Settings::default(),
        data_dir: buffer_dir,
        state_file: Some(paths.state_file),
        version: version.into(),
        clock,
        jitter: Arc::new(random_jitter),
        helper: Some(HelperClient::new(crate::helper::SOCKET, version)),
    };
    let daemon = Daemon::new(link, opts).map_err(|e| e.to_string())?;
    Ok(daemon.run().await)
}

#[cfg(test)]
mod tests;
