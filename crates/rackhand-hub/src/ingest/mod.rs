//! Receives probe and driver data, stages, acks, and writes series and events (7.2 Ingest, 7.3.2, 7.4.1).
//!
//! A report is staged (one `report_staging` row) and committed before it is acked. Compaction moves staged points into
//! chunk rows every 5 minutes, on shutdown and on start. The recent window holds the last 35 minutes of samples in
//! memory for rules, live charts and rollups. Ingest is the only writer of `events` ([`Ingest::raise_event`]).

mod clock;
mod compact;
mod events;
pub mod probe_checks;
pub mod probe_server;
mod replay_limits;
mod series;
mod staging;
mod wait;
mod window;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

use rackhand_proto::probe::{ContainerState, ServiceState, UpdateSummary};
use rackhand_store::{Db, StoreError, StoreWriter};

use crate::bus::Bus;
pub use compact::CompactStats;
pub use events::{Event, Severity};
pub use rackhand_store::series::chunk::Tier;
pub use replay_limits::ReplayLimits;
pub use staging::{Receipt, Stream};
pub use window::{SeriesId, WindowSample};

/// A `probe_ranges` row: machine, epoch, ranges as JSON.
type KeptRanges = (String, i64, String);
/// A staged report: machine, epoch, seq.
type StagedSeq = (String, i64, i64);

/// The recent window's length (D100: the longest rule window is 30 minutes).
pub const WINDOW_MS: i64 = 35 * 60_000;
/// Samples older than this when they arrive feed history and baselines but not threshold rules (7.3.2, E1).
pub const HISTORY_ONLY_AFTER_MS: i64 = 10 * 60_000;
/// Below this share of free disk the hub stops replays and new jobs (E32).
pub const DISK_LOW: f64 = 0.02;
const DEFAULT_INTERVAL_MS: i64 = 15_000;

/// The hub's free disk space, read for E32.
pub trait DiskSpace: Send + Sync + std::fmt::Debug {
    /// Free space as a share of the database's filesystem, 0 to 1.
    fn free_fraction(&self) -> f64;
}

#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("report frame: {0}")]
    Frame(String),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

/// What a machine's probe last reported about it, from its newest live report.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LatestFacts {
    pub reported_at_ms: i64,
    pub services: Vec<ServiceState>,
    pub containers: Vec<ContainerState>,
    /// The last summary sent (at most every 6 h or on change).
    pub updates: Option<UpdateSummary>,
}

impl LatestFacts {
    /// The services as JSON, for the dashboard and MCP's `get_machine`.
    pub fn services_json(&self) -> Vec<serde_json::Value> {
        self.services
            .iter()
            .map(|s| {
                let status = match rackhand_proto::probe::ServiceStatus::try_from(s.status) {
                    Ok(rackhand_proto::probe::ServiceStatus::Active) => "active",
                    Ok(rackhand_proto::probe::ServiceStatus::Inactive) => "inactive",
                    Ok(rackhand_proto::probe::ServiceStatus::Failed) => "failed",
                    Ok(rackhand_proto::probe::ServiceStatus::Activating) => "activating",
                    _ => "unknown",
                };
                serde_json::json!({ "name": s.name, "state": status, "enabled": s.enabled, "since_ms": s.since_ms })
            })
            .collect()
    }

    pub fn containers_json(&self) -> Vec<serde_json::Value> {
        self.containers
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.id, "name": c.name, "image": c.image, "state": c.state, "health": c.health,
                    "restart_count": c.restart_count, "started_at_ms": c.started_at_ms,
                })
            })
            .collect()
    }

    /// The pending updates as one summary, or none before the first summary arrives.
    pub fn updates_json(&self) -> Vec<serde_json::Value> {
        self.updates
            .iter()
            .map(|u| {
                serde_json::json!({
                    "pending": u.pending, "security": u.security, "reboot_required": u.reboot_required,
                    "packages": u.packages,
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct Ingest {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    db: Arc<Db>,
    writer: StoreWriter,
    bus: Bus,
    disk: Arc<dyn DiskSpace>,
    limits: ReplayLimits,
    state: Mutex<State>,
    /// One compaction at a time.
    compacting: tokio::sync::Mutex<()>,
    /// Reports staged since the hub started (`rackhand_hub_ingest_reports_total`).
    reports_total: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Default)]
struct State {
    machines: HashMap<String, Machine>,
    /// Bytes staged and not yet compacted.
    staging_bytes: u64,
    hub_replay: replay_limits::Bucket,
    disk_low: bool,
    /// The database failed its integrity check (E33): nothing is staged or acked and no job starts.
    integrity_failed: bool,
}

#[derive(Debug)]
struct Machine {
    /// Label tables by epoch: id to label set.
    labels: HashMap<u64, HashMap<u32, BTreeMap<String, String>>>,
    received: HashMap<u64, staging::Ranges>,
    clock: clock::Clock,
    window: window::Window,
    replay: replay_limits::Bucket,
    interval_ms: i64,
    latest: Option<LatestFacts>,
    unknown_labels_reported_ms: i64,
    counted: Counted,
    /// When the newest live report arrived.
    last_seen_ms: Option<i64>,
    /// What the probe said it can do in its last `Hello`.
    capabilities: Vec<i32>,
}

/// What the counted rules (7.6.1) need from a machine's live reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counted {
    /// Services reported not active, with how many reports in a row.
    pub services_down: std::collections::BTreeMap<String, u32>,
    /// Per container (by name): its last restart count and the arrival times of the restarts seen.
    pub restarts: std::collections::BTreeMap<String, (u32, Vec<i64>)>,
    /// Since when security updates have been pending, while they are.
    pub security_since: Option<i64>,
}

impl Default for Machine {
    fn default() -> Machine {
        Machine {
            labels: HashMap::new(),
            received: HashMap::new(),
            clock: clock::Clock::default(),
            window: window::Window::default(),
            replay: replay_limits::Bucket::default(),
            interval_ms: DEFAULT_INTERVAL_MS,
            latest: None,
            unknown_labels_reported_ms: i64::MIN,
            counted: Counted::default(),
            last_seen_ms: None,
            capabilities: Vec::new(),
        }
    }
}

impl Ingest {
    pub fn new(db: Arc<Db>, bus: Bus, disk: Arc<dyn DiskSpace>) -> Ingest {
        let writer = db.writer();
        Ingest {
            inner: Arc::new(Inner {
                db,
                writer,
                bus,
                disk,
                limits: ReplayLimits::default(),
                state: Mutex::default(),
                compacting: tokio::sync::Mutex::new(()),
                reports_total: std::sync::atomic::AtomicU64::new(0),
            }),
        }
    }

    /// Replaces the replay limits (before the hub serves probes).
    pub fn with_limits(self, limits: ReplayLimits) -> Ingest {
        let inner = Arc::try_unwrap(self.inner).expect("limits are set before the ingest is shared");
        Ingest { inner: Arc::new(Inner { limits, ..inner }) }
    }

    /// On start (E44): compacts what a stopped hub left staged, then rebuilds the recent window from tier 0, before
    /// any rule runs.
    pub async fn start(&self, now_ms: i64) -> Result<(), IngestError> {
        self.load_ranges()?;
        self.compact().await?;
        self.rebuild_window(now_ms)
    }

    /// The committed seq ranges of a stopped hub: those kept at its last compaction, and every report still staged
    /// (7.3.2), so `Welcome.received` is complete after a restart.
    fn load_ranges(&self) -> Result<(), IngestError> {
        let (kept, staged): (Vec<KeptRanges>, Vec<StagedSeq>) = self.inner.db.readers().with(|c| {
            let mut k = c.prepare("SELECT machine_id, epoch, ranges FROM probe_ranges")?;
            let kept =
                k.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            let mut s = c.prepare("SELECT machine_id, epoch, seq FROM report_staging")?;
            let staged =
                s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((kept, staged))
        })?;
        let mut s = self.state();
        for (machine, epoch, ranges) in kept {
            let list: Vec<(u64, u64)> = serde_json::from_str(&ranges).unwrap_or_default();
            let r = s.machines.entry(machine).or_default().received.entry(epoch as u64).or_default();
            for (a, b) in list {
                r.add(a, b);
            }
        }
        for (machine, epoch, seq) in staged {
            s.machines
                .entry(machine)
                .or_default()
                .received
                .entry(epoch as u64)
                .or_default()
                .add(seq as u64, seq as u64);
        }
        Ok(())
    }

    /// The machine's sample interval, for placing samples on their tick (default 15 s).
    pub fn set_interval(&self, machine: &str, interval_ms: i64) {
        self.state().machines.entry(machine.to_string()).or_default().interval_ms = interval_ms.max(1);
    }

    pub fn reports_total(&self) -> u64 {
        self.inner.reports_total.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The newest sample of every series in the recent window: (machine, series, time, value).
    pub fn latest_values(&self) -> Vec<(String, SeriesId, i64, f64)> {
        let s = self.state();
        let mut out = Vec::new();
        for (machine, m) in &s.machines {
            for (id, q) in m.window.all() {
                if let Some(last) = q.back() {
                    out.push((machine.clone(), id.clone(), last.at_ms, last.value));
                }
            }
        }
        out.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        out
    }

    /// The capabilities from the probe's last `Hello` (7.3.2).
    pub fn set_capabilities(&self, machine: &str, capabilities: &[i32]) {
        self.state().machines.entry(machine.to_string()).or_default().capabilities = capabilities.to_vec();
    }

    pub fn capabilities(&self, machine: &str) -> Vec<i32> {
        self.state().machines.get(machine).map(|m| m.capabilities.clone()).unwrap_or_default()
    }

    /// The counted-rule inputs of a machine's live reports.
    pub fn counted(&self, machine: &str) -> Counted {
        self.state().machines.get(machine).map(|m| m.counted.clone()).unwrap_or_default()
    }

    /// When the machine's newest live report arrived.
    pub fn last_seen(&self, machine: &str) -> Option<i64> {
        self.state().machines.get(machine).and_then(|m| m.last_seen_ms)
    }

    /// The machines Ingest has heard from.
    pub fn machines(&self) -> Vec<String> {
        self.state().machines.keys().cloned().collect()
    }

    /// The machine's sample interval.
    pub fn interval_ms(&self, machine: &str) -> i64 {
        self.state().machines.get(machine).map_or(DEFAULT_INTERVAL_MS, |m| m.interval_ms)
    }

    /// Every series of one metric in a machine's recent window (one per label set), oldest sample first.
    pub fn window_series(&self, machine: &str, metric: &str) -> Vec<(SeriesId, Vec<WindowSample>)> {
        let s = self.state();
        let Some(m) = s.machines.get(machine) else { return Vec::new() };
        let mut out: Vec<(SeriesId, Vec<WindowSample>)> = m
            .window
            .all()
            .filter(|(id, _)| id.name == metric)
            .map(|(id, q)| (id.clone(), q.iter().copied().collect()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// The recent window of one series, oldest first.
    pub fn window(&self, machine: &str, series: &SeriesId) -> Vec<WindowSample> {
        self.state().machines.get(machine).map(|m| m.window.samples(series)).unwrap_or_default()
    }

    /// The machine's clock offset (receive time minus sample time), once a live report has arrived.
    pub fn clock_offset(&self, machine: &str) -> Option<i64> {
        self.state().machines.get(machine).and_then(|m| m.clock.offset())
    }

    pub fn latest(&self, machine: &str) -> Option<LatestFacts> {
        self.state().machines.get(machine).and_then(|m| m.latest.clone())
    }

    /// Whether Actions may start new jobs (E32: not while the hub's disk is nearly full).
    pub fn accepting_jobs(&self) -> bool {
        let s = self.state();
        !s.disk_low && !s.integrity_failed
    }

    /// The database failed its integrity check (E33): from now on reports update the in-memory window only (the
    /// dashboard and the latest values stay current), nothing is staged or acked, so probes keep their reports
    /// buffered, and no job starts. It lasts until an admin restores from a backup and restarts the hub.
    pub fn set_integrity_failed(&self) {
        self.state().integrity_failed = true;
    }

    pub fn integrity_failed(&self) -> bool {
        self.state().integrity_failed
    }

    /// Reads the free disk space; below 2% stops replays and new jobs and raises one critical `hub.disk_low`.
    pub async fn check_disk(&self) -> Result<(), IngestError> {
        let free = self.inner.disk.free_fraction();
        let became_low = {
            let mut s = self.state();
            let was = s.disk_low;
            s.disk_low = free < DISK_LOW;
            s.disk_low && !was
        };
        if became_low {
            self.raise_event(Event::hub("hub.disk_low", Severity::Critical, serde_json::json!({ "free": free })))
                .await?;
        }
        Ok(())
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn labels_json(labels: &BTreeMap<String, String>) -> String {
    serde_json::to_string(labels).unwrap_or_else(|_| "{}".into())
}

/// The nearest tick of the sample interval.
fn tick(t: i64, interval_ms: i64) -> i64 {
    (t + interval_ms / 2).div_euclid(interval_ms) * interval_ms
}

#[cfg(test)]
mod tests;
