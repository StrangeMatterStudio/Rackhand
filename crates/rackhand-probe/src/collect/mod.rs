//! Linux collectors (7.4.2): every catalogue metric from `/proc` and `/sys` of a root (the real system or a fixture
//! tree), with the default exclusions and the 200-series cap. Rates come from two snapshots.

pub mod host;
pub mod procfs;

use std::collections::BTreeMap;

use rackhand_proto::catalogue;
use rackhand_proto::probe::{ServiceState, ServiceStatus};

pub use host::{FsStat, Host, RootHost};
use procfs::{CpuTimes, DiskCounters, NetCounters};

pub const SERIES_CAP: usize = 200;

/// The default exclusions, plus read-only image filesystems that are always full: squashfs through FUSE (snaps on
/// systems without loop devices), CD and DVD images, and EROFS.
const EXCLUDED_FS: &[&str] = &[
    "tmpfs",
    "devtmpfs",
    "overlay",
    "squashfs",
    "proc",
    "sysfs",
    "fuse.snapfuse",
    "fuse.squashfuse",
    "iso9660",
    "udf",
    "erofs",
];
const EXCLUDED_MOUNT_ROOTS: &[&str] = &["/run", "/sys", "/proc", "/var/lib/docker"];
const EXCLUDED_IFACES: &[&str] = &["lo", "veth*", "tap*", "fwbr*", "fwpr*", "fwln*", "docker*", "br-*"];
const EXCLUDED_DEVICES: &[&str] = &["loop*", "ram*", "dm-*"];
/// Pseudo filesystems that have no space to report.
const NO_SPACE_FS: &[&str] = &[
    "cgroup",
    "cgroup2",
    "devpts",
    "mqueue",
    "securityfs",
    "pstore",
    "debugfs",
    "tracefs",
    "configfs",
    "fusectl",
    "bpf",
    "hugetlbfs",
    "autofs",
    "binfmt_misc",
    "nsfs",
    "rpc_pipefs",
    "fuse.lxcfs",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    pub watched_services: Vec<String>,
    /// Mount points to leave out, besides the defaults; a trailing `*` matches a prefix.
    pub extra_mount_excludes: Vec<String>,
    pub extra_iface_excludes: Vec<String>,
    pub per_core_cpu: bool,
    /// The most series a collection keeps (7.8.1); 0 means [`SERIES_CAP`].
    pub series_cap: usize,
}

impl Config {
    /// The series cap in use.
    pub fn series_cap(&self) -> usize {
        if self.series_cap == 0 { SERIES_CAP } else { self.series_cap }
    }
}

/// The probe's own use, measured by the caller.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SelfUse {
    pub rss_bytes: u64,
    pub cpu_pct: f64,
    pub buffer_bytes: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Series {
    pub metric: &'static str,
    pub unit: &'static str,
    pub labels: BTreeMap<&'static str, String>,
    pub value: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub kind: &'static str,
    pub detail: String,
}

/// The counters rates are computed from.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Snapshot {
    pub at_ms: i64,
    /// A monotonic clock reading, for the interval rates are computed over.
    pub mono_ms: i64,
    cpu: Option<CpuTimes>,
    cores: Vec<CpuTimes>,
    disks: BTreeMap<String, DiskCounters>,
    nets: BTreeMap<String, NetCounters>,
}

impl Snapshot {
    /// A snapshot with no counters, for a collector that reads rates the system already computed (Windows).
    #[cfg(windows)]
    pub(crate) fn at(at_ms: i64, mono_ms: i64) -> Snapshot {
        Snapshot { at_ms, mono_ms, ..Snapshot::default() }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Collection {
    pub series: Vec<Series>,
    pub services: Vec<ServiceState>,
    pub events: Vec<Event>,
    pub snapshot: Snapshot,
}

/// The machine's interfaces and their MACs, for the Hello (guest binding, 7.3.12): those `/sys/class/net` lists with a
/// MAC, without the loopback and the guests' and containers' own devices.
pub fn interfaces(host: &dyn Host) -> Vec<rackhand_proto::common::IfaceInfo> {
    let mut names = host.list("sys/class/net");
    names.sort();
    names
        .into_iter()
        .filter(|n| !matches(n, EXCLUDED_IFACES))
        .filter_map(|name| {
            let mac = host.read(&format!("sys/class/net/{name}/address"))?.trim().to_ascii_lowercase();
            let real = !mac.is_empty() && mac.chars().any(|c| c.is_ascii_hexdigit() && c != '0');
            real.then(|| rackhand_proto::common::IfaceInfo { name, mac, addrs: vec![] })
        })
        .collect()
}

pub(crate) fn matches(name: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == *p,
    })
}

fn under(path: &str, root: &str) -> bool {
    path == root || path.strip_prefix(root).is_some_and(|rest| rest.starts_with('/'))
}

pub(crate) struct Out {
    pub(crate) series: Vec<Series>,
}

impl Out {
    pub(crate) fn push(&mut self, metric: &'static str, label: Option<String>, value: f64) {
        let Some(m) = catalogue::by_name(metric) else { return };
        let labels = match (m.label, label) {
            (Some(k), Some(v)) => BTreeMap::from([(k, v)]),
            _ => BTreeMap::new(),
        };
        if value.is_finite() {
            self.series.push(Series { metric: m.name, unit: m.unit, labels, value });
        }
    }
}

pub(crate) fn pct(part: f64, whole: f64) -> f64 {
    if whole > 0.0 { 100.0 * part / whole } else { 0.0 }
}

fn per_second(delta: u64, dt_s: f64) -> f64 {
    if dt_s > 0.0 { delta as f64 / dt_s } else { 0.0 }
}

/// When a collection is taken: the wall clock (`sampled_at_ms`) and a monotonic clock (the interval for rates).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    pub wall_ms: i64,
    pub mono_ms: i64,
}

/// A collection at `now_ms`, with the wall clock standing in for the monotonic one.
pub fn collect(host: &dyn Host, prev: Option<&Snapshot>, now_ms: i64, cfg: &Config, self_use: SelfUse) -> Collection {
    collect_at(host, prev, Stamp { wall_ms: now_ms, mono_ms: now_ms }, cfg, self_use)
}

pub fn collect_at(host: &dyn Host, prev: Option<&Snapshot>, at: Stamp, cfg: &Config, self_use: SelfUse) -> Collection {
    let now_ms = at.wall_ms;
    let mut out = Out { series: Vec::new() };
    let mut events = Vec::new();
    let (cpu, cores) = host.read("proc/stat").map(|t| procfs::stat(&t)).unwrap_or_default();
    let disks: BTreeMap<String, DiskCounters> = host
        .read("proc/diskstats")
        .map(|t| procfs::diskstats(&t))
        .unwrap_or_default()
        .into_iter()
        .filter(|(d, _)| !matches(d, EXCLUDED_DEVICES))
        .collect();
    let iface_excludes: Vec<&str> =
        EXCLUDED_IFACES.iter().copied().chain(cfg.extra_iface_excludes.iter().map(String::as_str)).collect();
    let nets: BTreeMap<String, NetCounters> = host
        .read("proc/net/dev")
        .map(|t| procfs::net_dev(&t))
        .unwrap_or_default()
        .into_iter()
        .filter(|(i, _)| !matches(i, &iface_excludes))
        .collect();
    let snapshot = Snapshot { at_ms: now_ms, mono_ms: at.mono_ms, cpu, cores: cores.clone(), disks, nets };
    let ncores = cores.len().max(1) as f64;

    // CPU, from the change since the last snapshot.
    if let (Some(p), Some(c)) = (prev.and_then(|p| p.cpu), snapshot.cpu) {
        let total = c.total().saturating_sub(p.total()) as f64;
        out.push("cpu.busy_pct", None, pct(c.busy().saturating_sub(p.busy()) as f64, total));
        out.push("cpu.iowait_pct", None, pct(c.iowait.saturating_sub(p.iowait) as f64, total));
        out.push("cpu.steal_pct", None, pct(c.steal.saturating_sub(p.steal) as f64, total));
        if cfg.per_core_cpu {
            for (i, (pc, cc)) in prev.map(|p| p.cores.as_slice()).unwrap_or(&[]).iter().zip(&snapshot.cores).enumerate()
            {
                let t = cc.total().saturating_sub(pc.total()) as f64;
                out.push("cpu.core_busy_pct", Some(i.to_string()), pct(cc.busy().saturating_sub(pc.busy()) as f64, t));
            }
        }
    }
    // Load.
    if let Some(load) = host.read("proc/loadavg") {
        let v: Vec<f64> = load.split_whitespace().take(3).filter_map(|x| x.parse().ok()).collect();
        if let [l1, l5, l15] = v[..] {
            out.push("load.1m", None, l1);
            out.push("load.5m", None, l5);
            out.push("load.15m", None, l15);
            out.push("load.15m_per_core", None, l15 / ncores);
        }
    }
    memory(host, &mut out);
    disk_space(host, cfg, &mut out);
    // Disk I/O and network, as rates.
    let dt_s = prev.map(|p| (at.mono_ms - p.mono_ms) as f64 / 1000.0).unwrap_or(0.0);
    if let Some(p) = prev.filter(|_| dt_s > 0.0) {
        for (dev, c) in &snapshot.disks {
            let Some(o) = p.disks.get(dev) else { continue };
            let d = |a: u64, b: u64| a.saturating_sub(b);
            out.push("diskio.read_bps", Some(dev.clone()), per_second(d(c.sectors_read, o.sectors_read) * 512, dt_s));
            out.push(
                "diskio.write_bps",
                Some(dev.clone()),
                per_second(d(c.sectors_written, o.sectors_written) * 512, dt_s),
            );
            out.push("diskio.read_iops", Some(dev.clone()), per_second(d(c.reads, o.reads), dt_s));
            out.push("diskio.write_iops", Some(dev.clone()), per_second(d(c.writes, o.writes), dt_s));
            out.push(
                "diskio.busy_pct",
                Some(dev.clone()),
                pct(d(c.io_ticks_ms, o.io_ticks_ms) as f64, dt_s * 1000.0).min(100.0),
            );
        }
        for (iface, c) in &snapshot.nets {
            let Some(o) = p.nets.get(iface) else { continue };
            let d = |a: u64, b: u64| a.saturating_sub(b);
            out.push("net.rx_bps", Some(iface.clone()), per_second(d(c.rx_bytes, o.rx_bytes), dt_s));
            out.push("net.tx_bps", Some(iface.clone()), per_second(d(c.tx_bytes, o.tx_bytes), dt_s));
            out.push("net.rx_pps", Some(iface.clone()), per_second(d(c.rx_packets, o.rx_packets), dt_s));
            out.push("net.tx_pps", Some(iface.clone()), per_second(d(c.tx_packets, o.tx_packets), dt_s));
            out.push(
                "net.errors",
                Some(iface.clone()),
                (d(c.rx_errors, o.rx_errors) + d(c.tx_errors, o.tx_errors)) as f64,
            );
        }
    }
    if let Some(up) =
        host.read("proc/uptime").and_then(|t| t.split_whitespace().next().and_then(|v| v.parse::<f64>().ok()))
    {
        out.push("uptime_s", None, up);
    }
    for zone in host.list("sys/class/thermal") {
        let base = format!("sys/class/thermal/{zone}");
        let Some(milli) = host.read(&format!("{base}/temp")).and_then(|t| t.trim().parse::<f64>().ok()) else {
            continue;
        };
        let sensor = host.read(&format!("{base}/type")).map(|t| t.trim().to_string()).unwrap_or(zone);
        out.push("temp.c", Some(sensor), milli / 1000.0);
    }
    out.push("probe.rss_bytes", None, self_use.rss_bytes as f64);
    out.push("probe.cpu_pct", None, self_use.cpu_pct);
    out.push("probe.buffer_bytes", None, self_use.buffer_bytes as f64);
    let ephemeral = host
        .read("proc/sys/net/ipv4/ip_local_port_range")
        .and_then(|t| {
            let v: Vec<u16> = t.split_whitespace().filter_map(|x| x.parse().ok()).collect();
            Some((*v.first()?, *v.get(1)?))
        })
        .unwrap_or((32768, 60999));
    let outbound: u64 = ["proc/net/tcp", "proc/net/tcp6"]
        .iter()
        .filter_map(|f| host.read(f))
        .map(|t| procfs::outbound_tcp(&t, ephemeral))
        .sum();
    out.push("conn.outbound_count", None, outbound as f64);

    let mut series = out.series;
    // Host-wide series first, then the root mount, network and disk I/O, then the other mounts, so the cap keeps
    // the machine-level picture and drops extra mounts first (7.4.2).
    let rank = |s: &Series| -> u8 {
        match s.labels.get("mount").map(String::as_str) {
            None if s.labels.is_empty() => 0,
            Some("/") => 1,
            None => 2,
            Some(_) => 3,
        }
    };
    series.sort_by(|a, b| {
        let key = |s: &Series| {
            (rank(s), s.labels.values().next().cloned().unwrap_or_default(), catalogue::by_name(s.metric).map(|m| m.id))
        };
        key(a).cmp(&key(b))
    });
    let cap = cfg.series_cap();
    if series.len() > cap {
        events.push(Event { kind: "series_cap_reached", detail: format!("{} series, {cap} kept", series.len()) });
        series.truncate(cap);
    }
    Collection { series, services: services(host, cfg), events, snapshot }
}

/// Memory (S11): on a ZFS host the ARC above its minimum counts as available, unless lxcfs gives this container its
/// own `/proc/meminfo` (the host's ARC isn't the container's). Used is total minus available.
fn memory(host: &dyn Host, out: &mut Out) {
    let Some(mem) = host.read("proc/meminfo").map(|t| procfs::meminfo(&t)) else { return };
    let get = |k: &str| mem.get(k).copied().unwrap_or(0) as f64;
    let total = get("MemTotal");
    let virtualized = host.read("proc/mounts").is_some_and(|m| {
        procfs::mounts(&m).iter().any(|(_, point, kind)| point == "/proc/meminfo" && kind.starts_with("fuse"))
    });
    let arc = if virtualized {
        0.0
    } else {
        host.read("proc/spl/kstat/zfs/arcstats")
            .and_then(|t| procfs::arcstats(&t))
            .map_or(0.0, |(size, min)| size.saturating_sub(min) as f64)
    };
    let available = (get("MemAvailable") + arc).min(total);
    out.push("mem.available_bytes", None, available);
    out.push("mem.available_pct", None, pct(available, total));
    out.push("mem.used_bytes", None, total - available);
    out.push("mem.used_pct", None, pct(total - available, total));
    out.push("mem.cached_bytes", None, get("Cached"));
    let swap_total = get("SwapTotal");
    let swap_used = (swap_total - get("SwapFree")).max(0.0);
    out.push("swap.used_bytes", None, swap_used);
    out.push("swap.used_pct", None, pct(swap_used, swap_total));
}

fn disk_space(host: &dyn Host, cfg: &Config, out: &mut Out) {
    let Some(text) = host.read("proc/mounts") else { return };
    let extra: Vec<&str> = cfg.extra_mount_excludes.iter().map(String::as_str).collect();
    let mut seen = std::collections::BTreeSet::new();
    for (_, point, kind) in procfs::mounts(&text) {
        if EXCLUDED_FS.contains(&kind.as_str())
            || NO_SPACE_FS.contains(&kind.as_str())
            || EXCLUDED_MOUNT_ROOTS.iter().any(|r| under(&point, r))
            || matches(&point, &extra)
            || !seen.insert(point.clone())
        {
            continue;
        }
        let Some(fs) = host.statvfs(&point) else { continue };
        if fs.total_bytes == 0 {
            continue;
        }
        let used = fs.total_bytes.saturating_sub(fs.free_bytes) as f64;
        out.push("disk.used_bytes", Some(point.clone()), used);
        out.push("disk.total_bytes", Some(point.clone()), fs.total_bytes as f64);
        // As df reports it: used over what users can have.
        out.push("disk.used_pct", Some(point.clone()), pct(used, used + fs.avail_bytes as f64));
        out.push(
            "disk.inodes_used_pct",
            Some(point.clone()),
            pct(fs.files.saturating_sub(fs.files_free) as f64, fs.files as f64),
        );
    }
}

/// Failed units always, and the watched services whatever their state.
fn services(host: &dyn Host, cfg: &Config) -> Vec<ServiceState> {
    let unit = |n: &str| if n.contains('.') { n.to_string() } else { format!("{n}.service") };
    let units: BTreeMap<String, (String, String)> = host
        .units()
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            Some((p.first()?.trim_start_matches('●').to_string(), (p.get(1)?.to_string(), p.get(2)?.to_string())))
        })
        .collect();
    let enabled: BTreeMap<String, bool> = host
        .unit_files()
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            Some((p.first()?.to_string(), matches!(*p.get(1)?, "enabled" | "enabled-runtime" | "static" | "alias")))
        })
        .collect();
    let watched: Vec<String> = cfg.watched_services.iter().map(|w| unit(w)).collect();
    let mut names: Vec<String> =
        units.iter().filter(|(_, (_, active))| active == "failed").map(|(n, _)| n.clone()).collect();
    names.extend(watched);
    names.sort();
    names.dedup();
    names
        .into_iter()
        .map(|name| {
            let status = match units.get(&name).map(|(load, active)| (load.as_str(), active.as_str())) {
                Some((_, "active" | "reloading")) => ServiceStatus::Active,
                Some((_, "failed")) => ServiceStatus::Failed,
                Some((_, "activating")) => ServiceStatus::Activating,
                _ => ServiceStatus::Inactive,
            };
            ServiceState {
                enabled: enabled.get(&name).copied().unwrap_or(false),
                name,
                status: status as i32,
                since_ms: 0,
            }
        })
        .collect()
}

/// One collection as JSON, for `rackhand-probe collect --once --json`.
pub fn to_json(c: &Collection, sampled_at_ms: i64) -> serde_json::Value {
    let series: Vec<serde_json::Value> = c
        .series
        .iter()
        .map(|s| serde_json::json!({ "metric": s.metric, "unit": s.unit, "labels": s.labels, "value": s.value }))
        .collect();
    let services: Vec<serde_json::Value> = c
        .services
        .iter()
        .map(|s| {
            let status =
                ServiceStatus::try_from(s.status).map(|st| st.as_str_name()).unwrap_or("SERVICE_STATUS_UNSPECIFIED");
            serde_json::json!({ "name": s.name, "status": status, "enabled": s.enabled })
        })
        .collect();
    let events: Vec<serde_json::Value> =
        c.events.iter().map(|e| serde_json::json!({ "kind": e.kind, "detail": e.detail })).collect();
    serde_json::json!({ "sampled_at_ms": sampled_at_ms, "series": series, "services": services, "events": events })
}

/// The probe's own resident memory from `/proc/self/status`.
pub fn own_rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|t| {
            t.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        })
        .map_or(0, |kb| kb * 1024)
}

#[cfg(test)]
mod tests;
