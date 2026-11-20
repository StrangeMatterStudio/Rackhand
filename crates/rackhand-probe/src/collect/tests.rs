use std::collections::BTreeSet;
use std::path::PathBuf;

use rackhand_proto::catalogue::{self, METRICS};
use rackhand_proto::probe::ServiceStatus;

use super::{Collection, Config, RootHost, SelfUse, collect};

fn fixture(case: &str, snap: &str) -> RootHost {
    RootHost::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/proc").join(case).join(snap))
}

/// Two snapshots 10 seconds apart; the second collection.
fn two(case: &str, cfg: &Config) -> Collection {
    let first = collect(&fixture(case, "a"), None, 0, cfg, SelfUse::default());
    collect(&fixture(case, "b"), Some(&first.snapshot), 10_000, cfg, SelfUse::default())
}

fn value(c: &Collection, metric: &str, label: Option<&str>) -> Option<f64> {
    c.series
        .iter()
        .find(|s| s.metric == metric && s.labels.values().next().map(String::as_str) == label)
        .map(|s| s.value)
}

fn labels_of(c: &Collection, metric: &str) -> BTreeSet<String> {
    c.series.iter().filter(|s| s.metric == metric).filter_map(|s| s.labels.values().next().cloned()).collect()
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-6 * b.abs().max(1.0)
}

#[test]
fn every_catalogue_metric_from_debian_fixture() {
    let c = two("debian-vm", &Config::default());
    // Every Linux metric except temp.c (the VM has no sensor) and the per-core one (off by default).
    for m in METRICS.iter().filter(|m| m.name != "temp.c" && m.name != "cpu.core_busy_pct") {
        let series: Vec<_> = c.series.iter().filter(|s| s.metric == m.name).collect();
        assert!(!series.is_empty(), "{} missing", m.name);
        for s in series {
            assert_eq!(s.unit, m.unit, "{}", m.name);
            assert_eq!(
                s.labels.keys().copied().collect::<Vec<_>>(),
                m.label.into_iter().collect::<Vec<_>>(),
                "{}",
                m.name
            );
            assert!(s.value.is_finite(), "{} = {}", m.name, s.value);
        }
    }
    assert!(labels_of(&c, "disk.used_pct").contains("/"));
    // The other captured systems give the host metrics too.
    for case in ["alpine-lxc", "proxmox-zfs"] {
        let c = two(case, &Config::default());
        for name in
            ["cpu.busy_pct", "load.15m_per_core", "mem.available_pct", "disk.used_pct", "net.rx_bps", "uptime_s"]
        {
            assert!(c.series.iter().any(|s| s.metric == name), "{case}: {name}");
        }
    }
    assert!(catalogue::by_name("cpu.busy_pct").is_some_and(|m| catalogue::by_id(m.id) == Some(m)));
}

#[test]
fn rates_from_two_snapshots() {
    let c = two("rates", &Config::default());
    // CPU deltas: user 200, system 100, idle 600, iowait 50, steal 50 of 1000.
    assert!(close(value(&c, "cpu.busy_pct", None).unwrap(), 30.0));
    assert!(close(value(&c, "cpu.iowait_pct", None).unwrap(), 5.0));
    assert!(close(value(&c, "cpu.steal_pct", None).unwrap(), 5.0));
    assert!(close(value(&c, "load.15m_per_core", None).unwrap(), 1.5), "3.00 over 2 cores");
    // sda over 10 s: 50 reads, 2000 sectors read, 100 writes, 4000 sectors written, 500 ms busy.
    assert!(close(value(&c, "diskio.read_iops", Some("sda")).unwrap(), 5.0));
    assert!(close(value(&c, "diskio.write_iops", Some("sda")).unwrap(), 10.0));
    assert!(close(value(&c, "diskio.read_bps", Some("sda")).unwrap(), 102_400.0));
    assert!(close(value(&c, "diskio.write_bps", Some("sda")).unwrap(), 204_800.0));
    assert!(close(value(&c, "diskio.busy_pct", Some("sda")).unwrap(), 5.0));
    // eth0 over 10 s: 10000 bytes and 100 packets in, 50000 bytes and 200 packets out, 3 new errors.
    assert!(close(value(&c, "net.rx_bps", Some("eth0")).unwrap(), 1_000.0));
    assert!(close(value(&c, "net.tx_bps", Some("eth0")).unwrap(), 5_000.0));
    assert!(close(value(&c, "net.rx_pps", Some("eth0")).unwrap(), 10.0));
    assert!(close(value(&c, "net.tx_pps", Some("eth0")).unwrap(), 20.0));
    assert!(close(value(&c, "net.errors", Some("eth0")).unwrap(), 3.0));
    // Memory and disk from one snapshot.
    assert!(close(value(&c, "mem.available_pct", None).unwrap(), 25.0));
    assert!(close(value(&c, "mem.used_pct", None).unwrap(), 75.0));
    assert!(close(value(&c, "mem.cached_bytes", None).unwrap(), 3_072_000_000.0));
    assert!(close(value(&c, "swap.used_pct", None).unwrap(), 25.0));
    // `/`: 60 GB used, 35 GB available to users (df's used / (used + available)), 25% of inodes.
    assert!(close(value(&c, "disk.used_bytes", Some("/")).unwrap(), 60e9));
    assert!(close(value(&c, "disk.used_pct", Some("/")).unwrap(), 100.0 * 60.0 / 95.0));
    assert!(close(value(&c, "disk.inodes_used_pct", Some("/")).unwrap(), 25.0));
    assert!(close(value(&c, "uptime_s", None).unwrap(), 1010.0));
    assert!(close(value(&c, "temp.c", Some("x86_pkg_temp")).unwrap(), 45.5));
    assert!(close(value(&c, "conn.outbound_count", None).unwrap(), 2.0), "two established from ephemeral ports");
    // The first collection has no rates yet.
    let first = collect(&fixture("rates", "a"), None, 0, &Config::default(), SelfUse::default());
    assert!(value(&first, "cpu.busy_pct", None).is_none() && value(&first, "net.rx_bps", Some("eth0")).is_none());
}

#[test]
fn excluded_mounts_interfaces_and_devices_skipped() {
    let c = two("rates", &Config::default());
    assert_eq!(labels_of(&c, "disk.used_pct"), BTreeSet::from(["/".to_string(), "/srv".to_string()]));
    assert_eq!(labels_of(&c, "net.rx_bps"), BTreeSet::from(["eth0".to_string(), "vmbr0".to_string()]));
    assert_eq!(labels_of(&c, "diskio.read_bps"), BTreeSet::from(["sda".to_string()]));
    let cfg = Config {
        extra_mount_excludes: vec!["/srv".into()],
        extra_iface_excludes: vec!["vmbr*".into()],
        ..Config::default()
    };
    let c = two("rates", &cfg);
    assert_eq!(labels_of(&c, "disk.used_pct"), BTreeSet::from(["/".to_string()]), "configured exclusions too");
    assert_eq!(labels_of(&c, "net.rx_bps"), BTreeSet::from(["eth0".to_string()]));
    // The captured Proxmox host keeps vmbr0 and drops the guests' tap and veth devices.
    let pve = two("proxmox-zfs", &Config::default());
    let ifaces = labels_of(&pve, "net.rx_bps");
    assert!(ifaces.contains("vmbr0"), "{ifaces:?}");
    assert!(!ifaces.iter().any(|i| i.starts_with("tap") || i.starts_with("veth") || i == "lo"), "{ifaces:?}");
}

#[test]
fn series_cap_drops_extra_and_raises_event() {
    let c = two("mounts-300", &Config::default());
    assert_eq!(c.series.len(), 200);
    let events: Vec<_> = c.events.iter().filter(|e| e.kind == "series_cap_reached").collect();
    assert_eq!(events.len(), 1, "{:?}", c.events);
    // Host-wide metrics are kept before per-mount ones.
    assert!(value(&c, "cpu.busy_pct", None).is_some() && value(&c, "mem.available_pct", None).is_some());
    assert!(value(&c, "disk.used_pct", Some("/")).is_some(), "the root mount sorts first");
    let under = two("rates", &Config::default());
    assert!(under.events.iter().all(|e| e.kind != "series_cap_reached"));
}

#[test]
fn series_cap_keeps_net_and_diskio_before_extra_mounts() {
    let c = two("mounts-300", &Config::default());
    assert_eq!(c.series.len(), 200);
    // network and disk I/O are machine-wide pictures; the extra mounts are what the cap drops
    for (metric, label) in
        [("net.rx_bps", "eth0"), ("net.tx_bps", "vmbr0"), ("diskio.read_bps", "sda"), ("diskio.busy_pct", "sda")]
    {
        assert!(value(&c, metric, Some(label)).is_some(), "{metric} {label} kept");
    }
    assert!(value(&c, "disk.used_pct", Some("/")).is_some(), "the root mount is kept too");
}

fn kib(text: &str, key: &str) -> f64 {
    text.lines()
        .find(|l| l.starts_with(&format!("{key}:")))
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap()
        .parse::<f64>()
        .unwrap()
        * 1024.0
}

fn arc(text: &str, key: &str) -> f64 {
    text.lines()
        .find_map(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            (p.len() == 3 && p[0] == key).then(|| p[2].parse::<f64>().unwrap())
        })
        .unwrap()
}

#[test]
fn zfs_arc_counted_as_available() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/proc/proxmox-zfs/b/proc");
    let meminfo = std::fs::read_to_string(dir.join("meminfo")).unwrap();
    let arcstats = std::fs::read_to_string(dir.join("spl/kstat/zfs/arcstats")).unwrap();
    let total = kib(&meminfo, "MemTotal");
    let available = kib(&meminfo, "MemAvailable") + (arc(&arcstats, "size") - arc(&arcstats, "c_min")).max(0.0);
    let c = two("proxmox-zfs", &Config::default());
    assert!(close(value(&c, "mem.available_bytes", None).unwrap(), available));
    assert!(close(value(&c, "mem.available_pct", None).unwrap(), 100.0 * available / total));
    assert!(close(value(&c, "mem.used_bytes", None).unwrap(), total - available), "used is total minus available");
    // In an LXC, lxcfs gives the container's own memory and the host's ARC isn't the container's.
    let lxc = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/proc/alpine-lxc/b/proc/meminfo");
    let lxc_meminfo = std::fs::read_to_string(lxc).unwrap();
    let c = two("alpine-lxc", &Config::default());
    assert!(close(value(&c, "mem.available_bytes", None).unwrap(), kib(&lxc_meminfo, "MemAvailable")));
}

#[test]
fn failed_units_and_watched_services_reported() {
    let cfg =
        Config { watched_services: vec!["ssh".into(), "nginx.service".into(), "missing".into()], ..Config::default() };
    let c = two("rates", &cfg);
    let states: Vec<(String, ServiceStatus, bool)> =
        c.services.iter().map(|s| (s.name.clone(), ServiceStatus::try_from(s.status).unwrap(), s.enabled)).collect();
    assert_eq!(
        states,
        [
            ("missing.service".to_string(), ServiceStatus::Inactive, false),
            ("nginx.service".to_string(), ServiceStatus::Failed, true),
            ("ssh.service".to_string(), ServiceStatus::Active, true),
        ]
    );
    // Without watched services, failed units are still reported.
    let c = two("rates", &Config::default());
    let names: Vec<&str> = c.services.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["nginx.service"]);
}
