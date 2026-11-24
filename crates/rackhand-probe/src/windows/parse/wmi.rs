//! The vitals and services of a Windows machine (FR-2): one object the probe builds with a single PowerShell line from CIM
//! classes, so a collection costs one process start:
//!
//! | Key | Source |
//! | --- | --- |
//! | `os` | `Win32_OperatingSystem`: memory in KiB and `UptimeS` |
//! | `cpu` | `Win32_PerfFormattedData_PerfOS_Processor`: `_Total` and each core, as a percent |
//! | `disks` | `Win32_LogicalDisk` |
//! | `net` | `Win32_PerfFormattedData_Tcpip_NetworkInterface`, per second |
//! | `physdisk` | `Win32_PerfFormattedData_PerfDisk_PhysicalDisk`, per second |
//! | `services` | `Win32_Service` |
//!
//! The formatted classes already give rates, so a Windows collection needs no earlier one to compare with.

use std::collections::BTreeMap;

use rackhand_proto::probe::{ServiceState, ServiceStatus};
use serde::Deserialize;

use crate::collect::{Config, Out, Series, matches, pct};

/// Interfaces that are not a network a person would watch, as lower-case patterns with `*` at either end.
const EXCLUDED_IFACES: &[&str] = &["isatap*", "teredo*", "6to4*", "loopback*", "*pseudo-interface*", "wan miniport*"];

/// A PowerShell `ConvertTo-Json` list: absent, one object or an array.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Many<T> {
    Nothing(()),
    Several(Vec<T>),
    One(T),
}

fn many<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(match Many::<T>::deserialize(d)? {
        Many::Nothing(()) => Vec::new(),
        Many::Several(v) => v,
        Many::One(o) => vec![o],
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Os {
    total_visible_memory_size: f64,
    free_physical_memory: f64,
    #[serde(default)]
    uptime_s: Option<f64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Cpu {
    name: String,
    percent_processor_time: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Disk {
    #[serde(rename = "DeviceID")]
    device_id: String,
    size: Option<f64>,
    free_space: Option<f64>,
    drive_type: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Net {
    name: String,
    bytes_received_persec: f64,
    bytes_sent_persec: f64,
    packets_received_persec: f64,
    packets_sent_persec: f64,
    packets_received_errors: f64,
    packets_outbound_errors: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PhysDisk {
    name: String,
    disk_read_bytes_persec: f64,
    disk_write_bytes_persec: f64,
    disk_reads_persec: f64,
    disk_writes_persec: f64,
    percent_disk_time: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Service {
    name: String,
    state: String,
    start_mode: String,
    #[serde(default)]
    exit_code: i64,
}

#[derive(Debug, Deserialize)]
struct Recorded {
    os: Option<Os>,
    #[serde(default, deserialize_with = "many")]
    cpu: Vec<Cpu>,
    #[serde(default, deserialize_with = "many")]
    disks: Vec<Disk>,
    #[serde(default, deserialize_with = "many")]
    net: Vec<Net>,
    #[serde(default, deserialize_with = "many")]
    physdisk: Vec<PhysDisk>,
    #[serde(default, deserialize_with = "many")]
    services: Vec<Service>,
}

/// What a collection gives besides what the probe adds itself.
#[derive(Debug, Clone, PartialEq)]
pub struct Parsed {
    pub series: Vec<Series>,
    pub services: Vec<ServiceState>,
}

/// An automatic service that stopped with an error of its own: not 0 (a clean stop), and not 1077 ("no attempt to start it
/// was made since the last boot", which is what a service waiting for its trigger reports).
fn failed(s: &Service) -> bool {
    s.state == "Stopped" && s.start_mode == "Auto" && s.exit_code != 0 && s.exit_code != 1077
}

fn status(s: &Service) -> ServiceStatus {
    match s.state.as_str() {
        "Running" | "Continue Pending" | "Pause Pending" | "Paused" => ServiceStatus::Active,
        "Start Pending" => ServiceStatus::Activating,
        _ if failed(s) => ServiceStatus::Failed,
        _ => ServiceStatus::Inactive,
    }
}

/// The failing services always, and the watched ones whatever their state.
fn services(all: &[Service], cfg: &Config) -> Vec<ServiceState> {
    let by_name: BTreeMap<&str, &Service> = all.iter().map(|s| (s.name.as_str(), s)).collect();
    let mut names: Vec<&str> = all.iter().filter(|s| failed(s)).map(|s| s.name.as_str()).collect();
    names.extend(cfg.watched_services.iter().map(String::as_str));
    names.sort_unstable();
    names.dedup();
    names
        .into_iter()
        .map(|name| match by_name.get(name) {
            Some(s) => ServiceState {
                name: name.to_string(),
                status: status(s) as i32,
                enabled: s.start_mode == "Auto",
                since_ms: 0,
            },
            None => ServiceState {
                name: name.to_string(),
                status: ServiceStatus::Inactive as i32,
                enabled: false,
                since_ms: 0,
            },
        })
        .collect()
}

/// A name against patterns with `*` at either end, on an already lower-cased name.
fn matches_lower(lower: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| match (p.strip_prefix('*'), p.strip_suffix('*')) {
        (Some(_), Some(_)) => lower.contains(p.trim_matches('*')),
        (None, Some(prefix)) => lower.starts_with(prefix),
        (Some(suffix), None) => lower.ends_with(suffix),
        (None, None) => lower == *p,
    })
}

pub fn parse(json: &str, cfg: &Config) -> Result<Parsed, String> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    if !value.is_object() {
        return Err("the collection isn't an object".into());
    }
    let rec: Recorded = serde_json::from_value(value).map_err(|e| e.to_string())?;
    let mut out = Out { series: Vec::new() };
    if let Some(total) = rec.cpu.iter().find(|c| c.name == "_Total") {
        out.push("cpu.busy_pct", None, total.percent_processor_time);
    }
    if cfg.per_core_cpu {
        for core in rec.cpu.iter().filter(|c| c.name != "_Total" && c.name.bytes().all(|b| b.is_ascii_digit())) {
            out.push("cpu.core_busy_pct", Some(core.name.clone()), core.percent_processor_time);
        }
    }
    if let Some(os) = &rec.os {
        let (total, free) = (os.total_visible_memory_size * 1024.0, os.free_physical_memory * 1024.0);
        let used = (total - free).max(0.0);
        out.push("mem.available_bytes", None, free);
        out.push("mem.available_pct", None, pct(free, total));
        out.push("mem.used_bytes", None, used);
        out.push("mem.used_pct", None, pct(used, total));
        if let Some(up) = os.uptime_s {
            out.push("uptime_s", None, up);
        }
    }
    let mount_excludes: Vec<&str> = cfg.extra_mount_excludes.iter().map(String::as_str).collect();
    for d in rec.disks.iter().filter(|d| d.drive_type == 3) {
        let (Some(size), Some(free)) = (d.size, d.free_space) else { continue };
        if size <= 0.0 || matches(&d.device_id, &mount_excludes) {
            continue;
        }
        let used = (size - free).max(0.0);
        out.push("disk.used_bytes", Some(d.device_id.clone()), used);
        out.push("disk.total_bytes", Some(d.device_id.clone()), size);
        out.push("disk.used_pct", Some(d.device_id.clone()), pct(used, size));
    }
    let iface_excludes: Vec<&str> = cfg.extra_iface_excludes.iter().map(String::as_str).collect();
    for n in &rec.net {
        if matches_lower(&n.name.to_lowercase(), EXCLUDED_IFACES) || matches(&n.name, &iface_excludes) {
            continue;
        }
        out.push("net.rx_bps", Some(n.name.clone()), n.bytes_received_persec);
        out.push("net.tx_bps", Some(n.name.clone()), n.bytes_sent_persec);
        out.push("net.rx_pps", Some(n.name.clone()), n.packets_received_persec);
        out.push("net.tx_pps", Some(n.name.clone()), n.packets_sent_persec);
        out.push("net.errors", Some(n.name.clone()), n.packets_received_errors + n.packets_outbound_errors);
    }
    for d in rec.physdisk.iter().filter(|d| d.name != "_Total") {
        out.push("diskio.read_bps", Some(d.name.clone()), d.disk_read_bytes_persec);
        out.push("diskio.write_bps", Some(d.name.clone()), d.disk_write_bytes_persec);
        out.push("diskio.read_iops", Some(d.name.clone()), d.disk_reads_persec);
        out.push("diskio.write_iops", Some(d.name.clone()), d.disk_writes_persec);
        out.push("diskio.busy_pct", Some(d.name.clone()), d.percent_disk_time.min(100.0));
    }
    Ok(Parsed { series: out.series, services: services(&rec.services, cfg) })
}
