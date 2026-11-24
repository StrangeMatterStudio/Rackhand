//! A collection on Windows (FR-2): the vitals and services from CIM through one PowerShell line, parsed by
//! [`super::parse::wmi`], plus what the probe knows of itself and the number of outbound connections.

use super::{conntable, parse, ps};
use crate::collect::{Collection, Config, Event, Out, SelfUse, Series, Snapshot, Stamp};

/// One object with every key [`parse::wmi`] reads. The formatted performance classes give rates, so nothing here needs an
/// earlier collection.
const SCRIPT: &str = r#"$ErrorActionPreference = 'SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
[pscustomobject]@{
  os = [pscustomobject]@{
    TotalVisibleMemorySize = $os.TotalVisibleMemorySize
    FreePhysicalMemory = $os.FreePhysicalMemory
    UptimeS = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
  }
  cpu = @(Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor | Select-Object Name, PercentProcessorTime)
  disks = @(Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace, DriveType)
  net = @(Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface | Select-Object Name, BytesReceivedPersec, BytesSentPersec, PacketsReceivedPersec, PacketsSentPersec, PacketsReceivedErrors, PacketsOutboundErrors)
  physdisk = @(Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk | Select-Object Name, DiskReadBytesPersec, DiskWriteBytesPersec, DiskReadsPersec, DiskWritesPersec, PercentDiskTime)
  services = @(Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, ExitCode)
} | ConvertTo-Json -Depth 4 -Compress"#;

/// A collection at `at`. A machine whose CIM can't be read still reports what the probe knows of itself, and the error as an
/// event, so the hub sees a probe that is up and a machine it can't read.
pub async fn collect(at: Stamp, cfg: &Config, self_use: SelfUse) -> Collection {
    let mut out = Out { series: Vec::new() };
    let mut events = Vec::new();
    let mut services = Vec::new();
    match ps::run(SCRIPT).await.and_then(|json| parse::wmi::parse(&json, cfg)) {
        Ok(parsed) => {
            out.series = parsed.series;
            services = parsed.services;
        }
        Err(e) => events.push(Event { kind: "collect_failed", detail: e }),
    }
    out.push("probe.rss_bytes", None, self_use.rss_bytes as f64);
    out.push("probe.cpu_pct", None, self_use.cpu_pct);
    out.push("probe.buffer_bytes", None, self_use.buffer_bytes as f64);
    let outbound = conntable::read().iter().filter(|s| s.outbound()).count();
    out.push("conn.outbound_count", None, outbound as f64);
    let mut series: Vec<Series> = out.series;
    if series.len() > crate::collect::SERIES_CAP {
        events.push(Event {
            kind: "series_cap_reached",
            detail: format!("{} series, {} kept", series.len(), crate::collect::SERIES_CAP),
        });
        series.truncate(crate::collect::SERIES_CAP);
    }
    Collection { series, services, events, snapshot: Snapshot::at(at.wall_ms, at.mono_ms) }
}
