//! The metric catalogue (7.4.2): each metric's wire id, unit and label key. `Sample.metric` carries the id; ids never
//! change meaning, and new metrics take new ids.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metric {
    pub id: u32,
    pub name: &'static str,
    pub unit: &'static str,
    /// The one label the metric's series are told apart by, if any.
    pub label: Option<&'static str>,
}

const fn m(id: u32, name: &'static str, unit: &'static str, label: Option<&'static str>) -> Metric {
    Metric { id, name, unit, label }
}

pub const METRICS: &[Metric] = &[
    m(1, "cpu.busy_pct", "%", None),
    m(2, "cpu.iowait_pct", "%", None),
    m(3, "cpu.steal_pct", "%", None),
    m(4, "cpu.core_busy_pct", "%", Some("core")),
    m(5, "load.1m", "ratio", None),
    m(6, "load.5m", "ratio", None),
    m(7, "load.15m", "ratio", None),
    m(8, "load.15m_per_core", "ratio", None),
    m(9, "mem.used_bytes", "bytes", None),
    m(10, "mem.used_pct", "%", None),
    m(11, "mem.available_bytes", "bytes", None),
    m(12, "mem.available_pct", "%", None),
    m(13, "mem.cached_bytes", "bytes", None),
    m(14, "swap.used_bytes", "bytes", None),
    m(15, "swap.used_pct", "%", None),
    m(16, "disk.used_bytes", "bytes", Some("mount")),
    m(17, "disk.total_bytes", "bytes", Some("mount")),
    m(18, "disk.used_pct", "%", Some("mount")),
    m(19, "disk.inodes_used_pct", "%", Some("mount")),
    m(20, "diskio.read_bps", "B/s", Some("device")),
    m(21, "diskio.write_bps", "B/s", Some("device")),
    m(22, "diskio.read_iops", "ops/s", Some("device")),
    m(23, "diskio.write_iops", "ops/s", Some("device")),
    m(24, "diskio.busy_pct", "%", Some("device")),
    m(25, "net.rx_bps", "B/s", Some("iface")),
    m(26, "net.tx_bps", "B/s", Some("iface")),
    m(27, "net.rx_pps", "pkts/s", Some("iface")),
    m(28, "net.tx_pps", "pkts/s", Some("iface")),
    m(29, "net.errors", "count", Some("iface")),
    m(30, "uptime_s", "s", None),
    m(31, "temp.c", "Celsius", Some("sensor")),
    m(32, "probe.rss_bytes", "bytes", None),
    m(33, "probe.cpu_pct", "%", None),
    m(34, "probe.buffer_bytes", "bytes", None),
    m(35, "conn.outbound_count", "count per interval", None),
];

pub fn by_name(name: &str) -> Option<&'static Metric> {
    METRICS.iter().find(|m| m.name == name)
}

pub fn by_id(id: u32) -> Option<&'static Metric> {
    METRICS.iter().find(|m| m.id == id)
}
