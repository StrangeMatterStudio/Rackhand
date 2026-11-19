//! Parsers for the `/proc` files the collectors read. Each takes the file's text and returns what it holds.

use std::collections::BTreeMap;

/// One `cpu` line of `/proc/stat`, in clock ticks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuTimes {
    pub fn total(&self) -> u64 {
        self.user + self.nice + self.system + self.idle + self.iowait + self.irq + self.softirq + self.steal
    }
    /// Time spent running work: user, nice, system, irq and softirq (guest time is inside user).
    pub fn busy(&self) -> u64 {
        self.user + self.nice + self.system + self.irq + self.softirq
    }
}

fn cpu_line(rest: &str) -> CpuTimes {
    let v: Vec<u64> = rest.split_whitespace().map(|x| x.parse().unwrap_or(0)).collect();
    let g = |i: usize| v.get(i).copied().unwrap_or(0);
    CpuTimes { user: g(0), nice: g(1), system: g(2), idle: g(3), iowait: g(4), irq: g(5), softirq: g(6), steal: g(7) }
}

/// The aggregate line and the per-core lines.
pub fn stat(text: &str) -> (Option<CpuTimes>, Vec<CpuTimes>) {
    let mut all = None;
    let mut cores = Vec::new();
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(char::is_whitespace) else { continue };
        if name == "cpu" {
            all = Some(cpu_line(rest));
        } else if name.strip_prefix("cpu").is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())) {
            cores.push(cpu_line(rest));
        }
    }
    (all, cores)
}

/// `/proc/meminfo` in bytes.
pub fn meminfo(text: &str) -> BTreeMap<String, u64> {
    text.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            let mut parts = v.split_whitespace();
            let n: u64 = parts.next()?.parse().ok()?;
            let bytes = if parts.next() == Some("kB") { n * 1024 } else { n };
            Some((k.trim().to_string(), bytes))
        })
        .collect()
}

/// The ARC's size and minimum from `/proc/spl/kstat/zfs/arcstats`.
pub fn arcstats(text: &str) -> Option<(u64, u64)> {
    let get = |key: &str| {
        text.lines().find_map(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            (p.len() == 3 && p[0] == key).then(|| p[2].parse::<u64>().ok()).flatten()
        })
    };
    Some((get("size")?, get("c_min")?))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiskCounters {
    pub reads: u64,
    pub sectors_read: u64,
    pub writes: u64,
    pub sectors_written: u64,
    pub io_ticks_ms: u64,
}

pub fn diskstats(text: &str) -> BTreeMap<String, DiskCounters> {
    text.lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            let n = |i: usize| p.get(i).and_then(|v| v.parse::<u64>().ok());
            Some((
                p.get(2)?.to_string(),
                DiskCounters {
                    reads: n(3)?,
                    sectors_read: n(5)?,
                    writes: n(7)?,
                    sectors_written: n(9)?,
                    io_ticks_ms: n(12)?,
                },
            ))
        })
        .collect()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetCounters {
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
}

pub fn net_dev(text: &str) -> BTreeMap<String, NetCounters> {
    text.lines()
        .filter_map(|l| {
            let (name, rest) = l.split_once(':')?;
            let v: Vec<u64> = rest.split_whitespace().map(|x| x.parse().unwrap_or(0)).collect();
            (v.len() >= 11).then(|| {
                (
                    name.trim().to_string(),
                    NetCounters {
                        rx_bytes: v[0],
                        rx_packets: v[1],
                        rx_errors: v[2],
                        tx_bytes: v[8],
                        tx_packets: v[9],
                        tx_errors: v[10],
                    },
                )
            })
        })
        .collect()
}

/// `(source, mount point, type)` from `/proc/mounts`, with octal escapes (`\040`) decoded.
pub fn mounts(text: &str) -> Vec<(String, String, String)> {
    let unescape = |s: &str| {
        let mut out = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let oct: String = chars.by_ref().take(3).collect();
                match u8::from_str_radix(&oct, 8) {
                    Ok(b) => out.push(b as char),
                    Err(_) => out.push_str(&oct),
                }
            } else {
                out.push(c);
            }
        }
        out
    };
    text.lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            Some((p.first()?.to_string(), unescape(p.get(1)?), p.get(2)?.to_string()))
        })
        .collect()
}

/// Established TCP connections whose local port is in the ephemeral range: connections this host opened.
pub fn outbound_tcp(text: &str, ephemeral: (u16, u16)) -> u64 {
    text.lines()
        .skip(1)
        .filter(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            let established = p.get(3) == Some(&"01");
            let port = p.get(1).and_then(|a| a.rsplit(':').next()).and_then(|h| u16::from_str_radix(h, 16).ok());
            established && port.is_some_and(|port| port >= ephemeral.0 && port <= ephemeral.1)
        })
        .count() as u64
}
