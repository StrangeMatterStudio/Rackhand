//! `run quarantine on <hub-address>... | off` (7.5.6, D104): an in-guest quarantine on a managed Linux machine. `on` loads one
//! nftables table, `rackhand_quarantine`, whose input and output chains drop everything except DHCP, the guest's QUIC
//! connection to the hub, and the hub's SSH and ping to the guest; `off` deletes that table and nothing else. The rules name
//! both directions of each allowed path (no connection tracking), so a connection that was open before the quarantine and
//! isn't one of those is cut at once; conntrack is flushed too when its tool is there.
//!
//! Hub addresses are `ip:port` or `[ipv6]:port` and nothing else, so no other text reaches nft. The table is advisory
//! against an attacker with root on the machine (the hypervisor's firewall is the enforced one); the dashboard says so.

use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::process::{Command, ExitCode, Stdio};

pub const TABLE: &str = "inet rackhand_quarantine";
const MAX_HUBS: usize = 16;

/// What the wrapper needs from the machine.
pub trait Host {
    /// Loads an nft script atomically.
    fn nft(&self, script: &str) -> Result<(), String>;
    /// Flushes the connection tracking table; whether there was a tool to do it.
    fn flush_conntrack(&self) -> bool;
}

/// `nft` and `conntrack` as the system has them.
#[derive(Debug)]
pub struct System;

const PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

impl Host for System {
    fn nft(&self, script: &str) -> Result<(), String> {
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .env_clear()
            .env("PATH", PATH)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("couldn't run nft: {e}"))?;
        if let Some(mut input) = child.stdin.take() {
            input.write_all(script.as_bytes()).map_err(|e| format!("couldn't write to nft: {e}"))?;
        }
        let out = child.wait_with_output().map_err(|e| format!("nft: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    fn flush_conntrack(&self) -> bool {
        Command::new("conntrack")
            .arg("-F")
            .env_clear()
            .env("PATH", PATH)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}

/// The hub's addresses from the command line, each `ip:port`.
pub fn parse_hubs(args: &[String]) -> Result<Vec<SocketAddr>, String> {
    if args.is_empty() || args.len() > MAX_HUBS {
        return Err(format!("quarantine on takes one to {MAX_HUBS} hub addresses, each ip:port"));
    }
    args.iter()
        .map(|a| {
            let addr: SocketAddr = a.parse().map_err(|_| format!("`{a}` isn't an ip:port"))?;
            let ip = addr.ip();
            let usable = !(ip.is_unspecified() || ip.is_multicast() || ip == IpAddr::from([255, 255, 255, 255]));
            if addr.port() == 0 || !usable {
                return Err(format!("`{a}` isn't a hub's address"));
            }
            Ok(addr)
        })
        .collect()
}

/// The script `on` loads: the table is replaced as one transaction.
pub fn ruleset(hubs: &[SocketAddr]) -> String {
    let mut input = String::new();
    let mut output = String::new();
    for hub in hubs {
        let (ip, port) = (hub.ip(), hub.port());
        let (family, icmp, request, reply) = match ip {
            IpAddr::V4(_) => ("ip", "icmp", "echo-request", "echo-reply"),
            IpAddr::V6(_) => ("ip6", "icmpv6", "echo-request", "echo-reply"),
        };
        input.push_str(&format!("    {family} saddr {ip} tcp dport 22 accept\n"));
        input.push_str(&format!("    {family} saddr {ip} {icmp} type {request} accept\n"));
        input.push_str(&format!("    {family} saddr {ip} udp sport {port} accept\n"));
        output.push_str(&format!("    {family} daddr {ip} udp dport {port} accept\n"));
        output.push_str(&format!("    {family} daddr {ip} tcp sport 22 accept\n"));
        output.push_str(&format!("    {family} daddr {ip} {icmp} type {reply} accept\n"));
    }
    // v4 rules first, then v6, each in the order given
    let sorted = |text: &str| -> String {
        let (v4, v6): (Vec<&str>, Vec<&str>) = text.lines().partition(|l| l.trim_start().starts_with("ip "));
        v4.into_iter().chain(v6).map(|l| format!("{l}\n")).collect()
    };
    let mut out = format!("add table {TABLE}
delete table {TABLE}
table {TABLE} {{
");
    out.push_str("  chain input {
    type filter hook input priority -300; policy drop;
");
    out.push_str("    iifname \"lo\" accept
    udp sport 67 udp dport 68 accept
");
    out.push_str(&sorted(&input));
    out.push_str("  }
  chain output {
    type filter hook output priority -300; policy drop;
");
    out.push_str("    oifname \"lo\" accept
    udp sport 68 udp dport 67 accept
");
    out.push_str(&sorted(&output));
    out.push_str("  }
}
");
    out
}

/// The script `off` loads: our table, whether or not it is there, deleted.
pub fn off_script() -> String {
    format!("add table {TABLE}\ndelete table {TABLE}\n")
}

pub fn on(host: &dyn Host, args: &[String]) -> Result<String, String> {
    let hubs = parse_hubs(args)?;
    host.nft(&ruleset(&hubs))?;
    let flushed = if host.flush_conntrack() { "conntrack flushed" } else { "conntrack not flushed" };
    Ok(format!("quarantine on: {} hub address(es), {flushed}", hubs.len()))
}

pub fn off(host: &dyn Host) -> Result<String, String> {
    host.nft(&off_script())?;
    Ok("quarantine off: the rackhand_quarantine table is removed".into())
}

/// `run quarantine on <hub-address>... | off`.
pub fn main(args: &[String]) -> ExitCode {
    let result = match args.first().map(String::as_str) {
        Some("on") => on(&System, &args[1..]),
        Some("off") if args.len() == 1 => off(&System),
        _ => Err("usage: quarantine on <ip:port>... | quarantine off".into()),
    };
    match result {
        Ok(said) => {
            println!("{said}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("run: quarantine: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
#[path = "quarantine_tests.rs"]
mod tests;
