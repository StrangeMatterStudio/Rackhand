//! Network namespaces for the network tier (design 14): a public segment, a relay on it, and two private sites that reach it
//! through NATs made with nftables. The test process is the public segment; each site and the relay run in a namespace of
//! their own.
//!
//! ```text
//!   rh-a (10.0.1.2) -- rh-nat-a (10.0.1.1 | 203.0.113.11) --+
//!                                                           |-- bridge rhpub (203.0.113.1) -- rh-relay (203.0.113.10)
//!   rh-b (10.0.2.2) -- rh-nat-b (10.0.2.1 | 203.0.113.12) --+
//! ```

use std::future::Future;
use std::os::fd::AsFd;
use std::process::Command;

use rustix::thread::{LinkNameSpaceType, move_into_link_name_space};

pub const RELAY_IP: &str = "203.0.113.10";
pub const A: &str = "rh-a";
pub const B: &str = "rh-b";
pub const RELAY: &str = "rh-relay";
/// The UDP port a hub that is forwarded listens on.
pub const FORWARDED_PORT: u16 = 40_000;

/// Runs a shell script as root; panics with its output if it fails.
pub fn sh(script: &str) {
    let out = Command::new("sh").arg("-c").arg(script).output().expect("sh runs");
    assert!(
        out.status.success(),
        "{script}\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// What a site's NAT does with a hub's UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nat {
    /// Masquerade: a new mapping for every destination. Two of these don't hole punch (S3).
    Symmetric,
    /// Masquerade plus a static forward of the hub's port: any host may reach the hub at the NAT's public address (S3).
    FullCone,
}

pub struct Lab;

fn site(tag: &str, n: u8, nat: Nat) -> String {
    let (nat_ns, lan_ns) = (format!("rh-nat-{tag}"), format!("rh-{tag}"));
    let forward = match nat {
        Nat::Symmetric => String::new(),
        Nat::FullCone => format!("iifname \"pub\" udp dport {FORWARDED_PORT} dnat to 10.0.{n}.2:{FORWARDED_PORT}"),
    };
    format!(
        "ip netns add {nat_ns}; ip netns add {lan_ns}
         ip link add rhn{tag} type veth peer name pub netns {nat_ns}
         ip link set rhn{tag} master rhpub up
         ip -n {nat_ns} addr add 203.0.113.{pub_host}/24 dev pub; ip -n {nat_ns} link set pub up; ip -n {nat_ns} link set lo up
         ip -n {nat_ns} link add lan type veth peer name eth0 netns {lan_ns}
         ip -n {nat_ns} addr add 10.0.{n}.1/24 dev lan; ip -n {nat_ns} link set lan up
         ip -n {lan_ns} addr add 10.0.{n}.2/24 dev eth0; ip -n {lan_ns} link set eth0 up; ip -n {lan_ns} link set lo up
         ip -n {lan_ns} route add default via 10.0.{n}.1
         ip netns exec {nat_ns} sysctl -qw net.ipv4.ip_forward=1
         ip netns exec {nat_ns} nft -f - <<'RULES'
table ip nat {{
  chain post {{
    type nat hook postrouting priority 100;
    oifname \"pub\" masquerade
  }}
  chain pre {{
    type nat hook prerouting priority -100;
    {forward}
  }}
}}
RULES
",
        pub_host = 10 + n,
    )
}

impl Lab {
    /// Brings the namespaces up; a hub in `rh-a` is behind `a`'s NAT and one in `rh-b` behind `b`'s.
    pub fn new(a: Nat, b: Nat) -> Lab {
        Lab::down();
        sh(&format!(
            "set -e
             ip link add rhpub type bridge; ip addr add 203.0.113.1/24 dev rhpub; ip link set rhpub up
             ip netns add {RELAY}
             ip link add rhrelay type veth peer name rhr1 netns {RELAY}
             ip link set rhrelay master rhpub up
             ip -n {RELAY} addr add {RELAY_IP}/24 dev rhr1; ip -n {RELAY} link set rhr1 up; ip -n {RELAY} link set lo up
             {}
             {}",
            site("a", 1, a),
            site("b", 2, b),
        ));
        Lab
    }

    fn down() {
        for ns in [RELAY, A, B, "rh-nat-a", "rh-nat-b"] {
            let _ = Command::new("ip").args(["netns", "del", ns]).output();
        }
        let _ = Command::new("ip").args(["link", "del", "rhpub"]).output();
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        Lab::down();
    }
}

/// A tokio runtime whose threads are in a namespace, so every socket made on it belongs to that namespace.
pub struct NsRuntime {
    handle: tokio::runtime::Handle,
    /// Dropping this ends the runtime's thread.
    _stop: std::sync::mpsc::Sender<()>,
}

impl NsRuntime {
    pub fn new(ns: &str) -> NsRuntime {
        let (handle_tx, handle_rx) = std::sync::mpsc::channel();
        let (stop, stopped) = std::sync::mpsc::channel::<()>();
        let ns = ns.to_string();
        std::thread::spawn(move || {
            let file = std::fs::File::open(format!("/var/run/netns/{ns}")).expect("the namespace exists");
            move_into_link_name_space(file.as_fd(), Some(LinkNameSpaceType::Network)).expect("setns");
            // built after setns, so its worker threads start in the namespace
            let rt =
                tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("a runtime");
            let _ = handle_tx.send(rt.handle().clone());
            let _ = stopped.recv();
            rt.shutdown_background();
        });
        NsRuntime { handle: handle_rx.recv().expect("the runtime started"), _stop: stop }
    }

    /// Runs a future on this runtime and returns what it gave.
    pub async fn run<T: Send + 'static>(&self, fut: impl Future<Output = T> + Send + 'static) -> T {
        self.handle.spawn(fut).await.expect("the task didn't panic")
    }

    pub fn spawn(&self, fut: impl Future<Output = ()> + Send + 'static) {
        self.handle.spawn(fut);
    }
}
