//! What the probe reports about connections and what is new on the machine (7.3.2, FR-4, FR-5, D17, D103, D196): every
//! 5 seconds the connection tables are read, the owner of each socket (executable, user, container) is asked of the
//! root helper by inode, and what was seen is kept per `(container, exe, dest_ip, dest_port, proto)` until the next report.
//! With the eBPF capture its maps are drained at the same reads and add every connect and send, however short, and
//! every start from a temporary directory; the tables are still read as without it, so a connection opened before the
//! capture was attached, or open across reads, is reported as before.

pub mod aggregate;
pub mod capability;
pub mod conntable;
pub mod ebpf;
#[cfg(target_os = "linux")]
pub mod feed;
pub mod listeners;
pub mod signals;

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use rackhand_proto::probe::{ConnRecord, ProbeEvent};

use crate::collect::Host;
use crate::helper::client::HelperClient;

/// How often the connection tables are read.
pub const EVERY: Duration = Duration::from_secs(5);

/// Who owns a socket, as the helper says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Owner {
    pub exe: String,
    pub user: String,
    pub pid: u32,
    /// The container's name, empty for a host process.
    pub container: String,
}

/// The eBPF capture's maps (Linux).
#[cfg(target_os = "linux")]
pub use ebpf::Capture as Captured;
/// There is no eBPF capture off Linux.
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub enum Captured {}

/// How many reads between asking the helper for the capture again (5 minutes): a helper that restarted has new maps.
#[cfg(target_os = "linux")]
const ASK_AGAIN_EVERY: u64 = 60;
/// The most cgroup ids kept named.
#[cfg(target_os = "linux")]
const MAX_CGROUPS: usize = 4096;

/// The capture's state between reads.
#[derive(Debug, Default)]
pub struct Sampler {
    listeners: listeners::Listeners,
    execs: listeners::TempExecs,
    owners: HashMap<u64, Owner>,
    signals: signals::Signals,
    ticks: u64,
    capture: Option<Captured>,
    /// The cgroup ids the helper named, a container's name or empty for none.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    cgroups: HashMap<u64, String>,
}

/// What the reads have seen since the last report. Reads take their time (they ask the helper), so a report never waits on
/// one: it takes what is here.
#[derive(Debug, Default)]
pub struct Pending {
    window: aggregate::Window,
    events: Vec<ProbeEvent>,
}

impl Pending {
    pub fn add(&mut self, seen: Vec<aggregate::Observed>, events: Vec<ProbeEvent>) {
        for o in seen {
            self.window.add(o);
        }
        self.events.extend(events);
    }

    /// The connection records (at most `max_tuples` with a destination) and the events for the next report.
    pub fn take(&mut self, at_ms: i64, max_tuples: usize) -> (Vec<ConnRecord>, Vec<ProbeEvent>) {
        let (records, overflow) = self.window.take(at_ms, max_tuples);
        let mut events = std::mem::take(&mut self.events);
        events.extend(overflow);
        (records, events)
    }
}

impl Sampler {
    /// A sampler reading `capture`'s maps for connections and starts, or the tables when there is none.
    pub fn new(capture: Option<Captured>) -> Sampler {
        Sampler { capture, ..Sampler::default() }
    }

    /// Whether connections come from the eBPF capture.
    pub fn capturing(&self) -> bool {
        self.capture.is_some()
    }

    /// Names the cgroup ids not named yet, by the helper; nothing is kept when it doesn't answer.
    #[cfg(target_os = "linux")]
    async fn name_cgroups(&mut self, conns: &[ebpf::Conn], helper: Option<&HelperClient>) {
        let unknown: BTreeSet<u64> = conns.iter().map(|c| c.cgroup).filter(|g| !self.cgroups.contains_key(g)).collect();
        let (false, Some(helper)) = (unknown.is_empty(), helper) else { return };
        let ids: Vec<u64> = unknown.into_iter().take(1024).collect();
        let Ok(names) = helper.container_of(&ids).await else { return };
        if self.cgroups.len() + ids.len() > MAX_CGROUPS {
            self.cgroups.clear();
        }
        for id in ids {
            self.cgroups.insert(id, String::new());
        }
        self.cgroups.extend(names);
    }

    /// Asks the helper for the capture again; new maps (a restarted helper's) replace the old ones.
    #[cfg(target_os = "linux")]
    async fn ask_again(&mut self, helper: Option<&HelperClient>) {
        let (Some(old), Some(helper)) = (self.capture.as_ref(), helper) else { return };
        if let Ok(new) = helper.ebpf_capture().await {
            if !old.same_maps(&new) {
                tracing::info!("the helper passed new eBPF maps (it restarted)");
                self.capture = Some(new);
            }
        }
    }

    /// One read of the tables. Owners are asked of the helper (when there is one) for the sockets not yet known.
    pub async fn tick(
        &mut self,
        host: &(dyn Host + Send + Sync),
        helper: Option<&HelperClient>,
        now_ms: i64,
    ) -> (Vec<aggregate::Observed>, Vec<ProbeEvent>) {
        let (mut seen, mut events) = (Vec::new(), Vec::new());
        #[cfg(target_os = "linux")]
        let drained = self.capture.as_mut().map(|c| c.drain());
        #[cfg(not(windows))]
        let sockets = conntable::read(host);
        // Windows has no /proc: the tables come from GetExtendedTcpTable and GetExtendedUdpTable (FR-4)
        #[cfg(windows)]
        let sockets = {
            let _ = host;
            crate::windows::conntable::read()
        };
        let interesting = |s: &&conntable::Socket| s.outbound() || s.listening();
        let present: BTreeSet<u64> = sockets.iter().filter(interesting).map(|s| s.inode).collect();
        let wanted: Vec<u64> = present.iter().copied().filter(|i| !self.owners.contains_key(i)).take(4096).collect();
        if let (false, Some(helper)) = (wanted.is_empty(), helper) {
            let found = helper.socket_owners(&wanted).await.unwrap_or_default();
            for o in found {
                let owner = Owner { exe: o.exe, user: o.user, pid: o.pid, container: o.container.unwrap_or_default() };
                self.owners.insert(o.inode, owner);
            }
            // a socket the helper didn't find is gone, or isn't anyone's: not asked about again until it changes
            for inode in wanted {
                self.owners.entry(inode).or_default();
            }
        }
        #[cfg(target_os = "linux")]
        if let Some((conns, execs)) = drained {
            self.name_cgroups(&conns, helper).await;
            let exes: HashMap<u32, String> = self
                .owners
                .values()
                .filter(|o| o.pid != 0 && !o.exe.is_empty())
                .map(|o| (o.pid, o.exe.clone()))
                .collect();
            let passwd = host.read("etc/passwd").unwrap_or_default();
            let names = feed::Names { containers: &self.cgroups, exes: &exes, passwd: &passwd };
            seen.extend(feed::observed(&conns, names));
            let (started, pids) = feed::exec_events(&execs, &passwd, now_ms);
            events.extend(started);
            self.execs.captured(&pids);
        }
        for s in sockets.iter().filter(|s| s.outbound()) {
            let o = self.owners.get(&s.inode).cloned().unwrap_or_default();
            seen.push(aggregate::Observed {
                container: o.container,
                exe: o.exe,
                user: o.user,
                pid: o.pid,
                dest: s.remote,
                port: s.remote_port,
                proto: s.proto,
                inode: s.inode,
                count: 0,
                bytes: 0,
            });
        }
        let owners = &self.owners;
        let owner_of = |inode: u64| owners.get(&inode).map(|o| (o.exe.clone(), o.user.clone()));
        events.extend(self.listeners.observe(&sockets, now_ms, &owner_of));
        if let Some(helper) = helper {
            if let Ok(scan) = helper.process_scan().await {
                events.extend(self.execs.observe(&scan, now_ms));
            }
        }
        self.owners.retain(|inode, _| present.contains(inode));
        // the helper's file hashes and authentication events, every third read (15 seconds)
        if let (0, Some(helper)) = (self.ticks % 3, helper) {
            events.extend(self.signals.poll(helper, now_ms).await);
        }
        #[cfg(target_os = "linux")]
        if self.ticks % ASK_AGAIN_EVERY == ASK_AGAIN_EVERY - 1 {
            self.ask_again(helper).await;
        }
        self.ticks += 1;
        (seen, events)
    }
}
