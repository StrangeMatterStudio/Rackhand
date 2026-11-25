//! What the probe reports about connections and what is new on the machine, without eBPF (7.3.2, FR-4, FR-5, D17, D103):
//! every 5 seconds the connection tables are read, the owner of each socket (executable, user, container) is asked of the
//! root helper by inode, and what was seen is kept per `(container, exe, dest_ip, dest_port, proto)` until the next report.

pub mod aggregate;
pub mod capability;
pub mod conntable;
pub mod ebpf;
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

/// The sampling capture's state between reads.
#[derive(Debug, Default)]
pub struct Sampler {
    listeners: listeners::Listeners,
    execs: listeners::TempExecs,
    owners: HashMap<u64, Owner>,
    signals: signals::Signals,
    ticks: u64,
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

    /// The connection records and the events for the next report.
    pub fn take(&mut self, at_ms: i64) -> (Vec<ConnRecord>, Vec<ProbeEvent>) {
        let (records, overflow) = self.window.take(at_ms);
        let mut events = std::mem::take(&mut self.events);
        events.extend(overflow);
        (records, events)
    }
}

impl Sampler {
    /// One read of the tables. Owners are asked of the helper (when there is one) for the sockets not yet known.
    pub async fn tick(
        &mut self,
        host: &(dyn Host + Send + Sync),
        helper: Option<&HelperClient>,
        now_ms: i64,
    ) -> (Vec<aggregate::Observed>, Vec<ProbeEvent>) {
        let (mut seen, mut events) = (Vec::new(), Vec::new());
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
        self.ticks += 1;
        (seen, events)
    }
}
