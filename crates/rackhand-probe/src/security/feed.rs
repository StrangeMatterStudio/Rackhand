//! What the eBPF capture drained becomes (FR-4, FR-5, D196): connections are kept per `(container, exe, dest_ip,
//! dest_port, proto)` like sampled sockets, with how many connects and sends there were; a process started from a
//! temporary directory is a `proc.exec_from_tmp` event at once, however short it lived.
//!
//! The executable is the one the exec hook saw start the process; for a process started before the capture was loaded
//! it is the one the helper named for one of its sockets, and empty when neither knows it.

use std::collections::HashMap;

use rackhand_proto::probe::ProbeEvent;

use super::aggregate::Observed;
use super::ebpf::{Conn, Exec};
use crate::helper::procscan::{suspicious, user_name};

/// What names the capture's numbers: cgroup ids to container names, pids to executables, uids to users.
#[derive(Debug, Clone, Copy)]
pub struct Names<'a> {
    pub containers: &'a HashMap<u64, String>,
    pub exes: &'a HashMap<u32, String>,
    pub passwd: &'a str,
}

/// The connections as observations: no socket inode, the number of connects and sends instead.
pub fn observed(conns: &[Conn], names: Names<'_>) -> Vec<Observed> {
    conns
        .iter()
        .map(|c| Observed {
            container: names.containers.get(&c.cgroup).cloned().unwrap_or_default(),
            exe: if c.exe.is_empty() { names.exes.get(&c.pid).cloned().unwrap_or_default() } else { c.exe.clone() },
            user: user_name(names.passwd, c.uid),
            pid: c.pid,
            dest: c.dest,
            port: c.port,
            proto: c.proto,
            inode: 0,
            count: c.count,
            bytes: 0,
        })
        .collect()
}

/// An event for each start from a temporary directory, and the pids it named (the helper's scan doesn't name them
/// again). A start by a relative path is left to the scan, which sees where the process really runs from.
pub fn exec_events(execs: &[Exec], passwd: &str, at_ms: i64) -> (Vec<ProbeEvent>, Vec<u32>) {
    let mut events = Vec::new();
    let mut pids = Vec::new();
    for e in execs.iter().filter(|e| suspicious(&e.path)) {
        let fields = [
            ("pid", e.pid.to_string()),
            ("ppid", "0".to_string()),
            ("exe", e.path.clone()),
            ("user", user_name(passwd, e.uid)),
            ("parent", String::new()),
        ];
        events.push(ProbeEvent {
            kind: super::listeners::EXEC_FROM_TMP.into(),
            at_ms,
            fields: fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        });
        pids.push(e.pid);
    }
    (events, pids)
}

#[cfg(test)]
mod tests;
