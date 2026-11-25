//! What is new on the machine (FR-5): a listening port nothing listened on before, and a process running from a temporary
//! directory or a file that has been deleted. Each is reported once.

use std::collections::BTreeSet;

use rackhand_proto::helper::ProcInfo;
use rackhand_proto::probe::ProbeEvent;

use super::conntable::{Proto, Socket};

/// `port.new_listener` (warning, 7.6.6).
pub const NEW_LISTENER: &str = "port.new_listener";
/// `proc.exec_from_tmp` (critical on Linux, 7.6.6).
pub const EXEC_FROM_TMP: &str = "proc.exec_from_tmp";

fn event(kind: &str, at_ms: i64, fields: &[(&str, String)]) -> ProbeEvent {
    ProbeEvent { kind: kind.into(), at_ms, fields: fields.iter().map(|(k, v)| (k.to_string(), v.clone())).collect() }
}

/// The ports listened on so far. The first look only learns what is already there.
#[derive(Debug, Default)]
pub struct Listeners {
    known: BTreeSet<(Proto, u16)>,
    started: bool,
}

impl Listeners {
    /// The listeners among `sockets` that weren't there before; `owner` names the executable and user of an inode.
    pub fn observe(
        &mut self,
        sockets: &[Socket],
        at_ms: i64,
        owner: &dyn Fn(u64) -> Option<(String, String)>,
    ) -> Vec<ProbeEvent> {
        let mut events = Vec::new();
        for s in sockets.iter().filter(|s| s.listening()) {
            if !self.known.insert((s.proto, s.local_port)) || !self.started {
                continue;
            }
            let (exe, user) = owner(s.inode).unwrap_or_default();
            let proto = if s.proto == Proto::Tcp { "tcp" } else { "udp" };
            events.push(event(
                NEW_LISTENER,
                at_ms,
                &[
                    ("port", s.local_port.to_string()),
                    ("proto", proto.into()),
                    ("exe", exe),
                    ("user", user),
                    ("address", s.local.to_string()),
                ],
            ));
        }
        self.started = true;
        events
    }
}

/// Processes already reported for running from a temporary directory.
#[derive(Debug, Default)]
pub struct TempExecs {
    reported: BTreeSet<(u32, i64)>,
    /// Pids the eBPF capture's events named since the last scan.
    captured: BTreeSet<u32>,
}

impl TempExecs {
    /// The pids the capture reported starting from a temporary directory: the next scan doesn't report them again.
    pub fn captured(&mut self, pids: &[u32]) {
        self.captured.extend(pids);
    }

    /// An event for each process of `scan` not reported before (a pid is told apart from a later one by its start time).
    pub fn observe(&mut self, scan: &[ProcInfo], at_ms: i64) -> Vec<ProbeEvent> {
        let mut events = Vec::new();
        let captured = std::mem::take(&mut self.captured);
        for p in scan {
            if !self.reported.insert((p.pid, p.started_at_ms)) || captured.contains(&p.pid) {
                continue;
            }
            events.push(event(
                EXEC_FROM_TMP,
                at_ms,
                &[
                    ("pid", p.pid.to_string()),
                    ("ppid", p.ppid.to_string()),
                    ("exe", p.exe.clone()),
                    ("user", p.user.clone()),
                    ("parent", p.parent_exe.clone()),
                ],
            ));
        }
        let live: BTreeSet<(u32, i64)> = scan.iter().map(|p| (p.pid, p.started_at_ms)).collect();
        self.reported.retain(|k| live.contains(k));
        events
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn listener(proto: Proto, port: u16, inode: u64) -> Socket {
        Socket {
            proto,
            local: "0.0.0.0".parse::<IpAddr>().unwrap(),
            local_port: port,
            remote: "0.0.0.0".parse::<IpAddr>().unwrap(),
            remote_port: 0,
            state: if proto == Proto::Tcp { 0x0A } else { 0x07 },
            inode,
            uid: 0,
        }
    }

    #[test]
    fn new_listener_event_once() {
        let mut l = Listeners::default();
        let owner = |inode: u64| (inode == 9).then(|| ("/usr/bin/nc".to_string(), "alice".to_string()));
        let base = [listener(Proto::Tcp, 22, 1)];
        assert!(l.observe(&base, 10, &owner).is_empty(), "what is there at the first look isn't new");
        assert!(l.observe(&base, 20, &owner).is_empty());
        let now = [listener(Proto::Tcp, 22, 1), listener(Proto::Tcp, 4444, 9), listener(Proto::Udp, 5353, 2)];
        let events = l.observe(&now, 30, &owner);
        assert_eq!(events.len(), 2);
        let nc = events.iter().find(|e| e.fields["port"] == "4444").unwrap();
        assert_eq!((nc.kind.as_str(), nc.at_ms), (NEW_LISTENER, 30));
        assert_eq!(
            (nc.fields["exe"].as_str(), nc.fields["user"].as_str(), nc.fields["proto"].as_str()),
            ("/usr/bin/nc", "alice", "tcp")
        );
        assert!(l.observe(&now, 40, &owner).is_empty(), "once");
        // a connected socket on a port isn't a listener
        let mut est = listener(Proto::Tcp, 9999, 3);
        est.state = 0x01;
        assert!(l.observe(&[est], 50, &owner).is_empty());
    }

    #[test]
    fn a_process_from_tmp_is_reported_once_until_it_ends() {
        let mut t = TempExecs::default();
        let p = |pid, started| ProcInfo {
            pid,
            ppid: 1,
            exe: "/tmp/x".into(),
            user: "root".into(),
            started_at_ms: started,
            parent_exe: String::new(),
        };
        assert_eq!(t.observe(&[p(7, 100)], 1).len(), 1);
        assert!(t.observe(&[p(7, 100)], 2).is_empty());
        assert_eq!(t.observe(&[p(7, 100), p(8, 200)], 3).len(), 1, "another process");
        assert!(t.observe(&[], 4).is_empty());
        assert_eq!(t.observe(&[p(7, 900)], 5).len(), 1, "the pid used again by a later process");
    }

    #[test]
    fn a_start_the_capture_reported_isnt_reported_again_by_the_scan() {
        let mut t = TempExecs::default();
        let p = |pid| ProcInfo {
            pid,
            ppid: 1,
            exe: "/tmp/x".into(),
            user: "root".into(),
            started_at_ms: 100,
            parent_exe: String::new(),
        };
        t.captured(&[7]);
        assert!(t.observe(&[p(7)], 1).is_empty(), "the capture's event named it");
        assert!(t.observe(&[p(7)], 2).is_empty(), "and it stays reported while it runs");
        assert_eq!(t.observe(&[p(7), p(8)], 3).len(), 1, "another process still is");
    }
}
