//! Connection tuples per report (7.3.2, E59): `(container, exe, dest_ip, dest_port, proto)` with how many sockets went
//! there, at most 500 per report. Past that, the 500 with the most bytes (then the most sockets) are kept and the rest are
//! folded, per container and executable, into records with no destination, which are counted and not scored (7.6.5); a
//! `conn.overflow` event says it happened.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rackhand_proto::probe::{ConnRecord, ProbeEvent, Proto as WireProto};

use super::conntable::Proto;

/// The most destination records one report carries.
pub const MAX_TUPLES: usize = 500;

/// One socket seen, with its owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// The container's name, empty for a host process.
    pub container: String,
    pub exe: String,
    pub user: String,
    pub pid: u32,
    pub dest: IpAddr,
    pub port: u16,
    pub proto: Proto,
    pub inode: u64,
    pub bytes: u64,
}

type Key = (String, String, IpAddr, u16, Proto);

#[derive(Debug, Default)]
struct Entry {
    inodes: std::collections::BTreeSet<u64>,
    bytes: u64,
    pid: u32,
    user: String,
}

/// What was seen since the last report.
#[derive(Debug, Default)]
pub struct Window {
    tuples: BTreeMap<Key, Entry>,
}

fn wire(p: Proto) -> i32 {
    match p {
        Proto::Tcp => WireProto::Tcp as i32,
        Proto::Udp => WireProto::Udp as i32,
    }
}

fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

impl Window {
    /// A socket seen again in the same window is the same socket: it counts once.
    pub fn add(&mut self, o: Observed) {
        let e = self.tuples.entry((o.container, o.exe, o.dest, o.port, o.proto)).or_default();
        e.inodes.insert(o.inode);
        e.bytes = e.bytes.max(o.bytes);
        e.pid = o.pid;
        e.user = o.user;
    }

    pub fn is_empty(&self) -> bool {
        self.tuples.is_empty()
    }

    /// The window as report records, and starts the next one. With more than [`MAX_TUPLES`] tuples, the rest are folded
    /// and a `conn.overflow` event comes with them.
    pub fn take(&mut self, at_ms: i64) -> (Vec<ConnRecord>, Option<ProbeEvent>) {
        let all = std::mem::take(&mut self.tuples);
        let mut records: Vec<ConnRecord> = all
            .into_iter()
            .map(|((container, exe, dest, port, proto), e)| ConnRecord {
                container,
                exe,
                dest_ip: octets(dest),
                dest_port: u32::from(port),
                proto: wire(proto),
                count: e.inodes.len() as u32,
                bytes: e.bytes,
                pid: e.pid,
                user: e.user,
                folded: false,
            })
            .collect();
        if records.len() <= MAX_TUPLES {
            return (records, None);
        }
        // the most bytes first, then the most sockets; the rest keep their order, so the choice is the same every time
        records.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(b.count.cmp(&a.count)));
        let rest = records.split_off(MAX_TUPLES);
        let folded_tuples = rest.len();
        let mut folds: BTreeMap<(String, String), ConnRecord> = BTreeMap::new();
        for r in rest {
            let f = folds.entry((r.container.clone(), r.exe.clone())).or_insert_with(|| ConnRecord {
                container: r.container.clone(),
                exe: r.exe.clone(),
                dest_ip: Vec::new(),
                dest_port: 0,
                proto: 0,
                count: 0,
                bytes: 0,
                pid: r.pid,
                user: r.user.clone(),
                folded: true,
            });
            f.count = f.count.saturating_add(r.count);
            f.bytes = f.bytes.saturating_add(r.bytes);
        }
        records.extend(folds.into_values());
        let event = ProbeEvent {
            kind: "conn.overflow".into(),
            at_ms,
            fields: [("folded_tuples".to_string(), folded_tuples.to_string())].into_iter().collect(),
        };
        (records, Some(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(i: u32, container: &str, bytes: u64) -> Observed {
        Observed {
            container: container.into(),
            exe: "/usr/bin/curl".into(),
            user: "root".into(),
            pid: 100 + i,
            dest: IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i)),
            port: 443,
            proto: Proto::Tcp,
            inode: u64::from(i) + 1,
            bytes,
        }
    }

    #[test]
    fn over_500_tuples_keeps_most_bytes_folds_rest() {
        let mut w = Window::default();
        // 600 tuples over three containers, the byte counts 0 to 599
        for i in 0..600u32 {
            w.add(seen(i, ["a", "b", "c"][(i % 3) as usize], u64::from(i)));
        }
        let (records, event) = w.take(1_000);
        let kept: Vec<&ConnRecord> = records.iter().filter(|r| !r.folded).collect();
        let folded: Vec<&ConnRecord> = records.iter().filter(|r| r.folded).collect();
        assert_eq!(kept.len(), 500);
        assert!(kept.iter().all(|r| r.bytes >= 100), "the 500 with the most bytes are the ones kept");
        assert_eq!(folded.len(), 3, "one folded record per container and executable");
        assert!(folded.iter().all(|r| r.dest_ip.is_empty() && r.dest_port == 0));
        assert_eq!(folded.iter().map(|r| r.count).sum::<u32>(), 100, "every socket past the cap is counted");
        assert_eq!(folded.iter().map(|r| r.bytes).sum::<u64>(), (0..100u64).sum::<u64>(), "and its bytes");
        let mut names: Vec<&str> = folded.iter().map(|r| r.container.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["a", "b", "c"]);
        let event = event.expect("one overflow event");
        assert_eq!((event.kind.as_str(), event.fields["folded_tuples"].as_str()), ("conn.overflow", "100"));
        // the next window starts empty; at the cap exactly, nothing is folded
        assert!(w.is_empty());
        for i in 0..500u32 {
            w.add(seen(i, "a", 5));
        }
        let (records, event) = w.take(2_000);
        assert_eq!((records.len(), records.iter().any(|r| r.folded), event), (500, false, None));
    }

    #[test]
    fn a_socket_seen_again_counts_once_and_a_second_socket_counts_again() {
        let mut w = Window::default();
        w.add(seen(1, "", 0));
        w.add(seen(1, "", 0));
        let mut other = seen(1, "", 0);
        other.inode = 999;
        w.add(other);
        let (records, _) = w.take(0);
        assert_eq!(records.len(), 1, "one destination");
        assert_eq!(records[0].count, 2, "two sockets to it");
        assert_eq!(records[0].dest_ip, vec![10, 0, 0, 1]);
        assert_eq!((records[0].dest_port, records[0].proto), (443, WireProto::Tcp as i32));
    }
}
