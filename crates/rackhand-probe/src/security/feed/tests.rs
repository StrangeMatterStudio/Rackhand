use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use super::{Names, exec_events, observed};
use crate::security::conntable::Proto;
use crate::security::ebpf::{Conn, Exec};
use crate::security::listeners::EXEC_FROM_TMP;

const PASSWD: &str = "root:x:0:0::/root:/bin/sh\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n";

fn conn(pid: u32, cgroup: u64, uid: u32, exe: &str) -> Conn {
    Conn {
        cgroup,
        pid,
        uid,
        dest: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        port: 443,
        proto: Proto::Tcp,
        exe: exe.into(),
        comm: "curl".into(),
        count: 3,
    }
}

#[test]
fn connections_are_named_by_container_exe_and_user() {
    let containers: HashMap<u64, String> = [(7, "web".to_string())].into_iter().collect();
    let exes: HashMap<u32, String> = [(42, "/usr/sbin/nginx".to_string())].into_iter().collect();
    let names = Names { containers: &containers, exes: &exes, passwd: PASSWD };
    let seen = observed(&[conn(10, 7, 33, "/usr/bin/curl"), conn(42, 1, 0, ""), conn(99, 1, 1234, "")], names);
    let curl = &seen[0];
    assert_eq!(
        (curl.container.as_str(), curl.exe.as_str(), curl.user.as_str(), curl.pid),
        ("web", "/usr/bin/curl", "www-data", 10)
    );
    assert_eq!((curl.dest, curl.port, curl.proto), (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 443, Proto::Tcp));
    assert_eq!((curl.inode, curl.count, curl.bytes), (0, 3, 0), "counted, not a socket");
    assert_eq!(
        (seen[1].container.as_str(), seen[1].exe.as_str(), seen[1].user.as_str()),
        ("", "/usr/sbin/nginx", "root"),
        "a host process started before the capture: the executable the helper named"
    );
    assert_eq!(
        (seen[2].exe.as_str(), seen[2].user.as_str()),
        ("", "1234"),
        "unknown: no executable rather than the process name, and the uid's number"
    );
}

fn exec(pid: u32, path: &str) -> Exec {
    Exec { cgroup: 1, pid, uid: 33, path: path.into(), comm: "x".into() }
}

#[test]
fn starts_from_temporary_directories_are_events() {
    let execs = [exec(5, "/tmp/evil"), exec(6, "/usr/bin/true"), exec(7, "/dev/shm/x"), exec(8, "./evil")];
    let (events, pids) = exec_events(&execs, PASSWD, 1_000);
    assert_eq!(pids, [5, 7], "only /tmp, /var/tmp and /dev/shm; a relative start is the scan's");
    let e = &events[0];
    assert_eq!((e.kind.as_str(), e.at_ms), (EXEC_FROM_TMP, 1_000));
    assert_eq!(
        (e.fields["pid"].as_str(), e.fields["exe"].as_str(), e.fields["user"].as_str()),
        ("5", "/tmp/evil", "www-data")
    );
    let keys: Vec<&str> = e.fields.keys().map(String::as_str).collect();
    let mut want = ["exe", "parent", "pid", "ppid", "user"];
    want.sort_unstable();
    let mut keys = keys;
    keys.sort_unstable();
    assert_eq!(keys, want, "the same fields as the scan's event");
}
