//! The probe's eBPF capture on a real kernel (T68: FR-4, FR-5, AC13, AC71, 7.3.3, E36, D196). Runs as root in the eBPF
//! tier's VM, one kernel at a time; the probe under test was built with the program (`cargo xtask ci ebpf` sets
//! `RACKHAND_PROBE_EBPF`). The helper's loader attaches the programs and the probe's side reads the maps from their
//! descriptors, as on a machine.

use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use rackhand_probe::security::conntable::Proto;
use rackhand_probe::security::ebpf::{Capture, Conn, Exec, LoadError, MAPS, OBJECT, Programs};

const CHILD: &str = "RACKHAND_EBPF_CHILD";

/// Loopback, cgroup v2 and tracefs, which the VM's init may leave down or unmounted.
pub(crate) fn mounts() {
    let _ = Command::new("ip").args(["link", "set", "lo", "up"]).status();
    // an address that isn't loopback, for what sampling only counts when it leaves the machine
    let _ = Command::new("ip").args(["addr", "add", "10.99.0.1/32", "dev", "lo"]).output();
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        let _ = Command::new("mount").args(["-t", "cgroup2", "none", "/sys/fs/cgroup"]).status();
    }
    if !Path::new("/sys/kernel/tracing/events").exists() {
        let _ = Command::new("mount").args(["-t", "tracefs", "none", "/sys/kernel/tracing"]).status();
    }
}

/// The helper's programs, attached, and the probe's capture reading their maps.
fn load() -> (Programs, Capture) {
    assert!(!OBJECT.is_empty(), "the probe was built without the eBPF program: run `cargo xtask ci ebpf`");
    mounts();
    let programs = Programs::load(OBJECT, Path::new("/")).unwrap_or_else(|e| panic!("loading the capture: {e}"));
    let names: Vec<String> = MAPS.iter().map(|m| m.to_string()).collect();
    let capture = Capture::from_fds(programs.map_fds().unwrap(), &names).unwrap();
    (programs, capture)
}

/// Drains until `found` matches or 5 seconds pass; everything drained is returned.
fn drain_until(capture: &mut Capture, found: impl Fn(&[Conn], &[Exec]) -> bool) -> (Vec<Conn>, Vec<Exec>) {
    let (mut conns, mut execs) = (Vec::new(), Vec::new());
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        let (c, e) = capture.drain();
        conns.extend(c);
        execs.extend(e);
        if found(&conns, &execs) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    (conns, execs)
}

fn bash(script: &str) -> u32 {
    let child = Command::new("/bin/bash").args(["-c", script]).spawn().expect("bash runs");
    let pid = child.id();
    let out = child.wait_with_output().expect("bash finishes");
    assert!(out.status.success(), "{script}");
    pid
}

#[test]
fn short_connect_seen() {
    let (_programs, mut capture) = load();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // a 10 ms connection, opened and closed between two 5 s polls, which sampling would miss
    let pid = bash(&format!("exec 3<>/dev/tcp/127.0.0.1/{port}; sleep 0.01; exec 3<&-"));
    let (conns, _) = drain_until(&mut capture, |c, _| c.iter().any(|c| c.port == port));
    let c = conns.iter().find(|c| c.port == port).unwrap_or_else(|| panic!("not recorded: {conns:?}"));
    assert_eq!((c.pid, c.proto, c.dest), (pid, Proto::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST)), "{c:?}");
    // the path the process was started with, as the kernel has it (not resolved: `/bin` is a link to `/usr/bin`)
    assert_eq!(c.exe, "/bin/bash", "the exec hook named the process: {c:?}");
    drop(listener);
}

#[test]
fn udp_flow_seen() {
    let (_programs, mut capture) = load();
    let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sink.local_addr().unwrap().port();
    let pid = bash(&format!("echo hello > /dev/udp/127.0.0.1/{port}"));
    let (conns, _) = drain_until(&mut capture, |c, _| c.iter().any(|c| c.port == port));
    let mine: Vec<&Conn> = conns.iter().filter(|c| c.port == port).collect();
    assert_eq!(mine.len(), 1, "a connected UDP socket is one flow: {mine:?}");
    assert_eq!((mine[0].pid, mine[0].proto), (pid, Proto::Udp));
    // and an unconnected send from an IPv6 socket to an IPv4 address comes back as IPv4
    let v6 = UdpSocket::bind("[::]:0").unwrap();
    v6.send_to(b"x", ("::ffff:127.0.0.1", port)).unwrap();
    let (conns, _) = drain_until(&mut capture, |c, _| c.iter().any(|c| c.port == port && c.pid == std::process::id()));
    let sent = conns.iter().find(|c| c.port == port && c.pid == std::process::id());
    assert_eq!(sent.map(|c| c.dest), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), "{conns:?}");
}

#[test]
fn exec_from_tmp_seen() {
    let (_programs, mut capture) = load();
    std::fs::copy("/bin/true", "/tmp/rackhand-ebpf-true").unwrap();
    let status = Command::new("/tmp/rackhand-ebpf-true").status().unwrap();
    assert!(status.success());
    // run from inside /tmp by a relative path too: the kernel's filename is what was asked, so the program records
    // the path the process was started with
    let (_, execs) = drain_until(&mut capture, |_, e| e.iter().any(|e| e.path.contains("rackhand-ebpf-true")));
    let e = execs.iter().find(|e| e.path.contains("rackhand-ebpf-true")).unwrap_or_else(|| panic!("{execs:?}"));
    assert_eq!(e.path, "/tmp/rackhand-ebpf-true");
    assert_eq!(e.uid, 0);
}

#[test]
fn two_containers_same_exe_attributed() {
    let (_programs, mut capture) = load();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (a, b) = ("a".repeat(64), "b".repeat(64));
    let mut ids = Vec::new();
    for id in [&a, &b] {
        let dir = format!("/sys/fs/cgroup/docker-{id}.scope");
        std::fs::create_dir_all(&dir).unwrap();
        bash(&format!("echo $$ > {dir}/cgroup.procs; exec 3<>/dev/tcp/127.0.0.1/{port}"));
        use std::os::unix::fs::MetadataExt;
        ids.push(std::fs::metadata(&dir).unwrap().ino());
    }
    let (conns, _) = drain_until(&mut capture, |c, _| c.iter().filter(|c| c.port == port).count() >= 2);
    let mut cgroups: Vec<u64> = conns.iter().filter(|c| c.port == port).map(|c| c.cgroup).collect();
    cgroups.sort();
    cgroups.dedup();
    let mut want = ids.clone();
    want.sort();
    assert_eq!(cgroups, want, "each connection names its own cgroup: {conns:?}");
    let name_of = |id: &str| Some(if id.starts_with('a') { "web".to_string() } else { "db".to_string() });
    let names = rackhand_probe::helper::sockets::container_names(Path::new("/sys/fs/cgroup"), &cgroups, &name_of);
    let mut got: Vec<&str> = names.iter().map(|(_, n)| n.as_str()).collect();
    got.sort();
    assert_eq!(got, ["db", "web"], "the helper names both containers");
    drop(listener);
}

const SOCKET: &str = "/tmp/rackhand-ebpf-helper/helper.sock";
const NOBODY: u32 = 65534;

/// In the child, as the probe's unit runs it: the capture from the helper's socket, a connection and a start seen.
fn child_reads_the_helpers_capture() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let client = rackhand_probe::helper::client::HelperClient::new(SOCKET, "0.1.0");
    let mut capture =
        runtime.block_on(client.ebpf_capture()).unwrap_or_else(|e| panic!("as rackhand-probe would: {e}"));
    let again = runtime.block_on(client.ebpf_capture()).unwrap();
    assert!(capture.same_maps(&again), "asking again gives the same maps");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let _c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    assert!(Command::new("/bin/true").status().unwrap().success());
    let (conns, execs) =
        drain_until(&mut capture, |c, e| c.iter().any(|c| c.port == port) && e.iter().any(|e| e.path == "/bin/true"));
    assert!(conns.iter().any(|c| c.port == port && c.uid == NOBODY), "{conns:?}");
    assert!(execs.iter().any(|e| e.path == "/bin/true" && e.uid == NOBODY), "{execs:?}");
}

#[test]
fn probe_with_only_cap_bpf_reads_the_helpers_capture() {
    if std::env::var_os(CHILD).is_some() {
        return child_reads_the_helpers_capture();
    }
    assert!(!OBJECT.is_empty(), "the probe was built without the eBPF program: run `cargo xtask ci ebpf`");
    mounts();
    // the helper, as root, on a socket only the child's user may use
    // the VM's /tmp is the host's, where the probe's group can't own a file: the socket goes on a tmpfs of the VM
    let dir = Path::new(SOCKET).parent().unwrap();
    std::fs::create_dir_all(dir).unwrap();
    let mounted = std::fs::read_to_string("/proc/self/mounts").unwrap().contains(&format!(" {} tmpfs", dir.display()));
    if !mounted {
        let status = Command::new("mount").args(["-t", "tmpfs", "none"]).arg(dir).status().unwrap();
        assert!(status.success(), "a tmpfs for the helper's socket");
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let listener = {
        let _in_runtime = runtime.enter();
        rackhand_probe::helper::server::bind(Path::new(SOCKET), Some(NOBODY)).unwrap()
    };
    std::thread::spawn(move || {
        let helper = rackhand_probe::helper::server::Helper::new("0.1.0");
        runtime.block_on(rackhand_probe::helper::server::serve(listener, NOBODY, helper));
    });
    let me = std::env::current_exe().unwrap();
    let caps = "-all,+bpf";
    let out = Command::new("setpriv")
        .args(["--reuid=65534", "--regid=65534", "--clear-groups"])
        .args([format!("--inh-caps={caps}"), format!("--ambient-caps={caps}"), format!("--bounding-set={caps}")])
        .arg("--no-new-privs")
        .arg("--")
        .arg(&me)
        .args([
            "--exact",
            "capture::probe_with_only_cap_bpf_reads_the_helpers_capture",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .expect("setpriv runs");
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "as nobody with CAP_BPF only:\n{text}");
}

#[test]
fn load_failure_falls_back_to_sampling() {
    mounts();
    // a root without the kernel's BTF: the capture isn't loaded, and the probe says sampling
    let root = std::env::temp_dir().join("rackhand-no-btf");
    std::fs::create_dir_all(root.join("sys/fs")).unwrap();
    assert_eq!(Programs::load(OBJECT, &root).unwrap_err(), LoadError::NoBtf);
    let host = rackhand_probe::collect::RootHost::new(&root);
    assert_eq!(
        rackhand_probe::security::capability::capture(&host, false),
        rackhand_proto::probe::Capability::Sampling
    );
    // sampling still sees a connection that stays open across a read of the tables
    let listener = TcpListener::bind("10.99.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let _open = std::net::TcpStream::connect(("10.99.0.1", port)).unwrap();
    let real = rackhand_probe::collect::RootHost::new("/");
    let sockets = rackhand_probe::security::conntable::read(&real);
    assert!(sockets.iter().any(|s| s.outbound() && s.remote_port == port), "sampling sees it");
}
