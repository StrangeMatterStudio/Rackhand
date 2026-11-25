//! The probe's reads with the eBPF capture (T68, FR-4, FR-5, D196): what the sampler hands the reports comes from the
//! capture's maps, through a real helper socket, as in the daemon.

use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

use rackhand_probe::collect::RootHost;
use rackhand_probe::helper::client::HelperClient;
use rackhand_probe::security::Sampler;
use rackhand_probe::security::conntable::Proto;

const SOCKET: &str = "/tmp/rackhand-ebpf-sampler/helper.sock";

/// A root helper on its own tmpfs (the VM's /tmp is the host's), answering this process.
fn helper(runtime: &tokio::runtime::Runtime) -> HelperClient {
    crate::capture::mounts();
    let dir = Path::new(SOCKET).parent().unwrap();
    std::fs::create_dir_all(dir).unwrap();
    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap();
    if !mounts.contains(&format!(" {} tmpfs", dir.display())) {
        assert!(Command::new("mount").args(["-t", "tmpfs", "none"]).arg(dir).status().unwrap().success());
    }
    let listener = {
        let _in_runtime = runtime.enter();
        rackhand_probe::helper::server::bind(Path::new(SOCKET), None).unwrap()
    };
    let helper = rackhand_probe::helper::server::Helper::new("0.1.0");
    runtime.spawn(rackhand_probe::helper::server::serve(listener, 0, helper));
    HelperClient::new(SOCKET, "0.1.0")
}

#[test]
fn reads_report_what_the_capture_saw() {
    assert!(!rackhand_probe::security::ebpf::OBJECT.is_empty(), "run `cargo xtask ci ebpf`");
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let client = helper(&runtime);
    // a connection opened before the capture is attached, and kept open (to an address that isn't loopback, which
    // sampling leaves out)
    let early = TcpListener::bind("10.99.0.1:0").unwrap();
    let early_port = early.local_addr().unwrap().port();
    let _open = std::net::TcpStream::connect(("10.99.0.1", early_port)).unwrap();
    let capture = runtime.block_on(client.ebpf_capture()).unwrap_or_else(|e| panic!("the helper's capture: {e}"));
    let mut sampler = Sampler::new(Some(capture));
    assert!(sampler.capturing());
    let host = RootHost::new("/");
    // a first read, so what follows is new; the connection from before the capture is in it, from the tables
    let (seen, _) = runtime.block_on(sampler.tick(&host, Some(&client), 1));
    let before: Vec<_> = seen.iter().filter(|o| o.port == early_port).collect();
    assert_eq!(before.len(), 1, "opened before the capture, still reported: {seen:?}");
    assert_eq!((before[0].count, before[0].pid), (0, std::process::id()), "a sampled socket: {:?}", before[0]);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    for _ in 0..3 {
        drop(std::net::TcpStream::connect(("127.0.0.1", port)).unwrap());
    }
    std::fs::copy("/bin/true", "/tmp/rackhand-ebpf-sampled").unwrap();
    assert!(Command::new("/tmp/rackhand-ebpf-sampled").status().unwrap().success());
    let (seen, events) = runtime.block_on(sampler.tick(&host, Some(&client), 2));
    let mine: Vec<_> = seen.iter().filter(|o| o.port == port).collect();
    assert_eq!(mine.len(), 1, "one destination: {seen:?}");
    let o = mine[0];
    assert_eq!((o.proto, o.count, o.inode, o.pid), (Proto::Tcp, 3, 0, std::process::id()), "{o:?}");
    assert_eq!((o.user.as_str(), o.container.as_str()), ("root", ""), "a host process, by name: {o:?}");
    // this process started before the capture: its executable is the one the helper named for its listening socket
    let me = std::env::current_exe().unwrap();
    assert_eq!(o.exe, me.to_string_lossy(), "{o:?}");
    let started: Vec<_> = events.iter().filter(|e| e.kind == "proc.exec_from_tmp").collect();
    assert_eq!(started.len(), 1, "{events:?}");
    assert_eq!(started[0].fields["exe"], "/tmp/rackhand-ebpf-sampled");
    // the next read: nothing new from the capture, and the helper's scan doesn't name the start again
    let (seen, events) = runtime.block_on(sampler.tick(&host, Some(&client), 3));
    assert!(seen.iter().all(|o| o.port != port), "drained once: {seen:?}");
    assert!(events.iter().all(|e| e.kind != "proc.exec_from_tmp"), "{events:?}");
    drop(listener);
}
