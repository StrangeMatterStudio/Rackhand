//! What the Windows collectors parse, on the recorded outputs of `tests/fixtures/windows` (invented machine and user
//! names, documentation addresses). These run on every platform; the calls that produce the outputs run only on Windows
//! and are the manual checklist (MV16).

use std::path::PathBuf;

use rackhand_proto::helper::AuthKind;
use rackhand_proto::probe::ServiceStatus;

use super::{conntable, logon, pipe, procs, wmi};
use crate::collect::Config;
use crate::security::conntable::Proto;
use crate::security::listeners::{EXEC_FROM_TMP, TempExecs};

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/windows").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A `.hex` fixture's bytes: comment lines and whitespace are not part of them.
fn bytes(name: &str) -> Vec<u8> {
    let text: String = fixture(name).lines().filter(|l| !l.starts_with('#')).collect();
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn tcp_udp_table_records_to_tuples() {
    let tcp4 = conntable::tcp4(&bytes("tcp4.hex"));
    assert_eq!(tcp4.len(), 3);
    let est = &tcp4[0];
    assert_eq!((est.proto, est.local.to_string(), est.local_port), (Proto::Tcp, "10.0.0.5".into(), 49152));
    assert_eq!(
        (est.remote.to_string(), est.remote_port, est.inode),
        ("192.0.2.7".into(), 443, 4120),
        "the pid is the owner"
    );
    assert!(est.outbound() && !est.listening(), "an established connection with an owner");
    assert_eq!(est.state, 0x01, "ESTABLISHED, as the kernel numbers it");
    let rdp = &tcp4[1];
    assert!(rdp.listening() && !rdp.outbound(), "a listener on 3389");
    assert_eq!((rdp.local_port, rdp.inode), (3389, 1188));
    let waiting = &tcp4[2];
    assert_eq!((waiting.state, waiting.inode), (0x06, 0), "TIME_WAIT belongs to no process");
    assert!(!waiting.outbound() && !waiting.listening());

    let tcp6 = conntable::tcp6(&bytes("tcp6.hex"));
    assert_eq!(tcp6.len(), 2);
    assert_eq!((tcp6[0].remote.to_string(), tcp6[0].remote_port, tcp6[0].inode), ("2001:db8:1::7".into(), 443, 4120));
    assert!(tcp6[0].outbound());
    assert!(tcp6[1].listening() && tcp6[1].local_port == 445 && tcp6[1].inode == 4);

    let udp4 = conntable::udp4(&bytes("udp4.hex"));
    assert_eq!(udp4.iter().map(|s| (s.local_port, s.inode)).collect::<Vec<_>>(), [(5353, 2200), (68, 1500)]);
    assert!(udp4.iter().all(|s| s.proto == Proto::Udp && s.listening()), "a bound UDP socket is a listener");
    let udp6 = conntable::udp6(&bytes("udp6.hex"));
    assert_eq!(udp6.len(), 1);
    assert!(udp6[0].listening() && udp6[0].local.to_string() == "::");

    // a table that says more rows than it holds gives the rows it holds, and bytes that aren't a table give none
    let mut cut = bytes("tcp4.hex");
    cut[0] = 9;
    assert_eq!(conntable::tcp4(&cut).len(), 3);
    cut.truncate(4 + 24 + 10);
    assert_eq!(conntable::tcp4(&cut).len(), 1);
    assert!(conntable::tcp4(&[1, 0]).is_empty() && conntable::udp6(&[]).is_empty());
}

#[test]
fn process_in_temp_or_downloads_is_warning() {
    let all = procs::parse(&fixture("processes.json")).unwrap();
    assert_eq!(all.len(), 8, "every row is read, those with no executable path too");
    let flagged = procs::from_temp_or_downloads(&all);
    let pids: Vec<u32> = flagged.iter().map(|p| p.pid).collect();
    // %TEMP% of a user, a user's Downloads, the system's Temp, and another drive in other letter case; but not System32,
    // Program Files or a folder that only has the word in its name
    assert_eq!(pids, [4120, 4188, 5300, 5500]);
    let first = &flagged[0];
    assert_eq!(first.exe, r"C:\Users\alice\AppData\Local\Temp\setup-3f9a.exe");
    assert_eq!((first.ppid, first.user.as_str(), first.started_at_ms), (3300, r"WS01\alice", 1_763_899_000_000));
    // the event is the one the hub gives a Windows severity of warning for (an exe path with a drive letter)
    let events = TempExecs::default().observe(&flagged, 1_763_899_999_000);
    assert_eq!(events.len(), 4);
    assert!(events.iter().all(|e| e.kind == EXEC_FROM_TMP && e.fields["exe"].as_bytes()[1] == b':'));
    assert!(procs::parse("not json").is_err());
}

#[test]
fn logon_types_2_3_10_only() {
    let events = logon::parse(&fixture("logons.json")).unwrap();
    let seen: Vec<(AuthKind, &str, Option<&str>, &str)> = events
        .iter()
        .map(|e| (e.kind.clone(), e.user.as_str(), e.source_ip.as_deref(), e.method.as_deref().unwrap_or("")))
        .collect();
    assert_eq!(
        seen,
        [
            (AuthKind::Logon, "alice", Some("192.0.2.55"), "remote_interactive"),
            (AuthKind::Logon, "alice", None, "interactive"),
            (AuthKind::Logon, "bob", Some("198.51.100.23"), "network"),
            (AuthKind::SshFailed, "admin", Some("203.0.113.9"), "network"),
            (AuthKind::SshFailed, "administrator", Some("203.0.113.9"), "remote_interactive"),
        ],
        "service, batch, unlock, cached and other types are left out, as are machine accounts, anonymous logons, and events that aren't logons"
    );
    assert_eq!(events[0].at_ms, 1_763_899_400_000);
    assert!(logon::parse("{").is_err());
}

#[test]
fn vitals_and_services_from_recorded_wmi() {
    let cfg = Config { watched_services: vec!["W32Time".into(), "Missing".into()], ..Config::default() };
    let parsed = wmi::parse(&fixture("cim.json"), &cfg).unwrap();
    let value = |metric: &str, label: Option<&str>| {
        parsed
            .series
            .iter()
            .find(|s| s.metric == metric && s.labels.values().next().map(String::as_str) == label)
            .map(|s| s.value)
    };
    assert_eq!(value("cpu.busy_pct", None), Some(23.0));
    assert_eq!(value("mem.available_bytes", None), Some(4_194_304.0 * 1024.0));
    assert_eq!(value("mem.used_bytes", None), Some((16_777_216.0 - 4_194_304.0) * 1024.0));
    assert_eq!(value("mem.used_pct", None), Some(75.0));
    assert_eq!(value("mem.available_pct", None), Some(25.0));
    assert_eq!(value("uptime_s", None), Some(172_800.0));
    // the fixed disks, by drive; the optical drive is out
    assert_eq!(value("disk.total_bytes", Some("C:")), Some(255_000_000_000.0));
    assert_eq!(value("disk.used_bytes", Some("C:")), Some(204_000_000_000.0));
    assert_eq!(value("disk.used_pct", Some("C:")), Some(80.0));
    assert_eq!(value("disk.used_pct", Some("D:")), Some(10.0));
    assert_eq!(value("disk.used_pct", Some("E:")), None);
    // the interfaces, without tunnel pseudo-interfaces and the loopback, and the physical disks without the total
    assert_eq!(value("net.rx_bps", Some("Ethernet Adapter #2")), Some(12_000.0));
    assert_eq!(value("net.errors", Some("Ethernet Adapter #2")), Some(3.0));
    assert!(value("net.rx_bps", Some("Loopback Pseudo-Interface 1")).is_none());
    assert!(parsed.series.iter().all(|s| !s.labels.values().any(|v| v.starts_with("isatap"))));
    assert_eq!(value("diskio.read_bps", Some("0 C: D:")), Some(400_000.0));
    assert_eq!(value("diskio.write_iops", Some("0 C: D:")), Some(60.0));
    assert_eq!(value("diskio.busy_pct", Some("0 C: D:")), Some(12.0));
    assert!(value("diskio.read_bps", Some("_Total")).is_none());
    // per-core CPU only when asked for
    assert!(value("cpu.core_busy_pct", Some("0")).is_none());
    let per_core = wmi::parse(&fixture("cim.json"), &Config { per_core_cpu: true, ..Config::default() }).unwrap();
    assert_eq!(per_core.series.iter().filter(|s| s.metric == "cpu.core_busy_pct").count(), 2);
    // every name is in the catalogue
    assert!(parsed.series.iter().all(|s| rackhand_proto::catalogue::by_name(s.metric).is_some()));
    // services: the watched ones whatever their state, and the automatic ones that stopped with an error
    let services: Vec<(&str, i32, bool)> =
        parsed.services.iter().map(|s| (s.name.as_str(), s.status, s.enabled)).collect();
    assert_eq!(
        services,
        [
            ("ExampleSync", ServiceStatus::Failed as i32, true),
            ("Missing", ServiceStatus::Inactive as i32, false),
            ("W32Time", ServiceStatus::Inactive as i32, false),
        ],
        "an automatic service that stopped with 1077 (never tried) or 0 is not a failure"
    );
    let all = Config { watched_services: vec!["Spooler".into(), "BITS".into()], ..Config::default() };
    let parsed = wmi::parse(&fixture("cim.json"), &all).unwrap();
    let by_name = |n: &str| parsed.services.iter().find(|s| s.name == n).map(|s| s.status);
    assert_eq!(by_name("Spooler"), Some(ServiceStatus::Active as i32));
    assert_eq!(by_name("BITS"), Some(ServiceStatus::Activating as i32));
    // PowerShell writes one object, not a list of one, and nothing at all for none
    let single = r#"{"os":{"TotalVisibleMemorySize":1000,"FreePhysicalMemory":500,"TotalVirtualMemorySize":1,"FreeVirtualMemory":1,"UptimeS":5},
        "cpu":{"Name":"_Total","PercentProcessorTime":7},"disks":null,"net":null,"physdisk":null,"services":null}"#;
    let one = wmi::parse(single, &Config::default()).unwrap();
    assert!(one.series.iter().any(|s| s.metric == "cpu.busy_pct" && s.value == 7.0));
    assert!(wmi::parse("[]", &Config::default()).is_err());
}

#[test]
fn pipe_acl_sddl_allows_only_probe_service() {
    // the service SID is derived from the name; `NT SERVICE\TrustedInstaller` is the documented one to check the derivation by
    assert_eq!(pipe::service_sid("TrustedInstaller"), "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    assert_eq!(
        pipe::service_sid("trustedinstaller"),
        pipe::service_sid("TrustedInstaller"),
        "the name's case doesn't matter"
    );
    let sid = pipe::service_sid("RackhandProbe");
    assert!(sid.starts_with("S-1-5-80-") && sid.matches('-').count() == 8, "{sid}");
    let sddl = pipe::sddl("RackhandProbe");
    // a protected DACL with two entries: SYSTEM (the helper itself) and the probe's service account, nobody else
    assert_eq!(sddl, format!("D:P(A;;GA;;;SY)(A;;GRGW;;;{sid})"));
    assert!(
        !sddl.contains("WD") && !sddl.contains("BU") && !sddl.contains("AU") && !sddl.contains("BA"),
        "no Everyone, Users, Authenticated Users or Administrators"
    );
    assert_eq!(sddl.matches("(A;").count(), 2);
    assert!(!sddl.contains("(D;"));
}
