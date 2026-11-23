//! The sampling capture (plan T67, 7.3.2, FR-4, FR-5, D103): the probe's `security` command against a Debian container under
//! systemd with the helper's own unit, which gives it who owns each socket.

use std::time::{Duration, Instant};

use crate::helper_it::{machine, start_helper};
use crate::helper_scan::fake_engine;
use crate::support::Container;

const WEB: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DB: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn own_ip(c: &Container) -> String {
    String::from_utf8_lossy(&c.root("hostname -i | cut -d' ' -f1").stdout).trim().to_string()
}

/// `rackhand-probe security` for `seconds`, as JSON.
fn sample(c: &Container, seconds: u32) -> serde_json::Value {
    let out = c.exec(
        Some("rackhand-probe"),
        &[
            "/usr/local/lib/rackhand/rackhand-probe",
            "security",
            "--seconds",
            &seconds.to_string(),
            "--every-ms",
            "1000",
        ],
        None,
    );
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text} {}", String::from_utf8_lossy(&out.stderr)))
}

/// AC71, D103: two containers run the same `socat`; a connection each of them holds open across the 5-second reads is
/// attributed to its own container.
#[test]
fn connection_open_across_poll_attributed_to_container() {
    let c = machine();
    fake_engine(&c, &[(WEB, "web"), (DB, "db")]);
    start_helper(&c);
    let ip = own_ip(&c);
    assert!(!ip.is_empty(), "the container has an address");
    // a listener on the machine, and a client of it in each container's cgroup, holding the connection open
    c.root("systemd-run --unit=target socat TCP-LISTEN:7777,reuseaddr,fork SYSTEM:'sleep 600'");
    std::thread::sleep(Duration::from_secs(1));
    for (id, _) in [(WEB, "web"), (DB, "db")] {
        c.root(&format!("systemd-run --unit=docker-{id} sh -c 'sleep 600 | socat - TCP:{ip}:7777'"));
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let out = sample(&c, 4);
        let records = out["connections"].as_array().unwrap().clone();
        let mine: Vec<(String, String)> = records
            .iter()
            .filter(|r| {
                r["dest_port"] == 7777
                    && r["dest_ip"] == ip.as_str()
                    && r["exe"].as_str().is_some_and(|e| e.ends_with("socat"))
            })
            .map(|r| (r["container"].as_str().unwrap().to_string(), r["user"].as_str().unwrap().to_string()))
            .collect();
        if mine.iter().any(|m| m.0 == "web") && mine.iter().any(|m| m.0 == "db") {
            assert!(mine.iter().all(|m| m.1 == "root"), "{mine:?}");
            return;
        }
        assert!(Instant::now() < deadline, "the two connections never showed with their containers: {records:?}");
    }
}

/// FR-5: a program run from `/tmp` and a port nothing listened on before are each reported, once.
#[test]
fn exec_from_tmp_and_new_port_reported() {
    let c = machine();
    start_helper(&c);
    // the first look learns the listeners that are there; what starts after it is new
    c.root("cp /bin/sleep /tmp/evil && systemd-run --unit=evil /tmp/evil 600");
    c.root("systemd-run --unit=newport socat TCP-LISTEN:4444,reuseaddr,fork /dev/null");
    let out = c.exec(
        Some("rackhand-probe"),
        &["/usr/local/lib/rackhand/rackhand-probe", "security", "--seconds", "1", "--every-ms", "500"],
        None,
    );
    let first: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let kinds = |v: &serde_json::Value| -> Vec<String> {
        v["events"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap().to_string()).collect()
    };
    assert!(kinds(&first).contains(&"proc.exec_from_tmp".to_string()), "{first}");
    let exec = first["events"].as_array().unwrap().iter().find(|e| e["kind"] == "proc.exec_from_tmp").unwrap();
    assert_eq!(exec["fields"]["exe"], "/tmp/evil");
    assert_eq!(kinds(&first).iter().filter(|k| *k == "proc.exec_from_tmp").count(), 1, "once");
    // a port that starts after a first look is new
    let c2 = &c;
    let background = std::thread::scope(|s| {
        let look = s.spawn(|| sample(c2, 8));
        std::thread::sleep(Duration::from_secs(3));
        c2.root("systemd-run --unit=later socat TCP-LISTEN:5555,reuseaddr,fork /dev/null");
        look.join().unwrap()
    });
    let listeners: Vec<String> = background["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "port.new_listener")
        .map(|e| e["fields"]["port"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(listeners, ["5555"], "only the port that appeared after the first look, once: {background}");
}
