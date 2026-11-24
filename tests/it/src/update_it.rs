//! Probe self-update (plan T92, 7.3.3, FR-22, E39, AC37): a hub built with the test release keys holds a signed release in
//! its release directory and offers it to a probe installed by `install.sh` in a Debian container; the probe downloads it
//! into its spool, the root helper copies it into the other slot and checks the copy, and the guard switches the slot and
//! waits for the new probe. The release's version is told to the probe's build by `RACKHAND_PROBE_VERSION`.

use std::time::{Duration, Instant};

use rackhand_proto::common::Access;
use rackhand_release::manifest::Manifest;

use crate::install_it::{Release, TARGET, add_machine, install, key_id, ok, reporting, seed, sh};
use crate::probe_hub::{Hub, within};
use crate::support::{Container, musl_binary_versioned, musl_binary_with};

const LIB: &str = "/usr/local/lib/rackhand";

/// A hub that trusts the test keys, a machine with the probe installed and reporting, and the release server that
/// installed it.
struct Lab {
    hub: Hub,
    c: Container,
    _release: Release,
}

fn name() -> String {
    format!("rackhand-probe-{TARGET}")
}

fn lab(label: &str) -> Lab {
    let mut hub = Hub::init_lab(label);
    hub.start();
    hub.first_run();
    // the installed probe is a lab build too, so that its helper checks releases against the test keys
    let probe = musl_binary_with("rackhand-probe", "rackhand-probe", "lab-build");
    let release = Release::with_probe(label, "current", false, probe);
    let (_, token) = add_machine(&hub, Access::Monitor, &[]);
    let c = Container::start_systemd_with("debian-install", &[]);
    ok(&install(&c, &hub, &release, &release.script(None), &token, "--monitor"));
    reporting(&hub);
    Lab { hub, c, _release: release }
}

/// Puts a probe release in the hub's release directory as the maintainer's signing leaves it: the file, its signature
/// naming the file and the version, and the signed manifest.
fn publish(hub: &Hub, bytes: &[u8], version: &str) {
    let dir = hub.data.join("release");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let signer = |data: &[u8], comment: &str| {
        rackhand_release::signing::sign(&seed("current"), key_id("current"), data, comment)
    };
    std::fs::write(dir.join(name()), bytes).unwrap();
    std::fs::write(
        dir.join(format!("{}.minisig", name())),
        signer(bytes, &format!("file:{} version:{version}", name())),
    )
    .unwrap();
    let manifest = Manifest::of_dir(version, &dir).unwrap().to_json();
    std::fs::write(dir.join("manifest.json"), &manifest).unwrap();
    std::fs::write(
        dir.join("manifest.json.minisig"),
        signer(manifest.as_bytes(), &format!("file:manifest.json version:{version}")),
    )
    .unwrap();
}

fn link(c: &Container) -> String {
    sh(c, &format!("readlink {LIB}/rackhand-probe"))
}

fn state(c: &Container) -> serde_json::Value {
    serde_json::from_str(&sh(c, "cat /run/rackhand-probe/probe.state 2>/dev/null")).unwrap_or_default()
}

fn connected_on(c: &Container, version: &str) -> bool {
    let s = state(c);
    s["state"] == "connected" && s["version"] == version
}

fn sha256(c: &Container, path: &str) -> String {
    sh(c, &format!("sha256sum {path} | cut -d' ' -f1"))
}

fn hub_rows(hub: &Hub, sql: &str) -> i64 {
    let db = rusqlite::Connection::open(hub.data.join("hub.db")).unwrap();
    db.query_row(sql, [], |r| r.get(0)).unwrap()
}

mod probe {
    use super::*;

    /// FR-22: the hub offers a newer release, the probe fetches it, the helper copies it into the other slot and checks
    /// it, the guard switches, and the probe reconnects as the new version. The old slot stays as it was for the way back.
    #[test]
    fn good_release_switches_slot() {
        let lab = lab("upd-good");
        let c = &lab.c;
        assert_eq!(link(c), "probe-a", "the installer puts the probe in slot A and links it");
        let installed = sha256(c, &format!("{LIB}/rackhand-probe"));
        let next =
            std::fs::read(musl_binary_versioned("rackhand-probe", "rackhand-probe", "lab-build", "0.1.1")).unwrap();
        publish(&lab.hub, &next, "0.1.1");
        within(Duration::from_secs(150), "the probe runs 0.1.1 from slot B and is connected", || {
            link(c) == "probe-b" && connected_on(c, "0.1.1")
        });
        assert_eq!(sh(c, &format!("{LIB}/rackhand-probe --version")), "rackhand-probe 0.1.1");
        let new_hash = {
            use sha2::{Digest, Sha256};
            format!("{:x}", Sha256::digest(&next))
        };
        assert_eq!(sha256(c, &format!("{LIB}/probe-b")), new_hash);
        assert_eq!(sha256(c, &format!("{LIB}/run")), new_hash, "the command wrapper is the new version too");
        assert_eq!(sha256(c, &format!("{LIB}/probe-a")), installed, "slot A is what was running, for the way back");
        assert_eq!(sh(c, "systemctl is-active rackhand-probe rackhand-probe-helper"), "active\nactive");
        assert_eq!(sh(c, &format!("stat -c '%a %U' {LIB}/probe-a {LIB}/probe-b")), "755 root\n755 root");
        reporting(&lab.hub);
        // the files changing to what the hub offered are not events, and nothing it did opened an incident
        std::thread::sleep(Duration::from_secs(45));
        assert_eq!(
            hub_rows(
                &lab.hub,
                "SELECT count(*) FROM events WHERE kind = 'file.changed' AND json_extract(data, '$.path') LIKE '/usr/local/lib/rackhand/%'"
            ),
            0
        );
        assert_eq!(hub_rows(&lab.hub, "SELECT count(*) FROM incidents"), 0);
    }

    /// E39, AC37: a release that is signed and doesn't work (it never connects) is replaced by the version that ran, by the
    /// guard, within 3 minutes of the switch.
    #[test]
    fn broken_release_restored_within_3_minutes() {
        let lab = lab("upd-broken");
        let c = &lab.c;
        let broken = b"#!/bin/sh\nexit 1\n";
        publish(&lab.hub, broken, "0.1.1");
        within(Duration::from_secs(300), "the guard switched to the new slot", || link(c) == "probe-b");
        let switched = Instant::now();
        within(Duration::from_secs(180), "back on slot A, connected as 0.1.0", || {
            link(c) == "probe-a" && connected_on(c, "0.1.0")
        });
        assert!(switched.elapsed() < Duration::from_secs(180), "restored in {:?}", switched.elapsed());
        assert_eq!(sh(c, &format!("{LIB}/rackhand-probe --version")), "rackhand-probe 0.1.0");
        assert_eq!(sh(c, "systemctl is-active rackhand-probe rackhand-probe-helper"), "active\nactive");
        let wrapper = sha256(c, &format!("{LIB}/run"));
        assert_eq!(wrapper, sha256(c, &format!("{LIB}/probe-a")), "the wrapper went back too");
        assert_ne!(sha256(c, &format!("{LIB}/probe-b")), wrapper, "the failed slot is left for inspection");
        reporting(&lab.hub);
    }

    /// 7.3.3: the state file is written by the probe user, so a probe that says `connected` falsely can keep a release the
    /// key signed, or lose one, and nothing else: no file the key didn't sign is ever run, and the probe user can't write
    /// the slots, the link or the wrapper.
    #[test]
    fn lying_state_file_only_keeps_or_loses_signed_version() {
        let lab = lab("upd-lying");
        let c = &lab.c;
        let broken = b"#!/bin/sh\nexit 1\n";
        publish(&lab.hub, broken, "0.1.1");
        // the probe user says it is connected on 0.1.1, over and over, from the start
        c.spawn_detached(
            "rackhand-probe",
            r#"while true; do printf '{"state":"connected","version":"0.1.1","at_ms":1}' > /run/rackhand-probe/probe.state.tmp && mv /run/rackhand-probe/probe.state.tmp /run/rackhand-probe/probe.state; sleep 1; done"#,
        );
        within(Duration::from_secs(300), "the guard switched to the new slot", || link(c) == "probe-b");
        // longer than the guard waits: it believed the file and kept what the key had signed
        std::thread::sleep(Duration::from_secs(150));
        assert_eq!(link(c), "probe-b", "the guard keeps the signed release it was told is connected");
        let signed = {
            use sha2::{Digest, Sha256};
            format!("{:x}", Sha256::digest(broken))
        };
        assert_eq!(sha256(c, &format!("{LIB}/probe-b")), signed, "and it is exactly the signed file");
        // nothing the probe user can do puts anything else there
        for target in ["probe-a", "probe-b", "run", "rackhand-probe"] {
            let out = c.exec(
                Some("rackhand-probe"),
                &["sh", "-c", &format!("echo '#!/bin/sh' > {LIB}/{target} 2>&1; ln -sf /tmp/evil {LIB}/{target} 2>&1")],
                None,
            );
            let said = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
            assert!(said.contains("Permission denied") || said.contains("Operation not permitted"), "{target}: {said}");
        }
        assert_eq!(sha256(c, &format!("{LIB}/probe-b")), signed);
        assert_eq!(link(c), "probe-b");
    }
}

/// What the hub and the machine were saying, when a test fails.
impl Drop for Lab {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let log = self.hub.log();
        let tail: Vec<&str> = log.lines().rev().take(40).collect::<Vec<_>>().into_iter().rev().collect();
        eprintln!("--- the hub's log (the end) ---\n{}", tail.join("\n"));
        let said = sh(
            &self.c,
            "journalctl -u rackhand-probe -u rackhand-probe-helper -u rackhand-update-guard --no-pager -n 60 2>&1 | cut -c1-300; \
             ls -la /usr/local/lib/rackhand /var/lib/rackhand-probe/update 2>&1; cat /run/rackhand-probe/probe.state 2>&1",
        );
        eprintln!("--- the machine ---\n{said}");
    }
}
