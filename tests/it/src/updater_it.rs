//! The hub's updater (plan T93, 7.5.7, 7.1, D98, AC67): a hub under its packaged unit in a Debian container with systemd, the
//! updater's path unit and service, and `rackhand self-update`. The hub and the release are `lab-build`s (the test release
//! keys pinned) told their versions with `RACKHAND_LAB_VERSION`. The hub is installed as it was before there were slots, a
//! plain file at `/usr/local/bin/rackhand`, so the first update moves it into slot A too.
//!
//! Systemd in a container can't give a service user its credential directory, so the hub's unit gets a test-only drop-in that
//! hands it the master key through a directory only its user can read (`HUB_TEST_DROPIN`); everything else is the packaged
//! unit.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rackhand_release::manifest::Manifest;

use crate::install_it::{key_id, seed, sh};
use crate::probe_hub::within;
use crate::support::{Container, musl_binary_versioned_by};

const LIB: &str = "/usr/local/lib/rackhand-server";

const HUB_TEST_DROPIN: &str = "# test containers only: the key through a directory only the hub's user can read\n\
[Service]\n\
LoadCredential=\n\
Environment=CREDENTIALS_DIRECTORY=/run/rackhand-test-credentials\n\
ExecStartPre=+/bin/sh -c 'install -d -m 0500 -o rackhand-hub /run/rackhand-test-credentials && install -m 0400 -o rackhand-hub /etc/rackhand/master.key /run/rackhand-test-credentials/master.key'\n";

fn artifact() -> String {
    "rackhand-x86_64-unknown-linux-musl".to_string()
}

fn packaging(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/systemd").join(name)
}

/// `rackhand` as a lab build of `version`.
fn hub_binary(version: &str) -> PathBuf {
    musl_binary_versioned_by("rackhand", "rackhand", "lab-build", "RACKHAND_LAB_VERSION", version)
}

fn healthy(c: &Container) -> bool {
    sh(c, "curl -sk --max-time 5 https://127.0.0.1:8443/healthz") == "ok"
}

/// A hub machine: the old version as a plain file, the packaged units, `hub init`, the hub running.
fn hub_machine(version: &str) -> Container {
    let c = Container::start_systemd_with("debian-install", &[]);
    c.copy_in(&hub_binary(version), "/usr/local/bin/rackhand");
    for unit in ["rackhand-hub.service", "rackhand-updater.path", "rackhand-updater.service"] {
        c.copy_in(&packaging(unit), &format!("/etc/systemd/system/{unit}"));
    }
    let dropin = std::env::temp_dir().join(format!("rackhand-hub-test-dropin-{}.conf", std::process::id()));
    std::fs::write(&dropin, HUB_TEST_DROPIN).unwrap();
    sh(&c, "mkdir -p /etc/systemd/system/rackhand-hub.service.d");
    c.copy_in(&dropin, "/etc/systemd/system/rackhand-hub.service.d/test.conf");
    let out = c.root(
        "set -e; chmod 0755 /usr/local/bin/rackhand
id rackhand-hub >/dev/null 2>&1 || useradd -r -U -M -d /var/lib/rackhand -s /usr/sbin/nologin rackhand-hub
/usr/local/bin/rackhand hub init >/dev/null
chown -R rackhand-hub:rackhand-hub /var/lib/rackhand
chown rackhand-hub:rackhand-hub /etc/rackhand/node.key
chown root:rackhand-hub /etc/rackhand/hub.toml
systemctl daemon-reload
systemctl enable --now rackhand-hub rackhand-updater.path",
    );
    assert!(out.status.success(), "installing the hub: {}", String::from_utf8_lossy(&out.stderr));
    within(Duration::from_secs(60), "the hub answers /healthz", || healthy(&c));
    c
}

/// A release in the hub's release directory, as the maintainer's signing leaves it: the file signed with its name and version,
/// and the signed manifest.
fn publish(c: &Container, bytes: &[u8], version: &str) {
    let dir = std::env::temp_dir().join(format!("rackhand-it-hub-release-{version}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let name = artifact();
    let signer = |data: &[u8], comment: &str| {
        rackhand_release::signing::sign(&seed("current"), key_id("current"), data, comment)
    };
    std::fs::write(dir.join(&name), bytes).unwrap();
    std::fs::write(dir.join(format!("{name}.minisig")), signer(bytes, &format!("file:{name} version:{version}")))
        .unwrap();
    let manifest = Manifest::of_dir(version, &dir).unwrap().to_json();
    std::fs::write(dir.join("manifest.json"), &manifest).unwrap();
    std::fs::write(
        dir.join("manifest.json.minisig"),
        signer(manifest.as_bytes(), &format!("file:manifest.json version:{version}")),
    )
    .unwrap();
    sh(c, "mkdir -p /var/lib/rackhand/release");
    for f in std::fs::read_dir(&dir).unwrap() {
        let f = f.unwrap();
        c.copy_in(&f.path(), &format!("/var/lib/rackhand/release/{}", f.file_name().to_string_lossy()));
    }
    sh(c, "chown -R rackhand-hub:rackhand-hub /var/lib/rackhand/release");
}

fn running(c: &Container) -> String {
    sh(c, &format!("readlink {LIB}/rackhand"))
}

/// The hub's database, copied out and opened here.
fn audit_actions(c: &Container) -> Vec<(String, String)> {
    let dir = std::env::temp_dir().join(format!("rackhand-it-updater-db-{}-{}", std::process::id(), rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    for f in ["hub.db", "hub.db-wal"] {
        let out = std::process::Command::new("docker")
            .args(["cp", &format!("{}:/var/lib/rackhand/{f}", c.name)])
            .arg(dir.join(f))
            .output()
            .unwrap();
        let _ = out;
    }
    let db = rusqlite::Connection::open(dir.join("hub.db")).unwrap();
    let mut st = db.prepare("SELECT action, data FROM audit_log ORDER BY seq").unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
}

fn rand_suffix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
}

mod updater {
    use super::*;

    /// 7.5.7: `rackhand self-update` takes a backup and a copy of the database, puts the release in the spool and asks; the
    /// updater checks it, copies it into slot B and starts the guard, which switches and keeps it once `/healthz` answers.
    #[test]
    fn good_update_switches_and_healthz_ok() {
        let c = hub_machine("0.1.0");
        let _diag = Diag(&c);
        publish(&c, &std::fs::read(hub_binary("0.1.1")).unwrap(), "0.1.1");
        let asked = c.root("/usr/local/bin/rackhand self-update");
        assert!(
            asked.status.success(),
            "{}{}",
            String::from_utf8_lossy(&asked.stdout),
            String::from_utf8_lossy(&asked.stderr)
        );
        within(Duration::from_secs(240), "the hub runs 0.1.1 from slot B and answers /healthz", || {
            running(&c) == "rackhand-b"
                && sh(&c, "/usr/local/bin/rackhand --version") == "rackhand 0.1.1"
                && healthy(&c)
        });
        assert_eq!(
            sh(&c, "readlink /usr/local/bin/rackhand"),
            format!("{LIB}/rackhand"),
            "the units' path is a link now"
        );
        assert_eq!(sh(&c, &format!("{LIB}/rackhand-a --version")), "rackhand 0.1.0", "slot A is the version before");
        within(Duration::from_secs(30), "the guard is done and has put the release's manifest beside hub.toml", || {
            sh(&c, "systemctl is-active rackhand-update-guard-hub") != "active"
                && sh(&c, "test -f /etc/rackhand/release-manifest.json && echo yes") == "yes"
        });
        let uids = sh(&c, "ps -o uid= -C rackhand");
        assert!(!uids.is_empty() && uids.lines().all(|u| u.trim() != "0"), "the hub isn't root: {uids}");
        // the hub, on its new version, recorded what the updater answered
        within(Duration::from_secs(30), "the answer recorded", || {
            sh(&c, "test -f /var/lib/rackhand/update/answer.seen.json && echo yes") == "yes"
        });
        let audit = audit_actions(&c);
        assert!(audit.iter().any(|(a, d)| a == "hub.update_started" && d.contains("0.1.1")), "{audit:?}");
    }

    /// 7.5.7, E39: a release that is signed, migrates the database and never answers `/healthz`: after 2 minutes the guard stops
    /// it, puts the database from before the update back (the migrated one wouldn't open on the old version), switches back,
    /// and the old hub records the rollback and the window it lost as the first thing it audits.
    #[test]
    fn bad_update_rolls_back_and_restores_backup_when_migrated() {
        let c = hub_machine("0.1.0");
        // the "new version" raises the database's schema version (user_version is the 4 bytes at offset 60) and exits
        let broken = b"#!/bin/sh\nprintf '\\000\\000\\000\\143' | dd of=/var/lib/rackhand/hub.db bs=1 seek=60 conv=notrunc 2>/dev/null\nexit 1\n";
        publish(&c, broken, "0.1.1");
        let asked = c.root("/usr/local/bin/rackhand self-update");
        assert!(asked.status.success(), "{}", String::from_utf8_lossy(&asked.stderr));
        within(Duration::from_secs(120), "the guard switched to slot B", || running(&c) == "rackhand-b");
        within(Duration::from_secs(240), "back on slot A, answering /healthz", || {
            running(&c) == "rackhand-a" && healthy(&c)
        });
        assert_eq!(sh(&c, "/usr/local/bin/rackhand --version"), "rackhand 0.1.0");
        within(Duration::from_secs(30), "the rollback recorded", || {
            sh(&c, "test -f /var/lib/rackhand/update/rolled-back.seen.json && echo yes") == "yes"
        });
        let record: serde_json::Value =
            serde_json::from_str(&sh(&c, "cat /var/lib/rackhand/update/rolled-back.seen.json")).unwrap();
        assert_eq!(record["restored_database"], true, "{record}");
        assert_eq!((record["from"].as_str(), record["to"].as_str()), (Some("0.1.0"), Some("0.1.1")));
        assert!(record["window_to_ms"].as_i64().unwrap() > record["window_from_ms"].as_i64().unwrap());
        let audit = audit_actions(&c);
        let at = audit.iter().position(|(a, _)| a == "hub.update_rolled_back").expect("audited");
        assert!(audit[at].1.contains("\"restored_database\":true"), "{audit:?}");
        // the restored database is the one from before the update: nothing the update asked for is in it, and the rollback
        // comes after the last entry it held
        assert!(audit[..at].iter().all(|(a, _)| a != "hub.update_started"), "{audit:?}");
    }

    /// D98, AC67: the hub's user can ask for an update but can't write its binary, the slots or the link, and can't read the
    /// master key by its path.
    #[test]
    fn hub_user_cannot_write_its_binary() {
        let c = hub_machine("0.1.0");
        let _diag = Diag(&c);
        // the layout as it is after an update: slots and links
        publish(&c, &std::fs::read(hub_binary("0.1.1")).unwrap(), "0.1.1");
        assert!(c.root("/usr/local/bin/rackhand self-update").status.success());
        within(Duration::from_secs(240), "the update in place", || running(&c) == "rackhand-b" && healthy(&c));
        for target in [
            "/usr/local/bin/rackhand",
            &format!("{LIB}/rackhand-a"),
            &format!("{LIB}/rackhand-b"),
            &format!("{LIB}/rackhand"),
        ] {
            let out = c.exec(
                Some("rackhand-hub"),
                &["sh", "-c", &format!("echo '#!/bin/sh' > {target} 2>&1; ln -sf /tmp/evil {target} 2>&1")],
                None,
            );
            let said = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
            assert!(said.contains("Permission denied") || said.contains("Operation not permitted"), "{target}: {said}");
        }
        let key = c.exec(Some("rackhand-hub"), &["cat", "/etc/rackhand/master.key"], None);
        assert!(!key.status.success(), "the master key isn't readable by its path");
        assert_eq!(running(&c), "rackhand-b");
    }

    /// AC67: the relay runs as its own user under its packaged unit, like the hub; neither process is root.
    #[test]
    fn relay_and_operator_not_root() {
        let c = hub_machine("0.1.0");
        c.copy_in(&packaging("rackhand-relay.service"), "/etc/systemd/system/rackhand-relay.service");
        let out = c.root(
            "set -e; id rackhand-relay >/dev/null 2>&1 || useradd -r -U -M -d /var/lib/rackhand-relay -s /usr/sbin/nologin rackhand-relay
systemctl daemon-reload; systemctl start rackhand-relay",
        );
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        within(Duration::from_secs(30), "the relay runs", || sh(&c, "systemctl is-active rackhand-relay") == "active");
        let users = sh(&c, "ps -o uid=,args= -C rackhand");
        assert!(users.lines().any(|l| l.contains("relay run")), "{users}");
        assert!(users.lines().any(|l| l.contains("hub run")), "{users}");
        for line in users.lines() {
            assert!(!line.trim_start().starts_with("0 "), "{line}");
        }
    }
}

/// The machine as it was, when a test fails: what the hub, the updater and the guard said, and the files.
struct Diag<'a>(&'a Container);

impl Drop for Diag<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let said = sh(
                self.0,
                "journalctl -u rackhand-hub -u rackhand-updater -u rackhand-update-guard-hub --no-pager -n 80 2>&1 | cut -c1-300; \
                 ls -la /usr/local/lib/rackhand-server /usr/local/bin/rackhand /var/lib/rackhand/update 2>&1; \
                 cat /var/lib/rackhand/update/answer*.json 2>&1",
            );
            eprintln!("--- the machine ---\n{said}");
        }
    }
}
