use std::cell::RefCell;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use rackhand_release::binary::Version;
use rackhand_release::manifest::Manifest;
use rackhand_release::signing::{public, sign};
use rackhand_release::{Pinned, PublicKey};

use super::apply::{Launcher, run};
use super::request::version_of;
use super::*;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

/// The keys this updater pins in the tests: current 0x11, standby 0x22.
fn keys() -> Vec<(Pinned, PublicKey)> {
    vec![(Pinned::Current, public(&key(0x11), [1; 8])), (Pinned::Standby, public(&key(0x22), [2; 8]))]
}

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

#[derive(Default)]
struct Fake {
    started: RefCell<Vec<(String, PathBuf, Vec<String>)>>,
    running: bool,
}

impl Launcher for Fake {
    fn start(&self, unit: &str, guard: &Path, args: &[String]) -> Result<(), String> {
        self.started.borrow_mut().push((unit.to_string(), guard.to_path_buf(), args.to_vec()));
        Ok(())
    }

    fn running(&self, _unit: &str) -> bool {
        self.running
    }
}

/// A hub machine as it was installed before there were slots: the binary at `/usr/local/bin/rackhand`, the hub's state
/// directory, its spool.
struct Machine {
    dir: PathBuf,
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Machine {
    fn new(name: &str) -> Machine {
        let dir = std::env::temp_dir().join(format!("rackhand-updater-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("usr/local/bin")).unwrap();
        std::fs::create_dir_all(dir.join(spool_dir(Component::Hub))).unwrap();
        std::fs::write(dir.join(BIN), b"the installed hub").unwrap();
        Machine { dir }
    }

    fn spool(&self) -> PathBuf {
        self.dir.join(spool_dir(Component::Hub))
    }

    /// A release in the spool as `rackhand self-update` leaves it: the file signed by `file_key` with `version`, a manifest of
    /// `manifest_version` signed by `manifest_key`, and a request.
    fn release(&self, bytes: &[u8], version: &str, manifest_version: &str, keys: (u8, u8), request: &str) {
        let (file_key, manifest_key) = keys;
        let spool = self.spool();
        let name = artifact();
        let sig = sign(&key(file_key), [file_key / 0x11; 8], bytes, &format!("file:{name} version:{version}"));
        std::fs::write(spool.join("rackhand"), bytes).unwrap();
        std::fs::write(spool.join("rackhand.minisig"), sig).unwrap();
        let manifest = Manifest::new(manifest_version, [(name.clone(), bytes)]).to_json();
        let msig =
            sign(&key(manifest_key), [manifest_key / 0x11; 8], manifest.as_bytes(), "file:manifest.json version:0");
        std::fs::write(spool.join(MANIFEST), &manifest).unwrap();
        std::fs::write(spool.join(MANIFEST_SIG), msig).unwrap();
        std::fs::write(spool.join(REQUEST), request).unwrap();
    }

    fn slot(&self, name: &str) -> Option<Vec<u8>> {
        std::fs::read(self.dir.join(LIB).join(name)).ok()
    }
}

#[test]
fn request_only_version_trusted() {
    // a request that names paths, hashes and other files: only its version is read
    let request = r#"{"version":"0.1.1","path":"/etc/shadow","file":"../../etc/passwd","sha256":"00","signature":"x"}"#;
    assert_eq!(version_of(request.as_bytes()).unwrap(), v("0.1.1"));
    for bad in [r#"{"path":"/etc/shadow"}"#, r#"{"version":"latest"}"#, "not json", r#"{"version":1}"#] {
        assert_eq!(version_of(bad.as_bytes()).unwrap_err().code, "bad_request", "{bad}");
    }
    // and an update made from such a request uses the spool's fixed files and the signed manifest's hash
    let m = Machine::new("only-version");
    m.release(b"the new hub", "0.1.1", "0.1.1", (0x11, 0x11), request);
    let launcher = Fake::default();
    let answer = run(&m.dir, Component::Hub, v("0.1.0"), &keys(), &launcher, 7);
    assert!(answer.ok, "{answer:?}");
    assert_eq!((answer.code.as_str(), answer.version.as_deref(), answer.at_ms), ("started", Some("0.1.1"), 7));
    assert_eq!(m.slot("rackhand-b").as_deref(), Some(&b"the new hub"[..]));
    assert!(!m.spool().join(REQUEST).exists(), "the request is answered once");
    let written: request::Answer = serde_json::from_slice(&std::fs::read(m.spool().join(ANSWER)).unwrap()).unwrap();
    assert_eq!(written, answer);
}

#[test]
fn unsigned_or_lower_version_refused_no_slot_change_audited() {
    // the release's bytes, its version, the manifest's version, the file's and the manifest's signing keys, the request
    type Release<'a> = (&'a [u8], &'a str, &'a str, (u8, u8), &'a str);
    let cases: [(&str, Release<'_>, &str); 4] = [
        // the manifest signed by a key this updater doesn't pin
        ("other key", (b"the new hub", "0.1.1", "0.1.1", (0x11, 0x33), r#"{"version":"0.1.1"}"#), "bad_signature"),
        // the file signed by one
        ("file other key", (b"the new hub", "0.1.1", "0.1.1", (0x33, 0x11), r#"{"version":"0.1.1"}"#), "bad_signature"),
        // a release that isn't newer than the installed one
        ("lower", (b"an old hub", "0.1.0", "0.1.0", (0x11, 0x11), r#"{"version":"0.1.0"}"#), "downgrade"),
        // a request for another version than the manifest's
        ("mismatch", (b"the new hub", "0.1.1", "0.1.1", (0x11, 0x11), r#"{"version":"0.1.2"}"#), "version_mismatch"),
    ];
    for (name, (bytes, version, manifest_version, keys_used, request), code) in cases {
        let m = Machine::new(&format!("refused-{}", name.replace(' ', "-")));
        m.release(bytes, version, manifest_version, keys_used, request);
        let launcher = Fake::default();
        let answer = run(&m.dir, Component::Hub, v("0.1.0"), &keys(), &launcher, 9);
        assert!(!answer.ok, "{name}: {answer:?}");
        assert_eq!(answer.code, code, "{name}: {answer:?}");
        assert!(m.slot("rackhand-b").is_none(), "{name}: no slot changes");
        assert!(launcher.started.borrow().is_empty(), "{name}: no guard");
        assert!(!m.spool().join(REQUEST).exists(), "{name}");
        // the hub records the refusal in its audit log when it next looks
        let recorded = ask::outcomes(&m.spool());
        assert_eq!(recorded.len(), 1, "{name}");
        assert_eq!(recorded[0].0, "hub.update_refused");
        assert_eq!(recorded[0].1["code"], code);
    }
    // a file changed after the manifest was signed
    let m = Machine::new("refused-tampered");
    m.release(b"the new hub", "0.1.1", "0.1.1", (0x11, 0x11), r#"{"version":"0.1.1"}"#);
    std::fs::write(m.spool().join("rackhand"), b"the new hub, changed").unwrap();
    let answer = run(&m.dir, Component::Hub, v("0.1.0"), &keys(), &Fake::default(), 9);
    assert_eq!(answer.code, "bad_hash", "{answer:?}");
    assert!(m.slot("rackhand-b").is_none());
}

#[test]
fn standby_key_release_accepted() {
    let m = Machine::new("standby");
    m.release(b"the new hub", "0.1.1", "0.1.1", (0x22, 0x22), r#"{"version":"0.1.1"}"#);
    let launcher = Fake::default();
    let answer = run(&m.dir, Component::Hub, v("0.1.0"), &keys(), &launcher, 1);
    assert!(answer.ok, "{answer:?}");
    // the installer's binary became slot A, the release slot B, and the units' path a link to the slots' link
    assert_eq!(m.slot("rackhand-a").as_deref(), Some(&b"the installed hub"[..]));
    assert_eq!(m.slot("rackhand-b").as_deref(), Some(&b"the new hub"[..]));
    assert_eq!(std::fs::read_link(m.dir.join(LIB).join("rackhand")).unwrap(), PathBuf::from("rackhand-a"));
    assert_eq!(std::fs::read_link(m.dir.join(BIN)).unwrap(), m.dir.join(LIB).join("rackhand"));
    let started = launcher.started.borrow();
    assert_eq!(started.len(), 1);
    let (unit, guard, args) = &started[0];
    assert_eq!(unit, "rackhand-update-guard-hub");
    assert_eq!(args, &["hub", "rackhand-a", "rackhand-b", "0.1.1"]);
    assert_eq!(std::fs::read(guard).unwrap(), b"the installed hub", "the guard is the running, known-good binary");
    assert!(guard.starts_with(m.dir.join(UPDATER)));
}

#[test]
fn a_second_update_while_a_guard_runs_is_refused() {
    let m = Machine::new("busy");
    m.release(b"the new hub", "0.1.1", "0.1.1", (0x11, 0x11), r#"{"version":"0.1.1"}"#);
    let launcher = Fake { running: true, ..Fake::default() };
    let answer = run(&m.dir, Component::Hub, v("0.1.0"), &keys(), &launcher, 1);
    assert_eq!(answer.code, "update_in_progress");
    assert!(m.slot("rackhand-b").is_none());
    assert!(std::fs::symlink_metadata(m.dir.join(BIN)).unwrap().is_file(), "nothing was moved either");
}

#[test]
fn a_rollback_puts_the_database_from_before_the_update_back() {
    let m = Machine::new("restore");
    let data = Path::new("var/lib/rackhand");
    std::fs::write(m.dir.join(data).join("hub.db"), b"migrated by the new version").unwrap();
    std::fs::write(m.dir.join(data).join("hub.db-wal"), b"its journal").unwrap();
    std::fs::write(m.dir.join(data).join("hub.db-shm"), b"its index").unwrap();
    // no copy in the spool: nothing to put back
    assert!(!guard::restore_database(&m.dir, data).unwrap());
    assert_eq!(std::fs::read(m.dir.join(data).join("hub.db")).unwrap(), b"migrated by the new version");
    // a link as the copy isn't followed
    let elsewhere = m.dir.join("elsewhere.db");
    std::fs::write(&elsewhere, b"someone else's").unwrap();
    std::os::unix::fs::symlink(&elsewhere, m.spool().join(PRE_UPDATE_DB)).unwrap();
    assert!(!guard::restore_database(&m.dir, data).unwrap());
    std::fs::remove_file(m.spool().join(PRE_UPDATE_DB)).unwrap();
    // the hub's copy goes back and the new version's journal goes
    std::fs::write(m.spool().join(PRE_UPDATE_DB), b"the database before the update").unwrap();
    assert!(guard::restore_database(&m.dir, data).unwrap());
    assert_eq!(std::fs::read(m.dir.join(data).join("hub.db")).unwrap(), b"the database before the update");
    assert!(!m.dir.join(data).join("hub.db-wal").exists() && !m.dir.join(data).join("hub.db-shm").exists());
}

#[test]
fn what_the_updater_and_the_guard_said_is_recorded_once_rollback_first() {
    let m = Machine::new("outcomes");
    let rolled = request::RolledBack {
        from: "0.1.0".into(),
        to: "0.1.1".into(),
        restored_database: true,
        window_from_ms: 100,
        window_to_ms: 220,
    };
    std::fs::write(m.spool().join(ROLLED_BACK), serde_json::to_string(&rolled).unwrap()).unwrap();
    let answer = request::Answer {
        ok: true,
        version: Some("0.1.1".into()),
        code: "started".into(),
        message: "".into(),
        at_ms: 90,
    };
    std::fs::write(m.spool().join(ANSWER), serde_json::to_string(&answer).unwrap()).unwrap();
    let recorded = ask::outcomes(&m.spool());
    let actions: Vec<&str> = recorded.iter().map(|(a, _)| *a).collect();
    assert_eq!(actions, ["hub.update_rolled_back", "hub.update_started"]);
    assert_eq!(recorded[0].1["window_from_ms"], 100);
    assert_eq!(recorded[0].1["window_to_ms"], 220);
    assert!(ask::outcomes(&m.spool()).is_empty(), "recorded once");
    assert!(m.spool().join(ask::ROLLED_BACK_SEEN).exists(), "kept for the dashboard");
}

#[test]
fn the_guard_takes_a_component_and_its_slots_only() {
    let (component, plan, version) =
        guard::parse_args(Path::new("/"), &["hub", "rackhand-a", "rackhand-b", "0.1.1"]).unwrap();
    assert_eq!((component, plan.layout.slot_name(plan.new), version), (Component::Hub, "rackhand-b", v("0.1.1")));
    for bad in [
        vec!["hub", "rackhand-a", "rackhand-a", "0.1.1"],
        vec!["hub", "probe-a", "probe-b", "0.1.1"],
        vec!["root", "rackhand-a", "rackhand-b", "0.1.1"],
        vec!["hub", "rackhand-a", "rackhand-b", "latest"],
        vec!["hub", "rackhand-a", "rackhand-b"],
    ] {
        assert!(guard::parse_args(Path::new("/"), &bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_machine_with_slots_already_is_left_as_it_is() {
    let m = Machine::new("prepared");
    prepare(&m.dir).unwrap();
    let link = std::fs::read_link(m.dir.join(BIN)).unwrap();
    prepare(&m.dir).unwrap();
    assert_eq!(std::fs::read_link(m.dir.join(BIN)).unwrap(), link);
    assert_eq!(std::fs::read(m.dir.join(LIB).join("rackhand")).unwrap(), b"the installed hub");
}
