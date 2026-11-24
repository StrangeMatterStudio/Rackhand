use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use data_encoding::BASE64;
use ed25519_dalek::SigningKey;
use rackhand_proto::helper::{HelperRequest, HelperResponse};
use rackhand_release::signing::{public, sign};
use rackhand_release::{Pinned, PublicKey};
use sha2::{Digest, Sha256};

use super::*;
use crate::helper::server::{Helper, Machine};
use crate::update::apply::Slot;
use crate::update::artifact_name;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}

fn keys() -> Vec<(Pinned, PublicKey)> {
    vec![(Pinned::Current, public(&key(), [1; 8]))]
}

#[derive(Debug, Default)]
struct Recorded {
    started: Mutex<Vec<(PathBuf, Vec<String>)>>,
    fail: Mutex<bool>,
}

impl Launcher for Arc<Recorded> {
    fn start(&self, guard: &Path, args: &[String]) -> Result<(), String> {
        if *self.fail.lock().unwrap() {
            return Err("no systemd-run".into());
        }
        self.started.lock().unwrap().push((guard.to_path_buf(), args.to_vec()));
        Ok(())
    }
}

struct Fixture {
    dir: PathBuf,
    launched: Arc<Recorded>,
    helper: Arc<Helper>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fixture {
    fn new(name: &str, keys: Vec<(Pinned, PublicKey)>) -> Fixture {
        let dir = std::env::temp_dir().join(format!("rackhand-helper-update-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = crate::update::apply::paths(&dir);
        for d in [paths.lib(), paths.spool_dir(), dir.join("var/lib/rackhand-helper")] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(paths.slot(Slot::A), b"the running probe").unwrap();
        symlink("probe-a", paths.link()).unwrap();
        let launched = Arc::new(Recorded::default());
        let mut machine = Machine::default();
        machine.roots.root = dir.clone();
        let helper = Helper::with_update(
            "0.1.0",
            crate::helper::keys::Files::default(),
            machine,
            Setup::new(keys, launched.clone()),
        );
        Fixture { dir, launched, helper }
    }

    fn spool(&self, bytes: &[u8]) {
        std::fs::write(crate::update::apply::paths(&self.dir).spool_file(), bytes).unwrap();
    }

    fn ask(&self, data: &[u8], version: &str) -> HelperResponse {
        let sig = sign(&key(), [1; 8], data, &format!("file:{} version:{version}", artifact_name()));
        let request = HelperRequest::ApplyUpdate {
            version: version.into(),
            sha256: format!("{:x}", Sha256::digest(data)),
            signature: BASE64.encode(sig.as_bytes()),
        };
        self.helper.answer(&serde_json::to_string(&request).unwrap())
    }
}

#[test]
fn an_update_starts_the_guard_from_a_copy_of_the_running_binary() {
    let f = Fixture::new("start", keys());
    f.spool(b"the new probe");
    assert_eq!(f.ask(b"the new probe", "0.1.1"), HelperResponse::UpdateStarted);
    let started = f.launched.started.lock().unwrap().clone();
    let guard = f.dir.join("var/lib/rackhand-helper/update-guard");
    assert_eq!(started, vec![(guard.clone(), vec!["probe-a".into(), "probe-b".into(), "0.1.1".into()])]);
    // the guard is the old, known-good binary, so a broken new one can't stop the rollback
    assert_eq!(std::fs::read(&guard).unwrap(), b"the running probe");
    assert_eq!(std::fs::metadata(&guard).unwrap().permissions().mode() & 0o7777, 0o700, "root's alone");
    assert_eq!(std::fs::read(crate::update::apply::paths(&f.dir).slot(Slot::B)).unwrap(), b"the new probe");
}

#[test]
fn a_refused_release_starts_no_guard_and_says_why() {
    let f = Fixture::new("refused", keys());
    f.spool(b"the new probe");
    let sig = sign(&key(), [1; 8], b"the new probe", &format!("file:{} version:0.1.1", artifact_name()));
    let wrong_hash = HelperRequest::ApplyUpdate {
        version: "0.1.1".into(),
        sha256: "00".repeat(32),
        signature: BASE64.encode(sig.as_bytes()),
    };
    let HelperResponse::Error { code, .. } = f.helper.answer(&serde_json::to_string(&wrong_hash).unwrap()) else {
        panic!("a wrong hash was accepted")
    };
    assert_eq!(code, "bad_hash");
    // not newer than 0.1.0
    f.spool(b"older");
    let HelperResponse::Error { code, .. } = f.ask(b"older", "0.1.0") else { panic!("the same version was accepted") };
    assert_eq!(code, "downgrade");
    assert!(f.launched.started.lock().unwrap().is_empty());
    assert!(!crate::update::apply::paths(&f.dir).slot(Slot::B).exists());
    assert!(!f.dir.join("var/lib/rackhand-helper/update-guard").exists());
    // and the helper isn't stuck: a good one goes through afterwards
    f.spool(b"the new probe");
    assert_eq!(f.ask(b"the new probe", "0.1.1"), HelperResponse::UpdateStarted);
}

#[test]
fn a_second_update_while_the_guard_runs_is_refused() {
    let f = Fixture::new("second", keys());
    f.spool(b"the new probe");
    assert_eq!(f.ask(b"the new probe", "0.1.1"), HelperResponse::UpdateStarted);
    f.spool(b"a newer probe");
    let HelperResponse::Error { code, .. } = f.ask(b"a newer probe", "0.1.2") else { panic!("two guards") };
    assert_eq!(code, "update_in_progress");
    assert_eq!(f.launched.started.lock().unwrap().len(), 1);
    assert_eq!(
        std::fs::read(crate::update::apply::paths(&f.dir).slot(Slot::B)).unwrap(),
        b"the new probe",
        "the slot the guard is switching to isn't touched"
    );
}

#[test]
fn a_guard_that_cannot_start_leaves_the_machine_as_it_was() {
    let f = Fixture::new("nolaunch", keys());
    f.spool(b"the new probe");
    *f.launched.fail.lock().unwrap() = true;
    let HelperResponse::Error { code, .. } = f.ask(b"the new probe", "0.1.1") else { panic!("no guard, no update") };
    assert_eq!(code, "guard_failed");
    assert_eq!(std::fs::read_link(crate::update::apply::paths(&f.dir).link()).unwrap(), PathBuf::from("probe-a"));
    *f.launched.fail.lock().unwrap() = false;
    assert_eq!(f.ask(b"the new probe", "0.1.1"), HelperResponse::UpdateStarted, "it can be tried again");
}

#[test]
fn a_build_that_pins_no_release_keys_installs_nothing() {
    let f = Fixture::new("nokeys", Vec::new());
    f.spool(b"the new probe");
    let HelperResponse::Error { code, .. } = f.ask(b"the new probe", "0.1.1") else {
        panic!("unsigned code was accepted")
    };
    assert_eq!(code, "no_keys");
    assert!(!crate::update::apply::paths(&f.dir).slot(Slot::B).exists());
}
