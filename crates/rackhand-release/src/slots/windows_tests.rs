//! The slots on Windows (7.3.3): the same copy and checks as on Linux, the spool opened without following a junction or a
//! link, and an activation that stands in for the services' binary path. Run on a Windows machine (cross-built, MV16).

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use data_encoding::BASE64;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use super::*;
use crate::signing::{public, sign};

const ARTIFACT: &str = "rackhand-probe-x86_64-pc-windows-gnu.exe";

fn keys() -> Vec<(Pinned, PublicKey)> {
    vec![(Pinned::Current, public(&SigningKey::from_bytes(&[0x11; 32]), [1; 8]))]
}

fn request(data: &[u8], version: &str) -> Request {
    let sig = sign(&SigningKey::from_bytes(&[0x11; 32]), [1; 8], data, &format!("file:{ARTIFACT} version:{version}"));
    Request {
        version: version.into(),
        sha256: format!("{:x}", Sha256::digest(data)),
        signature: BASE64.encode(sig.as_bytes()),
    }
}

/// What the services run, kept in memory: the installer's file to begin with.
#[derive(Default)]
struct FakeServices {
    running: RefCell<Option<Slot>>,
}

impl Activation for FakeServices {
    fn active(&self, _layout: &Layout) -> Result<Option<Slot>, ApplyError> {
        Ok(*self.running.borrow())
    }

    fn point_at(&self, _layout: &Layout, slot: Slot) -> std::io::Result<()> {
        *self.running.borrow_mut() = Some(slot);
        Ok(())
    }
}

struct Machine {
    dir: PathBuf,
    layout: Layout,
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Machine {
    fn new(name: &str) -> Machine {
        let dir = std::env::temp_dir().join(format!("rackhand-slots-win-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = Layout {
            root: PathBuf::new(),
            lib: dir.join("Program Files").join("Rackhand"),
            slots: ["probe-a.exe", "probe-b.exe"],
            link: "rackhand-probe.exe",
            wrapper: None,
            spool_dir: dir.join("ProgramData").join("Rackhand").join("probe").join("update"),
            spool_file: "probe",
            artifact: ARTIFACT.into(),
            max_bytes: MAX_RELEASE_BYTES,
        };
        std::fs::create_dir_all(layout.lib()).unwrap();
        std::fs::create_dir_all(layout.spool_dir()).unwrap();
        std::fs::write(layout.link(), b"installed by install.ps1").unwrap();
        Machine { dir, layout }
    }
}

fn junction(link: &Path, target: &Path) {
    let out = std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(link).arg(target).output().unwrap();
    assert!(out.status.success(), "mklink /J: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn the_installers_file_becomes_slot_a_and_the_release_goes_to_slot_b() {
    let m = Machine::new("good");
    let services = FakeServices::default();
    std::fs::write(m.layout.spool_file(), b"the new probe").unwrap();
    let applied = apply(&m.layout, &services, Version(0, 1, 0), &request(b"the new probe", "0.1.1"), &keys()).unwrap();
    assert_eq!((applied.old, applied.new), (Slot::A, Slot::B));
    assert_eq!(std::fs::read(m.layout.slot(Slot::A)).unwrap(), b"installed by install.ps1");
    assert_eq!(std::fs::read(m.layout.slot(Slot::B)).unwrap(), b"the new probe");
    assert_eq!(*services.running.borrow(), Some(Slot::A), "the services run slot A until the guard switches");
    // and the next one goes to slot A
    *services.running.borrow_mut() = Some(Slot::B);
    std::fs::write(m.layout.spool_file(), b"a newer probe").unwrap();
    let applied = apply(&m.layout, &services, Version(0, 1, 1), &request(b"a newer probe", "0.1.2"), &keys()).unwrap();
    assert_eq!((applied.old, applied.new), (Slot::B, Slot::A));
}

#[test]
fn a_junction_in_the_spool_is_not_followed() {
    let m = Machine::new("junction");
    let services = FakeServices::default();
    // the spool directory replaced by a junction to a directory that holds a well-signed file
    let elsewhere = m.dir.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("probe"), b"the new probe").unwrap();
    std::fs::remove_dir_all(m.layout.spool_dir()).unwrap();
    junction(&m.layout.spool_dir(), &elsewhere);
    let err = apply(&m.layout, &services, Version(0, 1, 0), &request(b"the new probe", "0.1.1"), &keys()).unwrap_err();
    assert_eq!(err.code, "spool_unreadable", "{err}");
    assert!(!m.layout.slot(Slot::B).exists());
    // a junction higher up, too
    std::fs::remove_dir(m.layout.spool_dir()).unwrap();
    let probe_dir = m.layout.spool_dir().parent().unwrap().to_path_buf();
    std::fs::remove_dir_all(&probe_dir).unwrap();
    let other = m.dir.join("other");
    std::fs::create_dir_all(other.join("update")).unwrap();
    std::fs::write(other.join("update").join("probe"), b"the new probe").unwrap();
    junction(&probe_dir, &other);
    let err = apply(&m.layout, &services, Version(0, 1, 0), &request(b"the new probe", "0.1.1"), &keys()).unwrap_err();
    assert_eq!(err.code, "spool_unreadable", "{err}");
    assert!(!m.layout.slot(Slot::B).exists());
}

#[test]
fn a_directory_as_the_spool_file_or_a_file_over_the_limit_is_refused() {
    let m = Machine::new("notfile");
    let services = FakeServices::default();
    std::fs::create_dir_all(m.layout.spool_file()).unwrap();
    let err = apply(&m.layout, &services, Version(0, 1, 0), &request(b"x", "0.1.1"), &keys()).unwrap_err();
    assert_eq!(err.code, "spool_unreadable");
    std::fs::remove_dir(m.layout.spool_file()).unwrap();
    std::fs::File::create(m.layout.spool_file()).unwrap().set_len(MAX_RELEASE_BYTES + 1).unwrap();
    let err = apply(&m.layout, &services, Version(0, 1, 0), &request(b"x", "0.1.1"), &keys()).unwrap_err();
    assert_eq!(err.code, "too_large");
}

#[test]
fn the_guard_switches_the_services_and_goes_back() {
    struct Never;
    impl Env for Never {
        fn restart(&self) -> Result<(), String> {
            Ok(())
        }
        fn up(&self) -> bool {
            false
        }
        fn rolling_back(&self) {}
        fn sleep(&self, _d: Duration) {}
        fn elapsed(&self) -> Duration {
            GUARD_TIMEOUT
        }
    }
    let m = Machine::new("guard");
    std::fs::write(m.layout.slot(Slot::A), b"a").unwrap();
    std::fs::write(m.layout.slot(Slot::B), b"b").unwrap();
    let services = FakeServices { running: RefCell::new(Some(Slot::A)) };
    let plan = Plan { layout: m.layout.clone(), old: Slot::A, new: Slot::B };
    assert_eq!(guard(&plan, &services, &Never), Outcome::RolledBack);
    assert_eq!(*services.running.borrow(), Some(Slot::A));
}
