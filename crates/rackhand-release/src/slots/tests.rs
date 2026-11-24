use std::cell::{Cell, RefCell};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;

use data_encoding::BASE64;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use super::*;
use crate::signing::{public, sign};

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn keys() -> Vec<(Pinned, PublicKey)> {
    vec![(Pinned::Current, public(&key(0x11), [1; 8])), (Pinned::Standby, public(&key(0x22), [2; 8]))]
}

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

const ARTIFACT: &str = "rackhand-probe-x86_64-unknown-linux-musl";

/// The probe's layout (7.3.3): two slots, a link, a command wrapper and a spool of the probe's own.
fn probe_layout(root: &std::path::Path) -> Layout {
    Layout {
        root: root.to_path_buf(),
        lib: "usr/local/lib/rackhand".into(),
        slots: ["probe-a", "probe-b"],
        link: "rackhand-probe",
        wrapper: Some("run"),
        spool_dir: "var/lib/rackhand-probe/update".into(),
        spool_file: "probe",
        artifact: ARTIFACT.into(),
    }
}

/// The hub's (7.5.7): no wrapper, and its own names.
fn hub_layout(root: &std::path::Path) -> Layout {
    Layout {
        root: root.to_path_buf(),
        lib: "usr/local/lib/rackhand".into(),
        slots: ["rackhand-a", "rackhand-b"],
        link: "rackhand",
        wrapper: None,
        spool_dir: "var/lib/rackhand/update".into(),
        spool_file: "rackhand",
        artifact: "rackhand-x86_64-unknown-linux-musl".into(),
    }
}

/// A machine root with the slots, the link and the spool as the installer leaves them.
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
        Machine::with(name, probe_layout)
    }

    fn with(name: &str, layout: fn(&std::path::Path) -> Layout) -> Machine {
        let dir = std::env::temp_dir().join(format!("rackhand-slots-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = layout(&dir);
        std::fs::create_dir_all(layout.lib()).unwrap();
        std::fs::create_dir_all(layout.spool_dir()).unwrap();
        std::fs::write(layout.slot(Slot::A), b"the installed program").unwrap();
        symlink(layout.slot_name(Slot::A), layout.link()).unwrap();
        Machine { dir, layout }
    }

    fn spool(&self, bytes: &[u8]) {
        std::fs::write(self.layout.spool_file(), bytes).unwrap();
    }

    fn slot_b(&self) -> Option<Vec<u8>> {
        std::fs::read(self.layout.slot(Slot::B)).ok()
    }
}

fn comment(artifact: &str, version: &str) -> String {
    format!("file:{artifact} version:{version}")
}

fn request_for(artifact: &str, data: &[u8], signed_version: &str, claimed: &str, signer: u8) -> Request {
    let sig = sign(&key(signer), [signer / 0x11; 8], data, &comment(artifact, signed_version));
    Request {
        version: claimed.into(),
        sha256: format!("{:x}", Sha256::digest(data)),
        signature: BASE64.encode(sig.as_bytes()),
    }
}

fn request(data: &[u8], signed_version: &str, claimed: &str, signer: u8) -> Request {
    request_for(ARTIFACT, data, signed_version, claimed, signer)
}

#[test]
fn a_good_release_goes_to_the_inactive_slot_and_nothing_else_changes() {
    let m = Machine::new("good");
    m.spool(b"the new program");
    let applied =
        apply(&m.layout, &Link, v("0.1.0"), &request(b"the new program", "0.1.1", "0.1.1", 0x11), &keys()).unwrap();
    assert_eq!(applied, Applied { version: v("0.1.1"), old: Slot::A, new: Slot::B });
    assert_eq!(m.slot_b().as_deref(), Some(&b"the new program"[..]));
    assert_eq!(std::fs::metadata(m.layout.slot(Slot::B)).unwrap().permissions().mode() & 0o7777, 0o755);
    // the guard switches the link, not apply
    assert_eq!(std::fs::read_link(m.layout.link()).unwrap(), PathBuf::from("probe-a"));
    assert_eq!(std::fs::read(m.layout.slot(Slot::A)).unwrap(), b"the installed program");
    assert_eq!(std::fs::read(m.layout.spool_file()).unwrap(), b"the new program", "the spool file isn't touched");
    // from slot B the next one goes to slot A
    std::fs::remove_file(m.layout.link()).unwrap();
    symlink("probe-b", m.layout.link()).unwrap();
    m.spool(b"and a newer one");
    let applied =
        apply(&m.layout, &Link, v("0.1.1"), &request(b"and a newer one", "0.1.2", "0.1.2", 0x22), &keys()).unwrap();
    assert_eq!((applied.old, applied.new), (Slot::B, Slot::A), "signed by the standby key (E64)");
    assert_eq!(std::fs::read(m.layout.slot(Slot::A)).unwrap(), b"and a newer one");
}

#[test]
fn another_layout_uses_its_own_names_and_artifact() {
    let m = Machine::with("hub", hub_layout);
    m.spool(b"the new hub");
    let hub = "rackhand-x86_64-unknown-linux-musl";
    // a signature for the probe's file isn't one for the hub's
    let probe_signed = request_for(ARTIFACT, b"the new hub", "0.1.1", "0.1.1", 0x11);
    assert_eq!(apply(&m.layout, &Link, v("0.1.0"), &probe_signed, &keys()).unwrap_err().code, "bad_signature");
    let applied =
        apply(&m.layout, &Link, v("0.1.0"), &request_for(hub, b"the new hub", "0.1.1", "0.1.1", 0x11), &keys())
            .unwrap();
    assert_eq!((applied.old, applied.new), (Slot::A, Slot::B));
    assert_eq!(std::fs::read(m.layout.slot(Slot::B)).unwrap(), b"the new hub");
    assert!(m.layout.lib().join("rackhand-b").is_file() && !m.layout.lib().join("probe-b").exists());
    assert_eq!(std::fs::read_link(m.layout.link()).unwrap(), PathBuf::from("rackhand-a"));
}

#[test]
fn a_plain_file_from_the_installer_becomes_slot_a() {
    let m = Machine::new("plain");
    std::fs::remove_file(m.layout.link()).unwrap();
    std::fs::remove_file(m.layout.slot(Slot::A)).unwrap();
    std::fs::write(m.layout.link(), b"installed by install.sh").unwrap();
    m.spool(b"the new program");
    // a release that fails leaves the installer's file where it was
    let bad = request(b"the new program", "0.0.9", "0.0.9", 0x11);
    assert_eq!(apply(&m.layout, &Link, v("0.1.0"), &bad, &keys()).unwrap_err().code, "downgrade");
    assert_eq!(std::fs::read(m.layout.link()).unwrap(), b"installed by install.sh");
    assert!(!m.layout.slot(Slot::A).exists());
    let applied =
        apply(&m.layout, &Link, v("0.1.0"), &request(b"the new program", "0.1.1", "0.1.1", 0x11), &keys()).unwrap();
    assert_eq!((applied.old, applied.new), (Slot::A, Slot::B));
    assert_eq!(std::fs::read(m.layout.slot(Slot::A)).unwrap(), b"installed by install.sh", "kept as slot A");
    assert_eq!(std::fs::read_link(m.layout.link()).unwrap(), PathBuf::from("probe-a"));
}

#[test]
fn reads_only_fixed_spool_file_without_following_links() {
    let m = Machine::new("links");
    let req = request(b"the new program", "0.1.1", "0.1.1", 0x11);
    // a link to a well-signed file elsewhere
    let elsewhere = m.dir.join("elsewhere");
    std::fs::write(&elsewhere, b"the new program").unwrap();
    symlink(&elsewhere, m.layout.spool_file()).unwrap();
    assert_eq!(apply(&m.layout, &Link, v("0.1.0"), &req, &keys()).unwrap_err().code, "spool_unreadable");
    assert_eq!(m.slot_b(), None);
    // the spool's directory replaced by a link to one that holds a well-signed file
    std::fs::remove_file(m.layout.spool_file()).unwrap();
    std::fs::remove_dir(m.layout.spool_dir()).unwrap();
    let other = m.dir.join("other-dir");
    std::fs::create_dir(&other).unwrap();
    std::fs::write(other.join(m.layout.spool_file().file_name().unwrap()), b"the new program").unwrap();
    symlink(&other, m.layout.spool_dir()).unwrap();
    assert_eq!(apply(&m.layout, &Link, v("0.1.0"), &req, &keys()).unwrap_err().code, "spool_unreadable");
    assert_eq!(m.slot_b(), None);
    // not a regular file: a directory, and a FIFO that would block a reader
    std::fs::remove_file(m.layout.spool_dir()).unwrap();
    std::fs::create_dir(m.layout.spool_dir()).unwrap();
    std::fs::create_dir(m.layout.spool_file()).unwrap();
    assert_eq!(apply(&m.layout, &Link, v("0.1.0"), &req, &keys()).unwrap_err().code, "spool_unreadable");
    std::fs::remove_dir(m.layout.spool_file()).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        m.layout.spool_file(),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    assert_eq!(
        apply(&m.layout, &Link, v("0.1.0"), &req, &keys()).unwrap_err().code,
        "spool_unreadable",
        "a FIFO isn't read"
    );
    assert_eq!(m.slot_b(), None);
}

#[test]
fn a_release_over_the_limit_is_refused_without_being_copied() {
    let m = Machine::new("big");
    let file = std::fs::File::create(m.layout.spool_file()).unwrap();
    file.set_len(MAX_RELEASE_BYTES + 1).unwrap();
    let req = request(b"x", "0.1.1", "0.1.1", 0x11);
    assert_eq!(apply(&m.layout, &Link, v("0.1.0"), &req, &keys()).unwrap_err().code, "too_large");
    assert_eq!(m.slot_b(), None);
}

#[test]
fn downgrade_refused() {
    let m = Machine::new("downgrade");
    // a release that was really signed, older than the installed one, offered as a newer one
    m.spool(b"an old program");
    let lying = request(b"an old program", "0.1.0", "0.1.9", 0x11);
    let err = apply(&m.layout, &Link, v("0.1.5"), &lying, &keys()).unwrap_err();
    assert_eq!(err.code, "version_mismatch", "the version is the one the key signed: {err}");
    assert_eq!(m.slot_b(), None);
    // honestly offered
    let honest = request(b"an old program", "0.1.0", "0.1.0", 0x11);
    assert_eq!(apply(&m.layout, &Link, v("0.1.5"), &honest, &keys()).unwrap_err().code, "downgrade");
    assert_eq!(m.slot_b(), None);
    // the same version isn't an update
    m.spool(b"the same program");
    let same = request(b"the same program", "0.1.5", "0.1.5", 0x11);
    assert_eq!(apply(&m.layout, &Link, v("0.1.5"), &same, &keys()).unwrap_err().code, "downgrade");
    // numbers, not text: 0.1.10 is newer than 0.1.9
    m.spool(b"ten");
    let ten = request(b"ten", "0.1.10", "0.1.10", 0x11);
    assert!(apply(&m.layout, &Link, v("0.1.9"), &ten, &keys()).is_ok());
}

#[test]
fn bad_hash_or_signature_deletes_slot_copy() {
    let m = Machine::new("bad");
    m.spool(b"the new program");
    // a copy that was in the slot before is gone too
    std::fs::write(m.layout.slot(Slot::B), b"left over").unwrap();
    let mut wrong_hash = request(b"the new program", "0.1.1", "0.1.1", 0x11);
    wrong_hash.sha256 = "00".repeat(32);
    assert_eq!(apply(&m.layout, &Link, v("0.1.0"), &wrong_hash, &keys()).unwrap_err().code, "bad_hash");
    assert_eq!(m.slot_b(), None, "a failed copy is deleted");

    let other_key = request(b"the new program", "0.1.1", "0.1.1", 0x33);
    assert_eq!(apply(&m.layout, &Link, v("0.1.0"), &other_key, &keys()).unwrap_err().code, "bad_signature");
    assert_eq!(m.slot_b(), None);

    // signed, but for other bytes than the spool holds
    let other_bytes = request(b"another program", "0.1.1", "0.1.1", 0x11);
    assert_eq!(apply(&m.layout, &Link, v("0.1.0"), &other_bytes, &keys()).unwrap_err().code, "bad_hash");
    let mut rehashed = request(b"another program", "0.1.1", "0.1.1", 0x11);
    rehashed.sha256 = request(b"the new program", "0.1.1", "0.1.1", 0x11).sha256;
    assert_eq!(apply(&m.layout, &Link, v("0.1.0"), &rehashed, &keys()).unwrap_err().code, "bad_signature");

    // signed for another file
    let other_file = request_for("rackhand-cli-x86_64-unknown-linux-musl", b"the new program", "0.1.1", "0.1.1", 0x11);
    assert_eq!(apply(&m.layout, &Link, v("0.1.0"), &other_file, &keys()).unwrap_err().code, "bad_signature");

    // not base64 at all, or not a version
    let mut junk = request(b"the new program", "0.1.1", "0.1.1", 0x11);
    junk.signature = "!!".into();
    assert_eq!(apply(&m.layout, &Link, v("0.1.0"), &junk, &keys()).unwrap_err().code, "bad_signature");
    let mut no_version = request(b"the new program", "0.1.1", "0.1.1", 0x11);
    no_version.version = "latest".into();
    assert_eq!(apply(&m.layout, &Link, v("0.1.0"), &no_version, &keys()).unwrap_err().code, "bad_request");
    assert_eq!(m.slot_b(), None);
}

// ---- the guard ----

fn guard_machine(name: &str, layout: fn(&std::path::Path) -> Layout) -> Machine {
    let m = Machine::with(name, layout);
    std::fs::write(m.layout.slot(Slot::B), b"new program").unwrap();
    if let Some(wrapper) = m.layout.wrapper() {
        std::fs::write(wrapper, b"the installed program").unwrap();
    }
    m
}

fn plan(m: &Machine) -> Plan {
    Plan { layout: m.layout.clone(), old: Slot::A, new: Slot::B }
}

/// A clock that only moves when the guard sleeps; the new version is up from a given time on, or never.
struct Fake {
    now: Cell<Duration>,
    up_from: Option<Duration>,
    /// What the link pointed at at each restart, and at the rollback hook.
    at_restart: RefCell<Vec<String>>,
    at_rollback: RefCell<Vec<String>>,
    link: PathBuf,
}

impl Fake {
    fn new(m: &Machine, up_from: Option<Duration>) -> Fake {
        Fake {
            now: Cell::new(Duration::ZERO),
            up_from,
            at_restart: RefCell::new(Vec::new()),
            at_rollback: RefCell::new(Vec::new()),
            link: m.layout.link(),
        }
    }

    fn pointing(&self) -> String {
        std::fs::read_link(&self.link).unwrap().to_string_lossy().into_owned()
    }
}

impl Env for Fake {
    fn restart(&self) -> Result<(), String> {
        self.at_restart.borrow_mut().push(self.pointing());
        Ok(())
    }

    fn up(&self) -> bool {
        self.up_from.is_some_and(|from| from <= self.now.get())
    }

    fn rolling_back(&self) {
        self.at_rollback.borrow_mut().push(self.pointing());
    }

    fn sleep(&self, d: Duration) {
        self.now.set(self.now.get() + d);
    }

    fn elapsed(&self) -> Duration {
        self.now.get()
    }
}

fn running(m: &Machine) -> String {
    std::fs::read_link(m.layout.link()).unwrap().to_string_lossy().into_owned()
}

#[test]
fn a_version_that_comes_up_is_kept() {
    let m = guard_machine("kept", probe_layout);
    let env = Fake::new(&m, Some(Duration::from_secs(14)));
    assert_eq!(guard(&plan(&m), &Link, &env), Outcome::Kept);
    assert_eq!(running(&m), "probe-b");
    assert_eq!(
        std::fs::read(m.layout.wrapper().unwrap()).unwrap(),
        b"new program",
        "the wrapper is the new version too"
    );
    assert_eq!(*env.at_restart.borrow(), ["probe-b"], "the services were restarted after the switch");
    assert!(env.at_rollback.borrow().is_empty());
    assert!(env.elapsed() < Duration::from_secs(20), "it stops waiting when the new version is up");
}

#[test]
fn broken_release_restored_within_two_minutes() {
    let m = guard_machine("broken", probe_layout);
    let env = Fake::new(&m, None);
    assert_eq!(guard(&plan(&m), &Link, &env), Outcome::RolledBack);
    assert_eq!(running(&m), "probe-a");
    assert_eq!(std::fs::read(m.layout.wrapper().unwrap()).unwrap(), b"the installed program");
    assert_eq!(*env.at_restart.borrow(), ["probe-b", "probe-a"], "restarted onto the new, then back onto the old");
    assert_eq!(*env.at_rollback.borrow(), ["probe-b"], "the hook runs while the new slot is still the one in use");
    assert!(
        env.elapsed() >= GUARD_TIMEOUT && env.elapsed() < GUARD_TIMEOUT + Duration::from_secs(10),
        "{:?}",
        env.elapsed()
    );
    assert_eq!(
        std::fs::read(m.layout.slot(Slot::B)).unwrap(),
        b"new program",
        "the failed slot is left for inspection"
    );
}

#[test]
fn a_layout_without_a_wrapper_switches_just_the_link() {
    let m = guard_machine("nowrapper", hub_layout);
    let env = Fake::new(&m, Some(Duration::ZERO));
    assert_eq!(guard(&plan(&m), &Link, &env), Outcome::Kept);
    assert_eq!(running(&m), "rackhand-b");
    assert!(m.layout.wrapper().is_none());
}

#[test]
fn a_switch_that_cannot_be_made_changes_nothing_and_restarts_nothing() {
    let m = guard_machine("noswitch", probe_layout);
    std::fs::remove_file(m.layout.slot(Slot::B)).unwrap();
    let env = Fake::new(&m, Some(Duration::ZERO));
    assert_eq!(guard(&plan(&m), &Link, &env), Outcome::NotSwitched);
    assert_eq!(running(&m), "probe-a");
    assert!(env.at_restart.borrow().is_empty());
}

/// 7.5.7: the updater reads the hub's request, the release's signature and its manifest from the spool the same way it reads
/// the release: by name, without following a link, and up to a limit.
#[test]
fn a_small_spool_file_is_read_by_name_without_following_links() {
    let m = Machine::with("small", hub_layout);
    std::fs::write(m.layout.spool_dir().join("request.json"), br#"{"version":"0.1.1"}"#).unwrap();
    assert_eq!(m.layout.read_spool("request.json", 4096).unwrap(), br#"{"version":"0.1.1"}"#);
    std::fs::write(m.layout.spool_dir().join("big.json"), vec![b' '; 5000]).unwrap();
    assert_eq!(m.layout.read_spool("big.json", 4096).unwrap_err().code, "too_large");
    let secret = m.dir.join("secret");
    std::fs::write(&secret, b"root's").unwrap();
    symlink(&secret, m.layout.spool_dir().join("answer.json")).unwrap();
    assert_eq!(m.layout.read_spool("answer.json", 4096).unwrap_err().code, "spool_unreadable");
    for name in ["../secret", "/etc/passwd", "..", ""] {
        assert_eq!(m.layout.read_spool(name, 4096).unwrap_err().code, "bad_request", "{name}");
    }
}
