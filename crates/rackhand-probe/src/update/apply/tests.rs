use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;

use data_encoding::BASE64;
use ed25519_dalek::SigningKey;
use rackhand_release::signing::{public, sign};
use sha2::{Digest, Sha256};

use super::*;
use crate::update::artifact_name;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn keys() -> Vec<(Pinned, PublicKey)> {
    vec![(Pinned::Current, public(&key(0x11), [1; 8])), (Pinned::Standby, public(&key(0x22), [2; 8]))]
}

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

/// A machine root with the slots, the link and the spool as the installer leaves them.
struct Machine {
    dir: PathBuf,
    paths: Paths,
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Machine {
    fn new(name: &str) -> Machine {
        let dir = std::env::temp_dir().join(format!("rackhand-apply-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = Paths::new(&dir);
        std::fs::create_dir_all(paths.lib()).unwrap();
        std::fs::create_dir_all(paths.spool_dir()).unwrap();
        std::fs::write(paths.slot(Slot::A), b"the installed probe").unwrap();
        symlink("probe-a", paths.link()).unwrap();
        Machine { dir, paths }
    }

    fn spool(&self, bytes: &[u8]) {
        std::fs::write(self.paths.spool_file(), bytes).unwrap();
    }

    fn slot_b(&self) -> Option<Vec<u8>> {
        std::fs::read(self.paths.slot(Slot::B)).ok()
    }
}

fn comment(version: &str) -> String {
    format!("file:{} version:{version}", artifact_name())
}

fn request(data: &[u8], signed_version: &str, claimed: &str, signer: u8) -> Request {
    let sig = sign(&key(signer), [signer / 0x11; 8], data, &comment(signed_version));
    Request {
        version: claimed.into(),
        sha256: format!("{:x}", Sha256::digest(data)),
        signature: BASE64.encode(sig.as_bytes()),
    }
}

#[test]
fn a_good_release_goes_to_the_inactive_slot_and_nothing_else_changes() {
    let m = Machine::new("good");
    m.spool(b"the new probe");
    let applied = apply(&m.paths, v("0.1.0"), &request(b"the new probe", "0.1.1", "0.1.1", 0x11), &keys()).unwrap();
    assert_eq!(applied, Applied { version: v("0.1.1"), old: Slot::A, new: Slot::B });
    assert_eq!(m.slot_b().as_deref(), Some(&b"the new probe"[..]));
    assert_eq!(std::fs::metadata(m.paths.slot(Slot::B)).unwrap().permissions().mode() & 0o7777, 0o755);
    // the guard switches the link, not the helper's apply
    assert_eq!(std::fs::read_link(m.paths.link()).unwrap(), PathBuf::from("probe-a"));
    assert_eq!(std::fs::read(m.paths.slot(Slot::A)).unwrap(), b"the installed probe");
    assert_eq!(
        std::fs::read(m.paths.spool_file()).unwrap(),
        b"the new probe",
        "the spool file is the probe's to clean"
    );
    // from slot B the next one goes to slot A
    std::fs::remove_file(m.paths.link()).unwrap();
    symlink("probe-b", m.paths.link()).unwrap();
    m.spool(b"and a newer one");
    let applied = apply(&m.paths, v("0.1.1"), &request(b"and a newer one", "0.1.2", "0.1.2", 0x22), &keys()).unwrap();
    assert_eq!((applied.old, applied.new), (Slot::B, Slot::A), "signed by the standby key (E64)");
    assert_eq!(std::fs::read(m.paths.slot(Slot::A)).unwrap(), b"and a newer one");
}

#[test]
fn a_plain_file_from_the_installer_becomes_slot_a() {
    let m = Machine::new("plain");
    std::fs::remove_file(m.paths.link()).unwrap();
    std::fs::remove_file(m.paths.slot(Slot::A)).unwrap();
    std::fs::write(m.paths.link(), b"installed by install.sh").unwrap();
    m.spool(b"the new probe");
    // a release that fails leaves the installer's file where it was
    let bad = request(b"the new probe", "0.0.9", "0.0.9", 0x11);
    assert_eq!(apply(&m.paths, v("0.1.0"), &bad, &keys()).unwrap_err().code, "downgrade");
    assert_eq!(std::fs::read(m.paths.link()).unwrap(), b"installed by install.sh");
    assert!(!m.paths.slot(Slot::A).exists());
    let applied = apply(&m.paths, v("0.1.0"), &request(b"the new probe", "0.1.1", "0.1.1", 0x11), &keys()).unwrap();
    assert_eq!((applied.old, applied.new), (Slot::A, Slot::B));
    assert_eq!(std::fs::read(m.paths.slot(Slot::A)).unwrap(), b"installed by install.sh", "kept as slot A");
    assert_eq!(std::fs::read_link(m.paths.link()).unwrap(), PathBuf::from("probe-a"));
}

#[test]
fn reads_only_fixed_spool_file_without_following_links() {
    let m = Machine::new("links");
    let req = request(b"the new probe", "0.1.1", "0.1.1", 0x11);
    // a link to a well-signed file elsewhere
    let elsewhere = m.dir.join("elsewhere");
    std::fs::write(&elsewhere, b"the new probe").unwrap();
    symlink(&elsewhere, m.paths.spool_file()).unwrap();
    assert_eq!(apply(&m.paths, v("0.1.0"), &req, &keys()).unwrap_err().code, "spool_unreadable");
    assert_eq!(m.slot_b(), None);
    // the spool's directory replaced by a link to one that holds a well-signed file
    std::fs::remove_file(m.paths.spool_file()).unwrap();
    std::fs::remove_dir(m.paths.spool_dir()).unwrap();
    let other = m.dir.join("other-dir");
    std::fs::create_dir(&other).unwrap();
    std::fs::write(other.join(m.paths.spool_file().file_name().unwrap()), b"the new probe").unwrap();
    symlink(&other, m.paths.spool_dir()).unwrap();
    assert_eq!(apply(&m.paths, v("0.1.0"), &req, &keys()).unwrap_err().code, "spool_unreadable");
    assert_eq!(m.slot_b(), None);
    // not a regular file: a directory, and a FIFO that would block a reader
    std::fs::remove_file(m.paths.spool_dir()).unwrap();
    std::fs::create_dir(m.paths.spool_dir()).unwrap();
    std::fs::create_dir(m.paths.spool_file()).unwrap();
    assert_eq!(apply(&m.paths, v("0.1.0"), &req, &keys()).unwrap_err().code, "spool_unreadable");
    std::fs::remove_dir(m.paths.spool_file()).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        m.paths.spool_file(),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    assert_eq!(apply(&m.paths, v("0.1.0"), &req, &keys()).unwrap_err().code, "spool_unreadable", "a FIFO isn't read");
    assert_eq!(m.slot_b(), None);
}

#[test]
fn a_release_over_the_limit_is_refused_without_being_copied() {
    let m = Machine::new("big");
    let file = std::fs::File::create(m.paths.spool_file()).unwrap();
    file.set_len(crate::update::MAX_RELEASE_BYTES + 1).unwrap();
    let req = request(b"x", "0.1.1", "0.1.1", 0x11);
    assert_eq!(apply(&m.paths, v("0.1.0"), &req, &keys()).unwrap_err().code, "too_large");
    assert_eq!(m.slot_b(), None);
}

#[test]
fn downgrade_refused() {
    let m = Machine::new("downgrade");
    // a release that was really signed, older than the installed one, offered as a newer one
    m.spool(b"an old probe");
    let lying = request(b"an old probe", "0.1.0", "0.1.9", 0x11);
    let err = apply(&m.paths, v("0.1.5"), &lying, &keys()).unwrap_err();
    assert_eq!(err.code, "version_mismatch", "the version is the one the key signed: {err}");
    assert_eq!(m.slot_b(), None);
    // honestly offered
    let honest = request(b"an old probe", "0.1.0", "0.1.0", 0x11);
    assert_eq!(apply(&m.paths, v("0.1.5"), &honest, &keys()).unwrap_err().code, "downgrade");
    assert_eq!(m.slot_b(), None);
    // the same version isn't an update
    m.spool(b"the same probe");
    let same = request(b"the same probe", "0.1.5", "0.1.5", 0x11);
    assert_eq!(apply(&m.paths, v("0.1.5"), &same, &keys()).unwrap_err().code, "downgrade");
    // numbers, not text: 0.1.10 is newer than 0.1.9
    m.spool(b"ten");
    let ten = request(b"ten", "0.1.10", "0.1.10", 0x11);
    assert!(apply(&m.paths, v("0.1.9"), &ten, &keys()).is_ok());
}

#[test]
fn bad_hash_or_signature_deletes_slot_copy() {
    let m = Machine::new("bad");
    m.spool(b"the new probe");
    // a copy that was in the slot before is gone too
    std::fs::write(m.paths.slot(Slot::B), b"left over").unwrap();
    let mut wrong_hash = request(b"the new probe", "0.1.1", "0.1.1", 0x11);
    wrong_hash.sha256 = "00".repeat(32);
    assert_eq!(apply(&m.paths, v("0.1.0"), &wrong_hash, &keys()).unwrap_err().code, "bad_hash");
    assert_eq!(m.slot_b(), None, "a failed copy is deleted");

    let other_key = request(b"the new probe", "0.1.1", "0.1.1", 0x33);
    assert_eq!(apply(&m.paths, v("0.1.0"), &other_key, &keys()).unwrap_err().code, "bad_signature");
    assert_eq!(m.slot_b(), None);

    // signed, but for other bytes than the spool holds
    let other_bytes = request(b"another probe", "0.1.1", "0.1.1", 0x11);
    assert_eq!(apply(&m.paths, v("0.1.0"), &other_bytes, &keys()).unwrap_err().code, "bad_hash");
    let mut rehashed = request(b"another probe", "0.1.1", "0.1.1", 0x11);
    rehashed.sha256 = request(b"the new probe", "0.1.1", "0.1.1", 0x11).sha256;
    assert_eq!(apply(&m.paths, v("0.1.0"), &rehashed, &keys()).unwrap_err().code, "bad_signature");

    // signed for another file
    let sig = sign(&key(0x11), [1; 8], b"the new probe", "file:rackhand-cli-x86_64-unknown-linux-musl version:0.1.1");
    let mut other_file = request(b"the new probe", "0.1.1", "0.1.1", 0x11);
    other_file.signature = BASE64.encode(sig.as_bytes());
    assert_eq!(apply(&m.paths, v("0.1.0"), &other_file, &keys()).unwrap_err().code, "bad_signature");

    // not base64 at all, or not a version
    let mut junk = request(b"the new probe", "0.1.1", "0.1.1", 0x11);
    junk.signature = "!!".into();
    assert_eq!(apply(&m.paths, v("0.1.0"), &junk, &keys()).unwrap_err().code, "bad_signature");
    let mut no_version = request(b"the new probe", "0.1.1", "0.1.1", 0x11);
    no_version.version = "latest".into();
    assert_eq!(apply(&m.paths, v("0.1.0"), &no_version, &keys()).unwrap_err().code, "bad_request");
    assert_eq!(m.slot_b(), None);
}
