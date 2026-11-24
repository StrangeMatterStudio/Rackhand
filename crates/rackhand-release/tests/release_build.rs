//! 13, D90: what a release build pins. The test keys of `tests/keys/` exist so tests can sign; a build made the way a release is
//! made (`RACKHAND_RELEASE=1`, no `test-keys`) must refuse what they sign, and can't be made at all with `test-keys` in it. A
//! workspace-wide `--all-targets` build can unify `test-keys` in, so each build here is a cargo run of its own, into its own
//! target directory.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ed25519_dalek::SigningKey;
use rackhand_release::signing::sign;

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
}

fn target(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("rackhand-release-build-{name}-{}", std::process::id()))
}

/// `cargo build` of the verifier the way a release or a lab build makes it.
fn build(name: &str, release: bool, features: &[&str]) -> (bool, String, PathBuf) {
    let dir = target(name);
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.args(["build", "--bin", "rackhand-verify", "--manifest-path"]).arg(manifest()).arg("--target-dir").arg(&dir);
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }
    // the settings of the test run's own cargo must not leak into these builds
    cmd.env_remove("RACKHAND_RELEASE").env_remove("CARGO_ENCODED_RUSTFLAGS").env_remove("RUSTFLAGS");
    if release {
        cmd.env("RACKHAND_RELEASE", "1");
    }
    let out = cmd.output().unwrap();
    let log = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), log, dir.join("debug/rackhand-verify"))
}

fn test_key(name: &str) -> SigningKey {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys");
    let seed = std::fs::read_to_string(dir.join(format!("test-{name}.seed"))).unwrap();
    let bytes: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&seed.trim()[2 * i..2 * i + 2], 16).unwrap()).collect();
    SigningKey::from_bytes(&bytes.try_into().unwrap())
}

fn signed_file(name: &str) -> (PathBuf, PathBuf) {
    let dir = target(&format!("files-{name}"));
    std::fs::create_dir_all(&dir).unwrap();
    let (file, sig) = (dir.join("artifact"), dir.join("artifact.minisig"));
    std::fs::write(&file, b"an artifact").unwrap();
    std::fs::write(&sig, sign(&test_key("current"), [1; 8], b"an artifact", "timestamp:1 file:artifact")).unwrap();
    (file, sig)
}

#[test]
fn release_build_pins_only_the_release_keys() {
    let (file, sig) = signed_file("a");
    // a lab build (test keys, no RACKHAND_RELEASE) takes what the test key signed: the signing works
    let (ok, log, lab) = build("lab", false, &["test-keys"]);
    assert!(ok, "{log}");
    let accepted = Command::new(&lab).arg(&file).arg(&sig).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&accepted.stdout).trim(), "ok current");
    // the same file, to a build made as a release is made, is refused: the release keys are the only ones it pins
    let (ok, log, release) = build("release", true, &[]);
    assert!(ok, "{log}");
    let refused = Command::new(&release).arg(&file).arg(&sig).output().unwrap();
    assert_eq!(refused.status.code(), Some(1), "{}", String::from_utf8_lossy(&refused.stdout));
    let why = String::from_utf8_lossy(&refused.stderr);
    assert!(why.contains("no release keys are pinned") || why.contains("isn't pinned"), "{why}");
    assert!(!String::from_utf8_lossy(&refused.stdout).contains("ok"), "a test-signed file must never verify");
}

#[test]
fn a_release_build_with_the_test_keys_cannot_be_made() {
    let (ok, log, _) = build("both", true, &["test-keys"]);
    assert!(!ok, "a release build with the test keys must fail");
    assert!(log.contains("test-keys") && log.contains("RACKHAND_RELEASE"), "{log}");
}

/// 5.2: `rackhand-verify --manifest <dir>` takes a release directory whole: the signed manifest, then every file.
#[test]
fn verify_checks_a_release_directory_against_its_signed_manifest() {
    use rackhand_release::manifest::Manifest;
    let (ok, log, verify) = build("manifest-lab", false, &["test-keys"]);
    assert!(ok, "{log}");
    let dir = target("release-dir");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("install.sh"), b"#!/bin/sh\n").unwrap();
    std::fs::write(dir.join("rackhand-probe-x86_64-unknown-linux-musl"), b"probe").unwrap();
    let text = Manifest::of_dir("0.1.0", &dir).unwrap().to_json();
    std::fs::write(dir.join("manifest.json"), &text).unwrap();
    let run = |expect_ok: bool| {
        let out = Command::new(&verify).arg("--manifest").arg(&dir).output().unwrap();
        assert_eq!(out.status.success(), expect_ok, "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
    };
    // unsigned: refused
    run(false);
    // signed by the current key, and then by the standby key: both fine
    std::fs::write(dir.join("manifest.json.minisig"), sign(&test_key("current"), [1; 8], text.as_bytes(), "timestamp:1")).unwrap();
    assert!(run(true).starts_with("ok current (2 artifacts, version 0.1.0)"));
    std::fs::write(dir.join("manifest.json.minisig"), sign(&test_key("standby"), [2; 8], text.as_bytes(), "timestamp:1")).unwrap();
    assert!(run(true).starts_with("ok standby"));
    // a changed artifact, a missing one and a stray one are each refused
    std::fs::write(dir.join("install.sh"), b"#!/bin/sh\nrm -rf /\n").unwrap();
    assert!(run(false).contains("install.sh"));
    std::fs::write(dir.join("install.sh"), b"#!/bin/sh\n").unwrap();
    std::fs::write(dir.join("stray"), b"x").unwrap();
    assert!(run(false).contains("stray"));
    std::fs::remove_file(dir.join("stray")).unwrap();
    std::fs::remove_file(dir.join("rackhand-probe-x86_64-unknown-linux-musl")).unwrap();
    assert!(run(false).contains("rackhand-probe"));
}
