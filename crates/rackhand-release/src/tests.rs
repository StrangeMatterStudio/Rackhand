use ed25519_dalek::SigningKey;

use super::signing::{public, sign};
use super::*;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn keys() -> Vec<(Pinned, PublicKey)> {
    vec![(Pinned::Current, public(&key(0x11), [1; 8])), (Pinned::Standby, public(&key(0x22), [2; 8]))]
}

#[test]
fn current_and_standby_signatures_verify() {
    let data = b"rackhand-probe 0.1.0";
    let current = sign(&key(0x11), [1; 8], data, "timestamp:1 file:rackhand-probe");
    assert_eq!(verify_with(data, &current, &keys()), Ok(Pinned::Current));
    let standby = sign(&key(0x22), [2; 8], data, "timestamp:1 file:rackhand-probe");
    assert_eq!(verify_with(data, &standby, &keys()), Ok(Pinned::Standby), "the standby key is accepted (E64)");
}

#[test]
fn tampered_file_or_comment_or_other_key_refused() {
    let data = b"rackhand-probe 0.1.0";
    let sig = sign(&key(0x11), [1; 8], data, "timestamp:1");
    assert_eq!(verify_with(b"rackhand-probe 0.1.1", &sig, &keys()), Err(VerifyError::BadSignature));
    let comment = sig.replace("trusted comment: timestamp:1", "trusted comment: timestamp:2");
    assert_eq!(verify_with(data, &comment, &keys()), Err(VerifyError::BadGlobalSignature));
    let other = sign(&key(0x33), [3; 8], data, "timestamp:1");
    assert_eq!(verify_with(data, &other, &keys()), Err(VerifyError::UnknownKey));
    // a key id that matches a pinned key but the wrong key behind it
    let forged = sign(&key(0x33), [1; 8], data, "timestamp:1");
    assert_eq!(verify_with(data, &forged, &keys()), Err(VerifyError::BadSignature));
    assert!(matches!(verify_with(data, "junk", &keys()), Err(VerifyError::Malformed(_))));
}

#[test]
fn public_key_files_round_trip() {
    let k = public(&key(0x11), [1; 8]);
    assert_eq!(PublicKey::parse(&k.to_file()), Ok(k));
}

#[test]
fn test_key_files_match_their_seeds() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys");
    for (name, id) in [("current", [1u8; 8]), ("standby", [2; 8])] {
        let seed = std::fs::read_to_string(dir.join(format!("test-{name}.seed"))).unwrap();
        let bytes: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&seed.trim()[2 * i..2 * i + 2], 16).unwrap()).collect();
        let expected = public(&SigningKey::from_bytes(&bytes.try_into().unwrap()), id).to_file();
        let path = dir.join(format!("test-{name}.pub"));
        if std::env::var_os("RACKHAND_WRITE_TEST_KEYS").is_some() {
            std::fs::write(&path, &expected).unwrap();
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap_or_default(), expected, "{name}");
    }
}

#[test]
fn release_build_pins_nothing_until_the_keys_exist() {
    #[cfg(not(feature = "test-keys"))]
    assert_eq!(verify(b"x", "junk"), Err(VerifyError::NoKeys), "the placeholders pin no key");
}

mod manifest {
    use super::*;
    use crate::manifest::{Manifest, ManifestError};

    fn files() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("rackhand-probe-x86_64-unknown-linux-musl", b"probe bytes".to_vec()),
            ("install.sh", b"#!/bin/sh\n".to_vec()),
            ("rackhand-x86_64-unknown-linux-musl", b"hub bytes".to_vec()),
        ]
    }

    fn manifest() -> Manifest {
        Manifest::new("0.1.0", files().iter().map(|(n, b)| (n.to_string(), b.as_slice())))
    }

    /// 5.2: a signed manifest lists every artifact's hash; the list is the same however the files were given.
    #[test]
    fn manifest_lists_every_artifact_hash() {
        use sha2::{Digest, Sha256};
        let m = manifest();
        assert_eq!(m.artifacts.len(), 3);
        let names: Vec<&str> = m.artifacts.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["install.sh", "rackhand-probe-x86_64-unknown-linux-musl", "rackhand-x86_64-unknown-linux-musl"]);
        for (name, bytes) in files() {
            let a = m.artifacts.iter().find(|a| a.name == name).unwrap();
            assert_eq!(a.sha256, format!("{:x}", Sha256::digest(&bytes)), "{name}");
            assert_eq!(a.size, bytes.len() as u64);
        }
        // the same text from the same files in another order, so two builds of one tag give one manifest
        let reversed = Manifest::new("0.1.0", files().iter().rev().map(|(n, b)| (n.to_string(), b.as_slice())));
        assert_eq!(m.to_json(), reversed.to_json());
        assert_eq!(Manifest::parse(&m.to_json()).unwrap(), m);
        assert!(m.to_json().ends_with('\n'));
    }

    #[test]
    fn a_changed_missing_or_extra_file_is_found() {
        let m = manifest();
        for (name, bytes) in files() {
            assert_eq!(m.check(name, &bytes), Ok(()), "{name}");
        }
        assert_eq!(
            m.check("install.sh", b"#!/bin/sh\nrm -rf /\n"),
            Err(ManifestError::HashMismatch("install.sh".into()))
        );
        assert_eq!(m.check("other", b"x"), Err(ManifestError::NotListed("other".into())));
        let dir = std::env::temp_dir().join(format!("rackhand-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, bytes) in files() {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        // signatures and the manifest itself are beside the artifacts and are not artifacts
        std::fs::write(dir.join("install.sh.minisig"), "sig").unwrap();
        std::fs::write(dir.join("manifest.json"), m.to_json()).unwrap();
        assert_eq!(m.check_dir(&dir), Ok(()));
        std::fs::write(dir.join("rackhand-x86_64-unknown-linux-musl"), b"changed").unwrap();
        assert_eq!(m.check_dir(&dir), Err(ManifestError::HashMismatch("rackhand-x86_64-unknown-linux-musl".into())));
        std::fs::remove_file(dir.join("install.sh")).unwrap();
        std::fs::write(dir.join("rackhand-x86_64-unknown-linux-musl"), b"hub bytes").unwrap();
        assert_eq!(m.check_dir(&dir), Err(ManifestError::Missing("install.sh".into())));
        std::fs::write(dir.join("install.sh"), b"#!/bin/sh\n").unwrap();
        std::fs::write(dir.join("surprise.bin"), b"x").unwrap();
        assert_eq!(m.check_dir(&dir), Err(ManifestError::NotListed("surprise.bin".into())));
    }

    #[test]
    fn a_manifest_that_isnt_one_is_refused() {
        for bad in ["", "{", "[]", r#"{"version":"1"}"#, r#"{"version":"1","artifacts":[{"name":"a","sha256":"xyz","size":1}]}"#] {
            assert!(Manifest::parse(bad).is_err(), "{bad:?}");
        }
        // a name that climbs out of the directory, or is listed twice
        let climb = r#"{"version":"1","artifacts":[{"name":"../x","sha256":"00","size":1}]}"#;
        assert!(Manifest::parse(climb).is_err());
        let digest = "0".repeat(64);
        let twice = format!(
            r#"{{"version":"1","artifacts":[{{"name":"a","sha256":"{digest}","size":1}},{{"name":"a","sha256":"{digest}","size":1}}]}}"#
        );
        assert!(Manifest::parse(&twice).is_err());
    }

    /// E64, AC67: a manifest signed with the standby key is as good as one signed with the current key; any other key is refused.
    #[test]
    fn a_signed_manifest_is_checked_against_the_pinned_keys() {
        let m = manifest();
        let text = m.to_json();
        let keys = keys();
        for (seed, id, which) in [(0x11, [1u8; 8], Pinned::Current), (0x22, [2; 8], Pinned::Standby)] {
            let sig = sign(&key(seed), id, text.as_bytes(), "timestamp:1 file:manifest.json");
            let (signed_by, parsed) = crate::manifest::verify_signed_with(text.as_bytes(), &sig, &keys).unwrap();
            assert_eq!((signed_by, &parsed), (which, &m));
        }
        let other = sign(&key(0x33), [3; 8], text.as_bytes(), "timestamp:1");
        assert_eq!(
            crate::manifest::verify_signed_with(text.as_bytes(), &other, &keys).unwrap_err(),
            ManifestError::Signature(VerifyError::UnknownKey)
        );
        // a manifest changed after it was signed
        let sig = sign(&key(0x11), [1; 8], text.as_bytes(), "timestamp:1");
        let changed = text.replace("install.sh", "install.sx");
        assert_eq!(
            crate::manifest::verify_signed_with(changed.as_bytes(), &sig, &keys).unwrap_err(),
            ManifestError::Signature(VerifyError::BadSignature)
        );
    }
}
