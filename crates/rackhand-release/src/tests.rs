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
