use crate::signed::{SignedError, sign, verify};

fn key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

#[test]
fn expired_not_newer_or_wrong_key_refused() {
    let hub = key(1);
    let now = 1_800_000_000_000;
    let payload = sign(&hub, "keys", 5, now, now + 3_600_000, b"authorized_keys");
    let ok = verify(&payload, &hub.verifying_key(), "keys", 4, now + 1000).unwrap();
    assert_eq!(ok.version, 5);
    assert_eq!(ok.body, b"authorized_keys");

    assert_eq!(verify(&payload, &hub.verifying_key(), "keys", 4, now + 3_600_001).unwrap_err(), SignedError::Expired);
    assert_eq!(verify(&payload, &hub.verifying_key(), "keys", 5, now).unwrap_err(), SignedError::NotNewer);
    assert_eq!(verify(&payload, &hub.verifying_key(), "keys", 6, now).unwrap_err(), SignedError::NotNewer);
    assert_eq!(verify(&payload, &key(2).verifying_key(), "keys", 4, now).unwrap_err(), SignedError::BadSignature);
    assert_eq!(verify(&payload, &hub.verifying_key(), "commands", 4, now).unwrap_err(), SignedError::WrongKind);

    let mut tampered = payload.clone();
    tampered.payload[0] ^= 1;
    assert!(verify(&tampered, &hub.verifying_key(), "keys", 4, now).is_err());
}
