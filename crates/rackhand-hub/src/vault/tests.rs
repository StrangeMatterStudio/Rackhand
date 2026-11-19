use std::collections::HashSet;
use std::sync::Arc;

use rackhand_store::Db;

use super::master_key::{MasterKey, recovery_code, restore_from_recovery_code};
use super::{Secret, Vault, VaultError};

fn setup(name: &str) -> (Arc<Db>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("rackhand-vault-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hub.db");
    (Arc::new(Db::open(&path).unwrap()), path)
}

#[tokio::test(flavor = "multi_thread")]
async fn put_then_get_returns_secret() {
    let (db, _) = setup("roundtrip");
    let vault = Vault::new(MasterKey::generate(), db.clone());
    vault.put("notify.discord.webhook", &Secret::from("https://discord.example/hook/abc")).await.unwrap();
    let back = vault.get("notify.discord.webhook").unwrap();
    assert_eq!(back.expose(), b"https://discord.example/hook/abc");
    assert!(matches!(vault.get("missing"), Err(VaultError::NotFound(_))));
}

#[tokio::test(flavor = "multi_thread")]
async fn database_without_master_key_reveals_nothing() {
    let (db, path) = setup("raw");
    let vault = Vault::new(MasterKey::generate(), db.clone());
    let secrets = ["correct-horse-battery-staple", "smtp-password-9f8e7d", "proxmox-token-uuid-1234"];
    for (i, s) in secrets.iter().enumerate() {
        vault.put(&format!("s{i}"), &Secret::from(*s)).await.unwrap();
    }
    let mut raw = std::fs::read(&path).unwrap();
    raw.extend(std::fs::read(path.with_extension("db-wal")).unwrap_or_default());
    for s in secrets {
        assert!(!raw.windows(s.len()).any(|w| w == s.as_bytes()), "`{s}` appears in the database files");
    }
    let other = Vault::new(MasterKey::generate(), db.clone());
    assert!(matches!(other.get("s0"), Err(VaultError::Decrypt(_))), "a different key can't decrypt");
}

#[test]
fn nonce_is_unique_per_write() {
    let key = MasterKey::generate();
    let mut seen = HashSet::new();
    for i in 0..10_000 {
        let sealed = key.seal("name", format!("value {i}").as_bytes()).unwrap();
        assert!(seen.insert(sealed.nonce), "nonce repeated at write {i}");
    }
}

#[test]
fn tampered_ciphertext_is_refused() {
    let key = MasterKey::generate();
    let mut sealed = key.seal("api.token", b"s3cret").unwrap();
    assert_eq!(key.open("api.token", &sealed).unwrap().expose(), b"s3cret");
    sealed.ciphertext[0] ^= 1;
    assert!(key.open("api.token", &sealed).is_err(), "a flipped bit fails authentication");
    let good = key.seal("api.token", b"s3cret").unwrap();
    assert!(key.open("other.name", &good).is_err(), "a ciphertext moved to another name fails");
}

#[test]
fn recovery_code_round_trips_the_master_key() {
    let key = MasterKey::generate();
    let code = recovery_code(&key);
    assert!(code.split('-').all(|g| g.len() <= 5), "{code}");
    let restored = restore_from_recovery_code(&code.to_lowercase()).unwrap();
    assert_eq!(restored.fingerprint(), key.fingerprint());
    let sealed = key.seal("x", b"y").unwrap();
    assert_eq!(restored.open("x", &sealed).unwrap().expose(), b"y");
    let mut typo: Vec<char> = code.chars().collect();
    typo[3] = if typo[3] == 'A' { 'B' } else { 'A' };
    assert!(restore_from_recovery_code(&typo.into_iter().collect::<String>()).is_err(), "a typo fails the checksum");
}

#[test]
fn secrets_never_appear_in_debug_output() {
    let secret = Secret::from("hunter2-very-secret");
    let key = MasterKey::generate();
    for text in [format!("{secret:?}"), format!("{key:?}")] {
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("redacted"), "{text}");
    }
}
