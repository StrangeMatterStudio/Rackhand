use std::sync::Arc;

use rackhand_hub::vault::Vault;
use rackhand_hub::vault::master_key::{MasterKey, recovery_code};
use rackhand_store::Db;

use super::recover;

fn temp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rackhand-recover-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A hub's database with one sealed secret, and the code of its key; the key file is gone.
async fn lost(name: &str) -> (std::path::PathBuf, std::path::PathBuf, String) {
    let dir = temp(name);
    let db_path = dir.join("hub.db");
    let key = MasterKey::generate();
    let code = recovery_code(&key);
    let db = Arc::new(Db::open(&db_path).unwrap());
    Vault::new(key, db).put("smtp", &rackhand_hub::vault::Secret::new(b"hunter2".to_vec())).await.unwrap();
    (dir.join("master.key"), db_path, code)
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_code_writes_the_key_that_opens_the_vault() {
    let (key_path, db_path, code) = lost("good").await;
    let opened = recover(&format!("{code}\n"), &key_path, &db_path).unwrap();
    assert_eq!(opened, 1, "the vault's secret opened with it");
    let restored = MasterKey::load(Some(&key_path)).unwrap();
    assert_eq!(
        restored.fingerprint(),
        rackhand_hub::vault::master_key::restore_from_recovery_code(&code).unwrap().fingerprint()
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777, 0o600, "root only");
    let again = recover(&code, &key_path, &db_path).unwrap_err();
    assert!(again.contains("already"), "an existing key is never overwritten: {again}");
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_or_garbled_code_writes_nothing() {
    let (key_path, db_path, _) = lost("wrong").await;
    let other = recovery_code(&MasterKey::generate());
    let wrong = recover(&other, &key_path, &db_path).unwrap_err();
    assert!(wrong.contains("doesn't open"), "{wrong}");
    assert!(!key_path.exists(), "nothing written for a code of another key");
    let garbled = recover("not-a-code-!!", &key_path, &db_path).unwrap_err();
    assert!(garbled.contains("recovery code"), "{garbled}");
    assert!(!key_path.exists());
}
