use std::sync::Arc;

use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use super::*;

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rackhand-backup-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn hub_db(dir: &Path) -> Arc<Db> {
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let site = Row::from([
        ("id", Value::Text("s1".into())),
        ("name", Value::Text("zebra-unique-site".into())),
        ("timezone", Value::Text("UTC".into())),
    ]);
    db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("sites", site)])).await.unwrap();
    db
}

fn rows(path: &Path) -> Vec<(String, String)> {
    let c = rusqlite::Connection::open(path).unwrap();
    let mut s = c.prepare("SELECT id, name FROM sites ORDER BY id").unwrap();
    s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn backup_is_encrypted_and_restores_identically() {
    let dir = temp("restore");
    let _db = hub_db(&dir).await;
    std::fs::write(dir.join("node.key"), [7u8; 32]).unwrap();
    let key = MasterKey::generate();
    let file = take(&dir.join("hub.db"), &key, &dir.join("node.key"), &dir.join("backups"), 1_000).unwrap();
    let raw = std::fs::read(&file).unwrap();
    assert!(!raw.windows(17).any(|w| w == b"zebra-unique-site"), "nothing readable in the file");
    assert!(raw.starts_with(b"RHBK1\n"));
    // a new machine: restore with the master key
    let new = temp("restore-new");
    restore(&file, &key, &new.join("hub.db"), &new.join("node.key")).unwrap();
    assert_eq!(rows(&new.join("hub.db")), rows(&dir.join("hub.db")), "the database restores as it was");
    assert_eq!(std::fs::read(new.join("node.key")).unwrap(), [7u8; 32], "with the node key, so probes stay pinned");
    // another key, and a cut file, are refused, and leave nothing behind
    let other = temp("restore-other");
    assert!(matches!(
        restore(&file, &MasterKey::generate(), &other.join("hub.db"), &other.join("node.key")),
        Err(BackupError::Sealed)
    ));
    assert!(!other.join("hub.db").exists() && !other.join("node.key").exists());
    let cut = dir.join("cut.rhbk");
    std::fs::write(&cut, &raw[..raw.len() - 10]).unwrap();
    assert!(restore(&cut, &key, &other.join("hub.db"), &other.join("node.key")).is_err(), "a truncated file");
    assert!(!other.join("hub.db").exists());
    // cut exactly after a whole chunk (the header): the missing last chunk is noticed too
    let header_len = u32::from_be_bytes(raw[6..10].try_into().unwrap()) as usize;
    std::fs::write(&cut, &raw[..6 + 4 + 24 + header_len]).unwrap();
    assert!(restore(&cut, &key, &other.join("hub.db"), &other.join("node.key")).is_err(), "cut at a chunk boundary");
    assert!(!other.join("hub.db").exists());
}

/// The copies kept are the `[backups] kept` setting of the database being backed up (7.8.1).
#[tokio::test(flavor = "multi_thread")]
async fn keeps_as_many_copies_as_the_setting_says() {
    let dir = temp("keep-setting");
    let db = hub_db(&dir).await;
    crate::library::config::put(&db, "hub", "[backups]\nkept = 3\n", "admin", 1).await.unwrap();
    std::fs::write(dir.join("node.key"), [7u8; 32]).unwrap();
    let key = MasterKey::generate();
    let backups = dir.join("backups");
    for at in [1_000, 2_000, 3_000, 4_000] {
        take(&dir.join("hub.db"), &key, &dir.join("node.key"), &backups, at).unwrap();
    }
    let kept = list(&backups);
    assert_eq!(kept.len(), 3, "{kept:?}");
    assert!(!backups.join("hub-1000.rhbk").exists(), "the oldest goes");
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_two_local_copies() {
    let dir = temp("keep");
    let _db = hub_db(&dir).await;
    std::fs::write(dir.join("node.key"), [7u8; 32]).unwrap();
    let key = MasterKey::generate();
    let backups = dir.join("backups");
    let first = take(&dir.join("hub.db"), &key, &dir.join("node.key"), &backups, 1_000).unwrap();
    take(&dir.join("hub.db"), &key, &dir.join("node.key"), &backups, 2_000).unwrap();
    take(&dir.join("hub.db"), &key, &dir.join("node.key"), &backups, 3_000).unwrap();
    let kept = list(&backups);
    assert_eq!(kept.len(), 2, "{kept:?}");
    assert!(!first.exists(), "the third backup deletes the oldest");
    assert!(
        std::fs::read_dir(&backups)
            .unwrap()
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().starts_with(".snapshot"))
    );
}
