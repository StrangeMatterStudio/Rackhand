use std::sync::Arc;

use rackhand_store::Db;

use super::{Audit, VerifyError, verify};

fn db(name: &str) -> (Arc<Db>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("rackhand-audit-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hub.db");
    (Arc::new(Db::open(&path).unwrap()), path)
}

async fn append_n(audit: &Audit, n: usize) {
    for i in 0..n {
        audit.append("owner", "test.action", Some(&format!("target-{i}")), &format!("{{\"i\":{i}}}")).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn chain_verifies_after_appends() {
    let (db, _) = db("chain");
    let audit = Audit::new(db.writer());
    append_n(&audit, 100).await;
    let report = verify(db.readers()).unwrap();
    assert_eq!(report.rows, 100);
    assert_eq!(report.last_seq, 100);
}

#[tokio::test(flavor = "multi_thread")]
async fn changed_row_fails_verify_naming_seq() {
    let (db, path) = db("changed");
    let audit = Audit::new(db.writer());
    append_n(&audit, 50).await;
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute("UPDATE audit_log SET data = '{\"i\":999}' WHERE seq = 37", [])
        .unwrap();
    assert_eq!(verify(db.readers()).unwrap_err(), VerifyError::HashMismatch { seq: 37 });
}

#[tokio::test(flavor = "multi_thread")]
async fn deleted_middle_row_fails_verify() {
    let (db, path) = db("deleted");
    let audit = Audit::new(db.writer());
    append_n(&audit, 50).await;
    rusqlite::Connection::open(&path).unwrap().execute("DELETE FROM audit_log WHERE seq = 20", []).unwrap();
    assert_eq!(verify(db.readers()).unwrap_err(), VerifyError::Gap { after: 19, next: 21 });
}

#[tokio::test(flavor = "multi_thread")]
async fn retention_with_checkpoint_still_verifies() {
    let (db, path) = db("retention");
    let audit = Audit::new(db.writer());
    append_n(&audit, 100).await;
    audit.checkpoint_and_remove_through(50).await.unwrap();
    let report = verify(db.readers()).unwrap();
    assert_eq!(report.first_seq, 51, "rows 1 to 50 are gone");
    assert_eq!(report.last_seq, 101, "the checkpoint row is the newest row");
    // Without the checkpoint the cut would be a missing-rows error.
    rusqlite::Connection::open(&path).unwrap().execute("DELETE FROM audit_log WHERE checkpoint = 1", []).unwrap();
    assert_eq!(verify(db.readers()).unwrap_err(), VerifyError::MissingStart { first: 51 });
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_appends_keep_one_chain() {
    let (db, _) = db("concurrent");
    let audit = Arc::new(Audit::new(db.writer()));
    let mut tasks = Vec::new();
    for t in 0..8 {
        let audit = audit.clone();
        tasks.push(tokio::spawn(async move {
            for i in 0..100 {
                audit.append(&format!("task-{t}"), "test.concurrent", None, &format!("{{\"i\":{i}}}")).await.unwrap();
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let report = verify(db.readers()).unwrap();
    assert_eq!((report.rows, report.first_seq, report.last_seq), (800, 1, 800));
}
