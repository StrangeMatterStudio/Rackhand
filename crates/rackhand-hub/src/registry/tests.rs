use std::sync::Arc;

use rackhand_store::ids::now_ms;
use rackhand_store::{Db, RowWrite, WriteCmd};
use rusqlite::types::Value;

use super::Registry;
use super::tokens::hash;

#[tokio::test(flavor = "multi_thread")]
async fn tokens_stored_hashed_never_plain() {
    let dir = std::env::temp_dir().join(format!("rackhand-registry-tokens-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    db.writer()
        .send(WriteCmd::Batch(vec![RowWrite::insert(
            "users",
            [
                ("id", Value::Text("u1".into())),
                ("name", Value::Text("admin".into())),
                ("role", Value::Text("admin".into())),
                ("created_at", Value::Integer(0)),
            ]
            .into_iter()
            .collect(),
        )]))
        .await
        .unwrap();
    let registry = Registry::load(db.clone()).unwrap();
    let tokens = [
        registry.invite_device("u1", "admin", now_ms()).await.unwrap(),
        registry.invite_operator("admin", now_ms()).await.unwrap(),
        registry.invite_peer("admin", now_ms()).await.unwrap(),
    ];
    let stored: Vec<Vec<u8>> = db
        .readers()
        .with(|c| {
            let mut stmt = c.prepare("SELECT hash FROM join_tokens")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect()
        })
        .unwrap();
    assert_eq!(stored.len(), 3);
    // Every byte the database holds, including the write-ahead log that hasn't been checkpointed.
    let mut bytes = Vec::new();
    for file in ["hub.db", "hub.db-wal"] {
        if let Ok(b) = std::fs::read(dir.join(file)) {
            bytes.extend(b);
        }
    }
    assert!(bytes.len() > 4096, "nothing to scan");
    let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    for t in &tokens {
        assert!(t.as_str().len() >= 26, "128 bits of token: {}", t.as_str().len());
        assert!(!contains(t.as_str().as_bytes()), "token text in the database");
        assert!(!contains(t.as_str().to_ascii_lowercase().as_bytes()), "token text in the database");
        let h = hash(t);
        assert!(stored.contains(&h.to_vec()), "the hash is what's stored");
        assert!(contains(&h), "the hash is in the file");
    }
}
