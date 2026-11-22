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

/// 7.3.12: revoking a machine marks it and stops admitting its probe, at once and after a restart.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_machine_closes_its_endpoint_and_marks_it() {
    use rackhand_net::registry::{Admission, Registry as _};
    let dir = std::env::temp_dir().join(format!("rackhand-registry-revoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let endpoint = iroh::SecretKey::from_bytes(&[5u8; 32]).public();
    let t = |s: &str| Value::Text(s.into());
    let machine = |id: &str, endpoint: Option<String>| {
        let mut row = rackhand_store::Row::from([
            ("id", t(id)),
            ("site_id", t("s")),
            ("name", t(id)),
            ("kind", t("linux")),
            ("state", t("enrolled")),
        ]);
        if let Some(e) = endpoint {
            row.insert("probe_endpoint_id", Value::Text(e));
        }
        RowWrite::insert("machines", row)
    };
    let site = rackhand_store::Row::from([("id", t("s")), ("name", t("home")), ("timezone", t("UTC"))]);
    db.writer()
        .send(WriteCmd::Batch(vec![
            RowWrite::insert("sites", site),
            machine("a", Some(endpoint.to_string())),
            machine("never", None),
        ]))
        .await
        .unwrap();
    let registry = Registry::load(db.clone()).unwrap();
    let probe = rackhand_proto::alpn::PROBE;
    assert_eq!(registry.admission(probe, &endpoint), Admission::Allowed);
    assert!(registry.revoke_machine("a").await.unwrap());
    assert_eq!(registry.admission(probe, &endpoint), Admission::Revoked, "at once");
    let state = |id: &str| -> String {
        db.readers().with(|c| c.query_row("SELECT state FROM machines WHERE id = ?1", [id], |r| r.get(0))).unwrap()
    };
    assert_eq!(state("a"), "revoked");
    assert!(registry.revoke_machine("a").await.unwrap(), "again is fine");
    assert!(registry.revoke_machine("never").await.unwrap(), "a machine that never enrolled has no endpoint to close");
    assert_eq!(state("never"), "revoked");
    assert!(!registry.revoke_machine("nobody").await.unwrap(), "no such machine");
    let reloaded = Registry::load(db.clone()).unwrap();
    assert_eq!(reloaded.admission(probe, &endpoint), Admission::Revoked, "after a restart");
}
