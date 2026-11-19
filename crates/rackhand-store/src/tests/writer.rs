use rusqlite::types::Value;

use crate::db::Db;
use crate::writer::{Row, RowWrite, StoreError, WriteCmd};

use super::db::temp;

fn schedule_row(i: i64) -> RowWrite {
    RowWrite::insert(
        "schedule_state",
        Row::from([
            ("kind", Value::Text("test".into())),
            ("key", Value::Text(format!("k{i:04}"))),
            ("last_run_ms", Value::Integer(i)),
            ("next_run_ms", Value::Integer(0)),
        ]),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn writes_are_serialized_in_send_order() {
    let path = temp("order");
    let db = Db::open(&path).unwrap();
    let writer = db.writer();
    // Enqueue 1000 commands from one task in order, then await them all concurrently.
    let mut pending = Vec::new();
    for i in 0..1000 {
        pending.push(writer.enqueue(WriteCmd::Batch(vec![schedule_row(i)])).await.unwrap());
    }
    let acks = futures_join(pending).await;
    let seqs: Vec<u64> = acks.into_iter().map(|a| a.unwrap().seq).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "commit order equals send order");
    let conn = rusqlite::Connection::open(&path).unwrap();
    let mut stmt = conn.prepare("SELECT last_run_ms FROM schedule_state ORDER BY rowid").unwrap();
    let order: Vec<i64> = stmt.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    assert_eq!(order, (0..1000).collect::<Vec<i64>>());
}

async fn futures_join<T>(handles: Vec<tokio::sync::oneshot::Receiver<T>>) -> Vec<T> {
    let mut out = Vec::new();
    for h in handles {
        out.push(h.await.unwrap());
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_table_command_is_one_transaction() {
    let path = temp("txn");
    let db = Db::open(&path).unwrap();
    let writer = db.writer();
    let site = RowWrite::insert(
        "sites",
        Row::from([
            ("id", Value::Text("01J00000000000000000000000".into())),
            ("name", Value::Text("a".into())),
            ("timezone", Value::Text("UTC".into())),
            ("is_local", Value::Integer(1)),
        ]),
    );
    let bad = RowWrite::insert("machines", Row::from([("no_such_column", Value::Integer(1))]));
    let err = writer.send(WriteCmd::Batch(vec![site, bad])).await.unwrap_err();
    assert!(matches!(err, StoreError::Sqlite(_)), "{err:?}");
    let conn = rusqlite::Connection::open(&path).unwrap();
    let sites: i64 = conn.query_row("SELECT count(*) FROM sites", [], |r| r.get(0)).unwrap();
    assert_eq!(sites, 0, "the first table is unchanged after the second failed");
    let unimplemented = writer.send(WriteCmd::CompactStaged).await.unwrap_err();
    assert!(matches!(unimplemented, StoreError::Unimplemented("CompactStaged")), "{unimplemented:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn put_policy_updates_in_place() {
    let path = temp("policy");
    let db = Db::open(&path).unwrap();
    let w = db.writer();
    let policy = |patch: &str| {
        Row::from([
            ("id", Value::Text("p1".into())),
            ("name", Value::Text("default".into())),
            ("patch", Value::Text(patch.into())),
        ])
    };
    w.send(WriteCmd::PutPolicy(policy("approve-only"))).await.unwrap();
    w.send(WriteCmd::Batch(vec![
        RowWrite::insert(
            "sites",
            Row::from([
                ("id", Value::Text("s1".into())),
                ("name", Value::Text("home".into())),
                ("timezone", Value::Text("UTC".into())),
            ]),
        ),
        RowWrite::insert(
            "machines",
            Row::from([
                ("id", Value::Text("m1".into())),
                ("site_id", Value::Text("s1".into())),
                ("name", Value::Text("web".into())),
                ("kind", Value::Text("linux".into())),
                ("policy_id", Value::Text("p1".into())),
            ]),
        ),
    ]))
    .await
    .unwrap();
    // A delete and re-insert would fail the machine's reference to the policy.
    w.send(WriteCmd::PutPolicy(policy("auto"))).await.unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    let (patch, policy_id): (String, String) = conn
        .query_row("SELECT p.patch, m.policy_id FROM policies p JOIN machines m ON m.policy_id = p.id", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((patch.as_str(), policy_id.as_str()), ("auto", "p1"));
}
