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
