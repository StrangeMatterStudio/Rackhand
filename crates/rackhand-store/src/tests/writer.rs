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
    let unimplemented = writer.send(WriteCmd::PutConnRecords(Vec::new())).await.unwrap_err();
    assert!(matches!(unimplemented, StoreError::Unimplemented("PutConnRecords")), "{unimplemented:?}");
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

#[tokio::test(flavor = "multi_thread")]
async fn job_rows_created_stepped_and_finished_once() {
    let path = temp("jobs");
    let db = Db::open(&path).unwrap();
    let w = db.writer();
    let t = |s: &str| Value::Text(s.into());
    w.send(WriteCmd::CreateJob(Row::from([
        ("id", t("j1")),
        ("kind", t("runbook")),
        ("name", t("restart-web")),
        ("requested_by", t("admin")),
        ("state", t("running")),
        ("started_at", Value::Integer(1)),
    ])))
    .await
    .unwrap();
    // A step is recorded before it runs, then its result fills in the rest; the command stays.
    let step = |cols: Vec<(&'static str, Value)>| {
        let mut row = Row::from([("job_id", t("j1")), ("step_id", t("restart"))]);
        row.extend(cols);
        WriteCmd::UpdateJobStep(row)
    };
    w.send(step(vec![
        ("state", t("running")),
        ("command", t("systemctl restart nginx")),
        ("started_at", Value::Integer(2)),
    ]))
    .await
    .unwrap();
    w.send(step(vec![
        ("state", t("succeeded")),
        ("exit_code", Value::Integer(0)),
        ("stdout", Value::Blob(b"ok".to_vec())),
    ]))
    .await
    .unwrap();
    let finish = |state: &str| {
        WriteCmd::FinishJob(Row::from([("id", t("j1")), ("state", t(state)), ("ended_at", Value::Integer(3))]))
    };
    w.send(finish("succeeded")).await.unwrap();
    // The first finish wins.
    assert!(matches!(w.send(finish("failed")).await, Err(StoreError::Conflict(_))));
    let conn = rusqlite::Connection::open(&path).unwrap();
    let (state, command, code): (String, String, i64) = conn
        .query_row("SELECT state, command, exit_code FROM job_steps WHERE job_id = 'j1'", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!((state.as_str(), command.as_str(), code), ("succeeded", "systemctl restart nginx", 0));
    let job: String = conn.query_row("SELECT state FROM jobs WHERE id = 'j1'", [], |r| r.get(0)).unwrap();
    assert_eq!(job, "succeeded");
}

#[tokio::test(flavor = "multi_thread")]
async fn put_user_changes_columns_and_keeps_an_admin() {
    let path = temp("users");
    let db = Db::open(&path).unwrap();
    let w = db.writer();
    let t = |s: &str| Value::Text(s.into());
    let user = |id: &str, role: &str| {
        WriteCmd::PutUser(Row::from([
            ("id", t(id)),
            ("name", t(id)),
            ("role", t(role)),
            ("created_at", Value::Integer(1)),
        ]))
    };
    w.send(user("a1", "admin")).await.unwrap();
    w.send(user("r1", "responder")).await.unwrap();
    // Some columns of an existing row.
    w.send(WriteCmd::PutUser(Row::from([("id", t("r1")), ("role", t("viewer"))]))).await.unwrap();
    // The only enabled admin can't be demoted or disabled.
    let demote = WriteCmd::PutUser(Row::from([("id", t("a1")), ("role", t("viewer"))]));
    assert!(matches!(w.send(demote).await, Err(StoreError::Conflict(_))));
    let disable = WriteCmd::PutUser(Row::from([("id", t("a1")), ("disabled_at", Value::Integer(5))]));
    assert!(matches!(w.send(disable.clone()).await, Err(StoreError::Conflict(_))));
    // With a second admin it can.
    w.send(user("a2", "admin")).await.unwrap();
    w.send(disable).await.unwrap();
    let missing = WriteCmd::PutUser(Row::from([("id", t("nobody")), ("role", t("viewer"))]));
    assert!(matches!(w.send(missing).await, Err(StoreError::NoSuchRow(_))));
    let conn = rusqlite::Connection::open(&path).unwrap();
    let rows: Vec<(String, String, Option<i64>)> = conn
        .prepare("SELECT id, role, disabled_at FROM users ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        rows,
        [
            ("a1".to_string(), "admin".to_string(), Some(5)),
            ("a2".into(), "admin".into(), None),
            ("r1".into(), "viewer".into(), None)
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_keys_and_job_tokens_stored_and_revoked() {
    let path = temp("mcp-keys");
    let db = Db::open(&path).unwrap();
    let w = db.writer();
    let t = |s: &str| Value::Text(s.into());
    let rows = vec![
        RowWrite::insert(
            "users",
            Row::from([
                ("id", t("u1")),
                ("name", t("bob")),
                ("role", t("responder")),
                ("created_at", Value::Integer(1)),
            ]),
        ),
        RowWrite::insert(
            "devices",
            Row::from([
                ("id", t("d1")),
                ("user_id", t("u1")),
                ("name", t("laptop")),
                ("endpoint_id", t("e1")),
                ("created_at", Value::Integer(1)),
            ]),
        ),
        RowWrite::insert("operators", Row::from([("id", t("o1")), ("name", t("op")), ("endpoint_id", t("e2"))])),
        RowWrite::insert(
            "jobs",
            Row::from([
                ("id", t("j1")),
                ("kind", t("assistant")),
                ("name", t("p")),
                ("requested_by", t("x")),
                ("state", t("running")),
            ]),
        ),
    ];
    w.send(WriteCmd::Batch(rows)).await.unwrap();
    w.send(WriteCmd::PutMcpKey(Row::from([
        ("id", t("k1")),
        ("user_id", t("u1")),
        ("device_id", t("d1")),
        ("scope", t("read")),
        ("hash", Value::Blob(vec![1; 32])),
        ("expires_at", Value::Integer(100)),
    ])))
    .await
    .unwrap();
    w.send(WriteCmd::PutJobToken(Row::from([
        ("job_id", t("j1")),
        ("operator_id", t("o1")),
        ("hash", Value::Blob(vec![2; 32])),
        ("hosts", t("[\"m1\"]")),
        ("tools", t("[\"get_incident\"]")),
        ("expires_at", Value::Integer(100)),
    ])))
    .await
    .unwrap();
    // Revoking names the row and the time only.
    w.send(WriteCmd::PutMcpKey(Row::from([("id", t("k1")), ("revoked_at", Value::Integer(5))]))).await.unwrap();
    w.send(WriteCmd::PutJobToken(Row::from([("job_id", t("j1")), ("revoked_at", Value::Integer(6))]))).await.unwrap();
    let missing = WriteCmd::PutMcpKey(Row::from([("id", t("nope")), ("revoked_at", Value::Integer(5))]));
    assert!(matches!(w.send(missing).await, Err(StoreError::NoSuchRow(_))));
    let conn = rusqlite::Connection::open(&path).unwrap();
    let k: (String, i64) =
        conn.query_row("SELECT scope, revoked_at FROM mcp_keys", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    let j: (String, i64) =
        conn.query_row("SELECT tools, revoked_at FROM job_tokens", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!(k, ("read".to_string(), 5));
    assert_eq!(j, ("[\"get_incident\"]".to_string(), 6));
}

#[tokio::test(flavor = "multi_thread")]
async fn checks_and_their_results_written() {
    let path = temp("checks");
    let db = Db::open(&path).unwrap();
    let w = db.writer();
    let check = |interval: i64| {
        Row::from([
            ("id", Value::Text("web".into())),
            ("kind", Value::Text("http".into())),
            ("target", Value::Text("http://192.0.2.80/".into())),
            ("interval_s", Value::Integer(interval)),
            ("settings", Value::Text("{}".into())),
        ])
    };
    w.send(WriteCmd::PutCheck(check(60))).await.unwrap();
    let result = |at: i64, ok: bool| {
        Row::from([
            ("check_id", Value::Text("web".into())),
            ("at_ms", Value::Integer(at)),
            ("ok", Value::Integer(ok as i64)),
            ("latency_ms", Value::Real(12.5)),
            ("detail", Value::Text("status 200".into())),
        ])
    };
    w.send(WriteCmd::PutCheckResults(vec![result(1_000, true), result(2_000, false)])).await.unwrap();
    // a result already stored isn't written twice; a changed check is updated in place (its results refer to it)
    w.send(WriteCmd::PutCheckResults(vec![result(2_000, false)])).await.unwrap();
    w.send(WriteCmd::PutCheck(check(30))).await.unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    let interval: i64 = conn.query_row("SELECT interval_s FROM checks WHERE id = 'web'", [], |r| r.get(0)).unwrap();
    let results: i64 = conn.query_row("SELECT count(*) FROM check_results", [], |r| r.get(0)).unwrap();
    assert_eq!((interval, results), (30, 2));
}

/// 7.3.12, D89: a machine's access level changes only in the transaction that uses up a join token, so nothing the hub
/// does alone can raise a monitor machine to managed.
mod level {
    use super::*;
    use crate::writer::{ConsumeToken, RegistryChange, RowUpdate};

    fn seed(path: &std::path::Path) {
        let c = rusqlite::Connection::open(path).unwrap();
        c.execute("INSERT INTO sites (id, name, timezone, is_local) VALUES ('s', 'home', 'UTC', 1)", []).unwrap();
        c.execute(
            "INSERT INTO machines (id, site_id, name, kind, access, state) VALUES ('m', 's', 'm', 'linux', 'monitor', 'enrolled')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO join_tokens (id, kind, hash, created_by, expires_at) VALUES ('t', 'machine', x'0102', 'admin', 9999999)",
            [],
        )
        .unwrap();
    }

    fn access(path: &std::path::Path) -> String {
        let c = rusqlite::Connection::open(path).unwrap();
        c.query_row("SELECT access FROM machines WHERE id = 'm'", [], |r| r.get(0)).unwrap()
    }

    fn set_access(to: &str) -> RowUpdate {
        RowUpdate {
            table: "machines",
            key: ("id", Value::Text("m".into())),
            set: Row::from([("access", Value::Text(to.into()))]),
        }
    }

    fn consume() -> ConsumeToken {
        ConsumeToken { hash: vec![1, 2], kind: "machine".into(), now_ms: 1000 }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_write_without_a_token_cannot_change_the_level() {
        let path = temp("level-alone");
        let db = Db::open(&path).unwrap();
        seed(&path);
        let w = db.writer();
        let update = RegistryChange { updates: vec![set_access("managed")], ..Default::default() };
        let refused = w.send(WriteCmd::RegistryChange(update)).await;
        assert!(matches!(refused, Err(StoreError::Conflict(m)) if m.contains("level")), "{refused:?}");
        let row = Row::from([("id", Value::Text("m".into())), ("access", Value::Text("managed".into()))]);
        for cmd in [
            WriteCmd::Batch(vec![RowWrite::upsert("machines", "id", row.clone())]),
            WriteCmd::Batch(vec![RowWrite { table: "machines", row, mode: crate::writer::WriteMode::Replace }]),
        ] {
            assert!(matches!(w.send(cmd).await, Err(StoreError::Conflict(_))));
        }
        assert_eq!(access(&path), "monitor");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_join_that_uses_a_token_changes_it_and_a_write_of_the_same_level_is_fine() {
        let path = temp("level-join");
        let db = Db::open(&path).unwrap();
        seed(&path);
        let w = db.writer();
        let same = RegistryChange { updates: vec![set_access("monitor")], ..Default::default() };
        w.send(WriteCmd::RegistryChange(same)).await.unwrap();
        let join =
            RegistryChange { consume: Some(consume()), updates: vec![set_access("managed")], ..Default::default() };
        w.send(WriteCmd::RegistryChange(join)).await.unwrap();
        assert_eq!(access(&path), "managed");
        // the token is used up, and a refused one changes nothing
        let again =
            RegistryChange { consume: Some(consume()), updates: vec![set_access("monitor")], ..Default::default() };
        assert!(w.send(WriteCmd::RegistryChange(again)).await.is_err());
        assert_eq!(access(&path), "managed");
    }
}
