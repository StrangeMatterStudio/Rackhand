use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::db::{DESIGN_TABLES, temp};
use crate::Db;
use crate::retention::{FIXED_SIZE, RetentionSettings, RuleKind, Sleeper, rules, run};

const DAY: i64 = 86_400_000;
const NOW: i64 = 1_795_068_000_000;

#[derive(Debug, Default)]
struct Counting(AtomicUsize);

impl Sleeper for Counting {
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        assert_eq!(d, Duration::from_millis(50));
        self.0.fetch_add(1, Ordering::Relaxed);
        Box::pin(async {})
    }
}

/// One chunk row ending at `end_ms`.
fn chunk_row(conn: &rusqlite::Connection, metric_key_id: i64, tier: i64, end_ms: i64) {
    conn.execute(
        "INSERT INTO series_chunks (machine_id, metric_key_id, tier, start_ms, end_ms, count, closed, data)
         VALUES ('m', ?1, ?2, ?3, ?3, 1, 1, x'00')",
        rusqlite::params![metric_key_id, tier, end_ms],
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn each_tier_removes_only_older_than_limit() {
    let path = temp("retention-tiers");
    let db = Db::open(&path).unwrap();
    let settings = RetentionSettings::default();
    assert_eq!(
        (settings.tier0_ms, settings.tier1_ms, settings.tier2_ms, settings.events_ms),
        (2 * DAY, 30 * DAY, 365 * DAY, 90 * DAY)
    );
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        for (tier, limit) in [(0, settings.tier0_ms), (1, settings.tier1_ms), (2, settings.tier2_ms)] {
            chunk_row(&conn, 1, tier, NOW - limit + 1);
            chunk_row(&conn, 2, tier, NOW - limit - 1);
        }
        for (id, at) in [("e1", NOW - settings.events_ms + 1), ("e2", NOW - settings.events_ms - 1)] {
            conn.execute(
                "INSERT INTO events (id, at_ms, kind, severity) VALUES (?1, ?2, 'k', 'info')",
                rusqlite::params![id, at],
            )
            .unwrap();
        }
    }
    let stats = run(&db.writer(), &settings, NOW, &Counting::default()).await.unwrap();
    assert_eq!(stats.deleted, 4);
    let conn = db.connection();
    let left: Vec<(i64, i64)> = conn
        .prepare("SELECT tier, metric_key_id FROM series_chunks ORDER BY tier")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(left, vec![(0, 1), (1, 1), (2, 1)], "1 ms inside the limit stays, 1 ms past it goes");
    let events: Vec<String> = conn
        .prepare("SELECT id FROM events")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(events, ["e1"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn deletes_in_batches_with_pauses() {
    let path = temp("retention-batches");
    let db = Db::open(&path).unwrap();
    {
        let mut conn = rusqlite::Connection::open(&path).unwrap();
        let tx = conn.transaction().unwrap();
        for i in 0..25_000 {
            chunk_row(&tx, i, 0, NOW - 3 * DAY - i);
        }
        tx.commit().unwrap();
    }
    let sleeper = Counting::default();
    let stats = run(&db.writer(), &RetentionSettings::default(), NOW, &sleeper).await.unwrap();
    assert_eq!((stats.deleted, stats.batches), (25_000, 3), "batches of 10 000");
    assert_eq!(sleeper.0.load(Ordering::Relaxed), 2, "a 50 ms pause between batches");
    let left: i64 = db.connection().query_row("SELECT count(*) FROM series_chunks", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 0);
}

#[test]
fn registry_lists_a_rule_for_every_growing_table() {
    let rules = rules(&RetentionSettings::default());
    for table in DESIGN_TABLES {
        let ruled = rules.iter().any(|r| r.table == *table);
        let fixed = FIXED_SIZE.contains(table);
        assert!(ruled ^ fixed, "{table}: a retention rule or fixed size, not both and not neither");
    }
    for r in &rules {
        assert!(DESIGN_TABLES.contains(&r.table), "rule for unknown table {}", r.table);
    }
    assert!(!rules.iter().any(|r| matches!(r.kind, RuleKind::Later(_))), "none left for later");
}

/// The rules of 7.4.1, by table: what is kept, and from which time.
#[test]
fn every_table_rule_from_design() {
    let s = RetentionSettings::default();
    let got: Vec<(&str, &str, Option<i64>)> = rules(&s)
        .iter()
        .map(|r| match r.kind {
            RuleKind::Age { keep_ms } => (r.name, r.table, Some(keep_ms)),
            RuleKind::Owner(_) => (r.name, r.table, None),
            RuleKind::Later(step) => panic!("{} is still left to {step}", r.name),
        })
        .collect();
    let want: Vec<(&str, &str, Option<i64>)> = vec![
        ("series_chunks.tier0", "series_chunks", Some(2 * DAY)),
        ("series_chunks.tier1", "series_chunks", Some(30 * DAY)),
        ("series_chunks.tier2", "series_chunks", Some(365 * DAY)),
        ("events", "events", Some(90 * DAY)),
        ("report_staging", "report_staging", None),
        ("rollup_dirty", "rollup_dirty", None),
        ("probe_labels", "probe_labels", Some(2 * DAY)),
        ("probe_ranges", "probe_ranges", Some(2 * DAY)),
        ("conn_records", "conn_records", Some(30 * DAY)),
        ("job_steps", "job_steps", Some(90 * DAY)),
        ("assistant_transcripts", "assistant_transcripts", Some(90 * DAY)),
        ("incidents", "incidents", Some(365 * DAY)),
        ("incident_events", "incident_events", None),
        ("approvals", "approvals", Some(365 * DAY)),
        ("audit_log", "audit_log", Some(365 * DAY)),
        ("check_results", "check_results", Some(30 * DAY)),
        ("notifications", "notifications", Some(90 * DAY)),
        ("peer_summaries", "peer_summaries", None),
        ("conn_baseline", "conn_baseline", Some(180 * DAY)),
        ("join_tokens", "join_tokens", Some(30 * DAY)),
        ("job_tokens", "job_tokens", Some(30 * DAY)),
        ("sessions", "sessions", Some(0)),
        ("known_devices", "known_devices", Some(365 * DAY)),
    ];
    assert_eq!(got, want);
}

fn exec(conn: &rusqlite::Connection, sql: &str, params: impl rusqlite::Params) {
    conn.execute(sql, params).unwrap_or_else(|e| panic!("{sql}: {e}"));
}

fn ids(conn: &rusqlite::Connection, sql: &str) -> Vec<String> {
    conn.prepare(sql).unwrap().query_map([], |r| r.get::<_, String>(0)).unwrap().map(Result::unwrap).collect()
}

/// Every rule's table seeded with a row 1 ms past its limit ("old") and one 1 ms inside it ("new").
#[tokio::test(flavor = "multi_thread")]
async fn run_leaves_nothing_older_than_rule() {
    use rusqlite::params;
    let path = temp("retention-every-table");
    let db = Db::open(&path).unwrap();
    let past = |keep: i64| NOW - keep - 1;
    let inside = |keep: i64| NOW - keep + 1;
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        exec(&conn, "PRAGMA foreign_keys = ON", []);
        exec(&conn, "INSERT INTO users (id, name, role, created_at) VALUES ('u', 'u', 'admin', 0)", []);
        exec(&conn, "INSERT INTO checks (id, kind, target, interval_s) VALUES ('c', 'tcp', 'x:1', 60)", []);
        exec(&conn, "INSERT INTO peers (id, site, endpoint_id, added_at) VALUES ('p', 's', 'e', 0)", []);
        exec(&conn, "INSERT INTO operators (id, name, endpoint_id) VALUES ('o', 'o', 'oe')", []);
        for id in ["old", "new"] {
            exec(
                &conn,
                "INSERT INTO jobs (id, kind, name, requested_by, state) VALUES (?1, 'runbook', 'r', 'u', 'succeeded')",
                [id],
            );
        }
        for (id, keep) in [("old", past(30 * DAY)), ("new", inside(30 * DAY))] {
            exec(
                &conn,
                "INSERT INTO conn_records (machine_id, bucket_ms, exe, dest_ip, dest_port, proto) VALUES ('m', ?2, ?1, 'x', 1, 'tcp')",
                params![id, keep],
            );
            exec(
                &conn,
                "INSERT INTO check_results (check_id, at_ms, ok, detail) VALUES ('c', ?2, 1, ?1)",
                params![id, keep],
            );
        }
        for (id, at) in [("old", past(90 * DAY)), ("new", inside(90 * DAY))] {
            exec(
                &conn,
                "INSERT INTO job_steps (job_id, step_id, state, stdout, stderr, ended_at) VALUES (?1, 's', 'succeeded', x'6f6b', x'21', ?2)",
                params![id, at],
            );
            exec(
                &conn,
                "INSERT INTO assistant_transcripts (job_id, seq, at_ms, kind, text) VALUES (?1, 1, ?2, 'turn', 'said')",
                params![id, at],
            );
            exec(
                &conn,
                "INSERT INTO notifications (id, notifier, at_ms, state) VALUES (?1, 'n', ?2, 'sent')",
                params![id, at],
            );
        }
        let year = 365 * DAY;
        for (id, resolved) in [("old", Some(past(year))), ("new", Some(inside(year))), ("open", None)] {
            exec(
                &conn,
                "INSERT INTO incidents (id, dedupe_key, kind, severity, state, title, opened_at, resolved_at)
                 VALUES (?1, ?1, 'k', 'warning', CASE WHEN ?2 IS NULL THEN 'open' ELSE 'resolved' END, 't', ?3, ?2)",
                params![id, resolved, NOW - 2 * year],
            );
            exec(
                &conn,
                "INSERT INTO incident_events (id, incident_id, at_ms, kind) VALUES (?1, ?1, ?2, 'opened')",
                params![id, NOW - 2 * year],
            );
        }
        for (id, decided) in [("old", past(year)), ("new", inside(year))] {
            exec(
                &conn,
                "INSERT INTO approvals (id, tool, args_hash, risk, requested_by, state, decided_at, expires_at)
                 VALUES (?1, 't', x'00', 'low', 'u', 'used', ?2, ?2)",
                params![id, decided],
            );
            exec(
                &conn,
                "INSERT INTO known_devices (user_id, cookie_hash, first_seen_at, last_seen_at) VALUES ('u', ?1, 0, ?2)",
                params![id, decided],
            );
        }
        for (id, seen) in [("old", past(180 * DAY)), ("new", inside(180 * DAY))] {
            exec(
                &conn,
                "INSERT INTO conn_baseline (machine_id, exe, dest_asn, dest_country, dest_port, proto, first_seen_ms, last_seen_ms)
                 VALUES ('m', ?1, 1, 'NL', 1, 'tcp', 0, ?2)",
                params![id, seen],
            );
        }
        for (id, expires) in [("old", past(30 * DAY)), ("new", inside(30 * DAY))] {
            exec(
                &conn,
                "INSERT INTO join_tokens (id, kind, hash, created_by, expires_at) VALUES (?1, 'machine', ?1, 'u', ?2)",
                params![id, expires],
            );
            exec(
                &conn,
                "INSERT INTO job_tokens (job_id, operator_id, hash, expires_at) VALUES (?1, 'o', ?1, ?2)",
                params![id, expires],
            );
        }
        for (id, expires) in [("old", NOW - 1), ("new", NOW + 1)] {
            exec(
                &conn,
                "INSERT INTO sessions (id_hash, user_id, created_at, last_seen_at, expires_at) VALUES (?1, 'u', 0, 0, ?2)",
                params![id, expires],
            );
        }
        exec(&conn, "INSERT INTO peer_summaries (peer_id, received_at_ms, summary) VALUES ('p', 0, x'00')", []);
        // label tables and committed ranges: machine m moved to epoch 2 long ago; machine n has only epoch 1, silent
        // for as long, and keeps it (its newest)
        for (machine, epoch, updated) in [("m", 1, past(2 * DAY)), ("m", 2, past(2 * DAY)), ("n", 1, past(9 * DAY))] {
            exec(
                &conn,
                "INSERT INTO probe_ranges (machine_id, epoch, ranges, updated_ms) VALUES (?1, ?2, '[]', ?3)",
                params![machine, epoch, updated],
            );
            exec(
                &conn,
                "INSERT INTO probe_labels (machine_id, epoch, labels_id) VALUES (?1, ?2, 1)",
                params![machine, epoch],
            );
        }
        exec(
            &conn,
            "INSERT INTO probe_ranges (machine_id, epoch, ranges, updated_ms) VALUES ('k', 1, '[]', ?1), ('k', 2, '[]', ?2)",
            params![inside(2 * DAY), NOW],
        );
        exec(&conn, "INSERT INTO probe_labels (machine_id, epoch, labels_id) VALUES ('k', 1, 1), ('k', 2, 1)", []);
    }
    // the audit chain through the writer, so its hashes are real
    for (n, at) in [(1, past(365 * DAY) - 5), (2, past(365 * DAY)), (3, inside(365 * DAY))] {
        let row: crate::Row = [
            ("at_ms", rusqlite::types::Value::Integer(at)),
            ("actor", rusqlite::types::Value::Text("u".into())),
            ("action", rusqlite::types::Value::Text(format!("a{n}"))),
            ("data", rusqlite::types::Value::Text("{}".into())),
        ]
        .into_iter()
        .collect();
        db.writer().send(crate::WriteCmd::AppendAudit(row)).await.unwrap();
    }

    run(&db.writer(), &RetentionSettings::default(), NOW, &Counting::default()).await.unwrap();

    let conn = db.connection();
    assert_eq!(ids(&conn, "SELECT exe FROM conn_records"), ["new"]);
    assert_eq!(ids(&conn, "SELECT detail FROM check_results"), ["new"]);
    assert_eq!(ids(&conn, "SELECT id FROM notifications"), ["new"]);
    assert_eq!(
        ids(
            &conn,
            "SELECT job_id || ':' || CASE WHEN stdout IS NULL THEN '-' ELSE hex(stdout) END || ':' || CASE WHEN stderr IS NULL THEN '-' ELSE hex(stderr) END FROM job_steps ORDER BY job_id"
        ),
        ["new:6F6B:21", "old:-:-"],
        "old output trimmed, its step kept"
    );
    assert_eq!(
        ids(&conn, "SELECT job_id || ':' || coalesce(text, '-') FROM assistant_transcripts ORDER BY job_id"),
        ["new:said", "old:-"],
        "old transcript text trimmed, its turns kept"
    );
    assert_eq!(ids(&conn, "SELECT id FROM incidents ORDER BY id"), ["new", "open"], "an open incident stays");
    assert_eq!(ids(&conn, "SELECT id FROM incident_events ORDER BY id"), ["new", "open"], "with their incident");
    assert_eq!(ids(&conn, "SELECT id FROM approvals"), ["new"]);
    assert_eq!(ids(&conn, "SELECT cast(cookie_hash AS TEXT) FROM known_devices"), ["new"]);
    assert_eq!(ids(&conn, "SELECT exe FROM conn_baseline"), ["new"]);
    assert_eq!(ids(&conn, "SELECT id FROM join_tokens"), ["new"]);
    assert_eq!(ids(&conn, "SELECT job_id FROM job_tokens"), ["new"]);
    assert_eq!(ids(&conn, "SELECT cast(id_hash AS TEXT) FROM sessions"), ["new"]);
    assert_eq!(ids(&conn, "SELECT peer_id FROM peer_summaries"), ["p"], "the latest summary of each peer stays");
    let epochs = "SELECT machine_id || cast(epoch AS TEXT) FROM probe_ranges ORDER BY 1";
    assert_eq!(ids(&conn, epochs), ["k1", "k2", "m2", "n1"], "an older epoch goes 48 h after its last report");
    let labels = "SELECT machine_id || cast(epoch AS TEXT) FROM probe_labels ORDER BY 1";
    assert_eq!(ids(&conn, labels), ["k1", "k2", "m2", "n1"], "its label table with it");
    let audit: Vec<String> = ids(&conn, "SELECT action FROM audit_log ORDER BY seq");
    assert_eq!(audit, ["a3", "audit.checkpoint"], "a checkpoint for the removed rows");
    let checkpoint = ids(&conn, "SELECT data FROM audit_log WHERE checkpoint = 1");
    assert!(checkpoint[0].contains("\"removed_through_seq\":2"), "{checkpoint:?}");
}

/// `peer_summaries` holds the latest summary of each peer only (7.4.1).
#[tokio::test(flavor = "multi_thread")]
async fn peer_summaries_one_row_per_peer() {
    let path = temp("retention-peer-summaries");
    let db = Db::open(&path).unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        for (id, site) in [("p1", "a"), ("p2", "b")] {
            exec(&conn, "INSERT INTO peers (id, site, endpoint_id, added_at) VALUES (?1, ?2, ?1, 0)", [id, site]);
        }
    }
    for (peer, at) in [("p1", 1), ("p1", 2), ("p2", 3), ("p1", 4)] {
        let row: crate::Row = [
            ("peer_id", rusqlite::types::Value::Text(peer.into())),
            ("received_at_ms", rusqlite::types::Value::Integer(at)),
            ("summary", rusqlite::types::Value::Blob(vec![at as u8])),
        ]
        .into_iter()
        .collect();
        db.writer().send(crate::WriteCmd::PutPeerSummary(row)).await.unwrap();
    }
    let conn = db.connection();
    assert_eq!(
        ids(&conn, "SELECT peer_id || ':' || cast(received_at_ms AS TEXT) FROM peer_summaries ORDER BY peer_id"),
        ["p1:4", "p2:3"]
    );
}
