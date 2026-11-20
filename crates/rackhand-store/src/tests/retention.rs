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
    // the rules this step runs; the others are completed in T98
    let running: Vec<&str> = rules.iter().filter(|r| matches!(r.kind, RuleKind::Age { .. })).map(|r| r.name).collect();
    assert_eq!(running, ["series_chunks.tier0", "series_chunks.tier1", "series_chunks.tier2", "events"]);
}
