use std::sync::Arc;

use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use super::*;

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn at(text: &str) -> i64 {
    text.parse::<jiff::Timestamp>().unwrap().as_millisecond()
}

async fn db(name: &str) -> Arc<Db> {
    let dir = std::env::temp_dir().join(format!("rackhand-patchwindows-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let site = |id: &str, tz: &str| {
        RowWrite::insert("sites", Row::from([("id", t(id)), ("name", t(id)), ("timezone", t(tz))]))
    };
    let machine = |id: &str, site: &str, policy: &str| {
        RowWrite::insert(
            "machines",
            Row::from([
                ("id", t(id)),
                ("site_id", t(site)),
                ("name", t(id)),
                ("kind", t("linux")),
                ("policy_id", t(policy)),
            ]),
        )
    };
    let policy = |id: &str, patch: &str, extra: &[(&'static str, Value)]| {
        let mut row = Row::from([("id", t(id)), ("name", t(id)), ("patch", t(patch))]);
        row.extend(extra.iter().cloned());
        RowWrite::insert("policies", row)
    };
    db.writer()
        .send(WriteCmd::Batch(vec![
            site("utc", "UTC"),
            site("chi", "America/Chicago"),
            policy("plain", "auto", &[]),
            policy("held", "hold", &[]),
            policy("own", "auto", &[("security_window", t("daily 10:00")), ("window_length_min", Value::Integer(60))]),
            policy("bad", "auto", &[("security_window", t("whenever"))]),
            machine("a", "utc", "plain"),
            machine("b", "chi", "plain"),
            machine("c", "utc", "held"),
            machine("d", "utc", "own"),
            machine("e", "utc", "bad"),
        ]))
        .await
        .unwrap();
    db
}

fn names(open: &[OpenWindow]) -> Vec<(String, String, bool)> {
    open.iter().map(|w| (w.policy.clone(), w.site.clone(), w.full)).collect()
}

/// 7.5.3 step 1: the security window defaults to daily 04:00 and the full window to Sunday 03:00, 180 minutes long, in
/// each site's timezone; a policy's own time and length replace them; `hold` has none, and an unreadable time opens
/// nothing rather than the default.
#[tokio::test(flavor = "multi_thread")]
async fn open_windows_by_policy_and_site_timezone() {
    let db = db("open").await;
    // Monday 2026-11-23 04:30 UTC: 22:30 on Sunday in Chicago
    let open = open(&db, at("2026-11-23T04:30:00Z")).unwrap();
    assert_eq!(names(&open), [("plain".to_string(), "utc".to_string(), false)]);
    assert_eq!((open[0].starts_ms, open[0].ends_ms), (at("2026-11-23T04:00:00Z"), at("2026-11-23T07:00:00Z")));
    assert_eq!(open[0].next_ends_ms, at("2026-11-24T07:00:00Z"));
    // 04:30 in Chicago (UTC-6 in November)
    let chicago = super::open(&db, at("2026-11-23T10:30:00Z")).unwrap();
    assert_eq!(
        names(&chicago),
        [("own".to_string(), "utc".to_string(), false), ("plain".to_string(), "chi".to_string(), false)]
    );
    assert_eq!(chicago[0].ends_ms - chicago[0].starts_ms, 60 * 60_000, "the policy's own length");
    // Sunday 2026-11-22 05:00 UTC: both windows
    let sunday = super::open(&db, at("2026-11-22T05:00:00Z")).unwrap();
    assert_eq!(
        names(&sunday),
        [
            ("bad".to_string(), "utc".to_string(), true),
            ("plain".to_string(), "utc".to_string(), false),
            ("plain".to_string(), "utc".to_string(), true)
        ]
    );
    assert_eq!(sunday[2].next_ends_ms, at("2026-11-29T06:00:00Z"));
    assert!(super::open(&db, at("2026-11-23T15:00:00Z")).unwrap().is_empty());
}
