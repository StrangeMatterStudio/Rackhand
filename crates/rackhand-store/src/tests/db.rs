use crate::db::{Db, OpenError, SCHEMA_VERSION};

pub fn temp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rackhand-store-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("hub.db")
}

/// The tables of design 7.4.1.
pub const DESIGN_TABLES: &[&str] = &[
    "sites",
    "machines",
    "devices",
    "operators",
    "peers",
    "peer_summaries",
    "join_tokens",
    "policies",
    "windows",
    "metric_keys",
    "report_staging",
    "probe_labels",
    "series_chunks",
    "rollup_dirty",
    "probe_ranges",
    "events",
    "conn_records",
    "conn_baseline",
    "baseline_buckets",
    "checks",
    "check_results",
    "incidents",
    "incident_events",
    "silences",
    "jobs",
    "job_steps",
    "assistant_transcripts",
    "approvals",
    "quarantine_rules",
    "library_items",
    "library_revisions",
    "library_drafts",
    "notifications",
    "secrets",
    "ssh_host_keys",
    "users",
    "credentials",
    "known_devices",
    "sessions",
    "mcp_keys",
    "job_tokens",
    "schedule_state",
    "audit_log",
];

#[test]
fn opens_in_wal_mode_with_schema_version() {
    let db = Db::open(&temp("wal")).unwrap();
    let conn = db.connection();
    let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
    assert_eq!(mode, "wal");
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
    assert_eq!(version, SCHEMA_VERSION);
}

#[test]
fn newer_database_is_refused() {
    let path = temp("newer");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(&format!("PRAGMA user_version = {}; CREATE TABLE marker(x);", SCHEMA_VERSION + 1)).unwrap();
    }
    match Db::open(&path) {
        Err(OpenError::DatabaseTooNew { found, supported }) => {
            assert_eq!(found, SCHEMA_VERSION + 1);
            assert_eq!(supported, SCHEMA_VERSION);
        }
        other => panic!("expected DatabaseTooNew, got {other:?}"),
    }
    let conn = rusqlite::Connection::open(&path).unwrap();
    let tables: i64 =
        conn.query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table'", [], |r| r.get(0)).unwrap();
    assert_eq!(tables, 1, "nothing was written to the newer database");
}

#[test]
fn every_table_in_the_design_exists() {
    let db = Db::open(&temp("tables")).unwrap();
    let conn = db.connection();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap();
    let found: Vec<String> = stmt.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    let mut want: Vec<String> = DESIGN_TABLES.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(found, want);
}

/// 7.5.3 step 9: a policy takes a snapshot before patching unless it says `optional`, and rolls back only when told to.
#[test]
fn policy_defaults_snapshot_required_no_auto_rollback() {
    let db = Db::open(&temp("policy-defaults")).unwrap();
    let conn = db.connection();
    conn.execute("INSERT INTO policies (id, name) VALUES ('p', 'servers')", []).unwrap();
    let got: (String, i64) = conn
        .query_row("SELECT snapshot, auto_rollback FROM policies WHERE id = 'p'", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    assert_eq!(got, ("required".to_string(), 0));
}

/// A database the way the previous build made it: the peers table without the address columns, at version 1.
fn previous_build(name: &str) -> std::path::PathBuf {
    let path = temp(name);
    drop(Db::open(&path).unwrap());
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "ALTER TABLE peers DROP COLUMN addrs; ALTER TABLE peers DROP COLUMN relays;
         INSERT INTO peers (id, site, endpoint_id, added_at) VALUES ('p1', 'beta', 'abc', 5);
         PRAGMA user_version = 1;",
    )
    .unwrap();
    path
}

#[test]
fn a_version_1_database_is_upgraded_and_keeps_its_rows() {
    let path = previous_build("upgrade");
    let db = Db::open(&path).unwrap();
    let conn = db.connection();
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
    assert_eq!(version, SCHEMA_VERSION);
    let (site, addrs, relays): (String, String, String) = conn
        .query_row("SELECT site, addrs, relays FROM peers WHERE id = 'p1'", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(
        (site.as_str(), addrs.as_str(), relays.as_str()),
        ("beta", "[]", "[]"),
        "the row stays, the new columns are empty"
    );
}

#[test]
fn opening_an_upgraded_database_again_changes_nothing() {
    let path = previous_build("again");
    drop(Db::open(&path).unwrap());
    let db = Db::open(&path).unwrap();
    let conn = db.connection();
    let n: i64 = conn.query_row("SELECT count(*) FROM peers", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 1);
}
