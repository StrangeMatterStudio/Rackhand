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
