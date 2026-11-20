//! Retention (7.4.1): every table that grows has a rule. The retention task runs the age rules hourly, deleting in
//! batches of 10 000 rows with a 50 ms pause between batches until nothing older is left.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::writer::{StoreError, StoreWriter, WriteCmd};

pub const BATCH: usize = 10_000;
pub const PAUSE: Duration = Duration::from_millis(50);
const DAY: i64 = 86_400_000;

/// The retention settings (7.8.1 ranges are checked where they are edited).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionSettings {
    pub tier0_ms: i64,
    pub tier1_ms: i64,
    pub tier2_ms: i64,
    pub events_ms: i64,
}

impl Default for RetentionSettings {
    fn default() -> RetentionSettings {
        RetentionSettings { tier0_ms: 2 * DAY, tier1_ms: 30 * DAY, tier2_ms: 365 * DAY, events_ms: 90 * DAY }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// Rows older than `keep_ms` are deleted by this task.
    Age { keep_ms: i64 },
    /// Rows are removed by their owner as part of its own work (staging by compaction, dirty marks by rollups).
    Owner(&'static str),
    /// The rule is designed (7.4.1) and its deletion is built in the named step.
    Later(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub name: &'static str,
    pub table: &'static str,
    pub kind: RuleKind,
}

/// Tables that don't grow without bound (7.4.1: "the rest").
pub const FIXED_SIZE: &[&str] = &[
    "sites",
    "machines",
    "devices",
    "operators",
    "peers",
    "policies",
    "windows",
    "metric_keys",
    "baseline_buckets",
    "checks",
    "silences",
    "jobs",
    "quarantine_rules",
    "library_items",
    "library_revisions",
    "library_drafts",
    "secrets",
    "ssh_host_keys",
    "users",
    "credentials",
    "mcp_keys",
    "schedule_state",
];

const fn rule(name: &'static str, table: &'static str, kind: RuleKind) -> Rule {
    Rule { name, table, kind }
}

pub fn rules(s: &RetentionSettings) -> Vec<Rule> {
    use RuleKind::{Age, Later, Owner};
    vec![
        rule("series_chunks.tier0", "series_chunks", Age { keep_ms: s.tier0_ms }),
        rule("series_chunks.tier1", "series_chunks", Age { keep_ms: s.tier1_ms }),
        rule("series_chunks.tier2", "series_chunks", Age { keep_ms: s.tier2_ms }),
        rule("events", "events", Age { keep_ms: s.events_ms }),
        rule("report_staging", "report_staging", Owner("compaction")),
        rule("rollup_dirty", "rollup_dirty", Owner("rollups")),
        rule("conn_records", "conn_records", Later("T98")),
        rule("job_steps", "job_steps", Later("T98")),
        rule("assistant_transcripts", "assistant_transcripts", Later("T98")),
        rule("incidents", "incidents", Later("T98")),
        rule("incident_events", "incident_events", Later("T98")),
        rule("approvals", "approvals", Later("T98")),
        rule("audit_log", "audit_log", Later("T98")),
        rule("check_results", "check_results", Later("T98")),
        rule("notifications", "notifications", Later("T98")),
        rule("peer_summaries", "peer_summaries", Later("T98")),
        rule("probe_labels", "probe_labels", Later("T98")),
        rule("conn_baseline", "conn_baseline", Later("T98")),
        rule("join_tokens", "join_tokens", Later("T98")),
        rule("job_tokens", "job_tokens", Later("T98")),
        rule("sessions", "sessions", Later("T98")),
        rule("known_devices", "known_devices", Later("T98")),
    ]
}

/// One batch of an age rule: at most `limit` rows older than `cutoff_ms`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub rule: String,
    pub cutoff_ms: i64,
    pub limit: usize,
}

/// The delete statement of an age rule (`?1` the cutoff, `?2` the batch size).
pub(crate) fn delete_sql(rule: &str) -> Option<&'static str> {
    Some(match rule {
        "series_chunks.tier0" | "series_chunks.tier1" | "series_chunks.tier2" => {
            "DELETE FROM series_chunks WHERE (machine_id, metric_key_id, tier, start_ms) IN (
               SELECT machine_id, metric_key_id, tier, start_ms FROM series_chunks
               WHERE tier = ?3 AND end_ms < ?1 LIMIT ?2)"
        }
        "events" => "DELETE FROM events WHERE rowid IN (SELECT rowid FROM events WHERE at_ms < ?1 LIMIT ?2)",
        _ => return None,
    })
}

pub(crate) fn tier_of(rule: &str) -> i64 {
    rule.strip_prefix("series_chunks.tier").and_then(|t| t.parse().ok()).unwrap_or(-1)
}

/// How the retention task waits between batches (injected in tests).
pub trait Sleeper: Send + Sync {
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

#[derive(Debug, Default)]
pub struct TokioSleeper;

impl Sleeper for TokioSleeper {
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(d))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionStats {
    pub deleted: usize,
    /// Batches that deleted something.
    pub batches: usize,
}

/// One retention run: every age rule until nothing older is left.
pub async fn run(
    writer: &StoreWriter,
    settings: &RetentionSettings,
    now_ms: i64,
    sleeper: &dyn Sleeper,
) -> Result<RetentionStats, StoreError> {
    let mut stats = RetentionStats::default();
    for r in rules(settings) {
        let RuleKind::Age { keep_ms } = r.kind else { continue };
        loop {
            let batch = Batch { rule: r.name.to_string(), cutoff_ms: now_ms - keep_ms, limit: BATCH };
            let n = writer.send(WriteCmd::RetentionBatch(batch)).await?.rows;
            if n > 0 {
                stats.deleted += n;
                stats.batches += 1;
            }
            if n < BATCH {
                break;
            }
            sleeper.sleep(PAUSE).await;
        }
    }
    Ok(stats)
}
