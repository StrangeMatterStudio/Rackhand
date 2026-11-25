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

/// The rules, in the order they run: a label table goes before its epoch's ranges, which it is judged by.
pub fn rules(s: &RetentionSettings) -> Vec<Rule> {
    use RuleKind::{Age, Owner};
    vec![
        rule("series_chunks.tier0", "series_chunks", Age { keep_ms: s.tier0_ms }),
        rule("series_chunks.tier1", "series_chunks", Age { keep_ms: s.tier1_ms }),
        rule("series_chunks.tier2", "series_chunks", Age { keep_ms: s.tier2_ms }),
        rule("events", "events", Age { keep_ms: s.events_ms }),
        rule("report_staging", "report_staging", Owner("compaction")),
        rule("rollup_dirty", "rollup_dirty", Owner("rollups")),
        // an epoch's label table and committed ranges, 48 h after its last report once the machine has a newer epoch;
        // the newest epoch's stay, so a machine back after days still knows what it already sent
        rule("probe_labels", "probe_labels", Age { keep_ms: 2 * DAY }),
        rule("probe_ranges", "probe_ranges", Age { keep_ms: 2 * DAY }),
        rule("conn_records", "conn_records", Age { keep_ms: 30 * DAY }),
        // output and transcript text only: the job's steps and turns stay
        rule("job_steps", "job_steps", Age { keep_ms: 90 * DAY }),
        rule("assistant_transcripts", "assistant_transcripts", Age { keep_ms: 90 * DAY }),
        // resolved ones, a year after they were resolved
        rule("incidents", "incidents", Age { keep_ms: 365 * DAY }),
        rule("incident_events", "incident_events", Owner("incidents (deleted with their incident)")),
        rule("approvals", "approvals", Age { keep_ms: 365 * DAY }),
        // with a checkpoint row before each deletion, so the chain stays verifiable
        rule("audit_log", "audit_log", Age { keep_ms: 365 * DAY }),
        rule("check_results", "check_results", Age { keep_ms: 30 * DAY }),
        rule("notifications", "notifications", Age { keep_ms: 90 * DAY }),
        rule("peer_summaries", "peer_summaries", Owner("peer links (one row per peer, replaced)")),
        rule("conn_baseline", "conn_baseline", Age { keep_ms: 180 * DAY }),
        rule("join_tokens", "join_tokens", Age { keep_ms: 30 * DAY }),
        rule("job_tokens", "job_tokens", Age { keep_ms: 30 * DAY }),
        rule("sessions", "sessions", Age { keep_ms: 0 }),
        rule("known_devices", "known_devices", Age { keep_ms: 365 * DAY }),
    ]
}

/// One batch of an age rule: at most `limit` rows older than `cutoff_ms`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub rule: String,
    pub cutoff_ms: i64,
    pub limit: usize,
    /// When the run started (an audit checkpoint's time).
    pub now_ms: i64,
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
        "probe_labels" => {
            "DELETE FROM probe_labels WHERE (machine_id, epoch, labels_id) IN (
               SELECT l.machine_id, l.epoch, l.labels_id FROM probe_labels l
               WHERE EXISTS (SELECT 1 FROM probe_ranges n WHERE n.machine_id = l.machine_id AND n.epoch > l.epoch)
                 AND NOT EXISTS (SELECT 1 FROM probe_ranges r
                                 WHERE r.machine_id = l.machine_id AND r.epoch = l.epoch AND r.updated_ms >= ?1)
               LIMIT ?2)"
        }
        "probe_ranges" => {
            "DELETE FROM probe_ranges WHERE (machine_id, epoch) IN (
               SELECT r.machine_id, r.epoch FROM probe_ranges r
               WHERE r.updated_ms < ?1
                 AND EXISTS (SELECT 1 FROM probe_ranges n WHERE n.machine_id = r.machine_id AND n.epoch > r.epoch)
               LIMIT ?2)"
        }
        "conn_records" => {
            "DELETE FROM conn_records WHERE (machine_id, bucket_ms, container, exe, dest_ip, dest_port, proto) IN (
               SELECT machine_id, bucket_ms, container, exe, dest_ip, dest_port, proto FROM conn_records
               WHERE bucket_ms < ?1 LIMIT ?2)"
        }
        "job_steps" => {
            "UPDATE job_steps SET stdout = NULL, stderr = NULL WHERE (job_id, step_id) IN (
               SELECT job_id, step_id FROM job_steps
               WHERE ended_at < ?1 AND (stdout IS NOT NULL OR stderr IS NOT NULL) LIMIT ?2)"
        }
        "assistant_transcripts" => {
            "UPDATE assistant_transcripts SET text = NULL WHERE (job_id, seq) IN (
               SELECT job_id, seq FROM assistant_transcripts WHERE at_ms < ?1 AND text IS NOT NULL LIMIT ?2)"
        }
        "incidents" => "DELETE FROM incidents WHERE id IN (SELECT id FROM incidents WHERE resolved_at < ?1 LIMIT ?2)",
        "approvals" => {
            "DELETE FROM approvals WHERE id IN (
               SELECT id FROM approvals WHERE coalesce(decided_at, expires_at) < ?1 LIMIT ?2)"
        }
        "check_results" => {
            "DELETE FROM check_results WHERE (check_id, at_ms) IN (
               SELECT check_id, at_ms FROM check_results WHERE at_ms < ?1 LIMIT ?2)"
        }
        "notifications" => {
            "DELETE FROM notifications WHERE id IN (SELECT id FROM notifications WHERE at_ms < ?1 LIMIT ?2)"
        }
        "conn_baseline" => {
            "DELETE FROM conn_baseline WHERE (machine_id, container, exe, dest_asn, dest_country, dest_port, proto) IN (
               SELECT machine_id, container, exe, dest_asn, dest_country, dest_port, proto FROM conn_baseline
               WHERE last_seen_ms < ?1 LIMIT ?2)"
        }
        "join_tokens" => {
            "DELETE FROM join_tokens WHERE id IN (SELECT id FROM join_tokens WHERE expires_at < ?1 LIMIT ?2)"
        }
        "job_tokens" => {
            "DELETE FROM job_tokens WHERE job_id IN (SELECT job_id FROM job_tokens WHERE expires_at < ?1 LIMIT ?2)"
        }
        "sessions" => {
            "DELETE FROM sessions WHERE id_hash IN (SELECT id_hash FROM sessions WHERE expires_at < ?1 LIMIT ?2)"
        }
        "known_devices" => {
            "DELETE FROM known_devices WHERE (user_id, cookie_hash) IN (
               SELECT user_id, cookie_hash FROM known_devices WHERE last_seen_at < ?1 LIMIT ?2)"
        }
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
            let batch = Batch { rule: r.name.to_string(), cutoff_ms: now_ms - keep_ms, limit: BATCH, now_ms };
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
