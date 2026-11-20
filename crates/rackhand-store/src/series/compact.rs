//! Compaction (7.3.2): staged points into chunk rows, label tables kept, staged rows deleted, in one transaction.

use rusqlite::{Connection, OptionalExtension, params};

use super::SeriesError;
use super::chunk::{SeriesKey, Tier, append, backfill, last_point};
use super::step::Step;

/// One series' staged tier 0 points, already placed at their corrected, tick-snapped times.
#[derive(Debug, Clone, PartialEq)]
pub struct SeriesPoints {
    pub name: String,
    pub unit: String,
    /// The label set as canonical JSON (sorted keys), as `metric_keys.label_set`.
    pub label_set: String,
    /// In time order, one point per timestamp.
    pub points: Vec<(i64, f64)>,
    /// The times of points that arrived after their minute ended, so a rollup may already have run without them.
    /// Only these can make a rolled-up range dirty.
    pub late: Vec<i64>,
}

/// A label table entry of a probe epoch (`probe_labels`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelRow {
    pub epoch: i64,
    pub labels_id: i64,
    pub labels: String,
}

/// Everything one machine's compaction writes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Compaction {
    pub machine_id: String,
    /// The staged reports compacted, as (epoch, seq); their rows are deleted.
    pub staged: Vec<(i64, i64)>,
    pub labels: Vec<LabelRow>,
    pub series: Vec<SeriesPoints>,
    /// The committed seq ranges per epoch (JSON), kept so they outlive the staged rows (7.3.2).
    pub ranges: Vec<(i64, String)>,
    pub now_ms: i64,
}

const MINUTE_MS: i64 = 60_000;
const HOUR_MS: i64 = 3_600_000;

/// Applies a compaction; returns the number of points written.
pub fn compact(conn: &Connection, c: &Compaction) -> Result<usize, SeriesError> {
    for l in &c.labels {
        conn.execute(
            "INSERT OR IGNORE INTO probe_labels (machine_id, epoch, labels_id, labels) VALUES (?1, ?2, ?3, ?4)",
            params![c.machine_id, l.epoch, l.labels_id, l.labels],
        )?;
    }
    let mut written = 0;
    for s in &c.series {
        if s.points.is_empty() {
            continue;
        }
        let key = SeriesKey {
            machine_id: c.machine_id.clone(),
            metric_key_id: metric_key(conn, &s.name, &s.unit, &s.label_set)?,
        };
        let step = Step::for_metric(&s.name, &s.unit);
        let last = last_point(conn, &key, Tier::Raw)?;
        let split = s.points.partition_point(|p| last.is_some_and(|l| p.0 <= l));
        let (older, newer) = s.points.split_at(split);
        let old_ts: Vec<i64> = older.iter().map(|p| p.0).collect();
        backfill(conn, &key, Tier::Raw, step, &old_ts, &[older.iter().map(|p| p.1).collect()])?;
        let ts: Vec<i64> = newer.iter().map(|p| p.0).collect();
        let values: Vec<f64> = newer.iter().map(|p| p.1).collect();
        append(conn, &key, Tier::Raw, step, &ts, &[values])?;
        mark_dirty(conn, &key, &s.late)?;
        written += s.points.len();
    }
    for (epoch, ranges) in &c.ranges {
        conn.execute(
            "INSERT INTO probe_ranges (machine_id, epoch, ranges, updated_ms) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (machine_id, epoch) DO UPDATE SET ranges = excluded.ranges, updated_ms = excluded.updated_ms",
            params![c.machine_id, epoch, ranges, c.now_ms],
        )?;
    }
    for (epoch, seq) in &c.staged {
        conn.execute(
            "DELETE FROM report_staging WHERE machine_id = ?1 AND epoch = ?2 AND seq = ?3",
            params![c.machine_id, epoch, seq],
        )?;
    }
    Ok(written)
}

/// The id of a series' metric key, added if new.
pub(crate) fn metric_key(conn: &Connection, name: &str, unit: &str, label_set: &str) -> Result<i64, SeriesError> {
    conn.execute(
        "INSERT OR IGNORE INTO metric_keys (name, unit, label_set) VALUES (?1, ?2, ?3)",
        params![name, unit, label_set],
    )?;
    Ok(conn.query_row(
        "SELECT id FROM metric_keys WHERE name = ?1 AND label_set = ?2",
        params![name, label_set],
        |r| r.get(0),
    )?)
}

/// Records the minutes and hours of `points` that were already rolled up (7.3.2), to be rolled up again.
fn mark_dirty(conn: &Connection, key: &SeriesKey, late: &[i64]) -> Result<(), SeriesError> {
    for (tier, width) in [(Tier::Minute, MINUTE_MS), (Tier::Hour, HOUR_MS)] {
        let rolled: Option<i64> = conn
            .query_row(
                "SELECT max(end_ms) FROM series_chunks WHERE machine_id = ?1 AND metric_key_id = ?2 AND tier = ?3",
                params![key.machine_id, key.metric_key_id, tier as i64],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let Some(rolled) = rolled else { continue };
        let starts: Vec<i64> = late.iter().map(|t| t - t.rem_euclid(width)).filter(|s| *s <= rolled).collect();
        let (Some(&from), Some(&last)) = (starts.iter().min(), starts.iter().max()) else { continue };
        conn.execute(
            "INSERT INTO rollup_dirty (machine_id, metric_key_id, tier, from_ms, to_ms) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (machine_id, metric_key_id, tier, from_ms) DO UPDATE SET to_ms = max(to_ms, excluded.to_ms)",
            params![key.machine_id, key.metric_key_id, tier as i64, from, last + width - 1],
        )?;
    }
    Ok(())
}
