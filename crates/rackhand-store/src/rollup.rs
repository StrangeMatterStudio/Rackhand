//! Rollups (7.4.1): tier 1 holds the min, max and avg of each minute of tier 0, tier 2 the min of the mins, max of the
//! maxes and avg of the avgs of each hour of tier 1. Minute rollups come from Ingest's recent window
//! ([`put_rollups`]); hourly ones and ranges that backfilled data made dirty are recomputed from chunk rows.

use rusqlite::{Connection, params};

use crate::series::SeriesError;
use crate::series::chunk::{SeriesKey, Tier, append, backfill, last_point};
use crate::series::query::range;
use crate::series::step::Step;

const MINUTE_MS: i64 = 60_000;
const HOUR_MS: i64 = 3_600_000;

/// One series' rollup points (window start, then min, max and avg).
#[derive(Debug, Clone, PartialEq)]
pub struct RollupSeries {
    pub machine_id: String,
    pub name: String,
    pub unit: String,
    /// Canonical JSON, as `metric_keys.label_set`.
    pub label_set: String,
    pub points: Vec<(i64, [f64; 3])>,
}

fn width(tier: Tier) -> i64 {
    if tier == Tier::Hour { HOUR_MS } else { MINUTE_MS }
}

fn source(tier: Tier) -> Tier {
    if tier == Tier::Hour { Tier::Minute } else { Tier::Raw }
}

/// Stores rollup points: after the series' newest they are appended; earlier ones (a recomputed range) replace what
/// the tier had at those times.
fn store(
    conn: &Connection,
    key: &SeriesKey,
    tier: Tier,
    step: Option<Step>,
    points: &[(i64, [f64; 3])],
) -> Result<(), SeriesError> {
    let last = last_point(conn, key, tier)?;
    let split = points.partition_point(|p| last.is_some_and(|l| p.0 <= l));
    let cols = |ps: &[(i64, [f64; 3])]| -> (Vec<i64>, Vec<Vec<f64>>) {
        let ts = ps.iter().map(|p| p.0).collect();
        let cols = (0..3).map(|c| ps.iter().map(|p| p.1[c]).collect()).collect();
        (ts, cols)
    };
    let (old_ts, old_cols) = cols(&points[..split]);
    backfill(conn, key, tier, step, &old_ts, &old_cols)?;
    let (new_ts, new_cols) = cols(&points[split..]);
    append(conn, key, tier, step, &new_ts, &new_cols)
}

/// Stores minute rollups made from the recent window.
pub fn put_rollups(conn: &Connection, tier: Tier, series: &[RollupSeries]) -> Result<usize, SeriesError> {
    let mut n = 0;
    for s in series {
        let id = crate::series::compact::metric_key(conn, &s.name, &s.unit, &s.label_set)?;
        let key = SeriesKey { machine_id: s.machine_id.clone(), metric_key_id: id };
        store(conn, &key, tier, Step::for_metric(&s.name, &s.unit), &s.points)?;
        n += s.points.len();
    }
    Ok(n)
}

/// Rolls up `[from_ms, to_ms)` of every series with source data there, from chunk rows; returns the points written.
pub fn rollup(conn: &Connection, tier: Tier, from_ms: i64, to_ms: i64) -> Result<usize, SeriesError> {
    let w = width(tier);
    let (start, end) = (from_ms - from_ms.rem_euclid(w), to_ms);
    let series: Vec<(String, i64)> = {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT machine_id, metric_key_id FROM series_chunks WHERE tier = ?1 AND start_ms < ?3
             AND end_ms >= ?2",
        )?;
        stmt.query_map(params![source(tier) as i64, start, end], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?
    };
    let mut n = 0;
    for (machine_id, metric_key_id) in series {
        n += rollup_series(conn, &SeriesKey { machine_id, metric_key_id }, tier, start, end)?;
    }
    Ok(n)
}

fn rollup_series(conn: &Connection, key: &SeriesKey, tier: Tier, start: i64, end: i64) -> Result<usize, SeriesError> {
    let (name, unit): (String, String) =
        conn.query_row("SELECT name, unit FROM metric_keys WHERE id = ?1", [key.metric_key_id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    let w = width(tier);
    let mut points: Vec<(i64, [f64; 3])> = Vec::new();
    let mut window: Vec<Vec<f64>> = Vec::new();
    let mut at = i64::MIN;
    let flush = |at: i64, window: &mut Vec<Vec<f64>>, points: &mut Vec<(i64, [f64; 3])>| {
        if window.is_empty() {
            return;
        }
        // tier 0 has one value per point; tier 1 has min, max and avg
        let (mins, maxes, avgs): (Vec<f64>, Vec<f64>, Vec<f64>) = if tier == Tier::Minute {
            let v: Vec<f64> = window.iter().map(|p| p[0]).collect();
            (v.clone(), v.clone(), v)
        } else {
            (
                window.iter().map(|p| p[0]).collect(),
                window.iter().map(|p| p[1]).collect(),
                window.iter().map(|p| p[2]).collect(),
            )
        };
        let min = mins.iter().copied().fold(f64::INFINITY, f64::min);
        let max = maxes.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let avg = avgs.iter().sum::<f64>() / avgs.len() as f64;
        points.push((at, [min, max, avg]));
        window.clear();
    };
    for (t, values) in range(conn, key, source(tier), start, end - 1)? {
        let w_start = t - t.rem_euclid(w);
        if w_start != at {
            flush(at, &mut window, &mut points);
            at = w_start;
        }
        window.push(values);
    }
    flush(at, &mut window, &mut points);
    store(conn, key, tier, Step::for_metric(&name, &unit), &points)?;
    Ok(points.len())
}

/// Recomputes every range marked dirty (tier 1 before tier 2) and clears its mark; returns how many ranges.
pub fn recompute_dirty(conn: &Connection) -> Result<usize, SeriesError> {
    let dirty: Vec<(String, i64, i64, i64, i64)> = {
        let mut stmt = conn.prepare(
            "SELECT machine_id, metric_key_id, tier, from_ms, to_ms FROM rollup_dirty ORDER BY tier, from_ms",
        )?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
            .collect::<Result<_, _>>()?
    };
    for (machine_id, metric_key_id, tier, from_ms, to_ms) in &dirty {
        let tier = if *tier == 2 { Tier::Hour } else { Tier::Minute };
        let key = SeriesKey { machine_id: machine_id.clone(), metric_key_id: *metric_key_id };
        rollup_series(conn, &key, tier, *from_ms, to_ms + 1)?;
        conn.execute(
            "DELETE FROM rollup_dirty WHERE machine_id = ?1 AND metric_key_id = ?2 AND tier = ?3 AND from_ms = ?4",
            params![machine_id, metric_key_id, tier as i64, from_ms],
        )?;
    }
    Ok(dirty.len())
}
