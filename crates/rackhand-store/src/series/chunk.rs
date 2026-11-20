//! Chunk rows (7.4.1): a row is open until it holds 120 points, and a tier 0 row also closes when its hour ends.

use rusqlite::{Connection, OptionalExtension, params};

use super::SeriesError;
use super::codec::{Chunk, Column, decode, encode};
use super::step::Step;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Tier 0: samples as reported.
    Raw = 0,
    /// Tier 1: min, max and avg per minute.
    Minute = 1,
    /// Tier 2: min, max and avg per hour.
    Hour = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeriesKey {
    pub machine_id: String,
    pub metric_key_id: i64,
}

pub const CHUNK_POINTS: usize = 120;
const HOUR_MS: i64 = 3_600_000;

/// Whether a row that starts at `start_ms` and holds `count` points is closed before a point at `next_ms` joins it.
pub fn closes_before(tier: Tier, start_ms: i64, count: usize, next_ms: i64) -> bool {
    count >= CHUNK_POINTS || (tier == Tier::Raw && next_ms.div_euclid(HOUR_MS) != start_ms.div_euclid(HOUR_MS))
}

struct Open {
    start_ms: i64,
    chunk: Chunk,
}

/// Appends points (strictly increasing `ts`, one `cols` entry per stored field) to the series' open row, closing and
/// opening rows by the chunk rule. Points at or before the open row's last point are refused.
pub fn append(
    conn: &Connection,
    key: &SeriesKey,
    tier: Tier,
    step: Option<Step>,
    ts: &[i64],
    cols: &[Vec<f64>],
) -> Result<(), SeriesError> {
    if cols.is_empty() || cols.iter().any(|c| c.len() != ts.len()) || ts.windows(2).any(|w| w[0] >= w[1]) {
        return Err(SeriesError::Shape);
    }
    if ts.is_empty() {
        return Ok(());
    }
    let mut open = load_open(conn, key, tier)?;
    if let Some(o) = &open {
        if o.chunk.cols.len() != cols.len() {
            return Err(SeriesError::Shape);
        }
        let last_ms = *o.chunk.ts.last().ok_or(SeriesError::Shape)?;
        if ts[0] <= last_ms {
            return Err(SeriesError::OutOfOrder { last_ms });
        }
    }
    for (i, &t) in ts.iter().enumerate() {
        if let Some(o) = open.take_if(|o| closes_before(tier, o.start_ms, o.chunk.ts.len(), t)) {
            write(conn, key, tier, &o, true)?;
        }
        let o = open.get_or_insert_with(|| Open {
            start_ms: t,
            chunk: Chunk { ts: Vec::new(), cols: cols.iter().map(|_| Column::from_values(step, &[])).collect() },
        });
        o.chunk.ts.push(t);
        for (col, values) in o.chunk.cols.iter_mut().zip(cols) {
            push(col, step, values[i]);
        }
    }
    if let Some(o) = &open {
        write(conn, key, tier, o, false)?;
    }
    Ok(())
}

/// Adds a value to a column, turning an integer column into a float one when the value has no integer at its step.
fn push(col: &mut Column, step: Option<Step>, v: f64) {
    if let Column::Int { step: s, values } = col {
        match (step == Some(*s)).then(|| s.to_int(v)).flatten() {
            Some(i) => {
                values.push(i);
                return;
            }
            None => *col = Column::Float(col.to_f64()),
        }
    }
    if let Column::Float(values) = col {
        values.push(v);
    }
}

fn load_open(conn: &Connection, key: &SeriesKey, tier: Tier) -> Result<Option<Open>, SeriesError> {
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT start_ms, data FROM series_chunks WHERE machine_id = ?1 AND metric_key_id = ?2 AND tier = ?3
             AND closed = 0 ORDER BY start_ms DESC LIMIT 1",
            params![key.machine_id, key.metric_key_id, tier as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(start_ms, data)| Ok(Open { start_ms, chunk: decode(&data)? })).transpose()
}

fn write(conn: &Connection, key: &SeriesKey, tier: Tier, open: &Open, closed: bool) -> Result<(), SeriesError> {
    let end_ms = *open.chunk.ts.last().ok_or(SeriesError::Shape)?;
    conn.execute(
        "INSERT INTO series_chunks (machine_id, metric_key_id, tier, start_ms, end_ms, count, closed, data)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT (machine_id, metric_key_id, tier, start_ms) DO UPDATE SET
           end_ms = excluded.end_ms, count = excluded.count, closed = excluded.closed, data = excluded.data",
        params![
            key.machine_id,
            key.metric_key_id,
            tier as i64,
            open.start_ms,
            end_ms,
            open.chunk.ts.len() as i64,
            closed as i64,
            encode(&open.chunk),
        ],
    )?;
    Ok(())
}

/// The time of the series' newest point in a tier (its open row's last point), if it has any.
pub fn last_point(conn: &Connection, key: &SeriesKey, tier: Tier) -> Result<Option<i64>, SeriesError> {
    Ok(conn
        .query_row(
            "SELECT max(end_ms) FROM series_chunks WHERE machine_id = ?1 AND metric_key_id = ?2 AND tier = ?3",
            params![key.machine_id, key.metric_key_id, tier as i64],
            |r| r.get(0),
        )
        .optional()?
        .flatten())
}

/// Writes points older than the series' newest point (replayed data) as closed rows by the chunk rule. A row that
/// already starts at a group's first point takes the group's points, which replace its own at the same times.
pub fn backfill(
    conn: &Connection,
    key: &SeriesKey,
    tier: Tier,
    step: Option<Step>,
    points: &[(i64, f64)],
) -> Result<(), SeriesError> {
    let mut start = 0;
    for i in 1..=points.len() {
        if i < points.len() && !closes_before(tier, points[start].0, i - start, points[i].0) {
            continue;
        }
        let group = &points[start..i];
        start = i;
        let existing: Option<(Vec<u8>, i64)> = conn
            .query_row(
                "SELECT data, closed FROM series_chunks WHERE machine_id = ?1 AND metric_key_id = ?2 AND tier = ?3
                 AND start_ms = ?4",
                params![key.machine_id, key.metric_key_id, tier as i64, group[0].0],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let mut merged: std::collections::BTreeMap<i64, f64> = std::collections::BTreeMap::new();
        let mut closed = true;
        if let Some((data, was_closed)) = existing {
            let chunk = decode(&data)?;
            if chunk.cols.len() != 1 {
                return Err(SeriesError::Shape);
            }
            merged.extend(chunk.ts.iter().copied().zip(chunk.cols[0].to_f64()));
            closed = was_closed == 1;
        }
        merged.extend(group.iter().copied());
        let ts: Vec<i64> = merged.keys().copied().collect();
        let values: Vec<f64> = merged.values().copied().collect();
        let open = Open { start_ms: group[0].0, chunk: Chunk { ts, cols: vec![Column::from_values(step, &values)] } };
        write(conn, key, tier, &open, closed)?;
    }
    Ok(())
}
