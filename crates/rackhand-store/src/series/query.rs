//! Range queries over chunk rows (7.4.1).

use std::collections::BTreeMap;

use rusqlite::{Connection, params};

use super::SeriesError;
use super::chunk::{SeriesKey, Tier};
use super::codec::decode;

/// The points of a series and tier with `from_ms <= ts <= to_ms`, in time order, one per timestamp. Where rows
/// overlap (backfilled data), the row with the later start wins.
pub fn range(
    conn: &Connection,
    key: &SeriesKey,
    tier: Tier,
    from_ms: i64,
    to_ms: i64,
) -> Result<Vec<(i64, Vec<f64>)>, SeriesError> {
    let mut stmt = conn.prepare_cached(
        "SELECT data FROM series_chunks WHERE machine_id = ?1 AND metric_key_id = ?2 AND tier = ?3
         AND start_ms <= ?5 AND end_ms >= ?4 ORDER BY start_ms",
    )?;
    let rows = stmt.query_map(params![key.machine_id, key.metric_key_id, tier as i64, from_ms, to_ms], |r| {
        r.get::<_, Vec<u8>>(0)
    })?;
    let mut points: BTreeMap<i64, Vec<f64>> = BTreeMap::new();
    for data in rows {
        let chunk = decode(&data?)?;
        let cols: Vec<Vec<f64>> = chunk.cols.iter().map(|c| c.to_f64()).collect();
        for (i, &t) in chunk.ts.iter().enumerate() {
            if (from_ms..=to_ms).contains(&t) {
                points.insert(t, cols.iter().map(|c| c[i]).collect());
            }
        }
    }
    Ok(points.into_iter().collect())
}
