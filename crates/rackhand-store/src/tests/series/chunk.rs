use rusqlite::Connection;

use crate::series::chunk::{SeriesKey, Tier, append};
use crate::series::step::Step;

pub fn conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("../../schema.sql")).unwrap();
    conn
}

pub fn key() -> SeriesKey {
    SeriesKey { machine_id: "01JD0000000000000000000000".into(), metric_key_id: 7 }
}

/// (start_ms, end_ms, count, closed) of every row of a series and tier, oldest first.
pub fn rows(conn: &Connection, tier: Tier) -> Vec<(i64, i64, i64, bool)> {
    let mut stmt = conn
        .prepare(
            "SELECT start_ms, end_ms, count, closed FROM series_chunks WHERE machine_id = ?1 AND metric_key_id = ?2
             AND tier = ?3 ORDER BY start_ms",
        )
        .unwrap();
    stmt.query_map(rusqlite::params![key().machine_id, key().metric_key_id, tier as i64], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, i64>(3)? == 1))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

/// An hour boundary, so tests start at the top of an hour.
pub const HOUR: i64 = 1_795_068_000_000;

#[test]
fn chunk_closes_at_120_points() {
    for (tier, every) in [(Tier::Raw, 15_000), (Tier::Minute, 60_000), (Tier::Hour, 3_600_000)] {
        let conn = conn();
        let ncols = if tier == Tier::Raw { 1 } else { 3 };
        // tier 0 at 15 s fills 120 points in 30 minutes, inside the hour
        let ts: Vec<i64> = (0..121).map(|i| HOUR + i * every).collect();
        let cols = vec![(0..121).map(|i| i as f64).collect::<Vec<_>>(); ncols];
        append(&conn, &key(), tier, Some(Step::One), &ts, &cols).unwrap();
        let r = rows(&conn, tier);
        assert_eq!(r.len(), 2, "{tier:?}: two rows");
        assert_eq!(r[0], (HOUR, HOUR + 119 * every, 120, true), "{tier:?}: first row closed at 120");
        assert_eq!(r[1], (HOUR + 120 * every, HOUR + 120 * every, 1, false), "{tier:?}: the 121st opens a row");
    }
}

#[test]
fn tier0_chunk_closes_at_hour_boundary() {
    let conn = conn();
    // 30 points every 60 s from 30 minutes into the hour, then one in the next hour
    let mut ts: Vec<i64> = (0..30).map(|i| HOUR + 1_800_000 + i * 60_000).collect();
    ts.push(HOUR + 3_600_000);
    let cols = vec![(0..31).map(|i| i as f64).collect::<Vec<_>>()];
    append(&conn, &key(), Tier::Raw, Some(Step::One), &ts, &cols).unwrap();
    let r = rows(&conn, Tier::Raw);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0], (HOUR + 1_800_000, HOUR + 1_800_000 + 29 * 60_000, 30, true));
    assert_eq!(r[1], (HOUR + 3_600_000, HOUR + 3_600_000, 1, false));
}

#[test]
fn tier1_chunk_spans_the_hour() {
    let conn = conn();
    // 90 minutes of tier 1 points cross an hour boundary and stay in one open row
    let ts: Vec<i64> = (0..90).map(|i| HOUR + 1_800_000 + i * 60_000).collect();
    let cols = vec![(0..90).map(|i| i as f64).collect::<Vec<_>>(); 3];
    append(&conn, &key(), Tier::Minute, Some(Step::One), &ts, &cols).unwrap();
    assert_eq!(rows(&conn, Tier::Minute), vec![(HOUR + 1_800_000, HOUR + 1_800_000 + 89 * 60_000, 90, false)]);
}

#[test]
fn append_to_open_chunk_preserves_points() {
    let ts: Vec<i64> = (0..100).map(|i| HOUR + i * 15_000).collect();
    let values: Vec<f64> = (0..100).map(|i| (i * i) as f64 * 0.25).collect();
    let one = conn();
    append(&one, &key(), Tier::Raw, Some(Step::Hundredths), &ts, std::slice::from_ref(&values)).unwrap();
    let two = conn();
    append(&two, &key(), Tier::Raw, Some(Step::Hundredths), &ts[..37], &[values[..37].to_vec()]).unwrap();
    append(&two, &key(), Tier::Raw, Some(Step::Hundredths), &ts[37..], &[values[37..].to_vec()]).unwrap();
    let blob = |c: &Connection| -> (Vec<u8>, i64) {
        c.query_row("SELECT data, count FROM series_chunks", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap()
    };
    assert_eq!(blob(&one), blob(&two));
    let got = crate::series::query::range(&two, &key(), Tier::Raw, HOUR, HOUR + 3_600_000).unwrap();
    assert_eq!(got.len(), 100);
    assert!(got.iter().zip(&values).all(|((_, v), want)| v[0] == *want));
}

#[test]
fn append_older_than_open_chunk_is_refused() {
    let conn = conn();
    append(&conn, &key(), Tier::Raw, Some(Step::One), &[HOUR + 60_000], &[vec![1.0]]).unwrap();
    let err = append(&conn, &key(), Tier::Raw, Some(Step::One), &[HOUR], &[vec![2.0]]).unwrap_err();
    assert!(matches!(err, crate::series::SeriesError::OutOfOrder { last_ms } if last_ms == HOUR + 60_000));
}
