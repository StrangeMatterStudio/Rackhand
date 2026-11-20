use crate::series::chunk::{Tier, append};
use crate::series::codec::{Chunk, Column, encode};
use crate::series::query::range;
use crate::series::step::Step;

use super::chunk::{HOUR, conn, key};

#[test]
fn range_query_returns_points_in_order_across_chunks() {
    let conn = conn();
    // 300 points at 15 s: rows of 120, 120 and 60
    let ts: Vec<i64> = (0..300).map(|i| HOUR + i * 15_000).collect();
    let values: Vec<f64> = (0..300).map(|i| i as f64).collect();
    append(&conn, &key(), Tier::Raw, Some(Step::One), &ts, std::slice::from_ref(&values)).unwrap();
    // a backfilled row overlapping the first two, with newer values for its points
    let overlap: Vec<i64> = (110..130).map(|i| HOUR + i * 15_000).collect();
    let chunk = Chunk { ts: overlap.clone(), cols: vec![Column::Float(vec![-1.0; 20])] };
    conn.execute(
        "INSERT INTO series_chunks (machine_id, metric_key_id, tier, start_ms, end_ms, count, closed, data)
         VALUES (?1, ?2, 0, ?3, ?4, 20, 1, ?5)",
        rusqlite::params![key().machine_id, key().metric_key_id, overlap[0] + 1, overlap[19], encode(&chunk)],
    )
    .unwrap();
    let from = HOUR + 100 * 15_000;
    let to = HOUR + 250 * 15_000;
    let got = range(&conn, &key(), Tier::Raw, from, to).unwrap();
    let got_ts: Vec<i64> = got.iter().map(|p| p.0).collect();
    let want_ts: Vec<i64> = (100..=250).map(|i| HOUR + i * 15_000).collect();
    assert_eq!(got_ts, want_ts, "sorted, one point per timestamp, within the range");
    for (t, v) in &got {
        let i = (t - HOUR) / 15_000;
        // a row with a later start wins: the overlapping row (starting 1 ms after point 110) is later than the
        // first row for points 110 to 119, and the second row (starting at point 120) is later than it
        let want = if (110..120).contains(&i) { -1.0 } else { i as f64 };
        assert_eq!(v[0], want, "point {i}");
    }
}
