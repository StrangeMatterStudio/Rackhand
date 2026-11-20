use rusqlite::Connection;

use super::series::chunk::{HOUR, conn, key};
use super::series::codec::Rng;
use crate::rollup::{RollupSeries, put_rollups, rollup};
use crate::series::chunk::{Tier, append};
use crate::series::query::range;

const MIN: i64 = 60_000;

/// A metric without a step, so values are stored exactly and averages compare exactly.
fn add_metric_key(conn: &Connection) {
    conn.execute("INSERT INTO metric_keys (id, name, unit, label_set) VALUES (7, 'test.value', '', '{}')", []).unwrap();
}

/// `n` minutes of tier 0 at 15 s with random values, from `start`.
fn raw(conn: &Connection, start: i64, minutes: i64, seed: u64) -> Vec<(i64, f64)> {
    let mut rng = Rng::new(seed);
    let points: Vec<(i64, f64)> =
        (0..minutes * 4).map(|i| (start + i * 15_000, rng.below(10_000) as f64 / 7.0)).collect();
    let ts: Vec<i64> = points.iter().map(|p| p.0).collect();
    let values: Vec<f64> = points.iter().map(|p| p.1).collect();
    append(conn, &key(), Tier::Raw, None, &ts, &[values]).unwrap();
    points
}

fn min_max_avg(values: &[f64]) -> [f64; 3] {
    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    [min, max, values.iter().sum::<f64>() / values.len() as f64]
}

#[test]
fn tier1_equals_min_max_avg_of_minute() {
    let conn = conn();
    add_metric_key(&conn);
    let points = raw(&conn, HOUR, 90, 1);
    rollup(&conn, Tier::Minute, HOUR, HOUR + 90 * MIN).unwrap();
    let tier1 = range(&conn, &key(), Tier::Minute, HOUR, HOUR + 90 * MIN).unwrap();
    assert_eq!(tier1.len(), 90);
    for (t, got) in &tier1 {
        let minute: Vec<f64> = points.iter().filter(|p| p.0 >= *t && p.0 < t + MIN).map(|p| p.1).collect();
        assert_eq!(minute.len(), 4);
        assert_eq!(got.as_slice(), min_max_avg(&minute), "minute {t}");
    }
}

#[test]
fn tier2_equals_min_max_avg_of_hour_of_tier1() {
    let conn = conn();
    add_metric_key(&conn);
    raw(&conn, HOUR, 180, 2);
    rollup(&conn, Tier::Minute, HOUR, HOUR + 180 * MIN).unwrap();
    rollup(&conn, Tier::Hour, HOUR, HOUR + 180 * MIN).unwrap();
    let tier1 = range(&conn, &key(), Tier::Minute, HOUR, HOUR + 180 * MIN).unwrap();
    let tier2 = range(&conn, &key(), Tier::Hour, HOUR, HOUR + 180 * MIN).unwrap();
    assert_eq!(tier2.iter().map(|p| p.0).collect::<Vec<_>>(), vec![HOUR, HOUR + 60 * MIN, HOUR + 120 * MIN]);
    for (t, got) in &tier2 {
        let minutes: Vec<&Vec<f64>> = tier1.iter().filter(|p| p.0 >= *t && p.0 < t + 60 * MIN).map(|p| &p.1).collect();
        assert_eq!(minutes.len(), 60);
        let mins: Vec<f64> = minutes.iter().map(|m| m[0]).collect();
        let maxes: Vec<f64> = minutes.iter().map(|m| m[1]).collect();
        let avgs: Vec<f64> = minutes.iter().map(|m| m[2]).collect();
        let want = [min_max_avg(&mins)[0], min_max_avg(&maxes)[1], min_max_avg(&avgs)[2]];
        assert_eq!(got.as_slice(), want, "hour {t}");
    }
}

#[test]
fn dirty_range_is_recomputed() {
    let conn = conn();
    add_metric_key(&conn);
    raw(&conn, HOUR, 10, 3);
    rollup(&conn, Tier::Minute, HOUR, HOUR + 10 * MIN).unwrap();
    let before = range(&conn, &key(), Tier::Minute, HOUR + 3 * MIN, HOUR + 3 * MIN).unwrap();
    // a replayed sample lands in minute 3 (as compaction writes backfill) and the minute is marked dirty
    crate::series::chunk::backfill(&conn, &key(), Tier::Raw, None, &[HOUR + 3 * MIN + 7_000], &[vec![1e6]]).unwrap();
    conn.execute(
        "INSERT INTO rollup_dirty (machine_id, metric_key_id, tier, from_ms, to_ms) VALUES (?1, 7, 1, ?2, ?3)",
        rusqlite::params![key().machine_id, HOUR + 3 * MIN, HOUR + 4 * MIN - 1],
    )
    .unwrap();
    let n = crate::rollup::recompute_dirty(&conn).unwrap();
    assert_eq!(n, 1, "one dirty range");
    let after = range(&conn, &key(), Tier::Minute, HOUR + 3 * MIN, HOUR + 3 * MIN).unwrap();
    assert_ne!(before, after);
    assert_eq!(after[0].1[1], 1e6, "the backfilled sample is the minute's max");
    let left: i64 = conn.query_row("SELECT count(*) FROM rollup_dirty", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 0, "the range is no longer dirty");
}

#[test]
fn minute_rollups_from_the_window_are_stored() {
    let conn = conn();
    let series = RollupSeries {
        machine_id: key().machine_id,
        name: "cpu.busy_pct".into(),
        unit: "%".into(),
        label_set: "{}".into(),
        points: vec![(HOUR, [1.0, 3.0, 2.0]), (HOUR + MIN, [2.0, 4.0, 3.25])],
    };
    put_rollups(&conn, Tier::Minute, &[series]).unwrap();
    let id: i64 = conn.query_row("SELECT id FROM metric_keys WHERE name = 'cpu.busy_pct'", [], |r| r.get(0)).unwrap();
    let k = crate::series::chunk::SeriesKey { machine_id: key().machine_id, metric_key_id: id };
    let got = range(&conn, &k, Tier::Minute, HOUR, HOUR + MIN).unwrap();
    assert_eq!(got, vec![(HOUR, vec![1.0, 3.0, 2.0]), (HOUR + MIN, vec![2.0, 4.0, 3.25])]);
}
