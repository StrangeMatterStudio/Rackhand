use crate::baseline::{Baseline, Bucket, floor_for, hour_of_day, hour_of_week};
use crate::rules::Severity;

const MIN: i64 = 60_000;
const HOUR: i64 = 60 * MIN;
const DAY: i64 = 24 * HOUR;
/// Tuesday 2026-11-17 00:00 UTC.
const TUESDAY: i64 = 1_794_873_600_000;
const MBIT: f64 = 125_000.0; // in bytes per second

fn learned(floor: f64) -> Baseline {
    let mut b = Baseline::new(floor);
    b.first_data_ms = Some(TUESDAY - 30 * DAY);
    b
}

/// Feeds `value` every 15 s from `from` to `to` inclusive; returns the first time a warning is open.
fn feed(b: &mut Baseline, from: i64, to: i64, value: f64) -> Option<i64> {
    let mut first = None;
    let mut t = from;
    while t <= to {
        if b.evaluate(t, value) == Some(Severity::Warning) && first.is_none() {
            first = Some(t);
        }
        t += 15_000;
    }
    first
}

#[test]
fn worked_example_warns_at_14_35_and_freezes() {
    assert_eq!(hour_of_week(TUESDAY + 14 * HOUR), 24 + 14, "Monday is 0");
    let mut b = learned(floor_for("net.tx_bps").unwrap());
    let at = TUESDAY + 14 * HOUR;
    *b.how_mut(at) = Bucket { mean: 2.0 * MBIT, var: MBIT * MBIT, n: 10, frozen_until_ms: None };
    assert_eq!(feed(&mut b, at, at + 20 * MIN - 15_000, 2.0 * MBIT), None);
    let opened = feed(&mut b, at + 20 * MIN, at + 50 * MIN, 40.0 * MBIT);
    assert_eq!(opened, Some(at + 35 * MIN), "15 minutes after 14:20");
    assert!(b.how(at).frozen_until_ms.is_some_and(|f| f > at + 50 * MIN), "frozen: {:?}", b.how(at));
    let before = *b.how(at);
    b.hourly_update(at, 40.0 * MBIT, at + HOUR);
    assert_eq!(*b.how(at), before, "a frozen bucket doesn't learn the anomaly");
}

#[test]
fn first_value_seeds_mean_variance_zero_then_weight_0_1() {
    let mut k = Bucket::default();
    k.update(50.0, 0);
    assert_eq!((k.mean, k.var, k.n), (50.0, 0.0, 1));
    k.update(60.0, HOUR);
    assert!((k.mean - 51.0).abs() < 1e-9, "{k:?}");
    assert!((k.var - 9.0).abs() < 1e-9, "0.9 * (0 + 0.1 * 10Â²): {k:?}");
    assert_eq!(k.n, 2);
    let mut b = Baseline::new(20.0);
    let at = TUESDAY + 9 * HOUR;
    b.hourly_update(at, 30.0, at + HOUR);
    assert_eq!((b.hod(at).n, b.how(at).n), (1, 1), "both buckets for the hour learn");
    assert_eq!(hour_of_day(at), 9);
}

#[test]
fn hour_of_week_used_when_n_at_least_3_else_hour_of_day() {
    let mut b = learned(20.0);
    let at = TUESDAY + 3 * HOUR;
    *b.hod_mut(at) = Bucket { mean: 10.0, var: 1.0, n: 20, frozen_until_ms: None };
    *b.how_mut(at) = Bucket { mean: 70.0, var: 1.0, n: 2, frozen_until_ms: None };
    assert_eq!(b.bucket_for(at).unwrap().mean, 10.0, "hour of week has n 2");
    b.how_mut(at).n = 3;
    assert_eq!(b.bucket_for(at).unwrap().mean, 70.0);
    let empty = learned(20.0);
    assert!(empty.bucket_for(at).is_none());
    let mut thin = learned(20.0);
    thin.hod_mut(at).n = 2;
    assert!(thin.bucket_for(at).is_none(), "neither is usable");
}

#[test]
fn std_dev_floor_prevents_noise_alerts() {
    // CPU: floor 20 points, so the standard deviation used is at least 10, and 4 of them is 40.
    let mut b = learned(floor_for("cpu.busy_pct").unwrap());
    let at = TUESDAY + 2 * HOUR;
    *b.how_mut(at) = Bucket { mean: 10.0, var: 0.01, n: 50, frozen_until_ms: None };
    assert_eq!(feed(&mut b, at, at + 30 * MIN, 49.0), None, "39 points over a flat bucket");
    assert!(feed(&mut b, at + 31 * MIN, at + 50 * MIN, 51.0).is_some(), "41 points");
    let mut tiny = learned(floor_for("cpu.busy_pct").unwrap());
    *tiny.how_mut(at) = Bucket { mean: 10.0, var: 0.0, n: 50, frozen_until_ms: None };
    assert_eq!(feed(&mut tiny, at, at + 30 * MIN, 10.5), None, "noise on a zero-variance bucket");
}

#[test]
fn no_alerts_during_7_day_learning() {
    let start = TUESDAY - 7 * DAY;
    let at = TUESDAY + 2 * HOUR;
    let mut b = Baseline::new(floor_for("cpu.busy_pct").unwrap());
    b.first_data_ms = Some(start);
    *b.hod_mut(at) = Bucket { mean: 5.0, var: 1.0, n: 6, frozen_until_ms: None };
    let day6 = at - DAY;
    *b.hod_mut(day6) = Bucket { mean: 5.0, var: 1.0, n: 6, frozen_until_ms: None };
    assert_eq!(feed(&mut b, day6, day6 + 30 * MIN, 95.0), None, "day 6");
    assert!(feed(&mut b, at, at + 30 * MIN, 95.0).is_some(), "day 7");
    let mut fresh = Baseline::new(20.0);
    assert_eq!(fresh.evaluate(at, 95.0), None, "no data at all");
}

#[test]
fn unfreezes_after_2_hours_without_deviation() {
    let mut b = learned(floor_for("cpu.busy_pct").unwrap());
    let at = TUESDAY + 5 * HOUR;
    *b.how_mut(at) = Bucket { mean: 10.0, var: 4.0, n: 10, frozen_until_ms: None };
    feed(&mut b, at, at + 20 * MIN, 90.0);
    let last_deviation = at + 20 * MIN;
    feed(&mut b, last_deviation + 15_000, at + 30 * MIN, 10.0); // back to normal
    assert_eq!(b.evaluate(at + 31 * MIN, 10.0), None, "cleared");
    let n = b.how(at).n;
    b.hourly_update(at, 10.0, last_deviation + 2 * HOUR - 1);
    assert_eq!(b.how(at).n, n, "still frozen just under 2 hours");
    b.hourly_update(at, 10.0, last_deviation + 2 * HOUR);
    assert_eq!(b.how(at).n, n + 1, "learns again at 2 hours");
}

#[test]
fn never_critical() {
    let mut b = learned(floor_for("diskio.write_bps").unwrap());
    let at = TUESDAY + 8 * HOUR;
    // Disk I/O: mean 100 MB/s, standard deviation 20 MB/s; 900 MB/s is 40 standard deviations.
    *b.how_mut(at) = Bucket { mean: 100e6, var: 4e14, n: 10, frozen_until_ms: None };
    let mut t = at;
    while t < at + 50 * MIN {
        let s = b.evaluate(t, 900e6);
        assert_ne!(s, Some(Severity::Critical));
        t += 15_000;
    }
    assert_eq!(b.evaluate(t, 900e6), Some(Severity::Warning));
}
