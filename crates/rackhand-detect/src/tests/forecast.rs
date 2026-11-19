use crate::forecast::{Fit, cert_expiry, disk_fill, fit_line, memory_growth};
use crate::rules::Severity;
use crate::samples::Sample;

const HOUR: i64 = 3_600_000;
const DAY: i64 = 24 * HOUR;

fn fit(slope_per_h: f64, r2: f64) -> Fit {
    Fit { slope_per_h, intercept: 0.0, r2 }
}

/// Hourly samples of `v(h)` from hour 0 to `hours`.
fn line(hours: i64, v: impl Fn(f64) -> f64) -> Vec<Sample> {
    (0..=hours).map(|h| Sample { at_ms: h * HOUR, value: v(h as f64) }).collect()
}

#[test]
fn worked_example_warns_with_eta_62_5_hours() {
    let f = disk_fill(500.0, 400.0, &[fit(1.2, 0.91), fit(1.6, 0.85)]).expect("a warning");
    assert_eq!(f.severity, Severity::Warning);
    assert!((f.eta_h - 62.5).abs() < 1e-9, "eta {}", f.eta_h);
    assert_eq!(f.summary("/data"), "/data fills in about 2.6 days");
    let six_hour_only = disk_fill(500.0, 400.0, &[fit(1.2, 0.91)]);
    assert_eq!(six_hour_only, None, "83.3 h is no alert");
}

#[test]
fn fit_below_r2_0_7_is_ignored() {
    assert_eq!(disk_fill(500.0, 400.0, &[fit(10.0, 0.69)]), None);
    assert!(disk_fill(500.0, 400.0, &[fit(10.0, 0.70)]).is_some());
    // A straight line fits with R² 1; a sawtooth around a slow climb doesn't reach 0.7.
    let exact = fit_line(&line(6, |h| 100.0 + 2.0 * h)).unwrap();
    assert!((exact.slope_per_h - 2.0).abs() < 1e-9 && (exact.r2 - 1.0).abs() < 1e-9, "{exact:?}");
    let noisy = fit_line(&line(6, |h| 100.0 + 0.1 * h + if h as i64 % 2 == 0 { 5.0 } else { -5.0 })).unwrap();
    assert!(noisy.r2 < 0.7, "{noisy:?}");
    assert_eq!(disk_fill(500.0, 499.0, &[noisy]), None);
    assert_eq!(fit_line(&line(0, |_| 1.0)), None, "one sample is no line");
}

#[test]
fn shortest_eta_wins_and_critical_under_24h() {
    let f = disk_fill(500.0, 400.0, &[fit(2.0, 0.9), fit(5.0, 0.8)]).unwrap();
    assert!((f.eta_h - 20.0).abs() < 1e-9);
    assert_eq!(f.severity, Severity::Critical);
    let at_24 = disk_fill(500.0, 400.0, &[fit(100.0 / 24.0, 0.9)]).unwrap();
    assert_eq!(at_24.severity, Severity::Warning, "exactly 24 h is not under 24");
    assert_eq!(disk_fill(500.0, 400.0, &[fit(100.0 / 72.0, 0.9)]), None, "exactly 72 h is not under 72");
    assert_eq!(disk_fill(500.0, 400.0, &[fit(-3.0, 0.99)]), None, "a shrinking disk never fills");
}

#[test]
fn memory_growth_needs_24h_since_boot() {
    let boot = 0;
    let rising = |hours| line(hours, |h| 50.0 + 0.5 * h); // 12 points a day
    assert_eq!(memory_growth(&rising(23), boot), None);
    assert_eq!(memory_growth(&rising(24), boot), Some(Severity::Warning));
    // Samples from before the boot don't count toward the 24 hours.
    assert_eq!(memory_growth(&rising(30), 7 * HOUR), None);
}

#[test]
fn memory_growth_warns_over_2_points_per_day_reaching_95_in_7_days() {
    let per_day = |slope: f64, start: f64| line(48, move |h| start + slope * h / 24.0);
    assert_eq!(memory_growth(&per_day(2.0, 90.0), 0), None, "exactly 2 points a day is not over 2");
    // From 89.2 at hour 48, 95 is 2.8 days away.
    assert_eq!(memory_growth(&per_day(2.1, 85.0), 0), Some(Severity::Warning), "reaches 95 in under 7 days");
    // At 2.5 a day from 72 at hour 48 (67 at hour 0), 95 is 9.2 days away.
    assert_eq!(memory_growth(&per_day(2.5, 67.0), 0), None, "too far away");
    // From 77.5 at hour 48 (72.5 at hour 0), 95 is exactly 7 days away.
    assert_eq!(memory_growth(&per_day(2.5, 72.5), 0), Some(Severity::Warning), "exactly 7 days is within 7 days");
}

#[test]
fn cert_expiry_warning_14_critical_3_days() {
    let now = 1_000 * DAY;
    assert_eq!(cert_expiry(now + 14 * DAY + 1, now), None);
    assert_eq!(cert_expiry(now + 14 * DAY, now), Some(Severity::Warning));
    assert_eq!(cert_expiry(now + 3 * DAY + 1, now), Some(Severity::Warning));
    assert_eq!(cert_expiry(now + 3 * DAY, now), Some(Severity::Critical));
    assert_eq!(cert_expiry(now - DAY, now), Some(Severity::Critical), "expired");
}
