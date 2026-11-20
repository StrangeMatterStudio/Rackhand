//! Per-metric steps and tick timestamps (7.4.1 chunk encoding, D109).

/// The resolution a metric's values are stored at, as whole multiples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    One,
    Hundredths,
    Tenths,
    /// 1 024: memory, swap and filesystem bytes, whose sources count kB.
    KiB,
}

/// The 7.4.2 catalogue units that are stored at a step of 1.
const WHOLE_UNITS: &[&str] = &["bytes", "B/s", "ops/s", "pkts/s", "count", "s"];

impl Step {
    /// The step for a metric of this name and 7.4.2 unit; `None` (stored as f64) for a unit outside the catalogue.
    pub fn for_metric(name: &str, unit: &str) -> Option<Step> {
        match unit {
            "%" | "ratio" => Some(Step::Hundredths),
            "Celsius" => Some(Step::Tenths),
            "bytes" if ["mem.", "swap.", "disk."].iter().any(|p| name.starts_with(p)) => Some(Step::KiB),
            u if WHOLE_UNITS.contains(&u) => Some(Step::One),
            _ => None,
        }
    }

    /// The value as a whole number of steps (rounded half away from zero), or `None` if it has none.
    pub fn to_int(self, v: f64) -> Option<i64> {
        let scaled = match self {
            Step::One => v,
            Step::Hundredths => v * 100.0,
            Step::Tenths => v * 10.0,
            Step::KiB => v / 1024.0,
        }
        .round();
        // i64::MAX as f64 rounds up to 2^63, which is out of range, so compare strictly below it
        (scaled.is_finite() && scaled >= i64::MIN as f64 && scaled < i64::MAX as f64).then_some(scaled as i64)
    }

    pub fn to_f64(self, v: i64) -> f64 {
        match self {
            Step::One => v as f64,
            Step::Hundredths => v as f64 / 100.0,
            Step::Tenths => v as f64 / 10.0,
            Step::KiB => v as f64 * 1024.0,
        }
    }

    pub(crate) fn code(self) -> u64 {
        match self {
            Step::One => 0,
            Step::Hundredths => 1,
            Step::Tenths => 2,
            Step::KiB => 3,
        }
    }

    pub(crate) fn from_code(code: u64) -> Step {
        match code & 3 {
            0 => Step::One,
            1 => Step::Hundredths,
            2 => Step::Tenths,
            _ => Step::KiB,
        }
    }
}

/// Rounds each sample's timestamp to the nearest multiple of the sample interval; when two land on one tick the
/// later sample is kept. Input in time order.
pub fn snap_to_tick(points: &[(i64, f64)], interval_ms: i64) -> Vec<(i64, f64)> {
    let mut out: Vec<(i64, f64)> = Vec::with_capacity(points.len());
    for &(t, v) in points {
        let tick = (t + interval_ms / 2).div_euclid(interval_ms) * interval_ms;
        match out.last_mut() {
            Some(last) if last.0 == tick => last.1 = v,
            _ => out.push((tick, v)),
        }
    }
    out
}
