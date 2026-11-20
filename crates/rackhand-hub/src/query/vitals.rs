//! Vitals for charts (7.7.1, 7.4.1): the recent window merged with chunk rows, so a sample shows within seconds of
//! arriving, at most 2000 points.

use std::collections::BTreeMap;

use crate::ingest::Ingest;

pub const MAX_POINTS: usize = 2000;

/// Fewer points by averaging neighbours, so a long range still fits [`MAX_POINTS`].
pub fn downsample(points: Vec<(i64, f64)>) -> Vec<(i64, f64)> {
    if points.len() <= MAX_POINTS {
        return points;
    }
    let per = points.len().div_ceil(MAX_POINTS);
    points.chunks(per).map(|c| (c[0].0, c.iter().map(|p| p.1).sum::<f64>() / c.len() as f64)).collect()
}

/// One series over `[from_ms, to_ms]`, sorted with one point per time; empty when nothing is stored.
pub fn vitals(
    ingest: &Ingest,
    machine: &str,
    metric: &str,
    labels: &BTreeMap<String, String>,
    from_ms: i64,
    to_ms: i64,
) -> Vec<(i64, f64)> {
    downsample(ingest.series(machine, metric, labels, from_ms, to_ms).unwrap_or_default())
}
