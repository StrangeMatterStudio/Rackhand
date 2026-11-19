//! Forecasts (7.6.2): disk fill, memory growth and certificate expiry.

use crate::rules::Severity;
use crate::samples::Sample;

const HOUR_MS: f64 = 3_600_000.0;
const DAY_MS: i64 = 86_400_000;
/// Boundaries are inclusive or exclusive as the design states; this absorbs float rounding in the fits.
const EPS: f64 = 1e-9;
const MIN_R2: f64 = 0.7;

/// A least-squares line. `intercept` is the value at the first sample's time.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Fit {
    pub slope_per_h: f64,
    pub intercept: f64,
    pub r2: f64,
}

/// Fits a line to the samples. `None` with fewer than 2 samples or all at the same time.
pub fn fit_line(samples: &[Sample]) -> Option<Fit> {
    let t0 = samples.first()?.at_ms;
    let points: Vec<(f64, f64)> = samples.iter().map(|s| ((s.at_ms - t0) as f64 / HOUR_MS, s.value)).collect();
    let n = points.len() as f64;
    let mean_x = points.iter().map(|p| p.0).sum::<f64>() / n;
    let mean_y = points.iter().map(|p| p.1).sum::<f64>() / n;
    let sxx: f64 = points.iter().map(|p| (p.0 - mean_x).powi(2)).sum();
    if points.len() < 2 || sxx <= 0.0 {
        return None;
    }
    let sxy: f64 = points.iter().map(|p| (p.0 - mean_x) * (p.1 - mean_y)).sum();
    let slope = sxy / sxx;
    let intercept = mean_y - slope * mean_x;
    let ss_tot: f64 = points.iter().map(|p| (p.1 - mean_y).powi(2)).sum();
    let ss_res: f64 = points.iter().map(|p| (p.1 - (intercept + slope * p.0)).powi(2)).sum();
    let r2 = if ss_tot > 0.0 { 1.0 - ss_res / ss_tot } else { 0.0 };
    Some(Fit { slope_per_h: slope, intercept, r2 })
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DiskForecast {
    pub severity: Severity,
    pub eta_h: f64,
}

impl DiskForecast {
    pub fn summary(&self, mount: &str) -> String {
        format!("{mount} fills in about {}", eta_text(self.eta_h))
    }
}

fn eta_text(hours: f64) -> String {
    if hours < 48.0 { format!("{} hours", hours.round()) } else { format!("{:.1} days", hours / 24.0) }
}

/// Disk fill from the 6-hour tier-1 fit and the 7-day tier-2 fit: the shortest time to full among the fits with a
/// positive slope and R² of at least 0.7. Warning under 72 hours, critical under 24.
pub fn disk_fill(capacity: f64, used: f64, fits: &[Fit]) -> Option<DiskForecast> {
    let eta_h = fits
        .iter()
        .filter(|f| f.slope_per_h > 0.0 && f.r2 >= MIN_R2)
        .map(|f| (capacity - used).max(0.0) / f.slope_per_h)
        .min_by(f64::total_cmp)?;
    let severity = if eta_h < 24.0 - EPS {
        Severity::Critical
    } else if eta_h < 72.0 - EPS {
        Severity::Warning
    } else {
        return None;
    };
    Some(DiskForecast { severity, eta_h })
}

/// Memory growth over `mem.used_pct` since the last boot: at least 24 hours of data and R² of at least 0.7; a warning
/// when the slope is over 2 points a day and the line reaches 95% within 7 days.
pub fn memory_growth(samples: &[Sample], boot_ms: i64) -> Option<Severity> {
    let since_boot: Vec<Sample> = samples.iter().copied().filter(|s| s.at_ms >= boot_ms).collect();
    let span_ms = since_boot.last()?.at_ms - since_boot.first()?.at_ms;
    if span_ms < DAY_MS {
        return None;
    }
    let fit = fit_line(&since_boot)?;
    let per_day = fit.slope_per_h * 24.0;
    if fit.r2 < MIN_R2 || per_day <= 2.0 + EPS {
        return None;
    }
    let now_value = fit.intercept + fit.slope_per_h * span_ms as f64 / HOUR_MS;
    let days_to_95 = (95.0 - now_value).max(0.0) / per_day;
    (days_to_95 <= 7.0 + EPS).then_some(Severity::Warning)
}

/// Certificate expiry: warning at 14 days left, critical at 3.
pub fn cert_expiry(not_after_ms: i64, now_ms: i64) -> Option<Severity> {
    let left = not_after_ms - now_ms;
    if left <= 3 * DAY_MS {
        Some(Severity::Critical)
    } else if left <= 14 * DAY_MS {
        Some(Severity::Warning)
    } else {
        None
    }
}
