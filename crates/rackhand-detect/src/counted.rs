//! Counted rules (7.6.1): watched services, container restarts, failing checks and pending security updates. They
//! have no metric value, so no clear margin.

use crate::rules::Severity;

const MIN_MS: i64 = 60_000;
const DAY_MS: i64 = 24 * 60 * MIN_MS;

fn levels(count: u64, warning_from: u64, critical_from: u64) -> Option<Severity> {
    if count >= critical_from {
        Some(Severity::Critical)
    } else if count >= warning_from {
        Some(Severity::Warning)
    } else {
        None
    }
}

/// A watched service reported not active in this many reports in a row.
pub fn service_not_active(reports_in_a_row: u32) -> Option<Severity> {
    levels(reports_in_a_row.into(), 2, 4)
}

/// Restarts of one container: more than 3 in the last 10 minutes is a warning, more than 10 critical.
pub fn container_restarts(restarts_ms: &[i64], now_ms: i64) -> Option<Severity> {
    let recent = restarts_ms.iter().filter(|t| **t > now_ms - 10 * MIN_MS && **t <= now_ms).count() as u64;
    levels(recent, 4, 11)
}

/// A check failing this many times in a row.
pub fn check_failing(failures_in_a_row: u32) -> Option<Severity> {
    levels(failures_in_a_row.into(), 2, 4)
}

/// Security updates pending since `oldest_pending_ms`: older than 7 days is a warning, older than 14 critical.
pub fn security_updates(oldest_pending_ms: Option<i64>, now_ms: i64) -> Option<Severity> {
    let age = now_ms - oldest_pending_ms?;
    if age > 14 * DAY_MS {
        Some(Severity::Critical)
    } else if age > 7 * DAY_MS {
        Some(Severity::Warning)
    } else {
        None
    }
}
