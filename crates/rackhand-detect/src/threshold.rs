//! Threshold matching and clearing (7.6.1, D95). Everything is counted in samples at the machine's own interval, so a
//! rule means the same at 5 seconds and at 300.

use crate::rules::{Rule, Severity, Threshold};
use crate::samples::Sample;

/// Presence needed in a window: 80% of the expected samples.
const PRESENCE: f64 = 0.8;
/// No rule fires on fewer than this many intervals.
const MIN_INTERVALS: u32 = 4;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleState {
    pub active: Option<Severity>,
    /// The newest sample this state has seen; an evaluation with no newer sample changes nothing.
    pub last_sample_ms: Option<i64>,
}

/// Whether `threshold` matches the window ending at `now_ms`.
pub fn window_matches(threshold: &Threshold, samples: &[Sample], interval_s: u32, now_ms: i64) -> bool {
    let interval_s = interval_s.max(1);
    let duration_s = threshold.duration_s.max(MIN_INTERVALS * interval_s);
    let expected = duration_s / interval_s;
    let needed = (f64::from(expected) * PRESENCE).ceil() as usize;
    let from = now_ms - i64::from(duration_s) * 1000;
    let mut present = 0usize;
    for s in samples.iter().filter(|s| s.at_ms > from && s.at_ms <= now_ms) {
        if !threshold.breached_by(s.value) {
            return false;
        }
        present += 1;
    }
    present >= needed.max(1)
}

/// Evaluates one rule. `samples` are the recent window, oldest first.
pub fn evaluate(rule: &Rule, samples: &[Sample], interval_s: u32, now_ms: i64, prev: &RuleState) -> RuleState {
    let newest = samples.iter().filter(|s| s.at_ms <= now_ms).map(|s| s.at_ms).max();
    if newest.is_none() || newest <= prev.last_sample_ms {
        return prev.clone();
    }
    let matching = [Severity::Critical, Severity::Warning]
        .into_iter()
        .find(|sev| rule.level(*sev).is_some_and(|t| window_matches(t, samples, interval_s, now_ms)));
    let active = match prev.active {
        Some(current) => {
            // severity follows the highest level whose window matches, so it rises and falls (7.5.2); with none
            // matching and the rule not cleared, it stays where it is
            if cleared(rule, samples, now_ms) { None } else { Some(matching.unwrap_or(current)) }
        }
        None => matching,
    };
    RuleState { active, last_sample_ms: newest }
}

/// A rule clears when the 2 most recent samples are both on the safe side of its lowest threshold by the margin.
fn cleared(rule: &Rule, samples: &[Sample], now_ms: i64) -> bool {
    let Some(lowest) = rule.warning.as_ref().or(rule.critical.as_ref()) else { return true };
    let mut recent: Vec<&Sample> = samples.iter().filter(|s| s.at_ms <= now_ms).collect();
    recent.sort_by_key(|s| s.at_ms);
    let last_two = &recent[recent.len().saturating_sub(2)..];
    last_two.len() == 2 && last_two.iter().all(|s| lowest.safe_by(s.value, rule.margin))
}
