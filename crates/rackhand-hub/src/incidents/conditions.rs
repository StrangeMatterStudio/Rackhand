//! Condition incidents of the rules other than thresholds (7.5.2): forecasts, baselines, machine silence and counted
//! rules. Each evaluation gives the rule's severity now; the incident opens, changes severity, or resolves once the
//! condition has been gone for the rule's own count (2 recomputations for a forecast, the first report for silence).

use rackhand_detect::rules::Severity;

use super::dedupe::condition_key;
use super::lifecycle::{Opening, State, by_key};
use super::{Incidents, IncidentsError};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct CondKey {
    pub machine: String,
    pub rule: String,
    /// Canonical JSON.
    pub labels: String,
}

impl CondKey {
    pub fn new(machine: &str, rule: &str, labels: &str) -> CondKey {
        CondKey { machine: machine.to_string(), rule: rule.to_string(), labels: labels.to_string() }
    }

    fn dedupe(&self) -> String {
        condition_key(&self.machine, &self.rule, &self.labels)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CondState {
    pub active: Option<Severity>,
    /// Evaluations in a row without the condition.
    pub calm: u32,
}

impl Incidents {
    /// Applies one evaluation of a condition rule.
    pub(crate) async fn condition(
        &self,
        key: CondKey,
        now: Option<Severity>,
        clear_after: u32,
        title: &str,
        now_ms: i64,
    ) -> Result<(), IncidentsError> {
        let prev = self.eval().conditions.get(&key).copied().unwrap_or_default();
        let mut next = prev;
        match (prev.active, now) {
            (_, Some(Severity::Info)) => return Ok(()),
            (None, Some(severity)) => {
                let opening = Opening {
                    // a check that belongs to no machine has an empty machine
                    machine_id: (!key.machine.is_empty()).then(|| key.machine.clone()),
                    rule_id: Some(key.rule.clone()),
                    dedupe_key: key.dedupe(),
                    kind: key.rule.clone(),
                    severity,
                    title: title.to_string(),
                };
                // under a silence nothing opens, and the rule tries again next time
                if self.open(opening, now_ms).await?.is_some() {
                    next = CondState { active: Some(severity), calm: 0 };
                }
            }
            (Some(a), Some(b)) => {
                if a != b {
                    if let Some(inc) = by_key(&self.inner.db, &key.dedupe())?.filter(|i| i.state != State::Resolved) {
                        self.change_severity(inc, b, now_ms).await?;
                    }
                }
                next = CondState { active: Some(b), calm: 0 };
            }
            (Some(_), None) => {
                next.calm += 1;
                if next.calm >= clear_after {
                    if let Some(inc) = by_key(&self.inner.db, &key.dedupe())?.filter(|i| i.state != State::Resolved) {
                        self.resolve(inc, "condition", now_ms).await?;
                    }
                    next = CondState::default();
                }
            }
            (None, None) => {}
        }
        let mut eval = self.eval();
        if next == CondState::default() {
            eval.conditions.remove(&key);
        } else {
            eval.conditions.insert(key, next);
        }
        Ok(())
    }

    /// The severity of the incident open for `key`. The counted rules' counts and first-seen times are in memory, so
    /// after a restart they start again: while the condition is still there, an incident open across the restart keeps
    /// at least its severity rather than reading the short count as the condition clearing.
    pub(crate) fn held(&self, key: &CondKey) -> Option<Severity> {
        self.eval().conditions.get(key).and_then(|s| s.active)
    }

    /// The condition rules of `rule` on `machine` that are active but weren't evaluated this time: they are gone.
    pub(crate) fn stale_conditions(&self, machine: &str, rule: &str, seen: &[CondKey]) -> Vec<CondKey> {
        self.eval()
            .conditions
            .keys()
            .filter(|k| k.machine == machine && k.rule == rule && !seen.contains(k))
            .cloned()
            .collect()
    }
}
