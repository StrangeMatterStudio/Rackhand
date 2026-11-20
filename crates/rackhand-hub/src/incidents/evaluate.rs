//! Evaluation every 15 s (7.5.2, 7.6.1): threshold rules over the recent window, and warning and critical events.

use rackhand_detect::rules::{Op, Severity};
use rackhand_detect::samples::Sample;
use rackhand_detect::threshold;

use super::dedupe::{EVENT_MERGE_MS, condition_key, event_key};
use super::lifecycle::{IncidentRow, Opening, State, by_key, parse_severity, severity_str};
use super::{Incidents, IncidentsError, SeriesRule};

/// What one evaluation changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EvalStats {
    pub opened: usize,
    pub changed: usize,
    pub resolved: usize,
}

struct EventRow {
    rowid: i64,
    machine: Option<String>,
    at_ms: i64,
    kind: String,
    severity: String,
    subject: Option<String>,
}

enum Change {
    Open { key: SeriesRule, severity: Severity, title: String, kind: &'static str },
    Severity { key: SeriesRule, to: Severity },
    Clear { key: SeriesRule },
}

impl Incidents {
    pub async fn evaluate(&self, now_ms: i64) -> Result<EvalStats, IncidentsError> {
        let mut stats = self.evaluate_rules(now_ms).await?;
        let events = self.evaluate_events().await?;
        stats.opened += events.opened;
        stats.changed += events.changed;
        Ok(stats)
    }

    async fn evaluate_rules(&self, now_ms: i64) -> Result<EvalStats, IncidentsError> {
        let ingest = &self.inner.ingest;
        let mut changes = Vec::new();
        {
            let mut eval = self.eval();
            for machine in ingest.machines() {
                let interval_s = (ingest.interval_ms(&machine) / 1000).max(1) as u32;
                for rule in &self.inner.rules {
                    for (series, samples) in ingest.window_series(&machine, rule.metric) {
                        // samples that arrived more than 10 minutes late are history only (E1)
                        let samples: Vec<Sample> = samples
                            .iter()
                            .filter(|s| !s.history_only)
                            .map(|s| Sample { at_ms: s.at_ms, value: s.value })
                            .collect();
                        let key = SeriesRule { machine: machine.clone(), rule: rule.id, labels: series.labels.clone() };
                        let prev = eval.rules.get(&key).cloned().unwrap_or_default();
                        let next = threshold::evaluate(rule, &samples, interval_s, now_ms, &prev);
                        match (prev.active, next.active) {
                            (None, Some(severity)) => changes.push(Change::Open {
                                key: key.clone(),
                                severity,
                                title: title(rule, severity),
                                kind: rule.id,
                            }),
                            (Some(a), Some(b)) if a != b => changes.push(Change::Severity { key: key.clone(), to: b }),
                            (Some(_), None) => changes.push(Change::Clear { key: key.clone() }),
                            // still active but never opened (a silence covered it): try again, the silence may be over
                            (Some(a), Some(_)) if eval.suppressed.contains(&key) => changes.push(Change::Open {
                                key: key.clone(),
                                severity: a,
                                title: title(rule, a),
                                kind: rule.id,
                            }),
                            _ => {}
                        }
                        eval.rules.insert(key, next);
                    }
                }
            }
        }
        let mut stats = EvalStats::default();
        for change in changes {
            match change {
                Change::Open { key, severity, title, kind } => {
                    let opening = Opening {
                        machine_id: Some(key.machine.clone()),
                        rule_id: Some(key.rule.to_string()),
                        dedupe_key: condition_key(&key.machine, key.rule, &key.labels),
                        kind: kind.to_string(),
                        severity,
                        title,
                    };
                    let opened = self.open(opening, now_ms).await?;
                    let mut eval = self.eval();
                    if opened.is_some() {
                        eval.suppressed.remove(&key);
                        stats.opened += 1;
                    } else {
                        eval.suppressed.insert(key);
                    }
                }
                Change::Severity { key, to } => {
                    if let Some(inc) = self.unresolved(&condition_key(&key.machine, key.rule, &key.labels))? {
                        self.change_severity(inc, to, now_ms).await?;
                        stats.changed += 1;
                    }
                }
                Change::Clear { key } => {
                    self.eval().suppressed.remove(&key);
                    if let Some(inc) = self.unresolved(&condition_key(&key.machine, key.rule, &key.labels))? {
                        self.resolve(inc, "condition", now_ms).await?;
                        stats.resolved += 1;
                    }
                }
            }
        }
        Ok(stats)
    }

    fn unresolved(&self, key: &str) -> Result<Option<IncidentRow>, IncidentsError> {
        Ok(by_key(&self.inner.db, key)?.filter(|i| i.state != State::Resolved))
    }

    /// Warning and critical events since the last evaluation: each opens an incident or joins the one with its
    /// dedupe key opened within the last 24 hours. Info events never open incidents.
    async fn evaluate_events(&self) -> Result<EvalStats, IncidentsError> {
        let last = self.eval().last_event;
        let events: Vec<EventRow> = self.inner.db.readers().with(|c| {
            let mut s = c.prepare(
                "SELECT rowid, machine_id, at_ms, kind, severity, subject FROM events WHERE rowid > ?1 ORDER BY rowid",
            )?;
            s.query_map([last], |r| {
                Ok(EventRow {
                    rowid: r.get(0)?,
                    machine: r.get(1)?,
                    at_ms: r.get(2)?,
                    kind: r.get(3)?,
                    severity: r.get(4)?,
                    subject: r.get(5)?,
                })
            })?
            .collect()
        })?;
        let mut stats = EvalStats::default();
        for EventRow { rowid, machine, at_ms, kind, severity, subject } in events {
            self.eval().last_event = rowid;
            let severity = parse_severity(&severity);
            if severity == Severity::Info {
                continue;
            }
            let machine_part = machine.clone().unwrap_or_else(|| "hub".into());
            let subject = subject.unwrap_or_default();
            let key = event_key(&machine_part, &kind, &subject);
            // one unresolved incident per key takes every matching event; a resolved one takes them for 24 hours
            // after its last event (reopening), after which a new incident opens
            let target = match by_key(&self.inner.db, &key)? {
                Some(i) if i.state != State::Resolved => Some(i),
                Some(i) if at_ms - self.last_event_at(&i.id)? < EVENT_MERGE_MS => {
                    let mut i = i;
                    i.state = State::Open;
                    i.resolved_at = None;
                    i.resolved_by = None;
                    let data = serde_json::json!({ "severity": severity_str(i.severity), "callout": true });
                    self.write(&i, "reopened", data, at_ms).await?;
                    Some(i)
                }
                _ => None,
            };
            if let Some(inc) = target {
                let data = serde_json::json!({ "kind": kind, "subject": subject, "severity": severity_str(severity) });
                self.write(&inc, "event", data, at_ms).await?;
                if severity > inc.severity {
                    self.change_severity(inc, severity, at_ms).await?;
                }
                stats.changed += 1;
                continue;
            }
            let title = if subject.is_empty() { kind.clone() } else { format!("{kind}: {subject}") };
            let opening = Opening { machine_id: machine, rule_id: None, dedupe_key: key, kind, severity, title };
            if self.open_new(opening, at_ms).await?.is_some() {
                stats.opened += 1;
            }
        }
        Ok(stats)
    }

    /// When an incident last took an event (or opened).
    fn last_event_at(&self, id: &str) -> Result<i64, IncidentsError> {
        Ok(self.inner.db.readers().with(|c| {
            c.query_row(
                "SELECT coalesce(max(at_ms), 0) FROM incident_events WHERE incident_id = ?1
                 AND kind IN ('opened', 'reopened', 'event')",
                [id],
                |r| r.get(0),
            )
        })?)
    }
}

fn title(rule: &rackhand_detect::rules::Rule, severity: Severity) -> String {
    match rule.level(severity) {
        Some(t) => {
            let op = if t.op == Op::Over { "over" } else { "under" };
            format!("{} {op} {} for {} min", rule.metric, t.value, t.duration_s / 60)
        }
        None => rule.metric.to_string(),
    }
}
