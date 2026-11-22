//! Incidents (7.2, 7.5.2): lifecycle, evaluation, silences, reconciliation and notes. Owns `incidents`,
//! `incident_events` and `silences`. Routing to runbooks is `routing` (T57); playbooks come with T78.

mod baselines;
mod checks;
mod conditions;
mod counted;
mod dedupe;
mod evaluate;
mod forecasts;
mod lifecycle;
pub mod machine_silence;
pub mod notes;
mod reconcile;
pub mod replay;
pub mod routing;
mod silences;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use rackhand_detect::rules::Rule;
use rackhand_detect::threshold::RuleState;
use rackhand_store::{Db, StoreError};

use crate::bus::Bus;
use crate::ingest::Ingest;
pub use evaluate::EvalStats;
pub use lifecycle::State;
pub use silences::{MAX_SILENCE_MS, Silence, SilenceTarget};

#[derive(Debug, thiserror::Error)]
pub enum IncidentsError {
    #[error("a silence lasts at most 30 days")]
    SilenceTooLong,
    #[error("the silence would already be over")]
    SilenceEnded,
    #[error("no such incident")]
    NoSuchIncident,
    #[error("reading series: {0}")]
    Ingest(String),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

/// One rule over one series of one machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SeriesRule {
    pub machine: String,
    pub rule: &'static str,
    pub labels: String,
}

#[derive(Debug, Default)]
struct Eval {
    rules: HashMap<SeriesRule, RuleState>,
    /// Rules that fired while a silence covered them.
    suppressed: HashSet<SeriesRule>,
    /// The newest `events` row already looked at.
    last_event: i64,
    /// Forecasts, baselines, machine silence and counted rules.
    conditions: HashMap<conditions::CondKey, conditions::CondState>,
    baselines: std::collections::BTreeMap<conditions::CondKey, baselines::Learned>,
    /// Machines expected offline that are silent (their info event went out).
    asleep: HashSet<String>,
    started_ms: i64,
    last_forecast_ms: i64,
}

#[derive(Debug, Clone)]
pub struct Incidents {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    db: Arc<Db>,
    ingest: Ingest,
    bus: Bus,
    rules: Vec<Rule>,
    eval: Mutex<Eval>,
    quiet: OnceLock<Arc<dyn machine_silence::Quiet>>,
}

impl Incidents {
    /// Evaluates the default rules (7.6.1); events already in the table when it starts are not looked at again.
    pub fn new(db: Arc<Db>, ingest: Ingest, bus: Bus) -> Incidents {
        let last_event = db
            .readers()
            .with(|c| c.query_row("SELECT coalesce(max(rowid), 0) FROM events", [], |r| r.get(0)))
            .unwrap_or(0);
        let rules = rackhand_detect::rules::default_rules();
        let now = rackhand_store::ids::now_ms();
        let (thresholds, conditions) = open_rule_states(&db, &rules);
        let eval = Eval {
            last_event,
            rules: thresholds,
            conditions,
            baselines: baselines::load(&db, now),
            started_ms: now,
            last_forecast_ms: i64::MIN / 2,
            ..Eval::default()
        };
        Incidents { inner: Arc::new(Inner { db, ingest, bus, rules, eval: Mutex::new(eval), quiet: OnceLock::new() }) }
    }

    fn eval(&self) -> MutexGuard<'_, Eval> {
        self.inner.eval.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The rule states of condition incidents still open when the hub starts, so their condition can clear them (a rule's
/// state is in memory; without this an incident open across a restart would never resolve). Threshold rules, then
/// the other condition rules.
type OpenStates = (HashMap<SeriesRule, RuleState>, HashMap<conditions::CondKey, conditions::CondState>);

fn open_rule_states(db: &Db, rules: &[Rule]) -> OpenStates {
    let open: Vec<(String, String, String)> = db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT dedupe_key, rule_id, severity FROM incidents WHERE state != 'resolved' AND rule_id IS NOT NULL",
            )?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
        })
        .unwrap_or_default();
    let (mut states, mut others) = (HashMap::new(), HashMap::new());
    for (key, rule_id, severity) in open {
        let Some((machine, rest)) = key.split_once(':') else { continue };
        let Some(labels) = rest.strip_prefix(&format!("{rule_id}:")) else { continue };
        let active = Some(lifecycle::parse_severity(&severity));
        match rules.iter().find(|r| r.id == rule_id) {
            Some(rule) => {
                let state = RuleState { active, last_sample_ms: None };
                states.insert(
                    SeriesRule { machine: machine.to_string(), rule: rule.id, labels: labels.to_string() },
                    state,
                );
            }
            None => {
                others.insert(
                    conditions::CondKey::new(machine, &rule_id, labels),
                    conditions::CondState { active, calm: 0 },
                );
            }
        }
    }
    (states, others)
}

#[cfg(test)]
mod tests;
