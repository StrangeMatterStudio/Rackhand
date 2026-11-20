//! Incidents (7.2, 7.5.2): lifecycle, evaluation, silences, reconciliation and notes. Owns `incidents`,
//! `incident_events` and `silences`. Routing beyond a person comes with runbooks and playbooks (T57, T78).

mod dedupe;
mod evaluate;
mod lifecycle;
pub mod notes;
mod reconcile;
mod silences;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

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
}

impl Incidents {
    /// Evaluates the default rules (7.6.1); events already in the table when it starts are not looked at again.
    pub fn new(db: Arc<Db>, ingest: Ingest, bus: Bus) -> Incidents {
        let last_event = db
            .readers()
            .with(|c| c.query_row("SELECT coalesce(max(rowid), 0) FROM events", [], |r| r.get(0)))
            .unwrap_or(0);
        let eval = Eval { last_event, ..Eval::default() };
        Incidents {
            inner: Arc::new(Inner {
                db,
                ingest,
                bus,
                rules: rackhand_detect::rules::default_rules(),
                eval: Mutex::new(eval),
            }),
        }
    }

    fn eval(&self) -> MutexGuard<'_, Eval> {
        self.inner.eval.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests;
