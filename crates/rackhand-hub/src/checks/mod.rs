//! Service checks (FR-9, 7.3.8): the checks of `config/checks.toml`, each run from the hub at its interval through its
//! driver. A run is one row of `check_results` and its readings are series (`check.up`, `check.latency_ms`, ...,
//! labelled `check`) of the check's machine, or of `hub` for a check that belongs to none. Incidents reads the results
//! (check failing) and the `check.cert_days` series (certificate expiry).
//!
//! A check taken out of the file keeps its row, since its results refer to it, with `interval_s` 0: it no longer runs
//! and its incidents resolve.
//!
//! Agentless machines (FR-10, 7.3.12) are polled the same way: every enrolled machine with a driver is a check
//! `driver:<machine id>` of its driver's kind, every 60 s, with the settings of its Vault entry `driver.<machine id>`
//! (read at each poll, so changed credentials apply at once). Their readings are series of the machine. Incidents
//! counts their failed polls in a row as the machine's silence (7.6.3) when it has no probe.

pub mod agentless;

pub mod config;
pub mod steps;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rackhand_drivers::{Driver, DriverKind, DriverReading, DriverTarget, check_driver};
use rackhand_store::series::compact::SeriesPoints;
use rackhand_store::{Db, Row, WriteCmd};
use rusqlite::types::Value;

use crate::ingest::Ingest;

/// The series key of a check that belongs to no machine.
pub const HUB_MACHINE: &str = "hub";
/// The longest a single run waits for an answer.
const MAX_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum ChecksError {
    #[error("{0}")]
    Config(String),
    #[error(transparent)]
    Store(#[from] rackhand_store::StoreError),
    #[error(transparent)]
    Read(#[from] rusqlite::Error),
    #[error(transparent)]
    Ingest(#[from] crate::ingest::IngestError),
}

#[derive(Debug, Clone)]
struct Scheduled {
    spec: config::CheckSpec,
    machine_id: Option<String>,
    next_ms: i64,
    /// An agentless machine's poll: its driver is an API driver and its settings are in the Vault.
    agentless: bool,
}

#[derive(Default)]
struct State {
    checks: BTreeMap<String, Scheduled>,
    /// The agentless machines' polls, by check id (`driver:<machine id>`).
    agentless: BTreeMap<String, Scheduled>,
    /// The `config/checks` text last synced, so a new revision is picked up.
    synced: Option<String>,
}

/// The API drivers, by name.
type ApiDrivers = BTreeMap<&'static str, Arc<dyn Driver>>;

struct Inner {
    db: Arc<Db>,
    ingest: Ingest,
    drivers: BTreeMap<&'static str, Box<dyn Driver>>,
    /// The Vault and the API drivers, for the agentless machines.
    api: Option<(Arc<crate::vault::Vault>, ApiDrivers)>,
    /// Guest binding, given each Proxmox host's guests and their MACs after a poll.
    bindings: Option<Arc<crate::registry::guest_binding::GuestBindings>>,
    state: Mutex<State>,
}

#[derive(Clone)]
pub struct Checks {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Checks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Checks").field("checks", &self.state().checks.len()).finish()
    }
}

fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

impl Checks {
    pub fn new(db: Arc<Db>, ingest: Ingest) -> Checks {
        let drivers = DriverKind::ALL.into_iter().filter_map(|k| check_driver(k).map(|d| (k.name(), d))).collect();
        Checks {
            inner: Arc::new(Inner {
                db,
                ingest,
                drivers,
                api: None,
                bindings: None,
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// Feeds guest binding each Proxmox host's guests after its polls. Called on a new `Checks`, before it is cloned.
    pub fn with_bindings(mut self, bindings: Arc<crate::registry::guest_binding::GuestBindings>) -> Checks {
        let inner = Arc::get_mut(&mut self.inner).expect("with_bindings on a Checks not yet cloned");
        inner.bindings = Some(bindings);
        self
    }

    /// Polls the agentless machines too, with these drivers and the credentials in `vault`. Called on a new
    /// `Checks`, before it is cloned.
    pub fn with_agentless(mut self, vault: Arc<crate::vault::Vault>, drivers: Vec<Arc<dyn Driver>>) -> Checks {
        let drivers = drivers.into_iter().map(|d| (d.kind().name(), d)).collect();
        let inner = Arc::get_mut(&mut self.inner).expect("with_agentless on a Checks not yet cloned");
        inner.api = Some((vault, drivers));
        self
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Makes the checks those of `text` (`config/checks.toml`): new and changed ones are stored and due now, unchanged
    /// ones keep their schedule, and ones no longer there stop. Returns how many run.
    pub async fn sync(&self, text_now: &str) -> Result<usize, ChecksError> {
        let file = config::parse(text_now).map_err(ChecksError::Config)?;
        let machines: BTreeMap<String, String> = self.inner.db.readers().with(|c| {
            let mut s = c.prepare("SELECT name, id FROM machines")?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })?;
        let mut next: BTreeMap<String, Scheduled> = BTreeMap::new();
        for spec in file.check {
            let machine_id = match &spec.machine {
                Some(name) => match machines.get(name) {
                    Some(id) => Some(id.clone()),
                    None => {
                        tracing::warn!(check = %spec.name, machine = %name, "check of an unknown machine: not run");
                        continue;
                    }
                },
                None => None,
            };
            let kept = self
                .state()
                .checks
                .get(&spec.name)
                .filter(|s| s.spec == spec && s.machine_id == machine_id)
                .map(|s| s.next_ms);
            let row = Row::from([
                ("id", text(&spec.name)),
                ("kind", text(&spec.kind)),
                ("target", text(&spec.target)),
                ("interval_s", Value::Integer(spec.interval_s.into())),
                ("machine_id", machine_id.as_deref().map_or(Value::Null, text)),
                ("settings", text(&spec.settings_json().to_string())),
            ]);
            self.inner.db.writer().send(WriteCmd::PutCheck(row)).await?;
            next.insert(
                spec.name.clone(),
                Scheduled { spec, machine_id, next_ms: kept.unwrap_or(i64::MIN), agentless: false },
            );
        }
        type Stored = (String, String, String, Option<String>, String);
        let stored: Vec<Stored> = self.inner.db.readers().with(|c| {
            let mut s = c.prepare("SELECT id, kind, target, machine_id, settings FROM checks WHERE interval_s != 0")?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?.collect()
        })?;
        let retired = stored.into_iter().filter(|c| !next.contains_key(&c.0) && !c.0.starts_with(agentless::PREFIX));
        for (id, kind, target, machine_id, settings) in retired {
            let row = Row::from([
                ("id", text(&id)),
                ("kind", text(&kind)),
                ("target", text(&target)),
                ("interval_s", Value::Integer(0)),
                ("machine_id", machine_id.as_deref().map_or(Value::Null, text)),
                ("settings", text(&settings)),
            ]);
            self.inner.db.writer().send(WriteCmd::PutCheck(row)).await?;
        }
        let n = next.len();
        let mut state = self.state();
        state.checks = next;
        state.synced = Some(text_now.to_string());
        Ok(n)
    }

    /// Syncs with the current `config/checks` revision when it changed since the last sync.
    pub async fn refresh(&self) -> Result<(), ChecksError> {
        let current = crate::library::config::current(&self.inner.db, "checks")
            .map_err(|e| ChecksError::Config(e.to_string()))?
            .unwrap_or_default();
        if self.state().synced.as_deref() != Some(current.as_str()) {
            self.sync(&current).await?;
        }
        if self.inner.api.is_some() {
            self.sync_agentless().await?;
        }
        Ok(())
    }

    /// Runs every check that is due at `now_ms`, all at once; returns how many ran.
    pub async fn run_due(&self, now_ms: i64) -> Result<usize, ChecksError> {
        let due: Vec<Scheduled> = {
            let mut guard = self.state();
            let state = &mut *guard;
            state
                .checks
                .values_mut()
                .chain(state.agentless.values_mut())
                .filter(|s| s.next_ms <= now_ms)
                .map(|s| {
                    s.next_ms = now_ms + i64::from(s.spec.interval_s) * 1000;
                    s.clone()
                })
                .collect()
        };
        let mut runs = tokio::task::JoinSet::new();
        for (i, s) in due.iter().enumerate() {
            let (checks, s) = (self.clone(), s.clone());
            runs.spawn(async move { (i, checks.run_one(&s).await) });
        }
        let mut readings: Vec<Option<DriverReading>> = vec![None; due.len()];
        while let Some(done) = runs.join_next().await {
            if let Ok((i, r)) = done {
                readings[i] = Some(r);
            }
        }
        let mut results = Vec::with_capacity(due.len());
        for (s, reading) in due.iter().zip(readings) {
            let reading = reading.unwrap_or_else(|| DriverReading::down("the check's run failed", vec![]));
            results.push(Row::from([
                ("check_id", text(&s.spec.name)),
                ("at_ms", Value::Integer(now_ms)),
                ("ok", Value::Integer(reading.ok.into())),
                ("latency_ms", reading.latency_ms.map_or(Value::Null, Value::Real)),
                ("detail", text(&reading.detail)),
            ]));
            let label_set = serde_json::json!({ "check": s.spec.name }).to_string();
            let mut series: Vec<SeriesPoints> = reading
                .metrics
                .iter()
                .map(|(name, value)| SeriesPoints {
                    name: name.clone(),
                    unit: unit(name).into(),
                    label_set: label_set.clone(),
                    points: vec![(now_ms, *value)],
                    late: vec![],
                })
                .collect();
            // a driver's own readings (7.4.2), labelled as it labels them
            series.extend(reading.points.iter().map(|p| SeriesPoints {
                name: p.name.clone(),
                unit: unit(&p.name).into(),
                label_set: serde_json::to_string(&p.labels).unwrap_or_else(|_| "{}".into()),
                points: vec![(now_ms, p.value)],
                late: vec![],
            }));
            self.inner.ingest.put_points(s.machine_id.as_deref().unwrap_or(HUB_MACHINE), series, now_ms).await?;
        }
        if !results.is_empty() {
            self.inner.db.writer().send(WriteCmd::PutCheckResults(results)).await?;
        }
        Ok(due.len())
    }

    async fn run_one(&self, s: &Scheduled) -> DriverReading {
        if s.agentless {
            return self.poll_agentless(s).await;
        }
        let Some(driver) = self.inner.drivers.get(s.spec.kind.as_str()) else {
            return DriverReading::down(format!("no driver for {}", s.spec.kind), vec![]);
        };
        let timeout = Duration::from_secs(s.spec.interval_s.into()).min(MAX_TIMEOUT);
        let target = DriverTarget { target: s.spec.target.clone(), settings: s.spec.settings_json(), timeout };
        match driver.poll(&target).await {
            Ok(r) => r,
            Err(e) => DriverReading::down(e.to_string(), vec![]),
        }
    }

    /// Runs the checks for good: every second, the due ones, picking up a changed `config/checks` within 15 s.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            let mut n: u64 = 0;
            loop {
                tick.tick().await;
                if n % 15 == 0 {
                    if let Err(e) = self.refresh().await {
                        tracing::warn!(error = %e, "config/checks");
                    }
                }
                n += 1;
                if let Err(e) = self.run_due(rackhand_store::ids::now_ms()).await {
                    tracing::warn!(error = %e, "checks");
                }
            }
        })
    }
}

fn unit(metric: &str) -> &'static str {
    match metric {
        "check.latency_ms" => "ms",
        "check.cert_days" => "days",
        _ => "",
    }
}

#[cfg(test)]
mod tests;
