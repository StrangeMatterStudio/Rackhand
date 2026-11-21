//! The runbook steps Checks runs for the Executor (7.8.7): `verify` and `api`.
//!
//! `verify` passes once every named check passes, trying again every 2 seconds until the step's time is up, and fails
//! with the name of the first that doesn't. The names (with parameters already substituted by the coordinator):
//! - `containers_running:<project>`: the machine's latest report has the Docker Compose project's containers, all
//!   running;
//! - `check:<name>`: the newest result of a service check bound to the machine, from after the step started, passed.
//!
//! `api` makes the step's `call` through the machine's driver (its `driver` column) at its address, and records the
//! driver's answer as the step's output.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rackhand_drivers::{Driver, DriverOp, DriverTarget};
use rackhand_runbook::runbook::{Step, StepKind};
use rackhand_store::Db;
use rusqlite::OptionalExtension;

use crate::actions::runner::{BoxFuture, StepCtx, StepOutcome, StepResult, StepRunner};
use crate::ingest::Ingest;

const AGAIN: Duration = Duration::from_secs(2);

fn succeeded(stdout: Vec<u8>, command: Option<String>) -> StepResult {
    StepResult { outcome: StepOutcome::Succeeded, command, stdout, ..StepResult::failed("") }
}

fn failed_with(reason: &str, why: String) -> StepResult {
    StepResult { stderr: why.into_bytes(), ..StepResult::failed(reason) }
}

pub struct Verify {
    db: Arc<Db>,
    ingest: Ingest,
}

impl std::fmt::Debug for Verify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verify").finish_non_exhaustive()
    }
}

/// Whether a named check passes now: `Ok(())`, or why not; `Err(None)` for a name it doesn't know.
type Outcome = Result<(), Option<String>>;

impl Verify {
    pub fn new(db: Arc<Db>, ingest: Ingest) -> Verify {
        Verify { db, ingest }
    }

    fn containers_running(&self, machine: &str, project: &str) -> Outcome {
        let Some(latest) = self.ingest.latest(machine) else { return Err(Some("no report from the machine".into())) };
        let ours: Vec<_> = latest.containers.iter().filter(|c| c.project == project).collect();
        if ours.is_empty() {
            return Err(Some(format!("no container of project {project}")));
        }
        let stopped: Vec<String> =
            ours.iter().filter(|c| c.state != "running").map(|c| format!("{} is {}", c.name, c.state)).collect();
        if stopped.is_empty() { Ok(()) } else { Err(Some(stopped.join(", "))) }
    }

    fn check_passes(&self, machine: &str, check: &str, since_ms: i64) -> Outcome {
        let newest: Option<(i64, bool, Option<String>)> = self
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT r.at_ms, r.ok, r.detail FROM check_results r JOIN checks k ON k.id = r.check_id
                     WHERE k.id = ?1 AND k.machine_id = ?2 ORDER BY r.at_ms DESC LIMIT 1",
                    [check, machine],
                    |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0, r.get(2)?)),
                )
                .optional()
            })
            .map_err(|e| Some(e.to_string()))?;
        match newest {
            None => Err(Some(format!("no check {check} bound to the machine has run"))),
            Some((at, _, _)) if at < since_ms => Err(Some(format!("check {check} hasn't run since the step started"))),
            Some((_, true, _)) => Ok(()),
            Some((_, false, detail)) => Err(Some(detail.unwrap_or_else(|| format!("check {check} failed")))),
        }
    }

    fn evaluate(&self, machine: &str, name: &str, since_ms: i64) -> Outcome {
        match name.split_once(':') {
            Some(("containers_running", project)) if !project.is_empty() => self.containers_running(machine, project),
            Some(("check", check)) if !check.is_empty() => self.check_passes(machine, check, since_ms),
            _ => Err(None),
        }
    }
}

impl StepRunner for Verify {
    fn run<'a>(&'a self, ctx: &'a StepCtx, step: &'a Step, _argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            if step.kind != StepKind::Verify {
                return StepResult::failed("verify_only");
            }
            let checks = step.checks.clone().unwrap_or_default();
            // a check result may be from the same millisecond the step started
            let since = rackhand_store::ids::now_ms() - 1;
            let deadline = tokio::time::Instant::now() + ctx.timeout;
            loop {
                let mut first_failing = None;
                for name in &checks {
                    match self.evaluate(&ctx.machine_id, name, since) {
                        Ok(()) => {}
                        Err(None) => return StepResult::failed(format!("unknown_check:{name}")),
                        Err(Some(why)) => {
                            first_failing = Some((name.clone(), why));
                            break;
                        }
                    }
                }
                let Some((name, why)) = first_failing else {
                    return succeeded(format!("passed: {}\n", checks.join(", ")).into_bytes(), None);
                };
                if tokio::time::Instant::now() + AGAIN >= deadline {
                    return failed_with(&name, why);
                }
                tokio::time::sleep(AGAIN.min(ctx.timeout / 4)).await;
            }
        })
    }
}

pub struct Api {
    db: Arc<Db>,
    drivers: BTreeMap<&'static str, Arc<dyn Driver>>,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api").field("drivers", &self.drivers.keys().collect::<Vec<_>>()).finish()
    }
}

impl Api {
    pub fn new(db: Arc<Db>) -> Api {
        Api { db, drivers: BTreeMap::new() }
    }

    /// Adds the driver for its kind (the API drivers arrive with their own steps, T47 to T49).
    pub fn with_driver(mut self, driver: Arc<dyn Driver>) -> Api {
        self.drivers.insert(driver.kind().name(), driver);
        self
    }
}

impl StepRunner for Api {
    fn run<'a>(&'a self, ctx: &'a StepCtx, step: &'a Step, _argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            if step.kind != StepKind::Api {
                return StepResult::failed("api_only");
            }
            let Some(call) = step.call.clone().filter(|c| !c.trim().is_empty()) else {
                return StepResult::failed("no_call");
            };
            let found: Result<Option<(Option<String>, Option<String>)>, _> = self.db.readers().with(|c| {
                c.query_row("SELECT driver, address FROM machines WHERE id = ?1", [&ctx.machine_id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()
            });
            let (kind, address) = match found {
                Ok(Some((Some(kind), address))) => (kind, address),
                Ok(_) => return StepResult::failed("no_driver"),
                Err(e) => return StepResult::failed(e.to_string()),
            };
            let Some(driver) = self.drivers.get(kind.as_str()) else {
                return StepResult::failed(format!("no_driver:{kind}"));
            };
            let target = DriverTarget {
                target: address.unwrap_or_default(),
                settings: serde_json::Value::Null,
                timeout: ctx.timeout,
            };
            let op = DriverOp { name: call.clone(), args: serde_json::Value::Null };
            let command = Some(format!("{kind} {call}"));
            match driver.call(&target, op).await {
                Ok(result) => {
                    let mut out = serde_json::to_vec_pretty(&result.output).unwrap_or_default();
                    out.push(b'\n');
                    succeeded(out, command)
                }
                Err(e) => StepResult { command, ..StepResult::failed(e.to_string()) },
            }
        })
    }
}
