//! The runbook steps Checks runs for the Executor (7.8.7): `verify` and `api`.
//!
//! `verify` passes once every named check passes, trying again every 2 seconds until the step's time is up, and fails
//! with the name of the first that doesn't. The names (with parameters already substituted by the coordinator):
//! - `containers_running:<project>`: the machine's latest report has the Docker Compose project's containers, all
//!   running;
//! - `check:<name>`: the newest result of a service check bound to the machine, from after the step started, passed;
//! - the patch runbooks' `patch_precheck`, `record_state`, `as_recorded`, `required_mounts` and `bound_checks`
//!   (`checks::patch`). The first two are judged once, before the others, and put their findings in the step's output.
//!
//! `api` makes the step's `call` through the machine's driver (its `driver` column) at its address, and records the
//! driver's answer as the step's output.
//!
//! `snapshot` and `rollback` act on a Proxmox guest through its hypervisor (7.5.3): the guest's confirmed binding
//! (`proxmox_ref`: `cluster`, the hypervisor machine; `node`, `vmid`, `type`) names it, and the hypervisor's driver
//! credentials are the Vault's `driver.<hypervisor id>` (`{token, fingerprint}`). The snapshot is the job's own,
//! `rackhand-<job id>`, and the rollback goes back to it. A binding that isn't confirmed blocks both (7.3.12). A patch
//! job's snapshot (its runbook `patch-*`) judges the guest's part of the precheck first, is named
//! `rackhand-patch-<YYYYMMDD-HHMM>` with the newest 3 kept, and a rollback in the job goes back to the snapshot it took.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rackhand_drivers::{Driver, DriverOp, DriverTarget};
use rackhand_runbook::runbook::{Step, StepKind};
use rackhand_store::Db;
use rusqlite::OptionalExtension;

use super::patch;
use crate::actions::patching::hypervisor::{HostGuest, HostView, Hosts};
use crate::actions::patching::precheck::{Guest, Snapshot, guest as guest_precheck};
use crate::actions::runner::{BoxFuture, StepCtx, StepOutcome, StepResult, StepRunner};
use crate::ingest::Ingest;

/// The names judged once, before the step's other names.
const ONCE: &[&str] = &["patch_precheck", "record_state"];

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

    fn evaluate(&self, ctx: &StepCtx, name: &str, since_ms: i64) -> Outcome {
        let machine = ctx.machine_id.as_str();
        match name {
            "as_recorded" => return patch::as_recorded(&self.db, &self.ingest, machine, &ctx.job_id).map_err(Some),
            "required_mounts" => return patch::required_mounts(&self.db, &self.ingest, machine).map_err(Some),
            "bound_checks" => {
                for check in patch::bound_checks(&self.db, machine).map_err(Some)? {
                    self.check_passes(machine, &check, since_ms)?;
                }
                return Ok(());
            }
            _ => {}
        }
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
            let all = step.checks.clone().unwrap_or_default();
            // a check result may be from the same millisecond the step started
            let since = rackhand_store::ids::now_ms() - 1;
            let mut output = Vec::new();
            for name in all.iter().filter(|n| ONCE.contains(&n.as_str())) {
                let judged = match name.as_str() {
                    "patch_precheck" => {
                        patch::patch_precheck(&self.db, &self.ingest, &ctx.machine_id).map_err(|reason| StepResult {
                            stderr: reason.clone().into_bytes(),
                            ..StepResult::failed(reason)
                        })
                    }
                    _ => patch::record_state(&self.ingest, &ctx.machine_id).map_err(|why| failed_with(name, why)),
                };
                match judged {
                    Ok(o) => output.push(o),
                    Err(failed) => return failed,
                }
            }
            let checks: Vec<String> = all.into_iter().filter(|n| !ONCE.contains(&n.as_str())).collect();
            if checks.is_empty() {
                return succeeded(format!("{}\n", output.join("\n")).into_bytes(), None);
            }
            let deadline = tokio::time::Instant::now() + ctx.timeout;
            loop {
                let mut first_failing = None;
                for name in &checks {
                    match self.evaluate(ctx, name, since) {
                        Ok(()) => {}
                        Err(None) => return StepResult::failed(format!("unknown_check:{name}")),
                        Err(Some(why)) => {
                            first_failing = Some((name.clone(), why));
                            break;
                        }
                    }
                }
                let Some((name, why)) = first_failing else {
                    output.push(format!("passed: {}", checks.join(", ")));
                    return succeeded(format!("{}\n", output.join("\n")).into_bytes(), None);
                };
                if tokio::time::Instant::now() + AGAIN >= deadline {
                    return failed_with(&name, why);
                }
                tokio::time::sleep(AGAIN.min(ctx.timeout / 4)).await;
            }
        })
    }
}

/// The arguments of a step's `call` (`clone vmid=9000 name=web`) as the driver takes them: the numbers the drivers read
/// as numbers, `set.<key>=<value>` collected into `set`, the rest text; with no argument, `Null`.
fn call_args(call: &str) -> (String, serde_json::Value) {
    const NUMBERS: [&str; 5] = ["vmid", "newid", "memory", "cores", "disk_gb"];
    let (name, words) = rackhand_runbook::runbook::call_parts(call);
    if words.is_empty() {
        return (name.to_string(), serde_json::Value::Null);
    }
    let mut args = serde_json::Map::new();
    for (key, value) in words {
        if let Some(inner) = key.strip_prefix("set.") {
            let set = args.entry("set").or_insert_with(|| serde_json::json!({}));
            set[inner] = serde_json::Value::String(value);
        } else if let (true, Ok(n)) = (NUMBERS.contains(&key.as_str()), value.parse::<u64>()) {
            args.insert(key, serde_json::json!(n));
        } else {
            args.insert(key, serde_json::Value::String(value));
        }
    }
    (name.to_string(), serde_json::Value::Object(args))
}

pub struct Api {
    db: Arc<Db>,
    drivers: BTreeMap<&'static str, Arc<dyn Driver>>,
    /// Where a machine's API credentials are kept (`driver.<machine id>`), when it has them.
    vault: Option<Arc<crate::vault::Vault>>,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api").field("drivers", &self.drivers.keys().collect::<Vec<_>>()).finish()
    }
}

impl Api {
    pub fn new(db: Arc<Db>) -> Api {
        Api { db, drivers: BTreeMap::new(), vault: None }
    }

    /// The machine's API credentials come from the Vault (`driver.<machine id>`).
    pub fn with_vault(mut self, vault: Arc<crate::vault::Vault>) -> Api {
        self.vault = Some(vault);
        self
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
            let settings = self
                .vault
                .as_ref()
                .and_then(|v| v.get(&format!("driver.{}", ctx.machine_id)).ok())
                .and_then(|s| serde_json::from_slice(s.expose()).ok())
                .unwrap_or(serde_json::Value::Null);
            let target = DriverTarget { target: address.unwrap_or_default(), settings, timeout: ctx.timeout };
            let (name, args) = call_args(&call);
            let op = DriverOp { name, args };
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

pub struct Hypervisor {
    db: Arc<Db>,
    vault: Arc<crate::vault::Vault>,
    drivers: BTreeMap<&'static str, Arc<dyn Driver>>,
}

impl std::fmt::Debug for Hypervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hypervisor").field("drivers", &self.drivers.keys().collect::<Vec<_>>()).finish()
    }
}

/// What a guest's step needs: the hypervisor's driver kind, address and credentials, and the guest on it.
struct Bound {
    driver: String,
    address: String,
    settings: serde_json::Value,
    guest: serde_json::Value,
}

impl Hypervisor {
    pub fn new(db: Arc<Db>, vault: Arc<crate::vault::Vault>) -> Hypervisor {
        Hypervisor { db, vault, drivers: BTreeMap::new() }
    }

    pub fn with_driver(mut self, driver: Arc<dyn Driver>) -> Hypervisor {
        self.drivers.insert(driver.kind().name(), driver);
        self
    }

    /// A hypervisor machine's driver kind, address and credentials.
    fn api(&self, host: &str) -> Result<(String, String, serde_json::Value), String> {
        let found: Option<(Option<String>, Option<String>)> = self
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT driver, address FROM machines WHERE id = ?1", [host], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()
            })
            .map_err(|e| e.to_string())?;
        let Some((Some(driver), Some(address))) = found else { return Err("no_hypervisor".into()) };
        let creds = self.vault.get(&format!("driver.{host}")).map_err(|_| "no_hypervisor_credentials".to_string())?;
        let settings = serde_json::from_slice(creds.expose()).map_err(|_| "no_hypervisor_credentials".to_string())?;
        Ok((driver, address, settings))
    }

    fn bound(&self, guest: &str) -> Result<Bound, String> {
        let row: Option<(Option<String>, String)> = self
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT proxmox_ref, proxmox_ref_state FROM machines WHERE id = ?1", [guest], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()
            })
            .map_err(|e| e.to_string())?;
        let Some((Some(reference), state)) = row else { return Err("not_a_proxmox_guest".into()) };
        if let Some(why) = crate::actions::hypervisor_guard::refusal(&state) {
            return Err(why.into());
        }
        let r: serde_json::Value =
            serde_json::from_str(&reference).map_err(|_| "guest_binding_unreadable".to_string())?;
        let host = r["cluster"].as_str().ok_or("guest_binding_unreadable")?.to_string();
        let (driver, address, settings) = self.api(&host)?;
        let guest = serde_json::json!({ "node": r["node"], "vmid": r["vmid"], "kind": r["type"] });
        Ok(Bound { driver, address, settings, guest })
    }
}

/// How long a hypervisor's API has to describe its host.
const VIEW_TIMEOUT: Duration = Duration::from_secs(10);

impl Hypervisor {
    /// One hypervisor-side call on a guest (7.3.12): only on the guest its confirmed binding names, and refused
    /// before any call to the API when the binding isn't confirmed. `extra` is added to the call's arguments.
    pub async fn guest_call(
        &self,
        machine_id: &str,
        action: crate::actions::hypervisor_guard::GuestAction,
        extra: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, String> {
        let b = self.bound(machine_id)?;
        let op = match action {
            crate::actions::hypervisor_guard::GuestAction::Snapshot => "snapshot",
            crate::actions::hypervisor_guard::GuestAction::Rollback => "rollback",
            crate::actions::hypervisor_guard::GuestAction::Firewall => "firewall_read",
            crate::actions::hypervisor_guard::GuestAction::Power => "power",
        };
        self.guest_op(&b, action, op, extra, timeout).await
    }

    /// A firewall operation on the guest the machine's confirmed binding names (`firewall_isolate`, `firewall_release`,
    /// `firewall_read`, `firewall_restore`), with `extra` added to its arguments.
    pub async fn guest_firewall(
        &self,
        machine_id: &str,
        op: &str,
        extra: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, String> {
        let b = self.bound(machine_id)?;
        self.guest_op(&b, crate::actions::hypervisor_guard::GuestAction::Firewall, op, extra, timeout).await
    }

    /// A named driver operation of an action on the bound guest.
    async fn guest_op(
        &self,
        b: &Bound,
        action: crate::actions::hypervisor_guard::GuestAction,
        op: &str,
        extra: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, String> {
        if !action.ops().contains(&op) {
            return Err(format!("{op}_is_not_a_{action:?}_operation").to_ascii_lowercase());
        }
        let driver = self.drivers.get(b.driver.as_str()).ok_or_else(|| format!("no_driver:{}", b.driver))?;
        let target = DriverTarget { target: b.address.clone(), settings: b.settings.clone(), timeout };
        let mut args = b.guest.clone();
        if let (Some(a), Some(e)) = (args.as_object_mut(), extra.as_object()) {
            a.extend(e.clone());
        }
        driver.call(&target, DriverOp { name: op.into(), args }).await.map(|r| r.output).map_err(|e| e.to_string())
    }
}

impl Hosts for Hypervisor {
    fn view<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<HostView, String>> {
        Box::pin(async move {
            let (kind, target, settings) = self.api(host)?;
            let driver = self.drivers.get(kind.as_str()).ok_or_else(|| format!("no_driver:{kind}"))?;
            let target = DriverTarget { target, settings, timeout: VIEW_TIMEOUT };
            let op = DriverOp { name: "host".into(), args: serde_json::Value::Null };
            let v = driver.call(&target, op).await.map_err(|e| e.to_string())?.output;
            let text = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
            let guests = v["guests"].as_array().into_iter().flatten();
            Ok(HostView {
                node: text(&v["node"]),
                nodes: v["nodes"].as_array().into_iter().flatten().map(&text).collect(),
                guests: guests
                    .map(|g| HostGuest {
                        vmid: g["vmid"].as_u64().unwrap_or_default(),
                        kind: text(&g["type"]),
                        name: text(&g["name"]),
                        running: g["running"].as_bool().unwrap_or(false),
                    })
                    .collect(),
            })
        })
    }
}

/// How many `rackhand-patch-*` snapshots a guest keeps (7.5.3).
const PATCH_SNAPSHOTS_KEPT: usize = 3;
const PATCH_PREFIX: &str = "rackhand-patch-";

impl Hypervisor {
    fn job_name(&self, job_id: &str) -> Option<String> {
        self.db
            .readers()
            .with(|c| c.query_row("SELECT name FROM jobs WHERE id = ?1", [job_id], |r| r.get(0)).optional())
            .ok()
            .flatten()
    }

    /// The machine's policy `snapshot`; `required` without a policy (7.5.3 step 9).
    fn snapshot_policy(&self, machine: &str) -> Snapshot {
        let policy: Option<String> = self
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT p.snapshot FROM machines m JOIN policies p ON p.id = m.policy_id WHERE m.id = ?1",
                    [machine],
                    |r| r.get(0),
                )
                .optional()
            })
            .ok()
            .flatten();
        policy.map_or(Snapshot::Required, |p| Snapshot::parse(&p))
    }

    /// The patch job a `rollback` job was given, and whether it was a job on this machine.
    fn named_job(&self, job_id: &str, machine: &str) -> Option<(String, bool)> {
        self.db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT json_extract(j.params, '$.job'),
                            EXISTS (SELECT 1 FROM jobs p WHERE p.id = json_extract(j.params, '$.job') AND p.target = ?2)
                     FROM jobs j WHERE j.id = ?1 AND json_extract(j.params, '$.job') IS NOT NULL",
                    [job_id, machine],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
            })
            .ok()
            .flatten()
    }

    /// The snapshot this job took, from its snapshot step's output.
    fn taken(&self, job_id: &str) -> Option<String> {
        let outputs: Vec<Vec<u8>> = self
            .db
            .readers()
            .with(|c| {
                let mut s = c.prepare(
                    "SELECT stdout FROM job_steps WHERE job_id = ?1 AND stdout IS NOT NULL ORDER BY started_at DESC",
                )?;
                s.query_map([job_id], |r| r.get(0))?.collect()
            })
            .unwrap_or_default();
        outputs
            .iter()
            .filter_map(|o| serde_json::from_slice::<serde_json::Value>(o).ok())
            .find_map(|v| v.get("snapshot").and_then(|s| s.as_str()).map(str::to_string))
    }

    /// A patch job's snapshot (7.5.3): the guest's part of the precheck first, then `rackhand-patch-<YYYYMMDD-HHMM>`
    /// (UTC), keeping the newest 3 of them. A machine that isn't a Proxmox guest, or a guest patched without a snapshot
    /// under `snapshot = "optional"`, passes with a note.
    async fn patch_snapshot(&self, ctx: &StepCtx) -> StepResult {
        let skip = |notes: Vec<String>| {
            let mut out =
                serde_json::to_vec(&serde_json::json!({ "snapshot": null, "notes": notes })).unwrap_or_default();
            out.push(b'\n');
            succeeded(out, None)
        };
        let row: Option<(Option<String>, String)> = self
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT proxmox_ref, proxmox_ref_state FROM machines WHERE id = ?1",
                    [&ctx.machine_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
            })
            .ok()
            .flatten();
        let Some((Some(_), binding)) = row else {
            return skip(vec!["not a Proxmox guest: nothing to snapshot".into()]);
        };
        let policy = self.snapshot_policy(&ctx.machine_id);
        let judged = |g: &Guest| match guest_precheck(g, policy) {
            Ok(notes) if notes.is_empty() => Ok(()),
            Ok(notes) => Err(skip(notes)),
            Err(reason) => Err(StepResult::failed(reason)),
        };
        if binding != "confirmed" {
            let unbound = Guest {
                binding_confirmed: false,
                datastore_free_pct: 100.0,
                datastore_free_bytes: u64::MAX,
                snapshots_supported: true,
            };
            return match judged(&unbound) {
                Ok(()) => StepResult::failed("guest_binding_unconfirmed"),
                Err(r) => r,
            };
        }
        let b = match self.bound(&ctx.machine_id) {
            Ok(b) => b,
            Err(reason) => return StepResult::failed(reason),
        };
        let Some(driver) = self.drivers.get(b.driver.as_str()) else {
            return StepResult::failed(format!("no_driver:{}", b.driver));
        };
        let target = DriverTarget { target: b.address.clone(), settings: b.settings.clone(), timeout: ctx.timeout };
        let call = |name: &str, extra: serde_json::Value| {
            let mut args = b.guest.clone();
            if let (Some(a), Some(e)) = (args.as_object_mut(), extra.as_object()) {
                a.extend(e.clone());
            }
            driver.call(&target, DriverOp { name: name.into(), args })
        };
        let room = match call("snapshot_room", serde_json::json!({})).await {
            Ok(r) => r.output,
            Err(e) => return StepResult::failed(format!("snapshot_room: {e}")),
        };
        let storages: Vec<&serde_json::Value> = room["storages"].as_array().into_iter().flatten().collect();
        let free_pct = |s: &serde_json::Value| {
            let total = s["total"].as_u64().unwrap_or(0) as f64;
            if total > 0.0 { 100.0 * s["avail"].as_u64().unwrap_or(0) as f64 / total } else { 0.0 }
        };
        let facts = Guest {
            binding_confirmed: true,
            datastore_free_pct: storages.iter().map(|s| free_pct(s)).fold(100.0, f64::min),
            datastore_free_bytes: storages.iter().map(|s| s["avail"].as_u64().unwrap_or(0)).min().unwrap_or(0),
            snapshots_supported: !storages.is_empty() && storages.iter().all(|s| s["snapshots"] == true),
        };
        if let Err(r) = judged(&facts) {
            return r;
        }
        let name = format!("{PATCH_PREFIX}{}", jiff::Timestamp::now().strftime("%Y%m%d-%H%M"));
        let command = Some(format!("{} snapshot {} {name}", b.driver, b.guest["vmid"]));
        if let Err(e) = call("snapshot", serde_json::json!({ "name": name })).await {
            return StepResult { command, ..StepResult::failed(e.to_string()) };
        }
        // Keep the newest 3 patch snapshots; the names sort by time. An admin's own snapshots aren't touched.
        let mut pruned = Vec::new();
        if let Ok(list) = call("snapshots", serde_json::json!({})).await {
            let mut ours: Vec<String> = list
                .output
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|s| s["name"].as_str().filter(|n| n.starts_with(PATCH_PREFIX)).map(str::to_string))
                .collect();
            ours.sort();
            let excess = ours.len().saturating_sub(PATCH_SNAPSHOTS_KEPT);
            for old in ours.into_iter().take(excess) {
                if call("delete_snapshot", serde_json::json!({ "name": old })).await.is_ok() {
                    pruned.push(old);
                }
            }
        }
        let mut out =
            serde_json::to_vec(&serde_json::json!({ "snapshot": name, "pruned": pruned })).unwrap_or_default();
        out.push(b'\n');
        succeeded(out, command)
    }
}

impl StepRunner for Hypervisor {
    fn run<'a>(&'a self, ctx: &'a StepCtx, step: &'a Step, _argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            let op = match step.kind {
                StepKind::Snapshot => "snapshot",
                StepKind::Rollback => "rollback",
                _ => return StepResult::failed("snapshot_or_rollback_only"),
            };
            let patching = self.job_name(&ctx.job_id).is_some_and(|n| n.starts_with("patch-"));
            if op == "snapshot" && patching {
                return self.patch_snapshot(ctx).await;
            }
            let b = match self.bound(&ctx.machine_id) {
                Ok(b) => b,
                Err(reason) => return StepResult::failed(reason),
            };
            let Some(driver) = self.drivers.get(b.driver.as_str()) else {
                return StepResult::failed(format!("no_driver:{}", b.driver));
            };
            // A rollback goes back to the snapshot the job it was given took (on this machine), or that its own job took;
            // otherwise the job's own name.
            let own = format!("rackhand-{}", ctx.job_id.to_ascii_lowercase());
            let name = match (op, self.named_job(&ctx.job_id, &ctx.machine_id)) {
                ("rollback", Some((job, ours))) => match self.taken(&job).filter(|_| ours) {
                    Some(name) => name,
                    None => return StepResult::failed("no_snapshot"),
                },
                ("rollback", None) => self.taken(&ctx.job_id).unwrap_or(own),
                _ => own,
            };
            let mut args = b.guest.clone();
            args["name"] = serde_json::json!(name);
            let command = Some(format!("{} {op} {} {}", b.driver, args["vmid"], name));
            let target = DriverTarget { target: b.address, settings: b.settings, timeout: ctx.timeout };
            match driver.call(&target, DriverOp { name: op.into(), args }).await {
                Ok(r) => {
                    let mut out =
                        serde_json::to_vec_pretty(&serde_json::json!({ "snapshot": name, "result": r.output }))
                            .unwrap_or_default();
                    out.push(b'\n');
                    succeeded(out, command)
                }
                Err(e) => StepResult { command, ..StepResult::failed(e.to_string()) },
            }
        })
    }
}
