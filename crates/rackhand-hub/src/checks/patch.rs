//! The `verify` names the patch runbooks use (7.5.3 steps 4 and 5, plan T59c).
//!
//! Before the update, judged once (they don't wait for anything to change):
//! - `patch_precheck`: the machine part of the precheck (`actions::patching::precheck`) on the latest report: 1 GB
//!   free on `/` and no open critical incident on the machine, the security-updates incident patching is about to
//!   clear left out. The package lock is waited on by the update steps themselves (apt `DPkg::Lock::Timeout`, apk
//!   `--wait`, E9), and no other job can run while this one holds the machine. A Proxmox guest's conditions are judged
//!   by the snapshot step, which has the hypervisor's driver. Fails with the precheck's reason.
//! - `record_state`: the active services and running containers, kept in the step's output (the job log), where
//!   `as_recorded` reads them back by job, so the record survives a hub restart.
//!
//! After it, retried until the step's time is up:
//! - `as_recorded`: every recorded service active and every recorded container running in the latest report;
//! - `required_mounts`: every mount in the machine's policy's `required_mounts` in the latest report (D66);
//! - `bound_checks`: every service check bound to the machine passed, with a result from after the step started.

use rackhand_proto::probe::ServiceStatus;
use rackhand_store::Db;
use rusqlite::OptionalExtension;
use serde_json::{Value, json};

use crate::actions::patching::precheck::{Facts, Snapshot, precheck};
use crate::ingest::Ingest;

/// Incidents patching clears, which mustn't stop it.
const CLEARED_BY_PATCHING: &str = "updates.%";

fn root_free(ingest: &Ingest, machine: &str) -> Option<u64> {
    let newest = |metric: &str| {
        ingest.window_series(machine, metric).into_iter().find_map(|(id, samples)| {
            let labels: Value = serde_json::from_str(&id.labels).ok()?;
            (labels["mount"] == "/").then(|| samples.last().map(|s| s.value)).flatten()
        })
    };
    let (total, used) = (newest("disk.total_bytes")?, newest("disk.used_bytes")?);
    Some((total - used).max(0.0) as u64)
}

/// `patch_precheck`: `Ok` with the step's output, or the precheck's reason.
pub fn patch_precheck(db: &Db, ingest: &Ingest, machine: &str) -> Result<String, String> {
    if ingest.latest(machine).is_none() {
        return Err("no_report".into());
    }
    let open_critical = db
        .readers()
        .with(|c| {
            c.query_row(
                "SELECT EXISTS (SELECT 1 FROM incidents WHERE machine_id = ?1 AND severity = 'critical'
                   AND state != 'resolved' AND kind NOT LIKE ?2)",
                rusqlite::params![machine, CLEARED_BY_PATCHING],
                |r| r.get::<_, bool>(0),
            )
        })
        .map_err(|e| format!("store: {e}"))?;
    let root = root_free(ingest, machine);
    let facts = Facts { root_free_bytes: root, lock_held: false, other_job: false, open_critical, guest: None };
    let notes = precheck(&facts, Snapshot::Required)?;
    Ok(json!({ "precheck": "passed", "root_free_bytes": root, "notes": notes }).to_string())
}

/// `record_state`: the step's output, the machine's active services and running containers.
pub fn record_state(ingest: &Ingest, machine: &str) -> Result<String, String> {
    let latest = ingest.latest(machine).ok_or("no report from the machine")?;
    let services: Vec<&str> =
        latest.services.iter().filter(|s| s.status == ServiceStatus::Active as i32).map(|s| s.name.as_str()).collect();
    let containers: Vec<&str> =
        latest.containers.iter().filter(|c| c.state == "running").map(|c| c.name.as_str()).collect();
    Ok(json!({ "recorded": { "services": services, "containers": containers } }).to_string())
}

/// What the job's `record_state` step kept.
fn recorded(db: &Db, job_id: &str) -> Result<Option<Value>, String> {
    let outputs: Vec<Vec<u8>> = db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT stdout FROM job_steps WHERE job_id = ?1 AND stdout IS NOT NULL ORDER BY started_at DESC",
            )?;
            s.query_map([job_id], |r| r.get(0))?.collect()
        })
        .map_err(|e| format!("store: {e}"))?;
    Ok(outputs.iter().filter_map(|o| serde_json::from_slice::<Value>(o).ok()).find_map(|v| v.get("recorded").cloned()))
}

fn names(v: &Value, key: &str) -> Vec<String> {
    v[key].as_array().into_iter().flatten().filter_map(|n| n.as_str().map(str::to_string)).collect()
}

/// `as_recorded`: `Ok`, or what isn't as it was.
pub fn as_recorded(db: &Db, ingest: &Ingest, machine: &str, job_id: &str) -> Result<(), String> {
    let record = recorded(db, job_id)?.ok_or("no recorded state in this job (a `record_state` step runs first)")?;
    let latest = ingest.latest(machine).ok_or("no report from the machine")?;
    let mut off = Vec::new();
    for name in names(&record, "services") {
        match latest.services.iter().find(|s| s.name == name) {
            Some(s) if s.status == ServiceStatus::Active as i32 => {}
            Some(_) => off.push(format!("{name} isn't active")),
            None => off.push(format!("{name} isn't reported")),
        }
    }
    for name in names(&record, "containers") {
        match latest.containers.iter().find(|c| c.name == name) {
            Some(c) if c.state == "running" => {}
            Some(c) => off.push(format!("container {name} is {}", c.state)),
            None => off.push(format!("container {name} is gone")),
        }
    }
    if off.is_empty() { Ok(()) } else { Err(off.join(", ")) }
}

/// `required_mounts`: `Ok`, or the mounts missing.
pub fn required_mounts(db: &Db, ingest: &Ingest, machine: &str) -> Result<(), String> {
    let required: Option<String> = db
        .readers()
        .with(|c| {
            c.query_row(
                "SELECT p.required_mounts FROM machines m JOIN policies p ON p.id = m.policy_id WHERE m.id = ?1",
                [machine],
                |r| r.get(0),
            )
            .optional()
        })
        .map_err(|e| format!("store: {e}"))?;
    let required: Vec<String> = required.and_then(|r| serde_json::from_str(&r).ok()).unwrap_or_default();
    if required.is_empty() {
        return Ok(());
    }
    let present = ingest.latest(machine).map(|l| l.mounts).unwrap_or_default();
    let missing: Vec<String> = required.into_iter().filter(|m| !present.contains(m)).collect();
    if missing.is_empty() { Ok(()) } else { Err(format!("not mounted: {}", missing.join(", "))) }
}

/// The service checks bound to the machine that are still scheduled.
pub fn bound_checks(db: &Db, machine: &str) -> Result<Vec<String>, String> {
    db.readers()
        .with(|c| {
            let mut s = c.prepare("SELECT id FROM checks WHERE machine_id = ?1 AND interval_s > 0 ORDER BY id")?;
            s.query_map([machine], |r| r.get(0))?.collect()
        })
        .map_err(|e| format!("store: {e}"))
}
