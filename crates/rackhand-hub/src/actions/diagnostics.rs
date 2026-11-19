//! The diagnostics allow-list (7.8.3, 7.3.6 `run_diagnostic`): only the built-in templates, run as the automation
//! identity with their parameters checked like runbook parameters, plus two bindings the hub checks (`ping` targets a
//! machine in the same site, `http_head` a URL of the machine's checks). Output is capped at 256 KB and goes back
//! wrapped as untrusted. A diagnostic is read-only, so it doesn't wait for the machine's job lock: a detached step that
//! holds the machine (E55) can still be looked into.

use std::collections::BTreeMap;
use std::time::Duration;

use rackhand_runbook::diagnostics::{self, Bind, DiagnosticError, Keep};
use rackhand_runbook::runbook::{Identity, Step, StepKind};
use rackhand_store::Db;
use rackhand_store::ids::{new_id, now_ms};
use rusqlite::OptionalExtension;

use super::jobs::{self, StepEnd};
use super::runner::{StepCtx, StepOutcome};
use super::{Actions, ActionsError};

/// The most output a diagnostic returns (7.3.6).
pub const OUTPUT_LIMIT: usize = 256 * 1024;
pub const TRUNCATED: &str = "\n[rackhand: output truncated at 256 KiB]\n";
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// A diagnostic ready to run on a machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub name: &'static str,
    pub argv: Vec<String>,
    pub sensitive: bool,
    pub keep: Keep,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticOutput {
    /// Standard output then standard error, as the hub keeps it, at most [`OUTPUT_LIMIT`].
    pub output: Vec<u8>,
    pub exit_code: Option<i64>,
    pub sensitive: bool,
}

fn param_error(e: DiagnosticError) -> ActionsError {
    match e {
        DiagnosticError::Unknown => ActionsError::UnknownDiagnostic,
        DiagnosticError::MissingParam(p) => ActionsError::InvalidParam(p, "missing".into()),
        DiagnosticError::ExtraParam(p) => ActionsError::InvalidParam(p, "not a parameter of this diagnostic".into()),
        DiagnosticError::Param(p, e) => ActionsError::InvalidParam(p, e.to_string()),
    }
}

fn bound(db: &Db, machine_id: &str, site_id: &str, bind: Bind, value: &str) -> Result<bool, ActionsError> {
    let found: Option<i64> = db.readers().with(|c| match bind {
        Bind::Site => c
            .query_row(
                "SELECT 1 FROM machines WHERE site_id = ?1 AND (name = ?2 OR address = ?2) AND state != 'revoked'",
                [site_id, value],
                |r| r.get(0),
            )
            .optional(),
        Bind::Checks => c
            .query_row("SELECT 1 FROM checks WHERE machine_id = ?1 AND target = ?2", [machine_id, value], |r| r.get(0))
            .optional(),
    })?;
    Ok(found.is_some())
}

/// Checks a diagnostic call for a machine and builds its argument list.
pub fn prepare(
    db: &Db,
    machine_id: &str,
    name: &str,
    args: &BTreeMap<String, String>,
) -> Result<Prepared, ActionsError> {
    let d = diagnostics::find(name).ok_or(ActionsError::UnknownDiagnostic)?;
    let machine: Option<(String, String)> = db.readers().with(|c| {
        c.query_row("SELECT kind, site_id FROM machines WHERE id = ?1", [machine_id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()
    })?;
    let (kind, site_id) = machine.ok_or(ActionsError::UnknownMachine)?;
    if kind == "windows" {
        // The Windows equivalents run through the dispatcher's scripts (T90).
        return Err(ActionsError::Unsupported("Windows diagnostics".into()));
    }
    let argv = d.argv(kind == "alpine", args).map_err(param_error)?;
    for (pname, p) in &d.params {
        if let (Some(bind), Some(value)) = (p.bind, args.get(pname))
            && !bound(db, machine_id, &site_id, bind, value)?
        {
            let why = match bind {
                Bind::Site => "not a machine in this machine's site",
                Bind::Checks => "not a URL of this machine's checks",
            };
            return Err(ActionsError::InvalidParam(pname.clone(), why.into()));
        }
    }
    Ok(Prepared { name: &d.name, argv, sensitive: d.sensitive, keep: d.keep })
}

/// A `du` size such as `1.5G` in bytes, for sorting.
fn du_size(line: &str) -> f64 {
    let size = line.split_whitespace().next().unwrap_or("");
    let (num, unit) = size.split_at(size.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(size.len()));
    let factor = match unit {
        "K" => 1e3,
        "M" => 1e6,
        "G" => 1e9,
        "T" => 1e12,
        "P" => 1e15,
        _ => 1.0,
    };
    num.parse::<f64>().unwrap_or(0.0) * factor
}

/// What the hub keeps of the output, then the 256 KB cap.
pub fn keep(how: Keep, output: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(output);
    let lines: Vec<&str> = text.lines().collect();
    let kept: Vec<&str> = match how {
        Keep::All => return cap(output.to_vec()),
        Keep::Head(n) => lines.iter().take(n).copied().collect(),
        Keep::Tail(n) => lines.iter().skip(lines.len().saturating_sub(n)).copied().collect(),
        Keep::DuSorted => {
            let mut sorted = lines.clone();
            sorted.sort_by(|a, b| du_size(b).total_cmp(&du_size(a)));
            sorted
        }
    };
    let mut out = kept.join("\n");
    out.push('\n');
    cap(out.into_bytes())
}

fn cap(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.len() > OUTPUT_LIMIT {
        bytes.truncate(OUTPUT_LIMIT - TRUNCATED.len());
        bytes.extend_from_slice(TRUNCATED.as_bytes());
    }
    bytes
}

/// Machine output as tools return it (7.3.6).
pub fn untrusted(output: &[u8]) -> serde_json::Value {
    serde_json::json!({ "untrusted_output": String::from_utf8_lossy(output) })
}

fn step_for(name: &str, argv: &[String]) -> Step {
    Step {
        id: format!("diag-{}-{}", name.replace('_', "-"), new_id().to_string().to_ascii_lowercase()),
        kind: StepKind::Ssh,
        cmd: Some(argv.to_vec()),
        windows_script: None,
        windows_args: None,
        checks: None,
        call: None,
        message: None,
        source: None,
        dest: None,
        port: None,
        timeout: Some(format!("{}s", TIMEOUT.as_secs())),
        on_failure: None,
        retries: 0,
        idempotent: true,
        resumable: false,
        detached: false,
    }
}

impl Actions {
    /// Runs a diagnostic on a machine. Within a job, it is recorded as one of the job's steps (the only place its
    /// output is stored, 7.8.3).
    pub async fn run_diagnostic(
        &self,
        job_id: Option<&str>,
        requested_by: &str,
        machine_id: &str,
        name: &str,
        args: &BTreeMap<String, String>,
    ) -> Result<DiagnosticOutput, ActionsError> {
        let machine = self.machine(machine_id)?;
        if machine.monitor_only() {
            return Err(ActionsError::MonitorOnly);
        }
        let prepared = prepare(&self.inner.db, machine_id, name, args)?;
        let step = step_for(name, &prepared.argv);
        let command = super::runner::display(&prepared.argv);
        if let Some(job) = job_id {
            jobs::step_started(&self.inner.db, job, &step.id, Some(&command), now_ms()).await?;
        }
        self.audit(requested_by, "diagnostic.run", &machine.id, serde_json::json!({ "name": name, "args": args }))
            .await;
        let ctx = StepCtx {
            job_id: job_id.unwrap_or_default().into(),
            machine_id: machine.id.clone(),
            machine_kind: machine.kind.clone(),
            address: machine.address.clone(),
            identity: Identity::Automation,
            timeout: TIMEOUT,
        };
        let runner = self.inner.runner.clone();
        let (argv, run_step) = (prepared.argv.clone(), step.clone());
        let handle = tokio::spawn(async move { runner.run(&ctx, &run_step, Some(&argv)).await });
        let result = match tokio::time::timeout(TIMEOUT, handle).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Ok(Err(_)) | Err(_) => super::runner::StepResult::failed("timeout"),
        };
        let mut raw = result.stdout.clone();
        raw.extend_from_slice(&result.stderr);
        let output = keep(prepared.keep, &raw);
        if let Some(job) = job_id {
            let state = if result.outcome == StepOutcome::Succeeded { "succeeded" } else { "failed" };
            let end = StepEnd {
                state,
                exit_code: result.exit_code,
                stdout: output.clone(),
                stderr: Vec::new(),
                now_ms: now_ms(),
            };
            jobs::step_finished(&self.inner.db, job, &step.id, end).await?;
        }
        Ok(DiagnosticOutput { output, exit_code: result.exit_code, sensitive: prepared.sensitive })
    }
}

#[cfg(test)]
#[path = "diagnostics_tests.rs"]
mod tests;
