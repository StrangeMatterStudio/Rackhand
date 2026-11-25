//! Gating (7.3.6, 7.6.8): every `run_diagnostic`, `exec` and `run_runbook` goes through `decide()`. A call that needs
//! an approval gets `needs_approval {approval_id}`; the approval binds the caller, the tool, the target, the
//! arguments and (for a runbook) its revision. The caller repeats the exact call with the id, and it runs once. No
//! tool decides an approval.

use rackhand_runbook::playbook::Playbook;
use rackhand_runbook::runbook::Risk;
use rackhand_store::Db;
use rusqlite::OptionalExtension;
use serde_json::{Value, json};

use super::ToolError;
use super::auth::Caller;
use crate::audit::Audit;
use crate::library::items::{Kind, Library};
use crate::policy::approvals::{ApprovalError, ApprovalRequest, Approvals, approval_hash};
use crate::policy::decide::{Access, Decision, Deny, Requester};

// How long a requested approval stays open is the approval expiry of `config/hub.toml` (7.8.1).

/// What gating needs to know about the target machine.
#[derive(Debug, Clone)]
pub(super) struct Target {
    pub access: Access,
    pub quarantined: bool,
    pub roles: Vec<String>,
    pub tags: Vec<String>,
}

impl Target {
    pub(super) fn load(db: &Db, id: &str) -> Result<Target, ToolError> {
        let row: Option<(String, String, String, String)> = db
            .readers()
            .with(|c| {
                c.query_row("SELECT access, quarantine, roles, tags FROM machines WHERE id = ?1", [id], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })
                .optional()
            })
            .map_err(|_| ToolError::new("internal", "the machine couldn't be read"))?;
        let (access, quarantine, roles, tags) = row.ok_or_else(|| ToolError::invalid(format!("no machine `{id}`")))?;
        Ok(Target {
            access: if access == "monitor" { Access::Monitor } else { Access::Managed },
            // Applying, active, releasing and failed: a quarantine that failed part-way leaves the machine suspect too;
            // one waiting for an approval has not isolated anything yet (7.5.6).
            quarantined: crate::policy::quarantine::State::parse(&quarantine).is_some_and(|s| s.blocks_actions()),
            roles: serde_json::from_str(&roles).unwrap_or_default(),
            tags: serde_json::from_str(&tags).unwrap_or_default(),
        })
    }
}

/// A job token may act only on its job's hosts.
pub(super) fn in_scope(caller: &Caller, machine_id: &str) -> Result<(), ToolError> {
    match caller {
        Caller::Job { hosts, .. } if !hosts.iter().any(|h| h == machine_id) => {
            Err(ToolError::new("out_of_scope", format!("`{machine_id}` isn't one of this job's hosts")))
        }
        _ => Ok(()),
    }
}

pub(super) fn requester(caller: &Caller) -> Requester {
    match caller {
        Caller::Job { .. } => Requester::AssistantJob,
        Caller::Key { .. } => Requester::PersonalKey,
    }
}

/// The autonomy level of a job's playbook; personal keys are treated as level 1 (D85).
pub(super) fn level(db: &Db, caller: &Caller) -> u8 {
    let Caller::Job { job_id, .. } = caller else { return 1 };
    let playbook: Option<String> = db
        .readers()
        .with(|c| c.query_row("SELECT name FROM jobs WHERE id = ?1", [job_id], |r| r.get(0)).optional())
        .ok()
        .flatten();
    playbook
        .and_then(|p| Library::current_in(db, Kind::Playbook, &p).ok().flatten())
        .and_then(|(_, text)| Playbook::parse(&text).ok())
        .map_or(0, |p| p.autonomy)
}

/// Approval errors as tool errors.
pub(super) fn approval_error(id: &str, e: &ApprovalError) -> ToolError {
    match e {
        ApprovalError::NotApproved => {
            ToolError::new("needs_approval", "the approval hasn't been decided yet").with(json!({ "approval_id": id }))
        }
        ApprovalError::Rejected => ToolError::new("approval_rejected", "the approval was rejected"),
        ApprovalError::Store(_) => ToolError::new("internal", "the approval couldn't be checked"),
        other => ToolError::new("approval_mismatch", other.to_string()),
    }
}

pub(super) enum Gate {
    /// Run the call.
    Run,
    /// A person must approve first.
    Approval { risk: Risk, step_up: bool },
}

/// `decide()`'s answer as a gate, or the error the caller gets.
pub(super) fn gate(decision: Decision) -> Result<Gate, ToolError> {
    match decision {
        Decision::Allow => Ok(Gate::Run),
        Decision::NeedsApproval { risk, step_up } => Ok(Gate::Approval { risk, step_up }),
        Decision::Deny(Deny::MonitorOnly) => Err(ToolError::new(
            "monitor_only",
            "the machine is at access level monitor: nothing can run on it with an account",
        )),
        Decision::Deny(Deny::TellOnly) => {
            Err(ToolError::new("tool_not_allowed", "at autonomy level 0 a job only tells a person what would run"))
        }
        Decision::Deny(_) => Err(ToolError::new("tool_not_allowed", "this caller can't do that")),
    }
}

/// The approval a gated call asks for: its id goes back as `needs_approval`.
pub(super) async fn request_approval(
    db: &std::sync::Arc<Db>,
    audit: &Audit,
    req: &ApprovalRequest,
    now_ms: i64,
) -> ToolError {
    let ttl = crate::library::config::hub_or_default(db).approvals.expiry_ms();
    match Approvals::new(db.clone()).create(req, now_ms, ttl).await {
        Ok(id) => {
            let data = json!({ "tool": req.tool, "target": req.target, "step_up": req.step_up });
            if let Err(e) = audit.append(&req.requester, "approval.requested", Some(&id), &data.to_string()).await {
                tracing::error!(error = %e, "audit");
            }
            ToolError::new("needs_approval", "a person must approve this call in the dashboard; repeat it with the id")
                .with(json!({ "approval_id": id }))
        }
        Err(e) => {
            tracing::error!(error = %e, "approval");
            ToolError::new("internal", "the approval couldn't be requested")
        }
    }
}

/// Uses the approval for exactly this call (same caller, same hash), once.
pub(super) async fn use_approval(
    db: &std::sync::Arc<Db>,
    audit: &Audit,
    id: &str,
    req: &ApprovalRequest,
    now_ms: i64,
) -> Result<(), ToolError> {
    Approvals::new(db.clone())
        .use_approval(id, &req.requester, &approval_hash(req), now_ms)
        .await
        .map_err(|e| approval_error(id, &e))?;
    let data = json!({ "tool": req.tool, "target": req.target });
    if let Err(e) = audit.append(&req.requester, "approval.used", Some(id), &data.to_string()).await {
        tracing::error!(error = %e, "audit");
    }
    Ok(())
}

pub(super) fn string_map(value: Option<&Value>) -> Result<std::collections::BTreeMap<String, String>, ToolError> {
    let Some(v) = value.filter(|v| !v.is_null()) else { return Ok(Default::default()) };
    let obj = v.as_object().ok_or_else(|| ToolError::invalid("expected an object of strings"))?;
    obj.iter()
        .map(|(k, v)| match v {
            Value::String(s) => Ok((k.clone(), s.clone())),
            Value::Number(n) => Ok((k.clone(), n.to_string())),
            Value::Bool(b) => Ok((k.clone(), b.to_string())),
            _ => Err(ToolError::invalid(format!("`{k}` must be a string"))),
        })
        .collect()
}
