//! The tools that act (7.3.6): `run_diagnostic`, `exec`, `run_runbook`, `propose_library_change`,
//! `add_incident_note` and `finish_job`. Machine output comes back untrusted.

use std::time::Duration;

use rackhand_runbook::runbook::{Identity, Runbook};
use serde_json::{Value, json};

use super::auth::Caller;
use super::gate::{self, Gate, Target};
use super::tools_read::resolve_machine;
use super::{Mcp, ToolError};
use crate::actions::diagnostics::{OUTPUT_LIMIT, untrusted};
use crate::actions::{ActionsError, JobKind, StartJob};
use crate::bus::JobOutcome;
use crate::library::items::{Kind, Library, SaveError};
use crate::policy::approvals::ApprovalRequest;
use crate::policy::decide::{Action, Request, Target as PolicyTarget, decide};

/// How long an `exec` may run.
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(10 * 60);

fn arg<'a>(args: &'a Value, name: &str) -> Result<&'a str, ToolError> {
    args.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ToolError::invalid(format!("`{name}` is required")))
}

fn actions_error(e: ActionsError) -> ToolError {
    match e {
        ActionsError::MachineBusy => ToolError::new("machine_busy", "another job holds the machine; try again later"),
        ActionsError::MonitorOnly => ToolError::new("monitor_only", "the machine is at access level monitor"),
        ActionsError::Approval(e) => gate::approval_error("", &e),
        ActionsError::InvalidParam(..)
        | ActionsError::UnknownDiagnostic
        | ActionsError::UnknownRunbook
        | ActionsError::InvalidRunbook(_)
        | ActionsError::Unsupported(_)
        | ActionsError::UnknownMachine => ToolError::invalid(e.to_string()),
        ActionsError::UnknownJob => ToolError::new("deadline_exceeded", "the job has ended"),
        ActionsError::Store(_) => ToolError::new("internal", "the hub couldn't record that"),
    }
}

fn capped(mut bytes: Vec<u8>) -> Value {
    bytes.truncate(OUTPUT_LIMIT);
    untrusted(&bytes)
}

fn policy_target<'a>(t: &Target, roles: &'a [&'a str], tags: &'a [&'a str]) -> PolicyTarget<'a> {
    PolicyTarget { access: t.access, roles, tags }
}

impl Mcp {
    fn actions(&self) -> Result<&crate::actions::Actions, ToolError> {
        self.inner.actions.as_ref().ok_or_else(|| ToolError::new("internal", "actions aren't available"))
    }

    fn library(&self) -> Result<&Library, ToolError> {
        self.inner.library.as_ref().ok_or_else(|| ToolError::new("internal", "the library isn't available"))
    }

    /// Runs the call if `decide()` allows it; otherwise uses its approval or asks for one.
    async fn gated(
        &self,
        decision: crate::policy::decide::Decision,
        req: ApprovalRequest,
        approval_id: Option<&str>,
        now: i64,
    ) -> Result<(), ToolError> {
        match gate::gate(decision)? {
            Gate::Run => Ok(()),
            Gate::Approval { risk, step_up } => {
                let req = ApprovalRequest { risk, step_up, ..req };
                match approval_id {
                    Some(id) => gate::use_approval(&self.inner.db, &self.inner.audit, id, &req, now).await,
                    None => Err(gate::request_approval(&self.inner.db, &self.inner.audit, &req, now).await),
                }
            }
        }
    }

    pub(super) async fn act(&self, caller: &Caller, tool: &str, args: &Value, now: i64) -> Result<Value, ToolError> {
        match tool {
            "run_diagnostic" => self.diagnostic(caller, args, now).await,
            "exec" => self.exec(caller, args, now).await,
            "run_runbook" => self.runbook(caller, args, now).await,
            "propose_library_change" => {
                let kind = match arg(args, "kind")? {
                    "runbook" => Kind::Runbook,
                    "playbook" => Kind::Playbook,
                    _ => return Err(ToolError::invalid("`kind` is runbook or playbook")),
                };
                let (name, content) = (arg(args, "name")?, arg(args, "content")?);
                let reason = args.get("reason").and_then(Value::as_str).unwrap_or("");
                match self.library()?.propose(kind, name, content, &caller.actor(), reason, now).await {
                    Ok(id) => Ok(json!({ "draft_id": id })),
                    Err(SaveError::Invalid(why)) => Err(ToolError::invalid(why)),
                    Err(e) => Err(ToolError::invalid(e.to_string())),
                }
            }
            "add_incident_note" => {
                let (incident, text) = (arg(args, "incident")?, arg(args, "text")?);
                match crate::incidents::notes::add_note(&self.inner.db, incident, text, &caller.actor(), now).await {
                    Ok(id) => Ok(json!({ "note_id": id })),
                    Err(e) => Err(ToolError::invalid(e.to_string())),
                }
            }
            "finish_job" => {
                let Caller::Job { job_id, .. } = caller else {
                    return Err(ToolError::new("tool_not_allowed", "jobs only"));
                };
                let outcome = arg(args, "outcome")?;
                if !matches!(outcome, "resolved" | "unresolved" | "handed_over") {
                    return Err(ToolError::invalid("`outcome` is resolved, unresolved or handed_over"));
                }
                let summary = args.get("summary").and_then(Value::as_str).unwrap_or("");
                self.actions()?.finish_assistant(job_id, outcome, summary).await.map_err(actions_error)?;
                Ok(json!({ "ok": true }))
            }
            _ => Err(ToolError::new("tool_not_allowed", format!("no tool `{tool}`"))),
        }
    }

    async fn diagnostic(&self, caller: &Caller, args: &Value, now: i64) -> Result<Value, ToolError> {
        let machine = resolve_machine(&self.inner.db, arg(args, "machine")?)?;
        gate::in_scope(caller, &machine)?;
        let name = arg(args, "name")?;
        let diag_args = gate::string_map(args.get("args"))?;
        let target = Target::load(&self.inner.db, &machine)?;
        let (roles, tags): (Vec<&str>, Vec<&str>) =
            (target.roles.iter().map(String::as_str).collect(), target.tags.iter().map(String::as_str).collect());
        let level = gate::level(&self.inner.db, caller);
        let decision = decide(&Request {
            requester: gate::requester(caller),
            action: Action::Diagnostic { name, level },
            target: policy_target(&target, &roles, &tags),
            peer_auto: false,
            auto_rollback: false,
        });
        let req = ApprovalRequest {
            requester: caller.actor(),
            tool: "run_diagnostic".into(),
            target: Some(machine.clone()),
            args: json!({ "name": name, "args": diag_args }),
            runbook_rev: None,
            risk: rackhand_runbook::runbook::Risk::Low,
            step_up: false,
            reason: args.get("reason").and_then(Value::as_str).unwrap_or("").into(),
        };
        self.gated(decision, req, args.get("approval_id").and_then(Value::as_str), now).await?;
        let job = match caller {
            Caller::Job { job_id, .. } => Some(job_id.as_str()),
            Caller::Key { .. } => None,
        };
        let out = self
            .actions()?
            .run_diagnostic(job, &caller.actor(), &machine, name, &diag_args)
            .await
            .map_err(actions_error)?;
        Ok(
            json!({ "machine": machine, "name": name, "exit_code": out.exit_code, "sensitive": out.sensitive, "output": untrusted(&out.output) }),
        )
    }

    async fn exec(&self, caller: &Caller, args: &Value, now: i64) -> Result<Value, ToolError> {
        let Caller::Job { job_id, .. } = caller else { return Err(ToolError::new("tool_not_allowed", "jobs only")) };
        let machine = resolve_machine(&self.inner.db, arg(args, "machine")?)?;
        gate::in_scope(caller, &machine)?;
        let command = arg(args, "command")?;
        let target = Target::load(&self.inner.db, &machine)?;
        if target.quarantined {
            return Err(ToolError::new(
                "machine_quarantined",
                "no exec on a quarantined machine; diagnostics still work",
            ));
        }
        let (roles, tags): (Vec<&str>, Vec<&str>) =
            (target.roles.iter().map(String::as_str).collect(), target.tags.iter().map(String::as_str).collect());
        let level = gate::level(&self.inner.db, caller);
        let decision = decide(&Request {
            requester: gate::requester(caller),
            action: Action::Exec { command, level },
            target: policy_target(&target, &roles, &tags),
            peer_auto: false,
            auto_rollback: false,
        });
        let req = ApprovalRequest {
            requester: caller.actor(),
            tool: "exec".into(),
            target: Some(machine.clone()),
            args: json!({ "command": command }),
            runbook_rev: None,
            risk: rackhand_runbook::runbook::Risk::Normal,
            step_up: false,
            reason: arg(args, "reason")?.into(),
        };
        self.gated(decision, req, args.get("approval_id").and_then(Value::as_str), now).await?;
        let r = self.actions()?.exec(job_id, &machine, command, EXEC_TIMEOUT).await.map_err(actions_error)?;
        if r.exit_code.is_none() {
            let why = match &r.outcome {
                crate::actions::runner::StepOutcome::Failed(why) => why.clone(),
                crate::actions::runner::StepOutcome::Succeeded => String::new(),
            };
            return Err(ToolError::new(
                "machine_unreachable",
                format!("the command didn't run to an exit status: {why}"),
            ));
        }
        Ok(
            json!({ "machine": machine, "exit_code": r.exit_code, "stdout": capped(r.stdout), "stderr": capped(r.stderr) }),
        )
    }

    async fn runbook(&self, caller: &Caller, args: &Value, now: i64) -> Result<Value, ToolError> {
        let name = arg(args, "name")?;
        let machine = resolve_machine(&self.inner.db, arg(args, "target")?)?;
        gate::in_scope(caller, &machine)?;
        let params = gate::string_map(args.get("params"))?;
        let Some((rev, source)) =
            Library::current_in(&self.inner.db, Kind::Runbook, name).map_err(|e| ToolError::invalid(e.to_string()))?
        else {
            return Err(ToolError::invalid(format!("no runbook `{name}`")));
        };
        let runbook = Runbook::parse(&source).map_err(|e| ToolError::invalid(e.to_string()))?;
        let target = Target::load(&self.inner.db, &machine)?;
        if target.quarantined && name != "quarantine-release" {
            return Err(ToolError::new(
                "machine_quarantined",
                "only diagnostics and the release run on a quarantined machine",
            ));
        }
        let commands: Vec<String> = if runbook.identity == Identity::Assistant {
            runbook.steps.iter().filter_map(|s| s.cmd.as_ref().map(|c| c.join(" "))).collect()
        } else {
            Vec::new()
        };
        let commands: Vec<&str> = commands.iter().map(String::as_str).collect();
        let (roles, tags): (Vec<&str>, Vec<&str>) =
            (target.roles.iter().map(String::as_str).collect(), target.tags.iter().map(String::as_str).collect());
        // Quarantine and its release are judged as such (always high risk, with exclusions), whatever the runbook
        // declares; any other runbook at the lower of the job's level and its own (new runbooks start at 1, 7.6.8).
        let action = if matches!(name, "quarantine" | "quarantine-release") {
            Action::Quarantine
        } else {
            Action::Runbook {
                risk: runbook.risk,
                level: gate::level(&self.inner.db, caller).min(runbook.autonomy),
                needs_account: runbook.steps.iter().any(|s| s.needs_account()),
                assistant_commands: &commands,
            }
        };
        let decision = decide(&Request {
            requester: gate::requester(caller),
            action,
            target: policy_target(&target, &roles, &tags),
            peer_auto: false,
            auto_rollback: false,
        });
        let approval_id = args.get("approval_id").and_then(Value::as_str);
        let run_with = match gate::gate(decision)? {
            Gate::Run => None,
            Gate::Approval { risk, step_up } => match approval_id {
                // Actions uses the approval when the job starts: the same caller, tool, target, arguments and revision.
                Some(id) => Some(id.to_string()),
                None => {
                    let req = ApprovalRequest {
                        requester: caller.actor(),
                        tool: "run_runbook".into(),
                        target: Some(machine.clone()),
                        args: json!({ "name": name, "params": params }),
                        runbook_rev: Some(rev),
                        risk,
                        step_up,
                        reason: args.get("reason").and_then(Value::as_str).unwrap_or("").into(),
                    };
                    return Err(gate::request_approval(&self.inner.db, &self.inner.audit, &req, now).await);
                }
            },
        };
        let incident = match caller {
            Caller::Job { job_id, .. } => self
                .inner
                .db
                .readers()
                .with(|c| {
                    c.query_row("SELECT incident_id FROM jobs WHERE id = ?1", [job_id], |r| {
                        r.get::<_, Option<String>>(0)
                    })
                })
                .ok()
                .flatten(),
            Caller::Key { .. } => None,
        };
        let start = StartJob {
            kind: JobKind::Runbook,
            name: name.into(),
            rev: None,
            machine_id: machine.clone(),
            params,
            requested_by: caller.actor(),
            incident_id: incident,
            approval_id: run_with.clone(),
        };
        let result = match self.actions()?.run(start).await {
            Ok(r) => r,
            Err(ActionsError::Approval(e)) => return Err(gate::approval_error(run_with.as_deref().unwrap_or(""), &e)),
            Err(e) => return Err(actions_error(e)),
        };
        if result.reason.as_deref() == Some("machine_busy") {
            return Err(ToolError::new("machine_busy", "another job holds the machine; try again later"));
        }
        let status = match result.outcome {
            JobOutcome::Succeeded => "succeeded",
            JobOutcome::Failed => "failed",
            JobOutcome::Cancelled => "cancelled",
            JobOutcome::TimedOut => "timed_out",
            JobOutcome::Interrupted => "interrupted",
        };
        Ok(json!({ "job_id": result.job_id, "status": status, "reason": result.reason }))
    }
}
