//! Quarantine from a finding (7.5.6, 7.8.2, D18, D57, D61, D80, AC17, AC18, AC58). Before an incident looks for a runbook of
//! its own, a security finding is judged for quarantine:
//!
//! - a machine that is never quarantined (hub, operator, relay, hypervisor, `no-quarantine`), a remote-mode machine and an
//!   appliance stay with a person, told why;
//! - a machine whose policy says `never` stays with a person;
//! - an enabled automatic rule that matches starts `quarantine` at once, with no approval (a monitor machine asks for one
//!   instead: no automatic policy applies to it);
//! - any other critical finding proposes `quarantine` for an approval with step-up, and the machine is `pending` until it
//!   is decided or expires.

use rackhand_detect::rules::Severity as FindingSeverity;

use super::*;
use crate::policy::quarantine::{self, Auto, Severity as RuleSeverity, State as QState, Target as QTarget};

const RUNBOOK: &str = "quarantine";

fn security_kind(kind: &str) -> bool {
    quarantine::SECURITY_PREFIXES.iter().any(|p| kind.starts_with(p))
}

impl Routing {
    /// Whether the finding was dealt with here (so ordinary routing doesn't look at it).
    pub(super) async fn quarantine_route(
        &self,
        inc: &IncidentRow,
        machine_id: &str,
        machine: &Machine,
        now_ms: i64,
    ) -> Result<bool, IncidentsError> {
        if !security_kind(&inc.kind) {
            return Ok(false);
        }
        let (mode, current, policy): (String, String, String) = self.db().readers().with(|c| {
            c.query_row(
                "SELECT m.mode, m.quarantine, coalesce(p.quarantine, 'approval') FROM machines m
                 LEFT JOIN policies p ON p.id = m.policy_id WHERE m.id = ?1",
                [machine_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
        })?;
        // one that is quarantined, or waiting for a decision, has what it needs: the incident
        if QState::parse(&current).unwrap_or(QState::None) != QState::None {
            return Ok(false);
        }
        let rules = quarantine::rules(self.db()).map_err(|e| IncidentsError::Ingest(e.to_string()))?;
        let severity = match inc.severity {
            FindingSeverity::Critical => RuleSeverity::Critical,
            FindingSeverity::Warning => RuleSeverity::Warning,
            FindingSeverity::Info => RuleSeverity::Info,
        };
        // only a finding that would have led to a quarantine is answered here
        let ruled = rules.iter().any(|r| r.enabled && r.event_kinds.contains(&inc.kind));
        if severity != RuleSeverity::Critical && !ruled {
            return Ok(false);
        }
        let roles: Vec<&str> = machine.facts.roles.iter().map(String::as_str).collect();
        let tags: Vec<&str> = machine.facts.tags.iter().map(String::as_str).collect();
        let target = QTarget {
            roles: &roles,
            tags: &tags,
            monitor: machine.access == Access::Monitor,
            remote: mode == "remote",
            appliance: machine.facts.kind == "appliance",
        };
        let decision = quarantine::auto_decision(&rules, &inc.kind, severity, &target);
        match &decision {
            Auto::Excluded => {
                let why = "quarantine isn't applied to this machine: hypervisors, the hub, operators and relays, and machines \
                           tagged `no-quarantine`, are never quarantined; the incident is all there is";
                self.to_person(&inc.id, why, now_ms).await?;
                return Ok(true);
            }
            Auto::Unsupported(why) => {
                self.to_person(&inc.id, &format!("this machine can't be quarantined here: {why}"), now_ms).await?;
                return Ok(true);
            }
            _ => {}
        }
        if policy == "never" {
            self.to_person(
                &inc.id,
                "the machine's policy says it is never quarantined; the incident is all there is",
                now_ms,
            )
            .await?;
            return Ok(true);
        }
        match decision {
            Auto::Quarantine { rule } => {
                let request = Request {
                    requester: Requester::Local,
                    action: Action::AutoQuarantine { rule_enabled: true },
                    target: Target { access: machine.access, roles: &roles, tags: &tags },
                    peer_auto: false,
                    auto_rollback: false,
                };
                if decide(&request) != Decision::Allow {
                    return self.propose_quarantine(inc, machine_id, now_ms).await.map(|()| true);
                }
                let mut job = StartJob::runbook(RUNBOOK, machine_id, &format!("rule:{rule}"));
                job.incident_id = Some(inc.id.clone());
                self.start(inc.clone(), job, now_ms).await?;
                Ok(true)
            }
            Auto::NeedsApproval { .. } => self.propose_quarantine(inc, machine_id, now_ms).await.map(|()| true),
            Auto::NoMatch if severity == RuleSeverity::Critical => {
                self.propose_quarantine(inc, machine_id, now_ms).await.map(|()| true)
            }
            _ => Ok(false),
        }
    }

    /// Asks for an approval with step-up to quarantine the machine, which is `pending` until it is decided.
    async fn propose_quarantine(&self, inc: &IncidentRow, machine_id: &str, now_ms: i64) -> Result<(), IncidentsError> {
        let rev = Library::current_in(self.db(), Kind::Runbook, RUNBOOK).ok().flatten().map(|(rev, _)| rev);
        let approval = ApprovalRequest {
            requester: requester(&inc.id),
            tool: "run_runbook".into(),
            target: Some(machine_id.to_string()),
            args: serde_json::json!({ "name": RUNBOOK, "params": {} }),
            runbook_rev: rev,
            risk: rackhand_runbook::runbook::Risk::High,
            step_up: true,
            reason: format!("finding: {}", inc.title),
        };
        let id = match Approvals::new(self.incidents.inner.db.clone()).create(&approval, now_ms, APPROVAL_TTL_MS).await
        {
            Ok(id) => id,
            Err(e) => {
                let why = format!("quarantine couldn't ask for an approval: {e}");
                return self.to_person(&inc.id, &why, now_ms).await;
            }
        };
        quarantine::set_state(self.db(), machine_id, QState::Pending)
            .await
            .map_err(|e| IncidentsError::Ingest(e.to_string()))?;
        let mut inc = inc.clone();
        inc.state = State::Automation;
        self.mark(&inc, "runbook.approval", serde_json::json!({ "runbook": RUNBOOK, "approval": id }), now_ms).await?;
        self.note(&inc.id, "quarantine waits for an approval with step-up", now_ms).await;
        Ok(())
    }

    /// A proposal that was rejected or ran out: the machine is no longer waiting.
    pub(super) async fn clear_pending(&self, machine_id: &str) {
        let _ = quarantine::clear_pending(self.db(), machine_id).await;
    }

    /// Machines `pending` with no approval left to decide: its proposal expired.
    pub(super) async fn expire_pending(&self, now_ms: i64) -> Result<(), IncidentsError> {
        let stale: Vec<String> = self.db().readers().with(|c| {
            let mut s = c.prepare(
                "SELECT m.id FROM machines m WHERE m.quarantine = 'pending' AND NOT EXISTS (
                   SELECT 1 FROM approvals a WHERE a.target = m.id AND a.tool = 'run_runbook'
                     AND json_extract(a.args, '$.name') = 'quarantine' AND a.state IN ('pending', 'approved')
                     AND a.expires_at > ?1)",
            )?;
            s.query_map([now_ms], |r| r.get(0))?.collect()
        })?;
        for machine in stale {
            self.clear_pending(&machine).await;
        }
        Ok(())
    }
}
