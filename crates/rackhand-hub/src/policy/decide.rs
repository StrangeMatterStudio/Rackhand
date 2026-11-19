//! `decide()` (7.6.8, 7.3.6, 7.3.12): whether an action runs, needs an approval (and step-up), or is refused.

use rackhand_runbook::runbook::Risk;

use super::exclusions::quarantine_excluded;
use super::risk::{SENSITIVE_DIAGNOSTICS, exec_risk};

/// Who asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requester {
    /// The hub itself: incident routing, the Scheduler.
    Local,
    /// A person acting in the dashboard.
    Person,
    /// A peer hub.
    Peer,
    /// A person's MCP key from their device (always level 1, D85).
    PersonalKey,
    /// An assistant job through its job token.
    AssistantJob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Managed,
    Monitor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target<'a> {
    pub access: Access,
    pub roles: &'a [&'a str],
    pub tags: &'a [&'a str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<'a> {
    /// A runbook at its playbook's level. `needs_account` when a step runs over SSH or transfers a file;
    /// `assistant_commands` for a runbook with `identity = "assistant"`, judged like an `exec` of each.
    Runbook { risk: Risk, level: u8, needs_account: bool, assistant_commands: &'a [&'a str] },
    /// Assistant `exec`.
    Exec { command: &'a str, level: u8 },
    /// `run_diagnostic` (a read tool).
    Diagnostic { name: &'a str, level: u8 },
    /// Quarantine or release asked for by a person or an assistant.
    Quarantine,
    /// An auto-quarantine rule matched.
    AutoQuarantine { rule_enabled: bool },
    /// Roll back after a failed patch (7.5.3).
    AutoRollback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'a> {
    pub requester: Requester,
    pub action: Action<'a>,
    pub target: Target<'a>,
    /// The target's policy has `peer_requests = "auto"` for this runbook.
    pub peer_auto: bool,
    /// The target's policy has `auto_rollback`.
    pub auto_rollback: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deny {
    /// Level 0: a person is told what would run.
    TellOnly,
    /// The action needs an account on a machine at access level `monitor`.
    MonitorOnly,
    /// The requester can't use this action at all.
    NotAllowed,
    /// The machine is never quarantined.
    Excluded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    NeedsApproval { risk: Risk, step_up: bool },
    Deny(Deny),
}

const HIGH: Decision = Decision::NeedsApproval { risk: Risk::High, step_up: true };

fn approval(risk: Risk) -> Decision {
    if risk == Risk::High { HIGH } else { Decision::NeedsApproval { risk, step_up: false } }
}

/// Levels for autonomous requesters: 0 tells, 1 proposes, 2 and 3 act.
fn by_level(level: u8, risk: Risk) -> Decision {
    match level {
        0 => Decision::Deny(Deny::TellOnly),
        1 => approval(risk),
        _ => {
            if risk == Risk::High {
                HIGH
            } else {
                Decision::Allow
            }
        }
    }
}

fn autonomous(requester: Requester) -> bool {
    matches!(requester, Requester::Local | Requester::AssistantJob)
}

pub fn decide(req: &Request<'_>) -> Decision {
    let t = req.target;
    let monitor = t.access == Access::Monitor;
    match req.action {
        Action::Quarantine | Action::AutoQuarantine { .. } if quarantine_excluded(t.roles, t.tags) => {
            Decision::Deny(Deny::Excluded)
        }
        Action::Quarantine => HIGH,
        Action::AutoQuarantine { rule_enabled } => {
            if rule_enabled && !monitor {
                Decision::Allow
            } else {
                HIGH
            }
        }
        Action::AutoRollback => {
            if req.auto_rollback && !monitor && !t.roles.contains(&"hub") {
                Decision::Allow
            } else {
                HIGH
            }
        }
        Action::Exec { command, level } => {
            if req.requester != Requester::AssistantJob {
                return Decision::Deny(Deny::NotAllowed);
            }
            if monitor {
                return Decision::Deny(Deny::MonitorOnly);
            }
            by_level(level, exec_risk(t.roles, command))
        }
        Action::Diagnostic { name, .. } => {
            if monitor {
                return Decision::Deny(Deny::MonitorOnly);
            }
            let sensitive = SENSITIVE_DIAGNOSTICS.contains(&name);
            match req.requester {
                Requester::PersonalKey if sensitive => approval(Risk::Low),
                Requester::Peer => approval(Risk::Low),
                _ => Decision::Allow,
            }
        }
        Action::Runbook { risk, level, needs_account, assistant_commands } => {
            if monitor && needs_account {
                return Decision::Deny(Deny::MonitorOnly);
            }
            let risk = assistant_commands.iter().map(|c| exec_risk(t.roles, c)).fold(risk, Risk::max);
            if autonomous(req.requester) && level == 0 {
                return Decision::Deny(Deny::TellOnly);
            }
            if risk == Risk::High {
                return HIGH;
            }
            if monitor {
                return approval(risk);
            }
            match req.requester {
                Requester::Local | Requester::AssistantJob => by_level(level, risk),
                Requester::Person => Decision::Allow,
                Requester::Peer if req.peer_auto => Decision::Allow,
                Requester::Peer | Requester::PersonalKey => approval(risk),
            }
        }
    }
}
