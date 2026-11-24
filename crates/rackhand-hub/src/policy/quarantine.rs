//! Quarantine (7.5.6, D18, D57, D61, D77, D80): the state machine, the automatic rules, and what quarantine is never applied to.
//! A finding that matches an enabled rule goes straight to `applying`; otherwise it needs an approval. Release always needs an
//! approval with step-up (D61). Enabling or changing a rule is high risk and needs a fresh step-up. The exclusions are checked
//! before any rule (E22).

use std::sync::Arc;

use rackhand_store::{Db, Row, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;

use super::exclusions::quarantine_excluded;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    None,
    Pending,
    Applying,
    Active,
    Releasing,
    Failed,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::None => "none",
            State::Pending => "pending",
            State::Applying => "applying",
            State::Active => "active",
            State::Releasing => "releasing",
            State::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<State> {
        Some(match s {
            "none" => State::None,
            "pending" => State::Pending,
            "applying" => State::Applying,
            "active" => State::Active,
            "releasing" => State::Releasing,
            "failed" => State::Failed,
            _ => return None,
        })
    }

    /// Whether the machine counts as quarantined: patching and runbooks other than diagnostics and release are blocked, and
    /// so is assistant `exec` (7.5.6). From the moment isolation starts, until it is released.
    pub fn blocks_actions(self) -> bool {
        matches!(self, State::Applying | State::Active | State::Releasing | State::Failed)
    }
}

/// What moves a machine along 7.5.6's arrows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// A finding, and the policy needs an approval.
    FindingNeedsApproval,
    /// A finding that matches an enabled automatic rule.
    FindingAutoRule,
    /// Approved with step-up.
    Approved,
    Rejected,
    Expired,
    /// Isolation and the snapshot are done.
    Done,
    StepFailed,
    /// A failed quarantine retried with an approval.
    RetryApproved,
    /// A failed quarantine dismissed by an admin.
    Dismissed,
    ReleaseApproved,
    /// The rules are removed and the machine is reachable.
    Released,
    ReleaseFailed,
}

/// The state a trigger leads to from a state, or `None` for an arrow that isn't there.
pub fn next(state: State, trigger: Trigger) -> Option<State> {
    use State::*;
    use Trigger::*;
    Some(match (state, trigger) {
        (None, FindingNeedsApproval) => Pending,
        (None, FindingAutoRule) => Applying,
        (Pending, Approved) => Applying,
        (Pending, Rejected | Expired) => None,
        (Applying, Done) => Active,
        (Applying, StepFailed) => Failed,
        (Failed, RetryApproved) => Applying,
        (Failed, Dismissed) => None,
        (Active, ReleaseApproved) => Releasing,
        (Releasing, Released) => None,
        (Releasing, ReleaseFailed) => Active,
        _ => return Option::None,
    })
}

/// How serious a finding is, for a rule's threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Severity {
        match s {
            "critical" => Severity::Critical,
            "warning" => Severity::Warning,
            _ => Severity::Info,
        }
    }
}

/// An automatic rule (7.8.2). `match_tags` and `match_roles` name the machines it applies to: it applies to a machine that has
/// any of them, and to every machine when both are empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub severity_at_least: Severity,
    pub event_kinds: Vec<String>,
    pub match_tags: Vec<String>,
    pub match_roles: Vec<String>,
    pub enabled: bool,
    pub enabled_by: Option<String>,
    pub enabled_at: Option<i64>,
}

/// What the rule needs to know of a machine.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    pub roles: &'a [&'a str],
    pub tags: &'a [&'a str],
    pub monitor: bool,
    /// A remote-mode probe: cutting its network would cut its path to the hub too.
    pub remote: bool,
    pub appliance: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auto {
    /// An enabled rule matched: quarantine without an approval.
    Quarantine {
        rule: String,
    },
    /// A machine that is never quarantined; the incident only.
    Excluded,
    NoMatch,
    /// A rule matched a monitor machine: nothing automatic applies to it; an approval is needed instead (D89).
    NeedsApproval {
        rule: String,
    },
    /// Not supported in v0.1 (D80): the incident says so and stays with a person.
    Unsupported(&'static str),
}

fn matches_machine(rule: &Rule, t: &Target<'_>) -> bool {
    let any = rule.match_tags.is_empty() && rule.match_roles.is_empty();
    any || rule.match_tags.iter().any(|x| t.tags.contains(&x.as_str()))
        || rule.match_roles.iter().any(|x| t.roles.contains(&x.as_str()))
}

/// What a finding of `kind` at `severity` on a machine does under `rules`. The exclusions come first, then what v0.1 can't do,
/// and only then the rules.
pub fn auto_decision(rules: &[Rule], kind: &str, severity: Severity, t: &Target<'_>) -> Auto {
    if quarantine_excluded(t.roles, t.tags) {
        return Auto::Excluded;
    }
    if t.appliance {
        return Auto::Unsupported("an appliance can't be quarantined in this version");
    }
    if t.remote {
        return Auto::Unsupported(
            "a remote-mode machine can't be quarantined: cutting its network cuts its path to the hub",
        );
    }
    let matching = rules.iter().find(|r| {
        r.enabled && severity >= r.severity_at_least && r.event_kinds.iter().any(|k| k == kind) && matches_machine(r, t)
    });
    match matching {
        None => Auto::NoMatch,
        Some(rule) if t.monitor => Auto::NeedsApproval { rule: rule.id.clone() },
        Some(rule) => Auto::Quarantine { rule: rule.id.clone() },
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QuarantineError {
    #[error("enabling or changing a quarantine rule needs a fresh step-up")]
    StepUpRequired,
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Store(#[from] rackhand_store::StoreError),
    #[error(transparent)]
    Read(#[from] rusqlite::Error),
}

fn list(v: &str) -> Vec<String> {
    serde_json::from_str(v).unwrap_or_default()
}

/// The stored rules.
pub fn rules(db: &Db) -> Result<Vec<Rule>, QuarantineError> {
    Ok(db.readers().with(|c| {
        let mut s = c.prepare(
            "SELECT id, name, severity_at_least, event_kinds, match, enabled, enabled_by, enabled_at FROM quarantine_rules ORDER BY name",
        )?;
        s.query_map([], |r| {
            let m: String = r.get(4)?;
            let m: serde_json::Value = serde_json::from_str(&m).unwrap_or_default();
            let names = |k: &str| -> Vec<String> {
                m[k].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect()
            };
            Ok(Rule {
                id: r.get(0)?,
                name: r.get(1)?,
                severity_at_least: Severity::parse(&r.get::<_, String>(2)?),
                event_kinds: list(&r.get::<_, String>(3)?),
                match_tags: names("tags"),
                match_roles: names("roles"),
                enabled: r.get::<_, i64>(5)? != 0,
                enabled_by: r.get(6)?,
                enabled_at: r.get(7)?,
            })
        })?
        .collect()
    })?)
}

/// Saves a rule. Enabling one, or changing one that is enabled, needs a fresh step-up (D61); turning one off, or saving one
/// that stays off, doesn't.
pub async fn put_rule(
    db: &Arc<Db>,
    rule: &Rule,
    by: &str,
    step_up_fresh: bool,
    now_ms: i64,
) -> Result<(), QuarantineError> {
    if rule.name.trim().is_empty() || rule.event_kinds.is_empty() {
        return Err(QuarantineError::Invalid("a rule has a name and the kinds of event it acts on".into()));
    }
    let before = rules(db)?.into_iter().find(|r| r.id == rule.id);
    let touched = rule.enabled
        && before.as_ref().is_none_or(|b| {
            !b.enabled || b != &Rule { enabled_by: b.enabled_by.clone(), enabled_at: b.enabled_at, ..rule.clone() }
        });
    if touched && !step_up_fresh {
        return Err(QuarantineError::StepUpRequired);
    }
    let kept = before.filter(|b| b.enabled && rule.enabled && !touched);
    let (enabled_by, enabled_at) = if rule.enabled {
        match kept {
            Some(b) => (b.enabled_by, b.enabled_at),
            None => (Some(by.to_string()), Some(now_ms)),
        }
    } else {
        (None, None)
    };
    let m = serde_json::json!({ "tags": rule.match_tags, "roles": rule.match_roles });
    let sev = match rule.severity_at_least {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "critical",
    };
    let row: Row = [
        ("id", Value::Text(rule.id.clone())),
        ("name", Value::Text(rule.name.clone())),
        ("severity_at_least", Value::Text(sev.into())),
        ("event_kinds", Value::Text(serde_json::to_string(&rule.event_kinds).unwrap_or_default())),
        ("match", Value::Text(m.to_string())),
        ("enabled", Value::Integer(i64::from(rule.enabled))),
        ("enabled_by", enabled_by.map_or(Value::Null, Value::Text)),
        ("enabled_at", enabled_at.map_or(Value::Null, Value::Integer)),
    ]
    .into_iter()
    .collect();
    db.writer().send(WriteCmd::PutQuarantineRule(row)).await?;
    Ok(())
}

/// What the probe and the hub raise as security findings (7.6.6): the event kinds a quarantine is judged for and the Security
/// page lists.
pub const SECURITY_PREFIXES: [&str; 7] = ["conn.", "proc.", "port.", "file.", "auth.", "user.", "group."];

/// Who stops a quarantined machine's traffic, which the dashboard says (D77).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// The hypervisor's firewall, outside the machine.
    Hypervisor,
    /// A table in the machine, which an attacker with root there can undo.
    InGuest,
}

/// What a quarantine recorded when it isolated the machine, if it hasn't been released: the output of the `isolate` step of
/// the oldest `quarantine` job since the last release that got that far (a retry after a failure goes back to the original).
pub fn record(db: &Db, machine: &str) -> Option<serde_json::Value> {
    let rows: Vec<(String, String, Option<Vec<u8>>)> = db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT j.name, j.state, s.stdout FROM jobs j
                 LEFT JOIN job_steps s ON s.job_id = j.id AND s.step_id = 'isolate' AND s.state = 'succeeded'
                 WHERE j.target = ?1 AND j.name IN ('quarantine', 'quarantine-release')
                 ORDER BY j.started_at DESC, j.id DESC",
            )?;
            s.query_map([machine], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
        })
        .ok()?;
    let mut found = None;
    for (name, state, stdout) in rows {
        if name == "quarantine-release" {
            if state == "succeeded" {
                break;
            }
            continue;
        }
        if let Some(out) = stdout {
            let text = String::from_utf8_lossy(&out);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(text.lines().next().unwrap_or("")) {
                found = Some(v);
            }
        }
    }
    found
}

/// Which kind a record is.
pub fn enforcement(record: &serde_json::Value) -> Enforcement {
    if record["method"] == "proxmox" { Enforcement::Hypervisor } else { Enforcement::InGuest }
}

/// Writes a machine's quarantine state.
pub async fn set_state(db: &Db, machine: &str, to: State) -> Result<(), QuarantineError> {
    let set = Row::from([("quarantine", Value::Text(to.as_str().into()))]);
    let update = rackhand_store::RowUpdate { table: "machines", key: ("id", Value::Text(machine.into())), set };
    let change = rackhand_store::RegistryChange { updates: vec![update], ..Default::default() };
    db.writer().send(WriteCmd::RegistryChange(change)).await?;
    Ok(())
}

/// A proposal that was rejected or ran out: a machine that was `pending` is `none` again; any other state stays.
pub async fn clear_pending(db: &Db, machine: &str) -> Result<(), QuarantineError> {
    let current: Option<String> = db
        .readers()
        .with(|c| c.query_row("SELECT quarantine FROM machines WHERE id = ?1", [machine], |r| r.get(0)).optional())?;
    if current.as_deref() == Some("pending") {
        set_state(db, machine, State::None).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [State; 6] =
        [State::None, State::Pending, State::Applying, State::Active, State::Releasing, State::Failed];
    const TRIGGERS: [Trigger; 11] = [
        Trigger::FindingNeedsApproval,
        Trigger::FindingAutoRule,
        Trigger::Approved,
        Trigger::Rejected,
        Trigger::Expired,
        Trigger::Done,
        Trigger::StepFailed,
        Trigger::RetryApproved,
        Trigger::Dismissed,
        Trigger::ReleaseApproved,
        Trigger::Released,
    ];

    #[test]
    fn state_machine_transitions() {
        use State::*;
        use Trigger::*;
        // every arrow of 7.5.6, and nothing else
        let arrows = [
            (None, FindingNeedsApproval, Pending),
            (None, FindingAutoRule, Applying),
            (Pending, Approved, Applying),
            (Pending, Rejected, None),
            (Pending, Expired, None),
            (Applying, Done, Active),
            (Applying, StepFailed, Failed),
            (Failed, RetryApproved, Applying),
            (Failed, Dismissed, None),
            (Active, ReleaseApproved, Releasing),
            (Releasing, Released, None),
            (Releasing, ReleaseFailed, Active),
        ];
        let mut found = 0;
        for state in ALL {
            for trigger in TRIGGERS.iter().copied().chain([ReleaseFailed]) {
                let expected = arrows.iter().find(|(s, t, _)| *s == state && *t == trigger).map(|(_, _, to)| *to);
                assert_eq!(next(state, trigger), expected, "{state:?} on {trigger:?}");
                found += usize::from(expected.is_some());
            }
        }
        assert_eq!(found, arrows.len());
        assert!(
            Applying.blocks_actions()
                && Active.blocks_actions()
                && Failed.blocks_actions()
                && Releasing.blocks_actions()
        );
        assert!(!None.blocks_actions() && !Pending.blocks_actions());
        for s in ALL {
            assert_eq!(State::parse(s.as_str()), Some(s));
        }
    }

    fn rule(enabled: bool) -> Rule {
        Rule {
            id: "r1".into(),
            name: "dmz".into(),
            severity_at_least: Severity::Critical,
            event_kinds: vec!["conn.known_bad".into()],
            match_tags: vec!["dmz".into()],
            match_roles: vec![],
            enabled,
            enabled_by: None,
            enabled_at: None,
        }
    }

    fn target<'a>(roles: &'a [&'a str], tags: &'a [&'a str]) -> Target<'a> {
        Target { roles, tags, monitor: false, remote: false, appliance: false }
    }

    #[test]
    fn auto_rule_matches_tag_quarantines_without_approval() {
        let rules = [rule(true)];
        let dmz = target(&[], &["dmz", "web"]);
        assert_eq!(
            auto_decision(&rules, "conn.known_bad", Severity::Critical, &dmz),
            Auto::Quarantine { rule: "r1".into() }
        );
        assert_eq!(next(State::None, Trigger::FindingAutoRule), Some(State::Applying), "straight to applying");
        // another kind, a lower severity, a machine without the tag, a rule that is off: nothing
        assert_eq!(auto_decision(&rules, "port.new_listener", Severity::Critical, &dmz), Auto::NoMatch);
        assert_eq!(auto_decision(&rules, "conn.known_bad", Severity::Warning, &dmz), Auto::NoMatch);
        assert_eq!(auto_decision(&rules, "conn.known_bad", Severity::Critical, &target(&[], &["lab"])), Auto::NoMatch);
        assert_eq!(auto_decision(&[rule(false)], "conn.known_bad", Severity::Critical, &dmz), Auto::NoMatch);
    }

    #[test]
    fn hypervisor_with_same_finding_not_quarantined() {
        let rules = [Rule { match_tags: vec![], ..rule(true) }];
        for roles in [&["hypervisor"][..], &["hub"], &["operator"], &["relay"]] {
            assert_eq!(
                auto_decision(&rules, "conn.known_bad", Severity::Critical, &target(roles, &["dmz"])),
                Auto::Excluded,
                "{roles:?}"
            );
        }
        assert_eq!(
            auto_decision(&rules, "conn.known_bad", Severity::Critical, &target(&[], &["no-quarantine"])),
            Auto::Excluded
        );
        assert_eq!(
            auto_decision(&rules, "conn.known_bad", Severity::Critical, &target(&[], &[])),
            Auto::Quarantine { rule: "r1".into() }
        );
    }

    #[test]
    fn remote_mode_and_appliance_unsupported_stay_with_person() {
        let rules = [rule(true)];
        let remote = Target { remote: true, ..target(&[], &["dmz"]) };
        let appliance = Target { appliance: true, ..target(&[], &["dmz"]) };
        assert!(
            matches!(auto_decision(&rules, "conn.known_bad", Severity::Critical, &remote), Auto::Unsupported(why) if why.contains("remote"))
        );
        assert!(
            matches!(auto_decision(&rules, "conn.known_bad", Severity::Critical, &appliance), Auto::Unsupported(why) if why.contains("appliance"))
        );
    }

    #[test]
    fn auto_rule_matching_monitor_machine_does_nothing() {
        let monitor = Target { monitor: true, ..target(&[], &["dmz"]) };
        assert_eq!(
            auto_decision(&[rule(true)], "conn.known_bad", Severity::Critical, &monitor),
            Auto::NeedsApproval { rule: "r1".into() },
            "no automatic policy applies to a monitor machine; an approval is needed"
        );
    }

    fn db(name: &str) -> Arc<Db> {
        let dir = std::env::temp_dir().join(format!("rackhand-quarantine-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(Db::open(&dir.join("hub.db")).unwrap())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn enabling_rule_requires_step_up() {
        let db = db("rules");
        // saved off, no step-up needed
        put_rule(&db, &rule(false), "admin", false, 1).await.unwrap();
        // enabled: refused without a fresh step-up, and nothing changes
        let refused = put_rule(&db, &rule(true), "admin", false, 2).await;
        assert!(matches!(refused, Err(QuarantineError::StepUpRequired)), "{refused:?}");
        assert!(!rules(&db).unwrap()[0].enabled);
        put_rule(&db, &rule(true), "admin", true, 3).await.unwrap();
        let r = &rules(&db).unwrap()[0];
        assert_eq!((r.enabled, r.enabled_by.as_deref(), r.enabled_at), (true, Some("admin"), Some(3)));
        // saving it again unchanged needs nothing and keeps who enabled it
        put_rule(&db, &rule(true), "other", false, 4).await.unwrap();
        assert_eq!(rules(&db).unwrap()[0].enabled_by.as_deref(), Some("admin"));
        // changing an enabled rule needs one; turning it off doesn't
        let wider = Rule { severity_at_least: Severity::Warning, ..rule(true) };
        assert!(matches!(put_rule(&db, &wider, "admin", false, 5).await, Err(QuarantineError::StepUpRequired)));
        put_rule(&db, &rule(false), "admin", false, 6).await.unwrap();
        assert!(!rules(&db).unwrap()[0].enabled);
        assert!(matches!(
            put_rule(&db, &Rule { event_kinds: vec![], ..rule(false) }, "a", true, 7).await,
            Err(QuarantineError::Invalid(_))
        ));
    }

    #[test]
    fn release_always_needs_approval_with_step_up() {
        use crate::policy::decide::{Access, Action, Decision, Request, Requester, Target, decide};
        use rackhand_runbook::runbook::Risk;
        let t = Target { access: Access::Managed, roles: &[], tags: &[] };
        for requester in
            [Requester::Local, Requester::Person, Requester::AssistantJob, Requester::PersonalKey, Requester::Peer]
        {
            let r = Request { requester, action: Action::Quarantine, target: t, peer_auto: true, auto_rollback: true };
            assert_eq!(decide(&r), Decision::NeedsApproval { risk: Risk::High, step_up: true }, "{requester:?}");
        }
        // the machine leaves quarantine only through an approved release
        assert_eq!(next(State::Active, Trigger::ReleaseApproved), Some(State::Releasing));
        assert_eq!(next(State::Active, Trigger::Released), None, "never straight from active to none");
    }
}
