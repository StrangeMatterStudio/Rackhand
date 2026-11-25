//! Security (7.7.1, 7.8.2, D77): the event feed, what each machine's baseline has learned, how fresh the threat lists and GeoIP
//! are, and the quarantine rules. Editing a rule is for admins; turning one on, or changing one that is on, needs a fresh
//! step-up (D61).

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use rusqlite::params_from_iter;

use super::{html, redirect, see_other, status};
use crate::policy::quarantine::{self, QuarantineError, Rule, SECURITY_PREFIXES, Severity};
use crate::web::auth::flow::to_step_up;
use crate::web::auth::step_up;
use crate::web::forms::{Choices, Form, Spec};
use crate::web::perms::{Permission, allowed};
use crate::web::ui::{self, Shell};
use crate::web::{Ctx, Web};

const DAY_MS: i64 = 86_400_000;
const FEED: usize = 100;

struct EventView {
    at: String,
    machine_id: Option<String>,
    machine: String,
    severity: String,
    kind: String,
    subject: String,
}

struct BaselineView {
    id: String,
    name: String,
    status: String,
}

struct ListView {
    label: &'static str,
    last_ok: Option<String>,
    entries: usize,
    error: Option<String>,
}

struct RuleView {
    name: String,
    severity: &'static str,
    kinds: String,
    applies_to: String,
    enabled: bool,
    by: String,
}

#[derive(Template)]
#[template(path = "security.html")]
struct Page<'a> {
    shell: Shell,
    csrf: &'a str,
    /// The dialog that is open: `rule` or `edit`.
    open: &'static str,
    events: Vec<EventView>,
    baselines: Vec<BaselineView>,
    lists: Vec<ListView>,
    /// No list has been downloaded yet (or there is nothing to download them).
    none_downloaded: bool,
    rules: Vec<RuleView>,
    can_edit: bool,
    rule: Form,
}

const SEVERITY: Choices = &[("critical", "Critical"), ("warning", "Warning")];

const RULE: &[Spec] = &[
    Spec::text("name", "Name").hint("1 to 64 characters. Saving a name that exists changes that rule.").length(1, 64),
    Spec::select("severity", "At least", SEVERITY),
    Spec::text("kinds", "Event kinds")
        .hint("Separated by commas, such as conn.known_bad.")
        .length(1, 200)
        .attrs("autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\""),
    Spec::text("tags", "Machine tags")
        .hint("Separated by commas. With no tags and no roles, every machine.")
        .optional()
        .length(0, 200)
        .attrs("autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\""),
    Spec::text("roles", "Machine roles").hint("Separated by commas.").optional().length(0, 200),
    Spec::checkbox("enabled", "On: quarantine matching machines at once, without an approval")
        .hint("Hypervisors, the hub, operators and relays are never quarantined. Turning a rule on needs a step-up."),
];

fn severity_word(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::Warning => "warning",
        Severity::Info => "info",
    }
}

fn comma(text: &str) -> Vec<String> {
    text.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect()
}

/// A rule's id: its name as a slug.
fn slug(name: &str) -> String {
    let mapped: String =
        name.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).collect();
    mapped.split('-').filter(|p| !p.is_empty()).collect::<Vec<_>>().join("-")
}

fn feed(web: &Web) -> Vec<EventView> {
    let like: Vec<String> = SECURITY_PREFIXES.iter().map(|p| format!("{p}%")).collect();
    let marks = vec!["e.kind LIKE ?"; like.len()].join(" OR ");
    let sql = format!(
        "SELECT e.at_ms, e.machine_id, coalesce(m.name, ''), e.severity, e.kind, coalesce(e.subject, '')
         FROM events e LEFT JOIN machines m ON m.id = e.machine_id WHERE {marks} ORDER BY e.at_ms DESC, e.rowid DESC LIMIT {FEED}"
    );
    web.0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare(&sql)?;
            s.query_map(params_from_iter(like.iter()), |r| {
                Ok(EventView {
                    at: ui::time(r.get(0)?),
                    machine_id: r.get(1)?,
                    machine: r.get(2)?,
                    severity: r.get(3)?,
                    kind: r.get(4)?,
                    subject: r.get(5)?,
                })
            })?
            .collect()
        })
        .unwrap_or_default()
}

/// What each enrolled machine's connection baseline has learned: the learning (a week by default, 7.8.1) raises nothing
/// (7.6.5).
fn baselines(web: &Web, now_ms: i64) -> Vec<BaselineView> {
    type Row = (String, String, String, Option<i64>);
    let learning_ms = crate::library::config::hub_or_default(&web.0.db).baseline.learning_ms();
    let rows: Vec<Row> = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT m.id, m.name,
                        coalesce(p.connections, CASE WHEN m.roles LIKE '%\"desktop\"%' THEN 'summary' ELSE 'full' END),
                        (SELECT min(b.first_seen_ms) FROM conn_baseline b WHERE b.machine_id = m.id)
                 FROM machines m LEFT JOIN policies p ON p.id = m.policy_id
                 WHERE m.state = 'enrolled' AND m.kind != 'appliance' ORDER BY m.name, m.id",
            )?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect()
        })
        .unwrap_or_default();
    rows.into_iter()
        .map(|(id, name, mode, first)| {
            let status = match (mode.as_str(), first) {
                ("full", Some(first)) if now_ms - first < learning_ms => {
                    let left = (learning_ms - (now_ms - first) + DAY_MS - 1) / DAY_MS;
                    format!("Learning, {left} day{} left", if left == 1 { "" } else { "s" })
                }
                ("full", Some(_)) => "Learned".to_string(),
                ("full", None) => "Nothing seen yet".to_string(),
                (other, _) => format!("Not learned: connections are {other}"),
            };
            BaselineView { id, name, status }
        })
        .collect()
}

fn lists(web: &Web, now_ms: i64) -> Vec<ListView> {
    let Some(intel) = &web.0.intel else { return Vec::new() };
    crate::intel::sources(now_ms)
        .into_iter()
        .map(|source| {
            let fresh = intel.freshness_of(source.id);
            ListView {
                label: source.label,
                last_ok: fresh.last_ok_ms.map(ui::time),
                entries: fresh.entries,
                error: fresh.error,
            }
        })
        .collect()
}

fn rule_views(rules: &[Rule]) -> Vec<RuleView> {
    rules
        .iter()
        .map(|r| {
            let applies: Vec<String> = r
                .match_tags
                .iter()
                .map(|t| format!("tag {t}"))
                .chain(r.match_roles.iter().map(|t| format!("role {t}")))
                .collect();
            RuleView {
                name: r.name.clone(),
                severity: severity_word(r.severity_at_least),
                kinds: r.event_kinds.join(", "),
                applies_to: if applies.is_empty() { "every machine".into() } else { applies.join(", ") },
                enabled: r.enabled,
                by: r.enabled_by.clone().unwrap_or_default(),
            }
        })
        .collect()
}

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    show(web, ctx, StatusCode::OK, None)
}

fn show(web: &Web, ctx: &Ctx, code: StatusCode, mut sent: Option<Form>) -> Response<Body> {
    let Ok(rules) = quarantine::rules(&web.0.db) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The quarantine rules couldn't be read");
    };
    let can_edit = ctx.user.as_ref().is_some_and(|u| allowed(u.role, Permission::EditLibrary));
    let mut open = if sent.is_some() || ui::asked(ctx, "add") == Some("rule") { "rule" } else { "" };
    let mut blank = Form::blank("rule", RULE);
    if let Some(r) =
        ui::asked(ctx, "edit").and_then(|name| rules.iter().find(|r| r.name == name)).filter(|_| open.is_empty())
    {
        open = "edit";
        blank = blank
            .with("name", &r.name)
            .with("severity", severity_word(r.severity_at_least))
            .with("kinds", &r.event_kinds.join(", "))
            .with("tags", &r.match_tags.join(", "))
            .with("roles", &r.match_roles.join(", "))
            .with("enabled", if r.enabled { "on" } else { "" });
    }
    if !can_edit {
        open = "";
    }
    let rule = blank.or_sent(&mut sent);
    let lists = lists(web, ctx.now_ms);
    let page = Page {
        shell: Shell::at(web, ctx, "Security", "/security"),
        csrf: &ctx.csrf,
        open,
        events: feed(web),
        baselines: baselines(web, ctx.now_ms),
        none_downloaded: lists.iter().all(|l| l.last_ok.is_none()),
        lists,
        rules: rule_views(&rules),
        can_edit,
        rule,
    };
    html(code, page.render())
}

pub(super) async fn save_rule(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let mut form = Form::sent("rule", RULE, ctx, &web.0.held);
    form.check();
    let id = slug(form.value("name"));
    if form.ok() && id.is_empty() {
        form.refuse("name", "A name needs letters or digits");
    }
    if !form.ok() {
        return show(web, ctx, StatusCode::BAD_REQUEST, Some(form));
    }
    let rule = Rule {
        id,
        name: form.value("name").trim().to_string(),
        severity_at_least: if form.value("severity") == "warning" { Severity::Warning } else { Severity::Critical },
        event_kinds: comma(form.value("kinds")),
        match_tags: comma(form.value("tags")),
        match_roles: comma(form.value("roles")),
        enabled: form.on("enabled"),
        enabled_by: None,
        enabled_at: None,
    };
    let fresh = step_up::fresh(&web.0.db, user.step_up_at, ctx.now_ms);
    match quarantine::put_rule(&web.0.db, &rule, &user.name, fresh, ctx.now_ms).await {
        Ok(()) => {
            let data = serde_json::json!({
                "name": rule.name, "enabled": rule.enabled, "severity": severity_word(rule.severity_at_least),
                "kinds": rule.event_kinds, "tags": rule.match_tags, "roles": rule.match_roles,
            });
            if let Err(e) = web
                .0
                .audit
                .append(&user.name, "quarantine.rule_saved", Some("quarantine_rules"), &data.to_string())
                .await
            {
                tracing::error!(error = %e, "audit");
            }
            see_other("/security")
        }
        Err(QuarantineError::StepUpRequired) => to_step_up("/security"),
        Err(QuarantineError::Invalid(why)) => {
            form.notice(why);
            show(web, ctx, StatusCode::BAD_REQUEST, Some(form))
        }
        Err(e) => {
            tracing::error!(error = %e, "quarantine rule");
            form.notice("The rule couldn't be saved; try again.");
            show(web, ctx, StatusCode::INTERNAL_SERVER_ERROR, Some(form))
        }
    }
}
