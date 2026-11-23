//! Patching (7.7.1): policies and their patch setting (holds included), maintenance windows, and the latest patch jobs.
//! Admins edit policies and windows here; each change is a revision of `config/policies.toml` (D33).

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};

use super::{html, redirect, status};
use crate::policy::store::{self, PolicyError, PolicyRow, WindowRow};
use crate::scheduler::rrule::Recurrence;
use crate::web::forms::{self, Choices, Form, Spec};
use crate::web::perms::{Permission, allowed};
use crate::web::ui::{self, Shell};
use crate::web::{Ctx, Web};

struct PatchRun {
    id: String,
    name: String,
    target: String,
    state: String,
}

/// A machine's updates as its latest report gave them, and what its policy does with them.
struct MachineUpdates {
    id: String,
    name: String,
    policy: String,
    patch: String,
    /// Pending, and the security ones among them.
    counts: Option<(u32, u32)>,
    reboot_required: bool,
}

#[derive(Template)]
#[template(path = "patching.html")]
struct Page<'a> {
    shell: Shell,
    q: String,
    /// The dialog that is open: `policy`, `edit` or `window`.
    open: &'static str,
    csrf: &'a str,
    machines: Vec<MachineUpdates>,
    policies: Vec<PolicyRow>,
    windows: Vec<WindowRow>,
    /// The machines' names, for the windows.
    names: std::collections::HashMap<String, String>,
    runs: Vec<PatchRun>,
    can_edit: bool,
    policy: Form,
    window: Form,
}

const PATCH: Choices =
    &[("approve-only", "Ask for approval first"), ("auto", "Automatically"), ("hold", "Never (hold)")];
const SNAPSHOT: Choices = &[("optional", "Optional"), ("required", "Required")];
const QUARANTINE: Choices = &[("approval", "After approval"), ("never", "Never")];
const PEER_REQUESTS: Choices = &[("approval", "After approval"), ("auto", "Automatically")];

const POLICY: &[Spec] = &[
    Spec::text("name", "Name").hint("1 to 64 characters. Saving a name that exists changes that policy.").length(1, 64),
    Spec::select("patch", "Patch", PATCH).hint(
        "Approval first: each patch waits on the Approvals page. Automatically: security updates install daily at \
         04:00 and the rest on Sundays at 03:00, in the site's timezone. Never: nothing is installed.",
    ),
    Spec::checkbox("auto_reboot", "Reboot when needed"),
    Spec::checkbox("auto_rollback", "Roll back after a failed patch"),
    Spec::select("snapshot", "Snapshot", SNAPSHOT).hint("Whether a patch needs a snapshot taken first."),
    Spec::select("quarantine", "Quarantine", QUARANTINE).hint(
        "Whether the hub may cut a machine off its network, all but its path to the hub, when a threat is found.",
    ),
    Spec::select("peer_requests", "Peer requests", PEER_REQUESTS)
        .hint("What another site's hub needs before a runbook it asks for runs here."),
];

impl Page<'_> {
    fn machine_name(&self, id: &str) -> String {
        self.names.get(id).cloned().unwrap_or_else(|| id.to_string())
    }

    fn said(&self, rule: &str) -> String {
        said(rule)
    }

    fn patch_said(&self, patch: &str) -> &'static str {
        PATCH.iter().find(|(v, _)| *v == patch).map_or("Unknown", |(_, l)| *l)
    }
}

const FOR: Choices = &[("tag", "Every machine with a tag"), ("machine", "One machine")];
const REPEAT: Choices = &[
    ("daily", "Every day"),
    ("mon", "Mondays"),
    ("tue", "Tuesdays"),
    ("wed", "Wednesdays"),
    ("thu", "Thursdays"),
    ("fri", "Fridays"),
    ("sat", "Saturdays"),
    ("sun", "Sundays"),
];
const LASTS: Choices = &[
    ("30", "30 minutes"),
    ("60", "1 hour"),
    ("90", "1 hour 30 minutes"),
    ("120", "2 hours"),
    ("180", "3 hours"),
    ("240", "4 hours"),
    ("360", "6 hours"),
    ("480", "8 hours"),
    ("720", "12 hours"),
];

const WINDOW: &[Spec] = &[
    Spec::select("for", "For", FOR),
    Spec::text("tag", "Tag")
        .hint("As the machines have it.")
        .length(1, 64)
        .when("for=tag")
        .attrs("autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\""),
    Spec::select("machine", "Machine", &[]).when("for=machine"),
    Spec::select("repeat", "Every", REPEAT),
    Spec::text("start", "Starts")
        .input("time")
        .pattern("([01][0-9]|2[0-3]):[0-5][0-9]", "A time of day, such as 03:00")
        .attrs("autocomplete=\"off\""),
    Spec::select("lasts", "Lasts", LASTS),
    forms::TIMEZONE,
];

/// The window as its rule is stored (7.5.3).
fn rule_of(form: &Form) -> String {
    let (repeat, start, lasts) = (form.value("repeat"), form.value("start"), form.value("lasts"));
    match repeat {
        "daily" => format!("daily {start} {lasts}m"),
        day => format!("weekly {day} {start} {lasts}m"),
    }
}

/// A stored rule, as a person says it: `Sundays, 03:00 to 05:00`.
fn said(rule: &str) -> String {
    let parts: Vec<&str> = rule.split(' ').collect();
    let (day, start, lasts) = match parts[..] {
        ["daily", start, lasts] => ("daily", start, lasts),
        ["weekly", day, start, lasts] => (day, start, lasts),
        _ => return rule.to_string(),
    };
    let when = REPEAT.iter().find(|(v, _)| *v == day).map_or(day, |(_, l)| *l);
    let minutes =
        |t: &str| t.split_once(':').and_then(|(h, m)| Some(h.parse::<u32>().ok()? * 60 + m.parse::<u32>().ok()?));
    let (Some(from), Some(long)) = (minutes(start), lasts.trim_end_matches('m').parse::<u32>().ok()) else {
        return rule.to_string();
    };
    let to = from + long;
    let end = format!("{:02}:{:02}", to / 60 % 24, to % 60);
    match to / 1440 {
        0 => format!("{when}, {start} to {end}"),
        1 => format!("{when}, {start} to {end} the next day"),
        n => format!("{when}, {start} to {end}, {n} days later"),
    }
}

/// The machines a window can be for.
fn machine_options(web: &Web) -> forms::Groups {
    let machines = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT id, name FROM machines ORDER BY name, id")?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })
        .unwrap_or_default();
    vec![(String::new(), machines)]
}

fn window_form(web: &Web) -> Form {
    Form::blank("window", WINDOW).options("machine", machine_options(web)).options(forms::ZONE, forms::timezones())
}

fn machine_updates(web: &Web) -> rusqlite::Result<Vec<MachineUpdates>> {
    type Listed = (String, String, Option<String>, Option<String>);
    let rows: Vec<Listed> = web.0.db.readers().with(|c| {
        let mut s = c.prepare(
            "SELECT m.id, m.name, p.name, p.patch FROM machines m LEFT JOIN policies p ON p.id = m.policy_id
             WHERE m.state = 'enrolled' ORDER BY m.name, m.id",
        )?;
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect()
    })?;
    let updates = |id: &str| web.0.ingest.as_ref().and_then(|i| i.latest(id)).and_then(|l| l.updates);
    Ok(rows
        .into_iter()
        .map(|(id, name, policy, patch)| {
            let u = updates(&id);
            MachineUpdates {
                name,
                policy: policy.unwrap_or_else(|| "no policy".into()),
                patch: patch.unwrap_or_else(|| "never".into()),
                counts: u.as_ref().map(|u| (u.pending, u.security)),
                reboot_required: u.is_some_and(|u| u.reboot_required),
                id,
            }
        })
        .collect())
}

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    show(web, ctx, StatusCode::OK, None)
}

/// The page, with the form that was refused as it was sent.
fn show(web: &Web, ctx: &Ctx, code: StatusCode, mut sent: Option<Form>) -> Response<Body> {
    let runs: Vec<PatchRun> = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT id, name, target, state FROM jobs WHERE name LIKE 'patch-%' ORDER BY started_at DESC LIMIT 50",
            )?;
            let rows = s.query_map([], |r| {
                Ok(PatchRun {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    target: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    state: r.get(3)?,
                })
            })?;
            rows.collect()
        })
        .unwrap_or_default();
    let (Ok(policies), Ok(windows), Ok(machines)) =
        (store::policies(&web.0.db), store::windows(&web.0.db), machine_updates(web))
    else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "Policies unreadable");
    };
    let can_edit = ctx.user.as_ref().is_some_and(|u| allowed(u.role, Permission::EditLibrary));
    let mut open = match sent.as_ref().map(|f| f.id()) {
        Some(id) => id,
        None => match ui::asked(ctx, "add") {
            Some("policy") => "policy",
            Some("window") => "window",
            _ => "",
        },
    };
    let editing = ui::asked(ctx, "edit").and_then(|name| policies.iter().find(|p| p.name == name));
    let mut blank = Form::blank("policy", POLICY);
    if let Some(p) = editing.filter(|_| open.is_empty()) {
        open = "edit";
        let on = |b: bool| if b { "on" } else { "" };
        blank = blank
            .with("name", &p.name)
            .with("patch", &p.patch)
            .with("auto_reboot", on(p.auto_reboot))
            .with("auto_rollback", on(p.auto_rollback))
            .with("snapshot", &p.snapshot)
            .with("quarantine", &p.quarantine)
            .with("peer_requests", &p.peer_requests);
    }
    if !can_edit {
        open = "";
    }
    let q = ui::query(ctx);
    let machines = machines.into_iter().filter(|m| ui::found(&q, &[&m.name, &m.policy, &m.patch])).collect();
    let policy = blank.or_sent(&mut sent);
    let window = window_form(web).or_sent(&mut sent);
    let names = machine_options(web).into_iter().flat_map(|(_, m)| m).collect();
    html(
        code,
        Page {
            names,
            shell: Shell::at(web, ctx, "Patching", "/patching"),
            q,
            open,
            csrf: &ctx.csrf,
            machines,
            policies,
            windows,
            runs,
            can_edit,
            policy,
            window,
        }
        .render(),
    )
}

/// The outcome of a policy or window change; a stored change also goes to the git mirror (7.3.13). A refused one shows
/// its form again.
fn answer(web: &Web, ctx: &Ctx, mut form: Form, result: Result<String, PolicyError>) -> Response<Body> {
    if let (Ok(_), Some(library), Some(user)) = (&result, &web.0.library, &ctx.user) {
        library.changed(&user.name, "edit config/policies");
    }
    match result {
        Ok(_) => redirect("/patching"),
        Err(PolicyError::Invalid(why)) => {
            form.notice(why);
            show(web, ctx, StatusCode::BAD_REQUEST, Some(form))
        }
        Err(e) => {
            tracing::error!(error = %e, "policy");
            form.notice("The change couldn't be saved; try again.");
            show(web, ctx, StatusCode::INTERNAL_SERVER_ERROR, Some(form))
        }
    }
}

async fn audit(web: &Web, ctx: &Ctx, action: &str, data: serde_json::Value) {
    if let Some(user) = &ctx.user
        && let Err(e) = web.0.audit.append(&user.name, action, Some("config/policies"), &data.to_string()).await
    {
        tracing::error!(error = %e, "audit");
    }
}

pub(super) async fn save_policy(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let mut form = Form::sent("policy", POLICY, ctx, &web.0.held);
    form.check();
    if !form.ok() {
        return show(web, ctx, StatusCode::BAD_REQUEST, Some(form));
    }
    let f = |k: &str| form.value(k).to_string();
    let p = PolicyRow {
        id: String::new(),
        name: f("name"),
        patch: f("patch"),
        auto_reboot: form.on("auto_reboot"),
        auto_rollback: form.on("auto_rollback"),
        snapshot: f("snapshot"),
        quarantine: f("quarantine"),
        peer_requests: f("peer_requests"),
    };
    let result = store::put_policy(&web.0.db, &p, &user.name, ctx.now_ms).await;
    if result.is_ok() {
        audit(web, ctx, "policy.saved", serde_json::to_value(&p).unwrap_or_default()).await;
    }
    answer(web, ctx, form, result)
}

pub(super) async fn save_window(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let mut form = Form::sent("window", WINDOW, ctx, &web.0.held).options("machine", machine_options(web));
    // a rule given as it is stored is taken as it is
    let typed = ctx.form.get("rrule").map(|r| r.trim().to_string());
    if let Some(rule) = &typed {
        return save_rule(web, ctx, form, rule, &user.name).await;
    }
    form.check();
    let rule = rule_of(&form);
    if form.ok() && rule.parse::<Recurrence>().is_err() {
        form.refuse("start", "That time and length don't make a window");
    }
    if !form.ok() {
        return show(web, ctx, StatusCode::BAD_REQUEST, Some(form));
    }
    let f = |k: &str| Some(form.value(k).to_string()).filter(|v| !v.is_empty());
    let one = form.value("for") == "machine";
    let (machine, tag) = if one { (f("machine"), None) } else { (None, f("tag")) };
    let tz = f(forms::ZONE).unwrap_or_default();
    let result =
        store::put_window(&web.0.db, machine.as_deref(), tag.as_deref(), &rule, &tz, &user.name, ctx.now_ms).await;
    if result.is_ok() {
        let data = serde_json::json!({ "machine": machine, "tag": tag, "rrule": rule, "timezone": tz });
        audit(web, ctx, "window.saved", data).await;
    }
    answer(web, ctx, form, result)
}

/// A window whose rule was sent as text, as it is stored (for what posts to the form without its fields).
async fn save_rule(web: &Web, ctx: &Ctx, mut form: Form, rule: &str, by: &str) -> Response<Body> {
    let f = |k: &str| ctx.form.get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let (machine, tag, tz) = (f("machine"), f("tag"), f(forms::ZONE).unwrap_or_default());
    let result = store::put_window(&web.0.db, machine.as_deref(), tag.as_deref(), rule, &tz, by, ctx.now_ms).await;
    if result.is_ok() {
        let data = serde_json::json!({ "machine": machine, "tag": tag, "rrule": rule, "timezone": tz });
        audit(web, ctx, "window.saved", data).await;
    }
    form.set("for", if machine.is_some() { "machine" } else { "tag" });
    answer(web, ctx, form, result)
}
