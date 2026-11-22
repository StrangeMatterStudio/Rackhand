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
    csrf: &'a str,
    machines: Vec<MachineUpdates>,
    policies: Vec<PolicyRow>,
    windows: Vec<WindowRow>,
    runs: Vec<PatchRun>,
    can_edit: bool,
    policy: Form,
    window: Form,
}

const PATCH: Choices =
    &[("approve-only", "Ask for approval first"), ("auto", "Automatically, in its windows"), ("hold", "Never (hold)")];
const SNAPSHOT: Choices = &[("optional", "Optional"), ("required", "Required")];
const QUARANTINE: Choices = &[("approval", "After approval"), ("never", "Never")];
const PEER_REQUESTS: Choices = &[("approval", "After approval"), ("auto", "Automatically")];

const POLICY: &[Spec] = &[
    Spec::text("name", "Name").hint("1 to 64 characters. Saving a name that exists changes that policy.").length(1, 64),
    Spec::select("patch", "Patch", PATCH),
    Spec::checkbox("auto_reboot", "Reboot when needed"),
    Spec::checkbox("auto_rollback", "Roll back after a failed patch"),
    Spec::select("snapshot", "Snapshot", SNAPSHOT).hint("Whether a patch needs a snapshot taken first."),
    Spec::select("quarantine", "Quarantine", QUARANTINE),
    Spec::select("peer_requests", "Peer requests", PEER_REQUESTS).hint("What a linked hub's requests need."),
];

const RULE: &str =
    "Write `daily HH:MM <minutes>m` or `weekly <mon..sun> HH:MM <minutes>m`, such as `weekly sun 03:00 120m`";

const WINDOW: &[Spec] = &[
    Spec::select("machine", "Machine", &[]).optional().hint("The window is for one machine, or for a tag."),
    Spec::text("tag", "Tag").optional().hint("Every machine with this tag, when no machine is chosen.").length(0, 64),
    Spec::text("rrule", "When")
        .hint("`daily HH:MM <minutes>m` or `weekly <mon..sun> HH:MM <minutes>m`, such as `weekly sun 03:00 120m`.")
        .pattern("(daily|weekly (mon|tue|wed|thu|fri|sat|sun)) [0-2][0-9]:[0-5][0-9] [0-9]{1,5}m", RULE)
        .attrs("autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\""),
    forms::TIMEZONE,
];

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
    vec![(String::new(), vec![(String::new(), "None: use the tag".to_string())]), ("Machines".into(), machines)]
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
    let policy = Form::blank("policy", POLICY).or_sent(&mut sent);
    let window = window_form(web).or_sent(&mut sent);
    html(code, Page { csrf: &ctx.csrf, machines, policies, windows, runs, can_edit, policy, window }.render())
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
    form.check();
    let fits = form.value("rrule").parse::<Recurrence>().is_ok();
    form.require("rrule", fits, RULE);
    match (form.value("machine").is_empty(), form.value("tag").is_empty()) {
        (true, true) => form.refuse("machine", "Choose a machine, or give a tag"),
        (false, false) => form.refuse("machine", "Choose a machine or give a tag, not both"),
        _ => {}
    }
    if !form.ok() {
        return show(web, ctx, StatusCode::BAD_REQUEST, Some(form));
    }
    let f = |k: &str| Some(form.value(k).to_string()).filter(|v| !v.is_empty());
    let (machine, tag) = (f("machine"), f("tag"));
    let (rule, tz) = (f("rrule").unwrap_or_default(), f(forms::ZONE).unwrap_or_default());
    let result =
        store::put_window(&web.0.db, machine.as_deref(), tag.as_deref(), &rule, &tz, &user.name, ctx.now_ms).await;
    if result.is_ok() {
        let data = serde_json::json!({ "machine": machine, "tag": tag, "rrule": rule, "timezone": tz });
        audit(web, ctx, "window.saved", data).await;
    }
    answer(web, ctx, form, result)
}
