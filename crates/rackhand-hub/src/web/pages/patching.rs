//! Patching (7.7.1): policies and their patch setting (holds included), maintenance windows, and the latest patch jobs.
//! Admins edit policies and windows here; each change is a revision of `config/policies.toml` (D33).

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};

use super::{html, redirect, status};
use crate::policy::store::{self, PolicyError, PolicyRow, WindowRow};
use crate::web::perms::{Permission, allowed};
use crate::web::{Ctx, Web};

struct PatchRun {
    id: String,
    name: String,
    target: String,
    state: String,
}

#[derive(Template)]
#[template(path = "patching.html")]
struct Page<'a> {
    csrf: &'a str,
    policies: Vec<PolicyRow>,
    windows: Vec<WindowRow>,
    runs: Vec<PatchRun>,
    can_edit: bool,
}

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
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
    let (Ok(policies), Ok(windows)) = (store::policies(&web.0.db), store::windows(&web.0.db)) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "Policies unreadable");
    };
    let can_edit = ctx.user.as_ref().is_some_and(|u| allowed(u.role, Permission::EditLibrary));
    html(StatusCode::OK, Page { csrf: &ctx.csrf, policies, windows, runs, can_edit }.render())
}

/// The outcome of a policy or window change; a stored change also goes to the git mirror (7.3.13).
fn answer(web: &Web, ctx: &Ctx, result: Result<String, PolicyError>) -> Response<Body> {
    if let (Ok(_), Some(library), Some(user)) = (&result, &web.0.library, &ctx.user) {
        library.changed(&user.name, "edit config/policies");
    }
    match result {
        Ok(_) => redirect("/patching"),
        Err(PolicyError::Invalid(why)) => status(StatusCode::BAD_REQUEST, &why),
        Err(e) => {
            tracing::error!(error = %e, "policy");
            status(StatusCode::INTERNAL_SERVER_ERROR, "The change couldn't be saved")
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
    let f = |k: &str| ctx.form.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
    let on = |k: &str| ctx.form.get(k).is_some_and(|v| v == "on");
    let p = PolicyRow {
        id: String::new(),
        name: f("name"),
        patch: f("patch"),
        auto_reboot: on("auto_reboot"),
        auto_rollback: on("auto_rollback"),
        snapshot: f("snapshot"),
        quarantine: f("quarantine"),
        peer_requests: f("peer_requests"),
    };
    let result = store::put_policy(&web.0.db, &p, &user.name, ctx.now_ms).await;
    if result.is_ok() {
        audit(web, ctx, "policy.saved", serde_json::to_value(&p).unwrap_or_default()).await;
    }
    answer(web, ctx, result)
}

pub(super) async fn save_window(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let f = |k: &str| ctx.form.get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let (machine, tag) = (f("machine"), f("tag"));
    let (rule, tz) = (f("rrule").unwrap_or_default(), f("timezone").unwrap_or_default());
    let result =
        store::put_window(&web.0.db, machine.as_deref(), tag.as_deref(), &rule, &tz, &user.name, ctx.now_ms).await;
    if result.is_ok() {
        let data = serde_json::json!({ "machine": machine, "tag": tag, "rrule": rule, "timezone": tz });
        audit(web, ctx, "window.saved", data).await;
    }
    answer(web, ctx, result)
}
