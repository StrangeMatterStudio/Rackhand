//! The assistant's pages (7.7.1, 7.7.2, 10): an incident's assistant jobs with their transcripts and Resume job; a person's own
//! MCP keys (scope capped by their role, at most a year); and the operators with the invite that adds one, the daily cap, and
//! the notice of what the AI provider receives.

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};

use super::{html, redirect, see_other, status};
use crate::library::config;
use crate::mcp::keys::{self, Scope};
use crate::web::perms::{Permission, Role, allowed};
use crate::web::ui::{self, Shell};
use crate::web::{Ctx, Web};

/// What an assistant job sends out (10): the notice the operator setup page carries.
pub const PROVIDER_NOTICE: &str = "An assistant job sends the brief and every tool result, including output from your machines, to the AI provider configured on the operator host. The daily cap below limits how many jobs, and so how much data and cost, there can be in a day.";

const DAY_MS: i64 = 86_400_000;
/// A personal key lasts at most a year (7.3.6).
const MAX_DAYS: i64 = 365;
const DEFAULT_DAYS: i64 = 90;

// ---- an incident's assistant jobs ---------------------------------------------------------------------------------------

pub(super) struct JobView {
    pub id: String,
    pub playbook: String,
    pub state: String,
    pub outcome: String,
    pub started: String,
    /// `(kind, text)`; the text is machine output, escaped when drawn.
    pub transcript: Vec<(String, String)>,
    pub resumable: bool,
}

/// The assistant jobs of an incident, newest first.
pub(super) fn jobs_of(web: &Web, incident: &str, now_ms: i64) -> Vec<JobView> {
    type Row = (String, String, String, Option<String>, Option<i64>);
    let rows: Vec<Row> = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT id, name, state, outcome, started_at FROM jobs WHERE kind = 'assistant' AND incident_id = ?1
                 ORDER BY started_at DESC, id DESC",
            )?;
            s.query_map([incident], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?.collect()
        })
        .unwrap_or_default();
    let _ = now_ms;
    rows.into_iter()
        .map(|(id, playbook, state, outcome, started)| {
            let transcript = web
                .0
                .db
                .readers()
                .with(|c| {
                    let mut s =
                        c.prepare("SELECT kind, text FROM assistant_transcripts WHERE job_id = ?1 ORDER BY seq")?;
                    s.query_map([&id], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
                })
                .unwrap_or_default();
            let resumable = web.0.assist.as_ref().is_some_and(|a| a.resumable(&id));
            JobView {
                id,
                playbook,
                state,
                outcome: outcome.unwrap_or_default(),
                started: started.map(ui::time).unwrap_or_default(),
                transcript,
                resumable,
            }
        })
        .collect()
}

/// `POST /incidents/{id}/resume`: a new job for the incident, with the approved call first (E21).
pub(super) async fn resume(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let Some(incident) = ctx.path.strip_prefix("/incidents/").and_then(|p| p.strip_suffix("/resume")) else {
        return status(StatusCode::NOT_FOUND, "No such incident");
    };
    let Some(assist) = web.0.assist.as_ref() else { return status(StatusCode::NOT_FOUND, "No assistant here") };
    let Some(job) = ctx.form.get("job").filter(|j| !j.is_empty()) else {
        return status(StatusCode::BAD_REQUEST, "Name the job to resume");
    };
    let mine: Option<i64> = web
        .0
        .db
        .readers()
        .with(|c| {
            use rusqlite::OptionalExtension;
            c.query_row(
                "SELECT 1 FROM jobs WHERE id = ?1 AND kind = 'assistant' AND incident_id = ?2",
                [job.as_str(), incident],
                |r| r.get(0),
            )
            .optional()
        })
        .ok()
        .flatten();
    if mine.is_none() {
        return status(StatusCode::NOT_FOUND, "No such job on this incident");
    }
    match assist.resume(job).await {
        Ok(_) => {
            let data = serde_json::json!({ "job": job, "incident": incident }).to_string();
            if let Err(e) = web.0.audit.append(&user.name, "assist.resume", Some(job), &data).await {
                tracing::error!(error = %e, "audit");
            }
            see_other(&format!("/incidents/{incident}"))
        }
        Err(why) => status(StatusCode::CONFLICT, &why),
    }
}

// ---- personal MCP keys --------------------------------------------------------------------------------------------------

struct KeyView {
    id: String,
    device: String,
    scope: &'static str,
    expires: String,
    state: &'static str,
}

#[derive(Template)]
#[template(path = "keys.html")]
struct KeysPage {
    shell: Shell,
    csrf: String,
    keys: Vec<KeyView>,
    devices: Vec<(String, String)>,
    can_request: bool,
    notice: Option<String>,
    /// The token of the key just made, shown this once.
    new_token: Option<String>,
    max_days: i64,
    default_days: i64,
}

fn keys_of(web: &Web, user_id: &str, now_ms: i64) -> Vec<KeyView> {
    type Row = (String, String, String, i64, Option<i64>);
    let rows: Vec<Row> = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT k.id, d.name, k.scope, k.expires_at, k.revoked_at FROM mcp_keys k JOIN devices d ON d.id = k.device_id
                 WHERE k.user_id = ?1 ORDER BY k.rowid DESC",
            )?;
            s.query_map([user_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?.collect()
        })
        .unwrap_or_default();
    rows.into_iter()
        .map(|(id, device, scope, expires, revoked)| KeyView {
            id,
            device,
            scope: if scope == "read_request" { "read and request" } else { "read" },
            expires: ui::time(expires),
            state: if revoked.is_some() {
                "Revoked"
            } else if expires <= now_ms {
                "Expired"
            } else {
                "Active"
            },
        })
        .collect()
}

fn show_keys(
    web: &Web,
    ctx: &Ctx,
    code: StatusCode,
    notice: Option<&str>,
    new_token: Option<String>,
) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let devices = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s =
                c.prepare("SELECT id, name FROM devices WHERE user_id = ?1 AND revoked_at IS NULL ORDER BY name")?;
            s.query_map([&user.user_id], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })
        .unwrap_or_default();
    let page = KeysPage {
        shell: Shell::at(web, ctx, "MCP keys", "/account/keys"),
        csrf: ctx.csrf.clone(),
        keys: keys_of(web, &user.user_id, ctx.now_ms),
        devices,
        can_request: user.role != Role::Viewer,
        notice: notice.map(str::to_string),
        new_token,
        max_days: MAX_DAYS,
        default_days: DEFAULT_DAYS,
    };
    html(code, page.render())
}

pub(super) fn keys_page(web: &Web, ctx: &Ctx) -> Response<Body> {
    show_keys(web, ctx, StatusCode::OK, None, None)
}

pub(super) async fn create_key(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let refuse = |why: &str| show_keys(web, ctx, StatusCode::BAD_REQUEST, Some(why), None);
    let scope = match ctx.form.get("scope").map(String::as_str) {
        Some("read") => Scope::Read,
        // a key never grants more than its user's role does in the dashboard (7.7.2)
        Some("read_request") if user.role != Role::Viewer => Scope::ReadRequest,
        Some("read_request") => return refuse("A viewer's keys can read only."),
        _ => return refuse("Choose what the key may do."),
    };
    let days: i64 = match ctx.form.get("days").and_then(|d| d.trim().parse().ok()) {
        Some(d) if (1..=MAX_DAYS).contains(&d) => d,
        _ => return refuse(&format!("A key lasts from 1 day to {MAX_DAYS} days.")),
    };
    let Some(device) = ctx.form.get("device").filter(|d| !d.is_empty()) else {
        return refuse("Choose the device the key is for. Add one first if you have none.");
    };
    match keys::create_personal_key(&web.0.db, &user.user_id, device, scope, ctx.now_ms + days * DAY_MS).await {
        Ok((id, token)) => {
            let data = serde_json::json!({ "scope": scope.as_str(), "days": days, "device": device }).to_string();
            if let Err(e) = web.0.audit.append(&user.name, "mcp_key.created", Some(&id), &data).await {
                tracing::error!(error = %e, "audit");
            }
            show_keys(web, ctx, StatusCode::OK, None, Some(token))
        }
        Err(e) => refuse(&e.to_string()),
    }
}

pub(super) async fn revoke_key(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let Some(id) = ctx.path.strip_prefix("/account/keys/").and_then(|p| p.strip_suffix("/revoke")) else {
        return status(StatusCode::NOT_FOUND, "No such key");
    };
    // only the user's own
    let own: Option<i64> = web
        .0
        .db
        .readers()
        .with(|c| {
            use rusqlite::OptionalExtension;
            c.query_row("SELECT 1 FROM mcp_keys WHERE id = ?1 AND user_id = ?2", [id, user.user_id.as_str()], |r| {
                r.get(0)
            })
            .optional()
        })
        .ok()
        .flatten();
    if own.is_none() {
        return status(StatusCode::NOT_FOUND, "No such key");
    }
    if keys::revoke_personal_key(&web.0.db, id, ctx.now_ms).await.is_ok() {
        if let Err(e) = web.0.audit.append(&user.name, "mcp_key.revoked", Some(id), "{}").await {
            tracing::error!(error = %e, "audit");
        }
    }
    see_other("/account/keys")
}

// ---- operators, the invite and the cap ----------------------------------------------------------------------------------

struct OperatorView {
    name: String,
    runners: String,
    last_seen: String,
    connected: bool,
    state: &'static str,
}

#[derive(Template)]
#[template(path = "assistant_settings.html")]
struct SettingsPage {
    shell: Shell,
    csrf: String,
    operators: Vec<OperatorView>,
    daily_cap: u32,
    notice_text: &'static str,
    can_invite: bool,
    /// What the invite just made says to run, shown this once.
    command: Option<String>,
    problem: Option<String>,
}

fn operators(web: &Web) -> Vec<OperatorView> {
    let connected = web.0.assist.as_ref().map(|a| a.connected_operators()).unwrap_or_default();
    type Row = (String, String, String, Option<i64>, Option<i64>);
    let rows: Vec<Row> = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT id, name, runners, last_seen_ms, revoked_at FROM operators ORDER BY \"order\", name",
            )?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?.collect()
        })
        .unwrap_or_default();
    rows.into_iter()
        .map(|(id, name, runners, seen, revoked)| {
            let list: Vec<serde_json::Value> = serde_json::from_str(&runners).unwrap_or_default();
            let runners = list
                .iter()
                .map(|r| {
                    format!("{} {}", r["name"].as_str().unwrap_or(""), r["version"].as_str().unwrap_or(""))
                        .trim()
                        .to_string()
                })
                .collect::<Vec<_>>()
                .join(", ");
            OperatorView {
                connected: connected.contains(&id),
                name,
                runners,
                last_seen: seen.map(ui::time).unwrap_or_default(),
                state: if revoked.is_some() { "Revoked" } else { "Joined" },
            }
        })
        .collect()
}

fn show_settings(
    web: &Web,
    ctx: &Ctx,
    code: StatusCode,
    command: Option<String>,
    problem: Option<&str>,
) -> Response<Body> {
    let cap = config::hub(&web.0.db).map(|c| c.assistant.daily_cap).unwrap_or(crate::assist::DEFAULT_DAILY_CAP);
    let page = SettingsPage {
        shell: Shell::at(web, ctx, "Assistant", "/settings/assistant"),
        csrf: ctx.csrf.clone(),
        operators: operators(web),
        daily_cap: cap,
        notice_text: PROVIDER_NOTICE,
        can_invite: ctx.user.as_ref().is_some_and(|u| allowed(u.role, Permission::Administer)),
        command,
        problem: problem.map(str::to_string),
    };
    html(code, page.render())
}

pub(super) fn settings_page(web: &Web, ctx: &Ctx) -> Response<Body> {
    show_settings(web, ctx, StatusCode::OK, None, None)
}

/// A 24-hour invite and the command that uses it, on the operator host.
pub(super) async fn invite(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let (Some(registry), Some(ticket)) = (web.0.registry.as_ref(), web.ticket()) else {
        return show_settings(
            web,
            ctx,
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            Some("The hub isn't ready for this; try again in a minute."),
        );
    };
    match registry.invite_operator(&user.name, ctx.now_ms).await {
        Ok(token) => {
            if let Err(e) = web.0.audit.append(&user.name, "operator.invited", None, "{}").await {
                tracing::error!(error = %e, "audit");
            }
            let command = format!(
                "rackhand operator join --ticket {ticket} --invite {} --name <a name for this host>",
                token.as_str()
            );
            show_settings(web, ctx, StatusCode::OK, Some(command), None)
        }
        Err(e) => {
            tracing::error!(error = %e, "operator invite");
            show_settings(
                web,
                ctx,
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
                Some("The invite couldn't be made; try again."),
            )
        }
    }
}

/// How many assistant jobs a day the hub starts.
pub(super) async fn set_cap(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let cap: u32 = match ctx.form.get("daily_cap").and_then(|c| c.trim().parse().ok()) {
        Some(c) if (1..=1000).contains(&c) => c,
        _ => {
            return show_settings(
                web,
                ctx,
                StatusCode::BAD_REQUEST,
                None,
                Some("The daily cap is a number from 1 to 1000."),
            );
        }
    };
    let Ok(mut current) = config::hub(&web.0.db) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "Settings unreadable");
    };
    current.assistant.daily_cap = cap;
    if let Err(e) = config::put(&web.0.db, config::HUB, &current.to_toml(), &user.name, ctx.now_ms).await {
        tracing::error!(error = %e, "settings");
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The settings couldn't be saved");
    }
    let data = serde_json::json!({ "daily_cap": cap }).to_string();
    if let Err(e) = web.0.audit.append(&user.name, "settings.assistant", Some("config/hub"), &data).await {
        tracing::error!(error = %e, "audit");
    }
    if let Some(library) = &web.0.library {
        library.changed(&user.name, "edit config/hub");
    }
    see_other("/settings/assistant")
}
