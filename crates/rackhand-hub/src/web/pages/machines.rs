//! Machine actions from the dashboard. Accepting a changed host key and confirming a guest binding are high risk
//! (7.6.8, 7.3.12): admin, after a step-up.

use axum::body::Body;
use axum::http::{Response, StatusCode};

use super::monitoring::show_machine;
use super::{redirect, see_other, status};
use crate::web::auth::flow::to_step_up;
use crate::web::auth::step_up;
use crate::web::{Ctx, Web};

fn machine_id(path: &str) -> Option<&str> {
    let id = path.strip_prefix("/machines/")?.split('/').next()?;
    (!id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')).then_some(id)
}

/// The machine's page, for a path under it.
fn here(path: &str) -> String {
    machine_id(path).map_or("/".into(), |id| format!("/machines/{id}"))
}

pub(super) async fn accept_host_key(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    if !step_up::fresh(&web.0.db, user.step_up_at, ctx.now_ms) {
        return to_step_up(&here(&ctx.path));
    }
    let Some(id) = machine_id(&ctx.path) else { return status(StatusCode::NOT_FOUND, "No such machine") };
    let Some(keys) = web.0.host_keys.as_ref() else { return status(StatusCode::NOT_FOUND, "No such machine") };
    // Bound to the key the admin was shown: if the machine offers another one meanwhile, nothing is accepted.
    let Some(fingerprint) = ctx.form.get("fingerprint").map(|f| f.trim().to_string()).filter(|f| !f.is_empty()) else {
        return show_machine(web, ctx, id, StatusCode::BAD_REQUEST, Some("Name the fingerprint you are accepting."));
    };
    let Some((key_type, _)) = keys.offered(id) else {
        return show_machine(web, ctx, id, StatusCode::NOT_FOUND, Some("This machine hasn't offered a new host key."));
    };
    match keys.accept_offered(id, &fingerprint, &user.name, ctx.now_ms).await {
        Ok(true) => {}
        Ok(false) => {
            return show_machine(
                web,
                ctx,
                id,
                StatusCode::CONFLICT,
                Some("The machine now offers a different key; check it again."),
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "host key");
            return show_machine(web, ctx, id, StatusCode::INTERNAL_SERVER_ERROR, Some("The key couldn't be stored."));
        }
    }
    let data = serde_json::json!({ "key_type": key_type, "fingerprint": fingerprint }).to_string();
    if let Err(e) = web.0.audit.append(&user.name, "ssh.host_key_accepted", Some(id), &data).await {
        tracing::error!(error = %e, "audit");
    }
    see_other(&here(&ctx.path))
}

/// Confirms the guest the form names as the machine's (its proposal or binding, or the guest it now looks like).
pub(super) async fn confirm_binding(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    if !step_up::fresh(&web.0.db, user.step_up_at, ctx.now_ms) {
        return to_step_up(&here(&ctx.path));
    }
    let Some(id) = machine_id(&ctx.path) else { return status(StatusCode::NOT_FOUND, "No such machine") };
    let Some(bindings) = web.0.bindings.as_ref() else { return status(StatusCode::NOT_FOUND, "No such machine") };
    let Some(guest) = ctx.form.get("guest").map(|g| g.trim().to_string()).filter(|g| !g.is_empty()) else {
        return show_machine(web, ctx, id, StatusCode::BAD_REQUEST, Some("Name the guest you are confirming."));
    };
    match bindings.confirm(id, &guest, &user.name, ctx.now_ms).await {
        Ok(true) => {}
        Ok(false) => {
            return show_machine(
                web,
                ctx,
                id,
                StatusCode::CONFLICT,
                Some("That guest isn't this machine's binding or what it looks like now."),
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "binding");
            return show_machine(
                web,
                ctx,
                id,
                StatusCode::INTERNAL_SERVER_ERROR,
                Some("The binding couldn't be stored."),
            );
        }
    }
    if let Err(e) = web.0.audit.append(&user.name, "machine.binding_confirmed", Some(id), &guest).await {
        tracing::error!(error = %e, "audit");
    }
    see_other(&here(&ctx.path))
}

/// The one-time command that changes a machine's access level (7.3.12, D89). The dashboard changes nothing itself: the
/// command is run as root on the machine, which is what adds or removes the hub's way in.
pub(super) async fn level(web: &Web, ctx: &Ctx) -> Response<Body> {
    use rusqlite::OptionalExtension;
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let Some(id) = machine_id(&ctx.path) else { return status(StatusCode::NOT_FOUND, "No such machine") };
    let (Some(registry), Some(ticket)) = (web.0.registry.as_ref(), web.ticket()) else {
        return show_machine(
            web,
            ctx,
            id,
            StatusCode::SERVICE_UNAVAILABLE,
            Some("The hub isn't ready for this; try again in a minute."),
        );
    };
    let found: Option<(String, String, String, String, String)> = web
        .0
        .db
        .readers()
        .with(|c| {
            c.query_row("SELECT name, kind, access, mode, state FROM machines WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .optional()
        })
        .ok()
        .flatten();
    let Some((name, kind, access, mode, state)) = found else {
        return status(StatusCode::NOT_FOUND, "No such machine");
    };
    let refuse = |code, why: &str| show_machine(web, ctx, id, code, Some(why));
    if state != "enrolled" || kind == "appliance" {
        return refuse(StatusCode::CONFLICT, "Only an enrolled machine with a probe changes its access level.");
    }
    let to = match ctx.form.get("access").map(String::as_str) {
        Some("managed") => rackhand_proto::common::Access::Managed,
        Some("monitor") => rackhand_proto::common::Access::Monitor,
        _ => return refuse(StatusCode::BAD_REQUEST, "Choose managed or monitor."),
    };
    let monitor = to == rackhand_proto::common::Access::Monitor;
    let wanted = if monitor { "monitor" } else { "managed" };
    if access == wanted {
        return refuse(StatusCode::BAD_REQUEST, &format!("{name} is already {wanted}."));
    }
    let Ok(ulid) = id.parse::<ulid::Ulid>() else { return status(StatusCode::NOT_FOUND, "No such machine") };
    let token = match registry.level_change_token(ulid, to, &user.name, ctx.now_ms).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "level change token");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, "The command couldn't be made; try again.");
        }
    };
    let data = serde_json::json!({ "from": access, "to": wanted }).to_string();
    if let Err(e) = web.0.audit.append(&user.name, "machine.level_change_issued", Some(id), &data).await {
        tracing::error!(error = %e, "audit");
    }
    let os = if kind == "alpine" || kind == "windows" { kind.as_str() } else { "linux" };
    let lines = super::add::install_commands(web, ctx, os, &ticket, token.as_str(), monitor, mode == "remote");
    let effect = if monitor {
        "It removes the hub's users, keys, sudoers file and command list, so the hub can no longer act on the machine."
    } else {
        "It adds the hub's users, keys, sudoers file and command list, so the hub can act on the machine."
    };
    let page = super::add::AddDone {
        shell: crate::web::ui::Shell::at(web, ctx, &format!("Change {name} to {wanted}"), &format!("/machines/{id}")),
        lines,
        note: format!(
            "The command works once, for 60 minutes. Run it as root on the machine. {effect} The machine keeps its history."
        ),
        back: (format!("/machines/{id}"), format!("Back to {name}")),
    };
    super::html(StatusCode::OK, askama::Template::render(&page))
}
