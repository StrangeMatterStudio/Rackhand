//! Machine actions from the dashboard. Accepting a changed host key and confirming a guest binding are high risk
//! (7.6.8, 7.3.12): admin, after a step-up.

use axum::body::Body;
use axum::http::{Response, StatusCode};

use super::monitoring::show_machine;
use super::{redirect, status};
use crate::web::auth::step_up;
use crate::web::{Ctx, Web};

fn machine_id(path: &str) -> Option<&str> {
    let id = path.strip_prefix("/machines/")?.split('/').next()?;
    (!id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')).then_some(id)
}

pub(super) async fn accept_host_key(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    if !step_up::fresh(user.step_up_at, ctx.now_ms) {
        return redirect("/step-up");
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
    redirect("/")
}

/// Confirms the guest the form names as the machine's (its proposal or binding, or the guest it now looks like).
pub(super) async fn confirm_binding(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    if !step_up::fresh(user.step_up_at, ctx.now_ms) {
        return redirect("/step-up");
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
    redirect("/")
}
