//! Machine actions from the dashboard. Accepting a changed host key is high risk (7.6.8): admin, after a step-up.

use axum::body::Body;
use axum::http::{Response, StatusCode};

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
    let Some((key_type, fingerprint)) = keys.offered(id) else {
        return status(StatusCode::NOT_FOUND, "This machine hasn't offered a new host key");
    };
    match keys.accept_offered(id, &user.name, ctx.now_ms).await {
        Ok(true) => {}
        Ok(false) => return status(StatusCode::NOT_FOUND, "This machine hasn't offered a new host key"),
        Err(e) => {
            tracing::error!(error = %e, "host key");
            return status(StatusCode::INTERNAL_SERVER_ERROR, "The key couldn't be stored");
        }
    }
    let data = serde_json::json!({ "key_type": key_type, "fingerprint": fingerprint }).to_string();
    if let Err(e) = web.0.audit.append(&user.name, "ssh.host_key_accepted", Some(id), &data).await {
        tracing::error!(error = %e, "audit");
    }
    redirect("/")
}
