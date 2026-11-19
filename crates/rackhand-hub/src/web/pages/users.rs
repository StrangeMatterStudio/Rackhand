//! Users, roles and devices on the settings page (7.7.1, 7.7.2): admin only. A new account gets its authenticator secret
//! here, shown once, so every account (OIDC ones too) has a local second factor from the start.

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use rackhand_store::{Row, StoreError, WriteCmd};
use rusqlite::types::Value;

use super::{html, redirect, status};
use crate::web::auth::users::{self, NewUser, UserError};
use crate::web::perms::{parse_role, role_name};
use crate::web::{Ctx, Web, totp};

#[derive(Template)]
#[template(path = "user_created.html")]
struct Created<'a> {
    name: &'a str,
    role: &'a str,
    secret: &'a str,
    uri: &'a str,
}

/// `/settings/<kind>/<id>/...` → the id, if it looks like one.
fn path_id<'a>(path: &'a str, kind: &str) -> Option<&'a str> {
    let id = path.strip_prefix("/settings/")?.strip_prefix(kind)?.strip_prefix('/')?.split('/').next()?;
    (!id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')).then_some(id)
}

fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b))
}

async fn audit(web: &Web, actor: &str, action: &str, target: &str, data: serde_json::Value) {
    if let Err(e) = web.0.audit.append(actor, action, Some(target), &data.to_string()).await {
        tracing::error!(error = %e, "audit");
    }
}

pub(super) async fn create(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(admin) = &ctx.user else { return redirect("/sign-in") };
    let f = |k: &str| ctx.form.get(k).map(|v| v.trim()).unwrap_or("");
    let name = f("name");
    if !valid_name(name) {
        return status(StatusCode::BAD_REQUEST, "A name is 1 to 64 letters, digits or . _ @ -");
    }
    let Some(role) = parse_role(f("role")) else { return status(StatusCode::BAD_REQUEST, "Choose a role") };
    let Ok(secret) = totp::new_secret() else { return status(StatusCode::INTERNAL_SERVER_ERROR, "No randomness") };
    let new = match f("auth") {
        "local" => NewUser::Local { password: ctx.form.get("password").map(String::as_str).unwrap_or("") },
        "oidc" if !f("subject").is_empty() => NewUser::Oidc { subject: f("subject") },
        "oidc" => return status(StatusCode::BAD_REQUEST, "An OIDC account needs the provider's subject (sub)"),
        _ => return status(StatusCode::BAD_REQUEST, "Choose local or OIDC"),
    };
    let auth = match new {
        NewUser::Local { .. } => "local",
        NewUser::Oidc { .. } => "oidc",
    };
    match users::create(&web.0.db, &web.0.vault, name, role, new, &secret, ctx.now_ms).await {
        Ok(_) => {}
        Err(UserError::Invalid(why)) => return status(StatusCode::BAD_REQUEST, &why),
        Err(UserError::Store(StoreError::Sqlite(e))) if e.to_string().contains("UNIQUE") => {
            return status(StatusCode::CONFLICT, "That name or subject is taken");
        }
        Err(e) => {
            tracing::error!(error = %e, "create user");
            return status(StatusCode::INTERNAL_SERVER_ERROR, "The account couldn't be created");
        }
    }
    audit(web, &admin.name, "user.created", name, serde_json::json!({ "role": role_name(role), "auth": auth })).await;
    let b32 = totp::encode_base32(&secret);
    let uri = totp::uri("Rackhand", name, &secret);
    html(StatusCode::OK, Created { name, role: role_name(role), secret: &b32, uri: &uri }.render())
}

async fn put_user(web: &Web, ctx: &Ctx, cols: Vec<(&'static str, Value)>) -> Result<String, Box<Response<Body>>> {
    let Some(id) = path_id(&ctx.path, "users") else {
        return Err(Box::new(status(StatusCode::NOT_FOUND, "No such user")));
    };
    let mut row = Row::from([("id", Value::Text(id.into()))]);
    row.extend(cols);
    match web.0.db.writer().send(WriteCmd::PutUser(row)).await {
        Ok(_) => Ok(id.to_string()),
        Err(StoreError::Conflict(_)) => Err(Box::new(status(
            StatusCode::CONFLICT,
            "The hub needs at least one enabled admin; add another admin first",
        ))),
        Err(StoreError::NoSuchRow(_)) => Err(Box::new(status(StatusCode::NOT_FOUND, "No such user"))),
        Err(e) => {
            tracing::error!(error = %e, "user");
            Err(Box::new(status(StatusCode::INTERNAL_SERVER_ERROR, "The account couldn't be changed")))
        }
    }
}

pub(super) async fn change_role(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(admin) = &ctx.user else { return redirect("/sign-in") };
    let Some(role) = ctx.form.get("role").and_then(|r| parse_role(r.trim())) else {
        return status(StatusCode::BAD_REQUEST, "Choose a role");
    };
    match put_user(web, ctx, vec![("role", Value::Text(role_name(role).into()))]).await {
        Ok(id) => {
            audit(web, &admin.name, "user.role_changed", &id, serde_json::json!({ "role": role_name(role) })).await;
            redirect("/settings")
        }
        Err(resp) => *resp,
    }
}

pub(super) async fn disable(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(admin) = &ctx.user else { return redirect("/sign-in") };
    // A disabled account's sessions stop at once: the session lookup only finds enabled users.
    match put_user(web, ctx, vec![("disabled_at", Value::Integer(ctx.now_ms))]).await {
        Ok(id) => {
            audit(web, &admin.name, "user.disabled", &id, serde_json::json!({})).await;
            redirect("/settings")
        }
        Err(resp) => *resp,
    }
}

pub(super) async fn revoke_device(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(admin) = &ctx.user else { return redirect("/sign-in") };
    let Some(id) = path_id(&ctx.path, "devices") else { return status(StatusCode::NOT_FOUND, "No such device") };
    let Some(registry) = &web.0.registry else { return status(StatusCode::NOT_FOUND, "No such device") };
    match registry.revoke_device(id, ctx.now_ms).await {
        Ok(true) => {
            audit(web, &admin.name, "device.revoked", id, serde_json::json!({})).await;
            redirect("/settings")
        }
        Ok(false) => status(StatusCode::NOT_FOUND, "No such device, or it is already revoked"),
        Err(e) => {
            tracing::error!(error = %e, "revoke device");
            status(StatusCode::INTERNAL_SERVER_ERROR, "The device couldn't be revoked")
        }
    }
}
