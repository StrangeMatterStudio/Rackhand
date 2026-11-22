//! Users, roles and devices on the settings page (7.7.1, 7.7.2): admin only. A new account gets its authenticator secret
//! here, shown once, so every account (OIDC ones too) has a local second factor from the start.

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use rackhand_store::{Row, StoreError, WriteCmd};
use rusqlite::types::Value;

use super::{html, redirect, status};
use crate::web::auth::password::MIN_LENGTH;
use crate::web::auth::users::{self, NewUser, UserError};
use crate::web::ui::{self, Confirm, Shell};
use crate::web::forms::{self, Choices, Form, Spec};
use crate::web::perms::{parse_role, role_name};
use crate::web::{Ctx, Web, totp};

#[derive(Template)]
#[template(path = "user_created.html")]
struct Created<'a> {
    shell: Shell,
    name: &'a str,
    role: &'a str,
    secret: &'a str,
    uri: &'a str,
    qr: String,
}

const ROLES: Choices = &[
    ("viewer", "Viewer: sees everything, changes nothing"),
    ("responder", "Responder: also handles incidents and normal approvals"),
    ("admin", "Admin: everything"),
];
const SIGN_IN: Choices = &[("local", "With a password"), ("oidc", "Through the identity provider (OIDC)")];

const USER: &[Spec] = &[
    Spec::text("name", "Name")
        .hint("1 to 64 letters, digits, dots, dashes, underscores or @.")
        .pattern(r"[A-Za-z0-9._@\-]{1,64}", "Use 1 to 64 letters, digits or . _ @ -, with no spaces")
        .attrs("autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\""),
    Spec::select("role", "Role", ROLES),
    Spec::select("auth", "Signs in", SIGN_IN)
        .hint("Either way the account gets an authenticator key on the next page."),
    Spec::secret("password", "Password")
        .hint("At least 12 characters.")
        .when("auth=local")
        .length(MIN_LENGTH, 1024)
        .attrs("autocomplete=\"new-password\""),
    Spec::secret("password_again", "Password, again")
        .optional()
        .same("password")
        .when("auth=local")
        .attrs("autocomplete=\"new-password\""),
    Spec::text("subject", "OIDC subject")
        .hint("The provider's `sub` for this person.")
        .when("auth=oidc"),
];

const ROLE: &[Spec] = &[Spec::select("role", "Role", ROLES)];

struct UserLine {
    id: String,
    name: String,
    role: String,
    auth: String,
    disabled: bool,
    factor: String,
    /// The person looking at the page.
    you: bool,
}

#[derive(Template)]
#[template(path = "users.html")]
struct UsersPage<'a> {
    shell: Shell,
    q: String,
    csrf: &'a str,
    notice: Option<&'a str>,
    users: Vec<UserLine>,
    devices: Vec<crate::registry::devices::DeviceRow>,
    /// The form that adds a user, when its dialog is open.
    add: Option<Form>,
    /// The account being edited, with its form.
    edit: Option<(String, String, bool, Form)>,
    confirm: String,
}

fn list(web: &Web, ctx: &Ctx) -> Vec<UserLine> {
    web.0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT u.id, u.name, u.role, u.auth, u.disabled_at IS NOT NULL,
                        (SELECT group_concat(DISTINCT c.kind) FROM credentials c WHERE c.user_id = u.id AND c.kind != 'password')
                 FROM users u ORDER BY u.name",
            )?;
            let rows = s.query_map([], |r| {
                let id: String = r.get(0)?;
                let kinds: String = r.get::<_, Option<String>>(5)?.unwrap_or_default();
                let mut factor = Vec::new();
                if kinds.contains("totp") {
                    factor.push("Authenticator");
                }
                if kinds.contains("passkey") {
                    factor.push("Passkey");
                }
                Ok(UserLine {
                    you: ctx.user.as_ref().is_some_and(|u| u.user_id == id),
                    id,
                    name: r.get(1)?,
                    role: r.get(2)?,
                    auth: r.get(3)?,
                    disabled: r.get(4)?,
                    factor: if factor.is_empty() { "None".into() } else { factor.join(", ") },
                })
            })?;
            rows.collect()
        })
        .unwrap_or_default()
}

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    show(web, ctx, StatusCode::OK, None, None)
}

/// Users and their devices (7.7.1), with the dialog the address asks for, or the form that was refused in its own.
fn show(web: &Web, ctx: &Ctx, code: StatusCode, sent: Option<Form>, notice: Option<&str>) -> Response<Body> {
    let all = list(web, ctx);
    let devices = web.0.registry.as_ref().and_then(|r| r.devices().ok()).unwrap_or_default();
    let editing = ui::asked(ctx, "edit").and_then(|id| all.iter().find(|u| u.id == id));
    let edit = editing.map(|u| {
        (u.id.clone(), u.name.clone(), u.disabled, Form::blank("role", ROLE).with("role", &u.role))
    });
    let confirm = match ui::asked(ctx, "confirm").and_then(|c| c.split_once(':')) {
        Some(("disable", id)) => all.iter().find(|u| u.id == id && !u.disabled).map(|u| Confirm {
            title: format!("Disable {}?", u.name),
            body: "They are signed out everywhere and can't sign in. Nothing they did is removed.".into(),
            action: format!("/settings/users/{id}/disable"),
            keep: "Keep it",
            does: format!("Disable {}", u.name),
            back: "/users",
        }),
        Some(("revoke", id)) => devices.iter().find(|d| d.id == id && d.revoked_at.is_none()).map(|d| Confirm {
            title: format!("Revoke {}?", d.name),
            body: "Its connection ends now, and it has to be invited again.".into(),
            action: format!("/settings/devices/{id}/revoke"),
            keep: "Keep it",
            does: format!("Revoke {}", d.name),
            back: "/users",
        }),
        _ => None,
    };
    let confirm = confirm.map(|c| c.html(&ctx.csrf)).unwrap_or_default();
    let add = sent.or_else(|| ui::asked(ctx, "add").filter(|a| *a == "user").map(|_| Form::blank("user", USER)));
    let q = ui::query(ctx);
    let users = all.into_iter().filter(|u| ui::found(&q, &[&u.name, &u.role, &u.auth])).collect();
    let shell = Shell::at(web, ctx, "Users", "/users");
    html(code, UsersPage { shell, q, csrf: &ctx.csrf, notice, users, devices, add, edit, confirm }.render())
}

/// `/settings/<kind>/<id>/...` → the id, if it looks like one.
fn path_id<'a>(path: &'a str, kind: &str) -> Option<&'a str> {
    let id = path.strip_prefix("/settings/")?.strip_prefix(kind)?.strip_prefix('/')?.split('/').next()?;
    (!id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')).then_some(id)
}

async fn audit(web: &Web, actor: &str, action: &str, target: &str, data: serde_json::Value) {
    if let Err(e) = web.0.audit.append(actor, action, Some(target), &data.to_string()).await {
        tracing::error!(error = %e, "audit");
    }
}

pub(super) async fn create(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(admin) = &ctx.user else { return redirect("/sign-in") };
    let mut form = Form::sent("user", USER, ctx, &web.0.held);
    // what the other way of signing in needs isn't looked at (a password is the usual one)
    if form.value("auth").is_empty() {
        form.set("auth", "local");
    }
    if form.value("auth") == "oidc" {
        form.set("password", "");
        form.set("password_again", "");
    }
    form.check();
    let (true, Some(role)) = (form.ok(), parse_role(form.value("role"))) else {
        form.hold(&web.0.held, ctx);
        return show(web, ctx, StatusCode::BAD_REQUEST, Some(form), None);
    };
    let Ok(secret) = totp::new_secret() else { return status(StatusCode::INTERNAL_SERVER_ERROR, "No randomness") };
    let auth = form.value("auth").to_string();
    let new = match auth.as_str() {
        "oidc" => NewUser::Oidc { subject: form.value("subject") },
        _ => NewUser::Local { password: form.value("password") },
    };
    let name = form.value("name").to_string();
    let name = name.as_str();
    let refused = match users::create(&web.0.db, &web.0.vault, name, role, new, &secret, ctx.now_ms).await {
        Ok(_) => None,
        Err(UserError::Invalid(why)) => {
            form.notice(why);
            Some(StatusCode::BAD_REQUEST)
        }
        Err(UserError::Store(StoreError::Sqlite(e))) if e.to_string().contains("UNIQUE") => {
            let field = if e.to_string().contains("oidc_subject") { "subject" } else { "name" };
            let why = format!("`{}` is taken by another account", form.value(field));
            form.refuse(field, why);
            Some(StatusCode::CONFLICT)
        }
        Err(e) => {
            tracing::error!(error = %e, "create user");
            form.notice("The account couldn't be created; try again.");
            Some(StatusCode::INTERNAL_SERVER_ERROR)
        }
    };
    if let Some(code) = refused {
        form.hold(&web.0.held, ctx);
        return show(web, ctx, code, Some(form), None);
    }
    audit(web, &admin.name, "user.created", name, serde_json::json!({ "role": role_name(role), "auth": auth })).await;
    let b32 = totp::encode_base32(&secret);
    let uri = totp::uri("Rackhand", name, &secret);
    let qr = forms::qr_svg(&uri, "QR code of the key for an authenticator app");
    html(StatusCode::OK, Created { shell: Shell::at(web, ctx, "Account created", "/users"), name, role: role_name(role), secret: &b32, uri: &uri, qr }.render())
}

/// What went wrong with one of the page's buttons, on the page.
fn explain(web: &Web, ctx: &Ctx, code: StatusCode, text: &str) -> Response<Body> {
    show(web, ctx, code, None, Some(text))
}

async fn put_user(web: &Web, ctx: &Ctx, cols: Vec<(&'static str, Value)>) -> Result<String, Box<Response<Body>>> {
    let Some(id) = path_id(&ctx.path, "users") else {
        return Err(Box::new(status(StatusCode::NOT_FOUND, "No such user")));
    };
    let mut row = Row::from([("id", Value::Text(id.into()))]);
    row.extend(cols);
    match web.0.db.writer().send(WriteCmd::PutUser(row)).await {
        Ok(_) => Ok(id.to_string()),
        Err(StoreError::Conflict(_)) => Err(Box::new(explain(
            web,
            ctx,
            StatusCode::CONFLICT,
            "The hub needs at least one enabled admin; add another admin first. Nothing was changed.",
        ))),
        Err(StoreError::NoSuchRow(_)) => Err(Box::new(explain(web, ctx, StatusCode::NOT_FOUND, "No such user."))),
        Err(e) => {
            tracing::error!(error = %e, "user");
            let code = StatusCode::INTERNAL_SERVER_ERROR;
            Err(Box::new(explain(web, ctx, code, "The account couldn't be changed; try again.")))
        }
    }
}

pub(super) async fn change_role(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(admin) = &ctx.user else { return redirect("/sign-in") };
    let Some(role) = ctx.form.get("role").and_then(|r| parse_role(r.trim())) else {
        return explain(web, ctx, StatusCode::BAD_REQUEST, "Choose a role.");
    };
    match put_user(web, ctx, vec![("role", Value::Text(role_name(role).into()))]).await {
        Ok(id) => {
            audit(web, &admin.name, "user.role_changed", &id, serde_json::json!({ "role": role_name(role) })).await;
            redirect("/users")
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
            redirect("/users")
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
            redirect("/users")
        }
        Ok(false) => explain(web, ctx, StatusCode::NOT_FOUND, "No such device, or it is already revoked."),
        Err(e) => {
            tracing::error!(error = %e, "revoke device");
            explain(web, ctx, StatusCode::INTERNAL_SERVER_ERROR, "The device couldn't be revoked; try again.")
        }
    }
}
