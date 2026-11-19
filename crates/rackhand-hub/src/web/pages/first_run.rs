//! First run (7.7.1): the installer's setup code, the admin with a password and a verified TOTP code, the site and
//! its timezone, and the outside sources. The admin, both credentials, the site and the first settings revision are
//! written in one command that succeeds only while there is no user, so two first runs can't make two admins; the
//! recovery code is shown in that one response and never again.

use argon2::password_hash::{PasswordHasher, SaltString};
use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use rackhand_store::{Row, RowWrite, StoreError, WriteCmd};
use rusqlite::types::Value;
use sha2::{Digest, Sha256};

use super::{html, redirect, status};
use crate::library::config::{self, HubConfig, Sources};
use crate::registry::peers::{local_site_row, valid_site_name};
use crate::vault::Secret;
use crate::web::{Ctx, Web, csrf, totp};

const MIN_PASSWORD: usize = 12;
const TOTP_PURPOSE: &str = "first-run-totp";

#[derive(Template)]
#[template(path = "first_run.html")]
struct Form<'a> {
    csrf: &'a str,
    totp_secret: &'a str,
    totp_sig: &'a str,
    totp_uri: &'a str,
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "first_run_done.html")]
struct Done<'a> {
    admin: &'a str,
    site: &'a str,
    recovery_code: &'a str,
}

pub(super) fn form(web: &Web, ctx: &Ctx) -> Response<Body> {
    render_form(web, ctx, None, StatusCode::OK)
}

fn render_form(web: &Web, ctx: &Ctx, error: Option<&str>, code: StatusCode) -> Response<Body> {
    let Ok(secret) = totp::new_secret() else { return status(StatusCode::INTERNAL_SERVER_ERROR, "No randomness") };
    let b32 = totp::encode_base32(&secret);
    let sig = csrf::sign(&web.0.config.csrf_key, TOTP_PURPOSE, &ctx.binding, &b32);
    let uri = totp::uri("Rackhand", "admin", &secret);
    html(code, Form { csrf: &ctx.csrf, totp_secret: &b32, totp_sig: &sig, totp_uri: &uri, error }.render())
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn valid_user_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

fn hash_password(password: &str) -> Result<String, String> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| e.to_string())?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| e.to_string())?;
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub(super) async fn submit(web: &Web, ctx: &Ctx) -> Response<Body> {
    let f = |k: &str| ctx.form.get(k).map(String::as_str).unwrap_or("").trim();
    let setup: [u8; 32] = Sha256::digest(f("setup_code").as_bytes()).into();
    if !same(&setup, &web.0.config.setup_code_hash) {
        return status(StatusCode::FORBIDDEN, "That isn't the setup code the installer printed");
    }
    let (name, password, site, tz) =
        (f("admin_name"), ctx.form.get("password").map(String::as_str).unwrap_or(""), f("site_name"), f("timezone"));
    let invalid = |msg| render_form(web, ctx, Some(msg), StatusCode::BAD_REQUEST);
    if !valid_user_name(name) {
        return invalid("Admin name: 1 to 64 of a-z, 0-9, dot, dash and underscore");
    }
    if password.chars().count() < MIN_PASSWORD {
        return invalid("The password needs at least 12 characters");
    }
    if !valid_site_name(site) {
        return invalid("Site name: 1 to 32 of a-z, 0-9 and dash");
    }
    if jiff::tz::TimeZone::get(tz).is_err() {
        return invalid("Unknown timezone; use a name like Europe/Berlin");
    }
    let secret_b32 = f("totp_secret");
    if !csrf::verify_signed(&web.0.config.csrf_key, TOTP_PURPOSE, &ctx.binding, secret_b32, f("totp_sig")) {
        return invalid("The authenticator secret changed; scan the new one");
    }
    let Some(secret) = totp::decode_base32(secret_b32) else { return invalid("The authenticator secret changed") };
    let Some(step) = totp::verify(&secret, f("totp_code"), ctx.now_ms / 1000) else {
        return invalid("That authenticator code doesn't match; check the app's clock and try the next code");
    };
    let Ok(password_hash) = hash_password(password) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "Password hashing failed");
    };
    let sources = Sources {
        feodo: f("source_feodo") == "on",
        spamhaus: f("source_spamhaus") == "on",
        dbip: f("source_dbip") == "on",
    };
    let settings = HubConfig { sources }.to_toml();

    let user_id = ulid::Ulid::new().to_string();
    let vault_name = format!("totp:{user_id}");
    if web.0.vault.put(&vault_name, &Secret::new(secret)).await.is_err() {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The Vault couldn't store the second factor");
    }
    let now = ctx.now_ms;
    let user: Row = [
        ("id", Value::Text(user_id.clone())),
        ("name", Value::Text(name.into())),
        ("role", Value::Text("admin".into())),
        ("auth", Value::Text("local".into())),
        ("created_at", Value::Integer(now)),
    ]
    .into_iter()
    .collect();
    let credential = |kind: &str, data: Vec<u8>, last_step: Option<i64>| {
        let mut row: Row = [
            ("id", Value::Text(ulid::Ulid::new().to_string())),
            ("user_id", Value::Text(user_id.clone())),
            ("kind", Value::Text(kind.into())),
            ("data", Value::Blob(data)),
            ("created_at", Value::Integer(now)),
        ]
        .into_iter()
        .collect();
        if let Some(s) = last_step {
            row.insert("last_totp_step", Value::Integer(s));
        }
        RowWrite::insert("credentials", row)
    };
    let mut writes = vec![
        RowWrite { table: "users", row: user, mode: rackhand_store::writer::WriteMode::InsertIfTableEmpty },
        credential("password", password_hash.into_bytes(), None),
        // The code used here can't be used again to sign in (7.7.2).
        credential("totp", format!("vault:{vault_name}").into_bytes(), Some(step)),
        local_site_row(site, tz),
    ];
    writes.extend(config::first_revision_rows(config::HUB, &settings, name, now));
    match web.0.db.writer().send(WriteCmd::Batch(writes)).await {
        Ok(_) => {}
        Err(StoreError::Conflict(_)) => return redirect("/sign-in"),
        Err(e) => {
            tracing::error!(error = %e, "first run");
            return status(StatusCode::INTERNAL_SERVER_ERROR, "First run couldn't be saved");
        }
    }
    let data = serde_json::json!({ "site": site, "timezone": tz, "sources": sources }).to_string();
    if let Err(e) = web.0.audit.append(name, "first_run.completed", Some(site), &data).await {
        tracing::error!(error = %e, "audit");
    }
    html(StatusCode::OK, Done { admin: name, site, recovery_code: &web.0.recovery_code }.render())
}
