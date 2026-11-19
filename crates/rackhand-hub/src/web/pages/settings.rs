//! Settings (7.7.1, 7.8): each change is a new revision of `config/hub.toml` and an audit row (FR-26).

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use russh::keys::PrivateKey;

use super::{html, redirect, status};
use crate::library::config::{self, GitMirror, HubConfig, Sources};
use crate::library::mirror::DEPLOY_KEY;
use crate::vault::Secret;
use crate::web::{Ctx, Web, auth};

#[derive(Template)]
#[template(path = "settings.html")]
struct Settings<'a> {
    csrf: &'a str,
    sources: Sources,
    mirror_url: &'a str,
    deploy_key: Option<String>,
    users: Vec<UserLine>,
    devices: Vec<crate::registry::devices::DeviceRow>,
    oidc: config::Oidc,
}

struct UserLine {
    id: String,
    name: String,
    role: String,
    auth: String,
    disabled: bool,
}

fn users(web: &Web) -> Vec<UserLine> {
    web.0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT id, name, role, auth, disabled_at IS NOT NULL FROM users ORDER BY name")?;
            let rows = s.query_map([], |r| {
                Ok(UserLine { id: r.get(0)?, name: r.get(1)?, role: r.get(2)?, auth: r.get(3)?, disabled: r.get(4)? })
            })?;
            rows.collect()
        })
        .unwrap_or_default()
}

fn deploy_public_key(web: &Web) -> Option<String> {
    let pem = web.0.vault.get(DEPLOY_KEY).ok()?;
    let key = PrivateKey::from_openssh(String::from_utf8_lossy(pem.expose()).as_ref()).ok()?;
    key.public_key().to_openssh().ok()
}

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Ok(current) = config::hub(&web.0.db) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "Settings unreadable");
    };
    let url = current.git_mirror.as_ref().map(|m| m.url.as_str()).unwrap_or("");
    html(
        StatusCode::OK,
        Settings {
            csrf: &ctx.csrf,
            sources: current.sources,
            mirror_url: url,
            deploy_key: deploy_public_key(web),
            users: users(web),
            devices: web.0.registry.as_ref().and_then(|r| r.devices().ok()).unwrap_or_default(),
            oidc: current.oidc.clone().unwrap_or_default(),
        }
        .render(),
    )
}

/// Saves a changed copy of the current settings and audits it.
async fn change(
    web: &Web,
    ctx: &Ctx,
    action: &str,
    edit: impl FnOnce(&mut HubConfig) -> serde_json::Value,
) -> Response<Body> {
    let Some(user) = ctx.user.as_ref() else { return redirect("/sign-in") };
    let Ok(mut current) = config::hub(&web.0.db) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "Settings unreadable");
    };
    let data = edit(&mut current);
    if let Err(e) = config::put(&web.0.db, config::HUB, &current.to_toml(), &user.name, ctx.now_ms).await {
        tracing::error!(error = %e, "settings");
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The settings couldn't be saved");
    }
    if let Err(e) = web.0.audit.append(&user.name, action, Some("config/hub"), &data.to_string()).await {
        tracing::error!(error = %e, "audit");
    }
    redirect("/settings")
}

pub(super) async fn sources(web: &Web, ctx: &Ctx) -> Response<Body> {
    let on = |k: &str| ctx.form.get(k).is_some_and(|v| v == "on");
    let sources = Sources { feodo: on("source_feodo"), spamhaus: on("source_spamhaus"), dbip: on("source_dbip") };
    change(web, ctx, "settings.sources", |c| {
        c.sources = sources;
        serde_json::to_value(sources).unwrap_or_default()
    })
    .await
}

/// The mirror's URL; the deploy key is generated into the Vault the first time and its public half shown.
pub(super) async fn git_mirror(web: &Web, ctx: &Ctx) -> Response<Body> {
    let url = ctx.form.get("url").map(|u| u.trim().to_string()).unwrap_or_default();
    if !url.starts_with("ssh://") || url.chars().any(|c| c.is_whitespace() || c.is_control()) || url.len() > 512 {
        return status(StatusCode::BAD_REQUEST, "The mirror URL must be an ssh:// URL");
    }
    if web.0.vault.get(DEPLOY_KEY).is_err() {
        let made = crate::ssh::keys::generate_ed25519("rackhand-mirror")
            .ok()
            .and_then(|(k, _)| k.to_openssh(russh::keys::ssh_key::LineEnding::LF).ok().map(|p| p.to_string()));
        let Some(pem) = made else {
            return status(StatusCode::INTERNAL_SERVER_ERROR, "The deploy key couldn't be made");
        };
        if web.0.vault.put(DEPLOY_KEY, &Secret::from(pem.as_str())).await.is_err() {
            return status(StatusCode::INTERNAL_SERVER_ERROR, "The Vault couldn't store the deploy key");
        }
    }
    change(web, ctx, "settings.git_mirror", |c| {
        let keep = c.git_mirror.as_ref().filter(|m| m.url == url).and_then(|m| m.host_fingerprint.clone());
        c.git_mirror = Some(GitMirror { url: url.clone(), branch: "main".into(), host_fingerprint: keep });
        serde_json::json!({ "url": url })
    })
    .await
}

/// OIDC sign-in (7.7.2): the client secret goes into the Vault; the settings and the audit log get only its reference.
/// An empty secret keeps the stored one.
pub(super) async fn oidc(web: &Web, ctx: &Ctx) -> Response<Body> {
    let f = |k: &str| ctx.form.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
    let (issuer, client_id, secret, redirect_url) =
        (f("issuer"), f("client_id"), f("client_secret"), f("redirect_url"));
    if !auth::oidc::allowed_url(&issuer) {
        return status(StatusCode::BAD_REQUEST, "The issuer must be an https:// URL (http:// only on this host)");
    }
    if client_id.is_empty()
        || !redirect_url.starts_with("https://")
        || !redirect_url.ends_with("/sign-in/oidc/callback")
    {
        return status(
            StatusCode::BAD_REQUEST,
            "Give the client id and the callback URL https://<hub>/sign-in/oidc/callback as registered",
        );
    }
    if secret.is_empty() {
        if web.0.vault.get(auth::oidc::SECRET_NAME).is_err() {
            return status(StatusCode::BAD_REQUEST, "Give the client secret");
        }
    } else if let Err(e) = web.0.vault.put(auth::oidc::SECRET_NAME, &Secret::new(secret.into_bytes())).await {
        tracing::error!(error = %e, "oidc secret");
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The client secret couldn't be stored");
    }
    change(web, ctx, "settings.oidc", |c| {
        c.oidc = Some(config::Oidc {
            issuer: issuer.clone(),
            client_id: client_id.clone(),
            client_secret: auth::oidc::secret_reference(),
            redirect_url: redirect_url.clone(),
        });
        serde_json::json!({ "issuer": issuer, "client_id": client_id, "redirect_url": redirect_url })
    })
    .await
}
