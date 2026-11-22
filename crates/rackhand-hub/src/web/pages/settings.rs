//! Settings (7.7.1, 7.8): each change is a new revision of `config/hub.toml` and an audit row (FR-26).

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use russh::keys::PrivateKey;

use super::{html, redirect, status};
use crate::library::config::{self, GitMirror, HubConfig, Sources};
use crate::library::mirror::DEPLOY_KEY;
use crate::vault::Secret;
use crate::web::ui::Shell;
use crate::web::forms::{self, Form, Spec};
use crate::web::{Ctx, Web, auth};

#[derive(Template)]
#[template(path = "settings.html")]
struct Settings<'a> {
    shell: Shell,
    csrf: &'a str,
    sources: Sources,
    /// What went wrong with a button on the page.
    notice: Option<&'a str>,
    mirror: Form,
    oidc: Form,
    deploy_key: Option<String>,
    notifiers: usize,
}

const MIRROR: &[Spec] = &[Spec::text("url", "Repository")
    .hint("The ssh:// address of the repository, such as ssh://git@git.example/homelab/rackhand.git.")
    .pattern(r"ssh:\/\/\S{1,500}", "The address starts with ssh:// and has no spaces")
    .attrs("autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\"")];

const OIDC: &[Spec] = &[
    Spec::text("issuer", "Issuer")
        .hint("The provider's issuer URL: https:// (http:// only on this host).")
        .pattern(r"https?:\/\/\S+", ISSUER_RULE)
        .attrs("autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\" inputmode=\"url\""),
    Spec::text("client_id", "Client id").hint("As the provider registered this hub."),
    Spec::secret("client_secret", "Client secret").hint("Goes into the Vault.").attrs("autocomplete=\"new-password\""),
    Spec::text("redirect_url", "Callback URL")
        .hint("https://<hub>/sign-in/oidc/callback, exactly as registered with the provider.")
        .pattern(
            r"https:\/\/\S+\/sign-in\/oidc\/callback",
            "The callback is https://<hub>/sign-in/oidc/callback as registered",
        )
        .attrs("autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\" inputmode=\"url\""),
];
const ISSUER_RULE: &str = "The issuer is an https:// URL (http:// only on this host)";

fn deploy_public_key(web: &Web) -> Option<String> {
    let pem = web.0.vault.get(DEPLOY_KEY).ok()?;
    let key = PrivateKey::from_openssh(String::from_utf8_lossy(pem.expose()).as_ref()).ok()?;
    key.public_key().to_openssh().ok()
}

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    show(web, ctx, StatusCode::OK, None, None)
}

/// The page, with the form that was refused as it was sent, or what went wrong with one of its buttons.
fn show(
    web: &Web,
    ctx: &Ctx,
    code: StatusCode,
    mut sent: Option<Form>,
    notice: Option<&str>,
) -> Response<Body> {
    let Ok(current) = config::hub(&web.0.db) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "Settings unreadable");
    };
    let url = current.git_mirror.as_ref().map(|m| m.url.as_str()).unwrap_or("");
    let oidc = current.oidc.clone().unwrap_or_default();
    let mut oidc_form = Form::blank("oidc", OIDC)
        .with("issuer", &oidc.issuer)
        .with("client_id", &oidc.client_id)
        .with("redirect_url", &oidc.redirect_url);
    if !oidc.client_secret.is_empty() {
        oidc_form.keep("client_secret", forms::STORED);
    }
    html(
        code,
        Settings {
            shell: Shell::at(web, ctx, "System settings", "/settings"),
            csrf: &ctx.csrf,
            sources: current.sources,
            notice,
            mirror: Form::blank("mirror", MIRROR).with("url", url).or_sent(&mut sent),
            oidc: oidc_form.or_sent(&mut sent),
            deploy_key: deploy_public_key(web),
            notifiers: super::notifiers::count(web),
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
    if let Some(library) = &web.0.library {
        library.changed(&user.name, "edit config/hub");
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
    let mut form = Form::sent("mirror", MIRROR, ctx, &web.0.held);
    form.check();
    let printable = !form.value("url").chars().any(char::is_control);
    form.require("url", printable, "The address starts with ssh:// and has no spaces");
    if !form.ok() {
        return show(web, ctx, StatusCode::BAD_REQUEST, Some(form), None);
    }
    let url = form.value("url").to_string();
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
    let mut form = Form::sent("oidc", OIDC, ctx, &web.0.held);
    if web.0.vault.get(auth::oidc::SECRET_NAME).is_ok() {
        form.keep("client_secret", forms::STORED);
    }
    form.check();
    let allowed = auth::oidc::allowed_url(form.value("issuer"));
    form.require("issuer", allowed, ISSUER_RULE);
    if !form.ok() {
        form.hold(&web.0.held, ctx);
        return show(web, ctx, StatusCode::BAD_REQUEST, Some(form), None);
    }
    let f = |k: &str| form.value(k).to_string();
    let (issuer, client_id, redirect_url) = (f("issuer"), f("client_id"), f("redirect_url"));
    let secret = form.value("client_secret").trim().to_string();
    if !secret.is_empty()
        && let Err(e) = web.0.vault.put(auth::oidc::SECRET_NAME, &Secret::new(secret.into_bytes())).await
    {
        tracing::error!(error = %e, "oidc secret");
        form.notice("The client secret couldn't be stored; try again.");
        form.hold(&web.0.held, ctx);
        return show(web, ctx, StatusCode::INTERNAL_SERVER_ERROR, Some(form), None);
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
