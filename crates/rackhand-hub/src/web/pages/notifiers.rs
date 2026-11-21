//! Settings: Notifiers (7.7.1): the notifiers of `config/notifiers.toml`, Send test, and the form that adds or replaces
//! one. Webhook URLs and SMTP passwords go into the Vault; the file (mirrored to git) holds only `secret:<name>`.
//! A saved notifier applies when the hub restarts (plan T39b).

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};

use super::{html, html_text, redirect, status};
use crate::library::config;
use crate::notify::config::{self as file, DiscordSpec, NotifiersFile, SmtpSpec};
use crate::vault::Secret;
use crate::web::{Ctx, Web, auth};

const FILE: &str = "notifiers";

#[derive(Template)]
#[template(path = "notifiers.html")]
struct NotifiersPage<'a> {
    csrf: &'a str,
    running: Vec<String>,
    saved: Vec<Saved>,
}

struct Saved {
    name: String,
    kind: &'static str,
    target: String,
}

fn saved(web: &Web) -> Result<NotifiersFile, String> {
    match config::current(&web.0.db, FILE).map_err(|e| e.to_string())? {
        Some(text) => file::parse(&text).map_err(|e| e.to_string()),
        None => Ok(NotifiersFile::default()),
    }
}

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    let running = web.0.notify.as_ref().map(|n| n.names()).unwrap_or_default();
    let Ok(current) = saved(web) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "config/notifiers.toml couldn't be read");
    };
    let mut list: Vec<Saved> = current
        .discord
        .iter()
        .map(|d| Saved { name: d.name.clone(), kind: "Discord", target: "webhook in the Vault".into() })
        .collect();
    list.extend(current.smtp.iter().map(|s| Saved {
        name: s.name.clone(),
        kind: "Email",
        target: format!("{} to {}", s.host, s.to.join(", ")),
    }));
    html(StatusCode::OK, NotifiersPage { csrf: &ctx.csrf, running, saved: list }.render())
}

/// Send test: one message through every running notifier.
pub(super) async fn test(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(notify) = web.0.notify.as_ref().filter(|n| !n.names().is_empty()) else {
        return html_text(StatusCode::CONFLICT, "Notifiers", "No notifier is running.", Some("/settings/notifiers"));
    };
    let by = ctx.user.as_ref().map(|u| u.name.clone()).unwrap_or_default();
    let _ = web.0.audit.append(&format!("user:{by}"), "notifier.test", None, "{}").await;
    match notify.send_text("Test message from Rackhand", ctx.now_ms).await {
        Ok(()) => html_text(StatusCode::OK, "Notifiers", "The test message was sent.", Some("/settings/notifiers")),
        Err(e) => html_text(
            StatusCode::BAD_GATEWAY,
            "Notifiers",
            &format!("The test failed: {e}"),
            Some("/settings/notifiers"),
        ),
    }
}

fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn plain(v: &str, max: usize) -> bool {
    !v.is_empty() && v.len() <= max && !v.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn address(v: &str) -> bool {
    plain(v, 254) && v.split_once('@').is_some_and(|(user, host)| !user.is_empty() && !host.is_empty())
}

/// A secret given in the form goes into the Vault; an empty one keeps the stored one, and a new notifier needs it.
async fn secret(web: &Web, name: &str, given: &str) -> Result<String, Refusal> {
    if given.is_empty() {
        if web.0.vault.get(name).is_err() {
            return Err((StatusCode::BAD_REQUEST, "Give the secret: none is stored for this notifier yet"));
        }
    } else if let Err(e) = web.0.vault.put(name, &Secret::from(given)).await {
        tracing::error!(error = %e, "notifier secret");
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "The secret couldn't be stored"));
    }
    Ok(format!("secret:{name}"))
}

/// A refused save: its status and the reason shown.
type Refusal = (StatusCode, &'static str);

enum Spec {
    Discord(DiscordSpec),
    Smtp(SmtpSpec),
}

/// Checks the form before anything is stored.
fn check(ctx: &Ctx) -> Result<(String, &'static str), &'static str> {
    let f = |k: &str| ctx.form.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
    let name = f("name");
    if !valid_name(&name) {
        return Err("The name is 1 to 64 of a-z, 0-9 and -");
    }
    match f("kind").as_str() {
        "discord" => {
            let webhook = f("webhook");
            if !webhook.is_empty() && (!auth::oidc::allowed_url(&webhook) || !plain(&webhook, 512)) {
                return Err("The webhook must be an https:// URL (http:// only on this host)");
            }
            Ok((name, "discord"))
        }
        "smtp" => {
            if !plain(&f("host"), 253) {
                return Err("Give the mail server's host name");
            }
            if !f("port").parse::<u16>().is_ok_and(|p| p > 0) {
                return Err("The port is 1 to 65535");
            }
            if !matches!(f("security").as_str(), "starttls" | "tls") {
                return Err("Security is starttls or tls");
            }
            let to: Vec<String> = f("to").split(',').map(|a| a.trim().to_string()).filter(|a| !a.is_empty()).collect();
            if !address(&f("from")) || to.is_empty() || !to.iter().all(|a| address(a)) {
                return Err("Give the sender and at least one recipient as name@domain");
            }
            let username = f("username");
            if !username.is_empty() && !plain(&username, 254) {
                return Err("The user name has no spaces");
            }
            Ok((name, "smtp"))
        }
        _ => Err("The kind is discord or smtp"),
    }
}

async fn spec(web: &Web, ctx: &Ctx, name: &str, kind: &str) -> Result<Spec, Refusal> {
    let f = |k: &str| ctx.form.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
    if kind == "discord" {
        let webhook = secret(web, &format!("notifier.{name}.webhook"), &f("webhook")).await?;
        return Ok(Spec::Discord(DiscordSpec { name: name.into(), webhook }));
    }
    let username = Some(f("username")).filter(|u| !u.is_empty());
    let password = match &username {
        Some(_) => Some(secret(web, &format!("notifier.{name}.password"), &f("password")).await?),
        None => None,
    };
    Ok(Spec::Smtp(SmtpSpec {
        name: name.into(),
        host: f("host"),
        port: f("port").parse().unwrap_or(587),
        security: f("security"),
        username,
        password,
        from: f("from"),
        to: f("to").split(',').map(|a| a.trim().to_string()).filter(|a| !a.is_empty()).collect(),
    }))
}

/// Adds a notifier, or replaces the one of that name; audited, and the change reaches the git mirror.
pub(super) async fn save(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = ctx.user.as_ref() else { return redirect("/sign-in") };
    let (name, kind) = match check(ctx) {
        Ok(v) => v,
        Err(why) => return status(StatusCode::BAD_REQUEST, why),
    };
    let Ok(mut current) = saved(web) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "config/notifiers.toml couldn't be read");
    };
    let spec = match spec(web, ctx, &name, kind).await {
        Ok(s) => s,
        Err((code, why)) => return status(code, why),
    };
    current.discord.retain(|d| d.name != name);
    current.smtp.retain(|s| s.name != name);
    match spec {
        Spec::Discord(d) => current.discord.push(d),
        Spec::Smtp(s) => current.smtp.push(s),
    }
    let text = match file::to_toml(&current) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "notifiers");
            return status(StatusCode::INTERNAL_SERVER_ERROR, "The notifiers couldn't be saved");
        }
    };
    if let Err(e) = config::put(&web.0.db, FILE, &text, &user.name, ctx.now_ms).await {
        tracing::error!(error = %e, "notifiers");
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The notifiers couldn't be saved");
    }
    let data = serde_json::json!({ "name": name, "kind": kind });
    if let Err(e) =
        web.0.audit.append(&user.name, "settings.notifier", Some("config/notifiers"), &data.to_string()).await
    {
        tracing::error!(error = %e, "audit");
    }
    if let Some(library) = &web.0.library {
        library.changed(&user.name, "edit config/notifiers");
    }
    redirect("/settings/notifiers")
}
