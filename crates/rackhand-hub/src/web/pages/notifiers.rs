//! Settings: Notifiers (7.7.1): the notifiers of `config/notifiers.toml`, Send test, and the form that adds or replaces
//! one. Webhook URLs and SMTP passwords go into the Vault; the file (mirrored to git) holds only `secret:<name>`.
//! A saved notifier applies when the hub restarts (plan T39b).

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};

use super::{html, redirect, status};
use crate::library::config;
use crate::notify::config::{self as file, DiscordSpec, NotifiersFile, SmtpSpec};
use crate::vault::Secret;
use crate::web::forms::{Choices, Form, Spec};
use crate::web::{Ctx, Web, auth};

const FILE: &str = "notifiers";

#[derive(Template)]
#[template(path = "notifiers.html")]
struct NotifiersPage<'a> {
    csrf: &'a str,
    running: Vec<String>,
    saved: Vec<Saved>,
    /// What went wrong with Send test, or that it worked.
    notice: Option<&'a str>,
    sent_ok: bool,
    discord: Form,
    smtp: Form,
}

const NAME: Spec = Spec::text("name", "Name")
    .hint("1 to 64 lower-case letters (a-z), digits and dashes.")
    .pattern(r"[a-z0-9\-]{1,64}", "Use 1 to 64 of a-z, 0-9 and dash, with no capitals or spaces")
    .attrs(PLAIN);
const PLAIN: &str = "autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\"";
const WEBHOOK_RULE: &str = "The webhook is an https:// URL (http:// only on this host)";
const ADDRESS_RULE: &str = "Write it as name@domain";

const DISCORD: &[Spec] = &[
    NAME,
    Spec::secret("webhook", "Webhook URL")
        .optional()
        .hint("From the channel's settings in Discord. Needed the first time; leave it empty to keep the stored one.")
        .length(1, 512)
        .attrs("autocomplete=\"off\""),
];

const SECURITY: Choices = &[("starttls", "STARTTLS (usually port 587)"), ("tls", "TLS (usually port 465)")];

const SMTP: &[Spec] = &[
    NAME,
    Spec::text("host", "Server")
        .hint("The mail server's host name, such as smtp.example.com.")
        .pattern(r"\S{1,253}", "A host name has no spaces and is at most 253 characters")
        .attrs(PLAIN),
    Spec::text("port", "Port")
        .hint("1 to 65535; usually 587 for STARTTLS and 465 for TLS.")
        .pattern("[0-9]{1,5}", "The port is a number from 1 to 65535")
        .attrs("autocomplete=\"off\" inputmode=\"numeric\""),
    Spec::select("security", "Security", SECURITY),
    Spec::text("username", "User name")
        .optional()
        .hint("Leave it empty if the server needs no sign-in.")
        .pattern(r"\S{1,254}", "The user name has no spaces")
        .attrs(PLAIN),
    Spec::secret("password", "Password")
        .optional()
        .hint("Needed the first time with a user name; leave it empty to keep the stored one.")
        .attrs("autocomplete=\"new-password\""),
    Spec::text("from", "From").hint("The sender, as name@domain.").pattern(r"[^\s@]+@\S+", ADDRESS_RULE).attrs(PLAIN),
    Spec::text("to", "To").hint("The recipients, as name@domain, with commas between them.").attrs(PLAIN),
];

const NEEDED: &str = "This is needed: none is stored for a notifier of this name";

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
    show(web, ctx, StatusCode::OK, None, None)
}

/// The page, with the form that was refused as it was sent, or what came of Send test.
fn show(web: &Web, ctx: &Ctx, code: StatusCode, mut sent: Option<Form>, notice: Option<&str>) -> Response<Body> {
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
    let page = NotifiersPage {
        csrf: &ctx.csrf,
        running,
        saved: list,
        notice,
        sent_ok: code.is_success(),
        discord: Form::blank("discord", DISCORD).or_sent(&mut sent),
        smtp: Form::blank("smtp", SMTP).with("port", "587").or_sent(&mut sent),
    };
    html(code, page.render())
}

/// Send test: one message through every running notifier.
pub(super) async fn test(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(notify) = web.0.notify.as_ref().filter(|n| !n.names().is_empty()) else {
        return show(web, ctx, StatusCode::CONFLICT, None, Some("No notifier is running."));
    };
    let by = ctx.user.as_ref().map(|u| u.name.clone()).unwrap_or_default();
    let _ = web.0.audit.append(&format!("user:{by}"), "notifier.test", None, "{}").await;
    match notify.send_text("Test message from Rackhand", ctx.now_ms).await {
        Ok(()) => show(web, ctx, StatusCode::OK, None, Some("The test message was sent.")),
        Err(e) => show(web, ctx, StatusCode::BAD_GATEWAY, None, Some(&format!("The test failed: {e}"))),
    }
}

fn plain(v: &str, max: usize) -> bool {
    !v.is_empty() && v.len() <= max && !v.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn address(v: &str) -> bool {
    plain(v, 254) && v.split_once('@').is_some_and(|(user, host)| !user.is_empty() && !host.is_empty())
}

/// The Vault's name for a notifier's secret.
fn vault_name(name: &str, field: &str) -> String {
    format!("notifier.{name}.{field}")
}

/// A secret given in the form goes into the Vault; an empty one keeps the stored one.
async fn store(web: &Web, name: &str, given: &str) -> Result<String, &'static str> {
    if !given.is_empty()
        && let Err(e) = web.0.vault.put(name, &Secret::from(given)).await
    {
        tracing::error!(error = %e, "notifier secret");
        return Err("The secret couldn't be stored; try again.");
    }
    Ok(format!("secret:{name}"))
}

enum Made {
    Discord(DiscordSpec),
    Smtp(SmtpSpec),
}

/// A secret that has to be given, unless one is stored for the notifier already.
fn need_secret(web: &Web, form: &mut Form, field: &'static str) {
    if form.value(field).is_empty() && web.0.vault.get(&vault_name(form.value("name"), field)).is_err() {
        form.refuse(field, NEEDED);
    }
}

/// Checks the form before anything is stored.
fn check(web: &Web, form: &mut Form, kind: &str) {
    form.check();
    if kind == "discord" {
        let webhook = form.value("webhook").trim().to_string();
        let fits = auth::oidc::allowed_url(&webhook) && plain(&webhook, 512);
        form.require("webhook", fits, WEBHOOK_RULE);
        need_secret(web, form, "webhook");
        return;
    }
    let port = form.value("port").parse::<u16>().is_ok_and(|p| p > 0);
    form.require("port", port, "The port is a number from 1 to 65535");
    let host = plain(form.value("host"), 253);
    form.require("host", host, "A host name has no spaces and is at most 253 characters");
    let from = address(form.value("from"));
    form.require("from", from, ADDRESS_RULE);
    let to = recipients(form);
    form.require("to", !to.is_empty() && to.iter().all(|a| address(a)), "Write each recipient as name@domain");
    if !form.value("username").is_empty() {
        need_secret(web, form, "password");
    }
}

fn recipients(form: &Form) -> Vec<String> {
    form.value("to").split(',').map(|a| a.trim().to_string()).filter(|a| !a.is_empty()).collect()
}

async fn spec(web: &Web, form: &Form, kind: &str) -> Result<Made, &'static str> {
    let f = |k: &str| form.value(k).to_string();
    let name = f("name");
    if kind == "discord" {
        let webhook = store(web, &vault_name(&name, "webhook"), form.value("webhook").trim()).await?;
        return Ok(Made::Discord(DiscordSpec { name, webhook }));
    }
    let username = Some(f("username")).filter(|u| !u.is_empty());
    let password = match &username {
        Some(_) => Some(store(web, &vault_name(&name, "password"), form.value("password")).await?),
        None => None,
    };
    Ok(Made::Smtp(SmtpSpec {
        name,
        host: f("host"),
        port: f("port").parse().unwrap_or(587),
        security: f("security"),
        username,
        password,
        from: f("from"),
        to: recipients(form),
    }))
}

/// Adds a notifier, or replaces the one of that name; audited, and the change reaches the git mirror.
pub(super) async fn save(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = ctx.user.as_ref() else { return redirect("/sign-in") };
    let (kind, id, specs) = match ctx.form.get("kind").map(|k| k.trim()) {
        Some("discord") => ("discord", "discord", DISCORD),
        Some("smtp") => ("smtp", "smtp", SMTP),
        _ => return show(web, ctx, StatusCode::BAD_REQUEST, None, Some("The kind is discord or smtp.")),
    };
    let mut form = Form::sent(id, specs, ctx, &web.0.held);
    check(web, &mut form, kind);
    if !form.ok() {
        form.hold(&web.0.held, ctx);
        return show(web, ctx, StatusCode::BAD_REQUEST, Some(form), None);
    }
    // what couldn't be saved is on the form, to be sent again
    let failed = |mut form: Form, why: &str| {
        form.notice(why);
        form.hold(&web.0.held, ctx);
        show(web, ctx, StatusCode::INTERNAL_SERVER_ERROR, Some(form), None)
    };
    let name = form.value("name").to_string();
    let Ok(mut current) = saved(web) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "config/notifiers.toml couldn't be read");
    };
    let spec = match spec(web, &form, kind).await {
        Ok(s) => s,
        Err(why) => return failed(form, why),
    };
    current.discord.retain(|d| d.name != name);
    current.smtp.retain(|s| s.name != name);
    match spec {
        Made::Discord(d) => current.discord.push(d),
        Made::Smtp(s) => current.smtp.push(s),
    }
    let text = match file::to_toml(&current) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "notifiers");
            return failed(form, "The notifiers couldn't be saved; try again.");
        }
    };
    if let Err(e) = config::put(&web.0.db, FILE, &text, &user.name, ctx.now_ms).await {
        tracing::error!(error = %e, "notifiers");
        return failed(form, "The notifiers couldn't be saved; try again.");
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
