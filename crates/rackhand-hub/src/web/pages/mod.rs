//! Page handlers, called by the gate once its checks have passed.

pub(crate) mod account;
mod add;
mod appliance;
mod approvals;
mod assistant;
mod audit;
mod find;
mod first_run;
mod jobs;
mod library;
mod machines;
mod monitoring;
mod notifiers;
mod overview;
mod patching;
mod peers;
mod security;
mod settings;
mod users;

use askama::Template;
use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode, header};

pub(crate) use first_run::Drafts as FirstRunDrafts;

use super::routes::Page;
use super::ui::{self, Shell};
use super::{Ctx, Web, auth};

pub(crate) async fn render(web: &Web, page: Page, ctx: &Ctx) -> Response<Body> {
    match page {
        Page::Healthz => plain(StatusCode::OK, "ok"),
        Page::Vendor => vendor(ctx.path.strip_prefix("/static/vendor/").unwrap_or("")),
        Page::InstallScript => add::release_file(web, "install.sh"),
        Page::ReleaseFile => add::release_file(web, ctx.path.strip_prefix("/release/").unwrap_or("")),
        Page::AppCss => own("text/css", ui::APP_CSS),
        Page::AppJs => own("text/javascript", ui::APP_JS),
        Page::Icon => own("image/svg+xml", ui::MARK.as_bytes()),
        Page::Version => version(),
        Page::Theme => theme(ctx),
        Page::Find => find::page(web, ctx),
        Page::About => about(web, ctx),
        Page::Shortcuts => shortcuts(web, ctx),
        Page::Users => users::page(web, ctx),
        Page::NotFound => status(StatusCode::NOT_FOUND, "Not found. The address may be old, or mistyped."),
        Page::FormsJs => own("text/javascript", ui::FORMS_JS),
        Page::PasskeyJs => own("text/javascript", PASSKEY_JS),
        Page::SignIn => auth::flow::password_page(web, ctx),
        Page::SignInSubmit => auth::flow::password_step(web, ctx).await,
        Page::SignInCode => auth::flow::code_page(web, ctx),
        Page::SignInCodeSubmit => auth::flow::code_step(web, ctx).await,
        Page::SignOut => auth::flow::sign_out(web, ctx).await,
        Page::StepUp => auth::flow::step_up_page(web, ctx),
        Page::StepUpSubmit => auth::flow::step_up(web, ctx).await,
        Page::FirstRunForm => first_run::form(web, ctx),
        Page::FirstRunSubmit => first_run::submit(web, ctx).await,
        Page::FirstRunFactor => first_run::factor(web, ctx),
        Page::FirstRunFactorSubmit => first_run::factor_submit(web, ctx).await,
        Page::Overview => overview::page(web, ctx),
        Page::Settings => settings::page(web, ctx),
        Page::SettingsSources => settings::sources(web, ctx).await,
        Page::SettingsGitMirror => settings::git_mirror(web, ctx).await,
        Page::SettingsDeadman => settings::deadman(web, ctx).await,
        Page::AcceptHostKey => machines::accept_host_key(web, ctx).await,
        Page::BindingConfirm => machines::confirm_binding(web, ctx).await,
        Page::MachineLevel => machines::level(web, ctx).await,
        Page::Add => add::page(web, ctx),
        Page::AddMachine => add::machine(web, ctx).await,
        Page::AddInvite => add::invite(web, ctx).await,
        Page::AddAppliance => appliance::start(web, ctx).await,
        Page::AddApplianceAccept => appliance::accept(web, ctx).await,
        Page::UserCreate => users::create(web, ctx).await,
        Page::UserRole => users::change_role(web, ctx).await,
        Page::UserDisable => users::disable(web, ctx).await,
        Page::DeviceRevoke => users::revoke_device(web, ctx).await,
        Page::Account => account::page(web, ctx),
        Page::PasskeyRegisterOptions => auth::passkey::register_options(web, ctx),
        Page::PasskeyRegister => auth::passkey::register(web, ctx).await,
        Page::PasskeySignInOptions => auth::passkey::sign_in_options(web, ctx),
        Page::PasskeySignIn => auth::passkey::sign_in(web, ctx).await,
        Page::PasskeyStepUpOptions => auth::passkey::step_up_options(web, ctx),
        Page::PasskeyStepUp => auth::passkey::step_up(web, ctx).await,
        Page::OidcStart => auth::oidc::start(web, ctx).await,
        Page::OidcCallback => auth::oidc::callback(web, ctx).await,
        Page::SettingsOidc => settings::oidc(web, ctx).await,
        Page::Approvals => approvals::page(web, ctx),
        Page::ApprovalApprove => approvals::decide(web, ctx, true).await,
        Page::ApprovalReject => approvals::decide(web, ctx, false).await,
        Page::Jobs => jobs::list(web, ctx),
        Page::Job => jobs::detail(web, ctx),
        Page::Library => library::list(web, ctx),
        Page::LibraryItem => library::item(web, ctx),
        Page::LibrarySave => library::save(web, ctx).await,
        Page::DraftApply => library::apply_draft(web, ctx).await,
        Page::Patching => patching::page(web, ctx),
        Page::PolicySave => patching::save_policy(web, ctx).await,
        Page::WindowSave => patching::save_window(web, ctx).await,
        Page::Site => monitoring::site(web, ctx),
        Page::Machine => monitoring::machine(web, ctx),
        Page::MachineVitals => monitoring::vitals(web, ctx),
        Page::Incidents => monitoring::incidents(web, ctx),
        Page::Incident => monitoring::incident(web, ctx),
        Page::Audit => audit::page(web, ctx),
        Page::Security => security::page(web, ctx),
        Page::Keys => assistant::keys_page(web, ctx),
        Page::KeyCreate => assistant::create_key(web, ctx).await,
        Page::KeyRevoke => assistant::revoke_key(web, ctx).await,
        Page::AssistantSettings => assistant::settings_page(web, ctx),
        Page::AssistantInvite => assistant::invite(web, ctx).await,
        Page::AssistantCap => assistant::set_cap(web, ctx).await,
        Page::IncidentResume => assistant::resume(web, ctx).await,
        Page::SecurityRuleSave => security::save_rule(web, ctx).await,
        Page::SettingsNotifiers => notifiers::page(web, ctx),
        Page::NotifierSave => notifiers::save(web, ctx).await,
        Page::NotifierTest => notifiers::test(web, ctx).await,
        Page::Peers => peers::page(web, ctx),
        Page::PeersJoin => peers::join(web, ctx).await,
        Page::PeerSettings => peers::settings(web, ctx).await,
        Page::PeerUnlink => peers::unlink(web, ctx).await,
        Page::PeerRequest => peers::request(web, ctx).await,
        Page::RelayListsSave => peers::relay_lists(web, ctx).await,
        // answered before the gate (bearer token, no session)
        Page::Metrics => status(StatusCode::NOT_FOUND, "Not here"),
    }
}

/// What a page that is only a message says; the gate draws it in the shell of whoever is signed in.
#[derive(Debug, Clone)]
pub(crate) struct Said {
    title: &'static str,
    text: String,
}

#[derive(Template)]
#[template(path = "message.html")]
struct Message<'a> {
    shell: Shell,
    text: &'a str,
}

#[derive(Template)]
#[template(path = "message_alone.html")]
struct MessageAlone<'a> {
    theme: &'a str,
    title: &'a str,
    text: &'a str,
}

/// A message, drawn for the person who gets it.
pub(crate) fn said(web: &Web, ctx: &Ctx, code: StatusCode, said: &Said) -> Response<Body> {
    if ctx.user.is_some() {
        return html(code, Message { shell: Shell::new(web, ctx, said.title), text: &said.text }.render());
    }
    html(code, MessageAlone { theme: ui::theme(ctx), title: said.title, text: &said.text }.render())
}

#[derive(Template)]
#[template(path = "about.html")]
struct About {
    shell: Shell,
}

fn about(web: &Web, ctx: &Ctx) -> Response<Body> {
    html(StatusCode::OK, About { shell: Shell::new(web, ctx, "About") }.render())
}

#[derive(Template)]
#[template(path = "shortcuts.html")]
struct Shortcuts {
    shell: Shell,
}

fn shortcuts(web: &Web, ctx: &Ctx) -> Response<Body> {
    html(StatusCode::OK, Shortcuts { shell: Shell::new(web, ctx, "Keyboard shortcuts") }.render())
}

/// Which hub this is: a page that was open while it was updated notices by it.
fn version() -> Response<Body> {
    let mut resp =
        Response::new(Body::from(serde_json::json!({ "version": ui::VERSION, "build": ui::build() }).to_string()));
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

/// The theme, kept in the browser: the system's when nothing is chosen.
fn theme(ctx: &Ctx) -> Response<Body> {
    let chosen = match ctx.form.get("theme").map(String::as_str) {
        Some("light") => super::session::cookie(ui::THEME_COOKIE, "light", 31_536_000),
        Some("dark") => super::session::cookie(ui::THEME_COOKIE, "dark", 31_536_000),
        _ => super::session::cookie(ui::THEME_COOKIE, "", 0),
    };
    let mut resp = see_other(ui::local(ctx.form.get("back").map(String::as_str).unwrap_or("/")));
    if let Ok(v) = HeaderValue::from_str(&chosen) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

pub(crate) fn see_other(to: &str) -> Response<Body> {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(v) = HeaderValue::from_str(to) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

/// What's said where nothing was reported.
pub(crate) fn shown(text: &str) -> &str {
    if text.is_empty() { "Not reported" } else { text }
}

pub(crate) fn html(status: StatusCode, rendered: askama::Result<String>) -> Response<Body> {
    match rendered {
        Ok(body) => {
            let mut resp = Response::new(Body::from(body));
            *resp.status_mut() = status;
            resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
            resp
        }
        Err(e) => {
            tracing::error!(error = %e, "template");
            plain(StatusCode::INTERNAL_SERVER_ERROR, "template error")
        }
    }
}

#[derive(Template)]
#[template(path = "continue.html")]
struct Continue<'a> {
    theme: &'a str,
    title: &'a str,
    text: &'a str,
    to: &'a str,
}

/// A short page that moves on to `to` by itself (a same-site navigation, unlike a redirect from another site).
pub(crate) fn html_text(code: StatusCode, title: &str, text: &str, to: Option<&str>) -> Response<Body> {
    match to {
        Some(to) => html(code, Continue { theme: "", title, text, to }.render()),
        None => html(code, MessageAlone { theme: "", title, text }.render()),
    }
}

pub(crate) fn status(code: StatusCode, text: &str) -> Response<Body> {
    let title = match code {
        StatusCode::NOT_FOUND => "Not found",
        StatusCode::FORBIDDEN => "Not allowed",
        StatusCode::TOO_MANY_REQUESTS => "Too many attempts",
        c if c.is_server_error() => "Something went wrong",
        _ => "That didn't work",
    };
    let mut resp = html(code, MessageAlone { theme: "", title, text }.render());
    resp.extensions_mut().insert(Said { title, text: text.to_string() });
    resp
}

pub(crate) fn plain(code: StatusCode, text: &'static str) -> Response<Body> {
    let mut resp = Response::new(Body::from(text));
    *resp.status_mut() = code;
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    resp
}

pub(crate) fn redirect(to: &'static str) -> Response<Body> {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut().insert(header::LOCATION, HeaderValue::from_static(to));
    resp
}

/// The browser half of passkeys: no inline script, so it is a static file (the CSP allows `'self'` only).
const PASSKEY_JS: &[u8] = include_bytes!("../../../static/passkey.js");
/// The vendored files (D9), embedded at build time.
const VENDOR: &[(&str, &str, &[u8])] = &[
    ("htmx-2.0.11.min.js", "text/javascript", include_bytes!("../../../static/vendor/htmx-2.0.11.min.js")),
    ("uPlot-1.6.32.iife.min.js", "text/javascript", include_bytes!("../../../static/vendor/uPlot-1.6.32.iife.min.js")),
    ("uPlot-1.6.32.min.css", "text/css", include_bytes!("../../../static/vendor/uPlot-1.6.32.min.css")),
];

fn asset(content_type: &'static str, bytes: &'static [u8]) -> Response<Body> {
    let mut resp = Response::new(Body::from(bytes));
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=86400"));
    resp
}

/// One of the hub's own files: short-lived in a cache, so an updated hub's pages don't wait a day for their styles.
fn own(content_type: &'static str, bytes: &'static [u8]) -> Response<Body> {
    let mut resp = asset(content_type, bytes);
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=300"));
    resp
}

fn vendor(name: &str) -> Response<Body> {
    match VENDOR.iter().find(|(n, _, _)| *n == name) {
        Some((_, content_type, bytes)) => asset(content_type, bytes),
        None => status(StatusCode::NOT_FOUND, "Not found"),
    }
}
