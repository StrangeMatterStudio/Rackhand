//! Page handlers, called by the gate once its checks have passed.

mod account;
mod add;
mod appliance;
mod approvals;
mod audit;
mod first_run;
mod jobs;
mod library;
mod machines;
mod monitoring;
mod notifiers;
mod overview;
mod patching;
mod settings;
mod users;

use askama::Template;
use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode, header};

use super::routes::Page;
use super::{Ctx, Web, auth};

pub(crate) async fn render(web: &Web, page: Page, ctx: &Ctx) -> Response<Body> {
    match page {
        Page::Healthz => plain(StatusCode::OK, "ok"),
        Page::Vendor => vendor(ctx.path.strip_prefix("/static/vendor/").unwrap_or("")),
        Page::InstallScript => add::release_file(web, "install.sh"),
        Page::ReleaseFile => add::release_file(web, ctx.path.strip_prefix("/release/").unwrap_or("")),
        Page::AppCss => asset("text/css", APP_CSS),
        Page::PasskeyJs => asset("text/javascript", PASSKEY_JS),
        Page::SignIn => auth::flow::password_page(web, ctx),
        Page::SignInSubmit => auth::flow::password_step(web, ctx).await,
        Page::SignInCode => auth::flow::code_page(web, ctx),
        Page::SignInCodeSubmit => auth::flow::code_step(web, ctx).await,
        Page::SignOut => auth::flow::sign_out(web, ctx).await,
        Page::StepUp => auth::flow::step_up_page(web, ctx),
        Page::StepUpSubmit => auth::flow::step_up(web, ctx).await,
        Page::FirstRunForm => first_run::form(web, ctx),
        Page::FirstRunSubmit => first_run::submit(web, ctx).await,
        Page::Overview => overview::page(web, ctx),
        Page::Settings => settings::page(web, ctx),
        Page::SettingsSources => settings::sources(web, ctx).await,
        Page::SettingsGitMirror => settings::git_mirror(web, ctx).await,
        Page::AcceptHostKey => machines::accept_host_key(web, ctx).await,
        Page::BindingConfirm => machines::confirm_binding(web, ctx).await,
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
        Page::SettingsNotifiers => notifiers::page(web, ctx),
        Page::NotifierSave => notifiers::save(web, ctx).await,
        Page::NotifierTest => notifiers::test(web, ctx).await,
        // answered before the gate (bearer token, no session)
        Page::Metrics => status(StatusCode::NOT_FOUND, "Not here"),
    }
}

#[derive(Template)]
#[template(path = "message.html")]
struct Message<'a> {
    title: &'a str,
    text: &'a str,
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
    title: &'a str,
    text: &'a str,
    to: &'a str,
}

/// A short page that moves on to `to` by itself (a same-site navigation, unlike a redirect from another site).
pub(crate) fn html_text(code: StatusCode, title: &str, text: &str, to: Option<&str>) -> Response<Body> {
    match to {
        Some(to) => html(code, Continue { title, text, to }.render()),
        None => html(code, Message { title, text }.render()),
    }
}

pub(crate) fn status(code: StatusCode, text: &str) -> Response<Body> {
    let title = code.canonical_reason().unwrap_or("Error");
    html(code, Message { title, text }.render())
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

const APP_CSS: &[u8] = include_bytes!("../../../static/app.css");
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

fn vendor(name: &str) -> Response<Body> {
    match VENDOR.iter().find(|(n, _, _)| *n == name) {
        Some((_, content_type, bytes)) => asset(content_type, bytes),
        None => status(StatusCode::NOT_FOUND, "Not found"),
    }
}
