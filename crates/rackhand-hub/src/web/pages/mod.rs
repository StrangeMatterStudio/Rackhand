//! Page handlers, called by the gate once its checks have passed.

mod first_run;
mod machines;
mod overview;
mod settings;

use askama::Template;
use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode, header};

use super::routes::Page;
use super::{Ctx, Web, auth};

pub(crate) async fn render(web: &Web, page: Page, ctx: &Ctx) -> Response<Body> {
    match page {
        Page::Healthz => plain(StatusCode::OK, "ok"),
        Page::Vendor => vendor(ctx.path.strip_prefix("/static/vendor/").unwrap_or("")),
        Page::AppCss => asset("text/css", APP_CSS),
        Page::SignIn => auth::flow::password_page(ctx),
        Page::SignInSubmit => auth::flow::password_step(web, ctx).await,
        Page::SignInCode => auth::flow::code_page(web, ctx),
        Page::SignInCodeSubmit => auth::flow::code_step(web, ctx).await,
        Page::SignOut => auth::flow::sign_out(web, ctx).await,
        Page::StepUp => auth::flow::step_up_page(ctx),
        Page::StepUpSubmit => auth::flow::step_up(web, ctx).await,
        Page::FirstRunForm => first_run::form(web, ctx),
        Page::FirstRunSubmit => first_run::submit(web, ctx).await,
        Page::Overview => overview::page(web, ctx),
        Page::Settings => settings::page(web, ctx),
        Page::SettingsSources => settings::sources(web, ctx).await,
        Page::SettingsGitMirror => settings::git_mirror(web, ctx).await,
        Page::AcceptHostKey => machines::accept_host_key(web, ctx).await,
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
