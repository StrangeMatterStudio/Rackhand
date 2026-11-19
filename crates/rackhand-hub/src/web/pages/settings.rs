//! Settings (7.7.1, 7.8): each change is a new revision of `config/hub.toml` and an audit row (FR-26).

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};

use super::{html, redirect, status};
use crate::library::config::{self, HubConfig, Sources};
use crate::web::{Ctx, Web};

#[derive(Template)]
#[template(path = "settings.html")]
struct Settings<'a> {
    csrf: &'a str,
    sources: Sources,
}

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Ok(current) = config::hub(&web.0.db) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "Settings unreadable");
    };
    html(StatusCode::OK, Settings { csrf: &ctx.csrf, sources: current.sources }.render())
}

pub(super) async fn sources(web: &Web, ctx: &Ctx) -> Response<Body> {
    let on = |k: &str| ctx.form.get(k).is_some_and(|v| v == "on");
    let sources = Sources { feodo: on("source_feodo"), spamhaus: on("source_spamhaus"), dbip: on("source_dbip") };
    let Some(user) = ctx.user.as_ref() else { return redirect("/sign-in") };
    let content = HubConfig { sources }.to_toml();
    if let Err(e) = config::put(&web.0.db, config::HUB, &content, &user.name, ctx.now_ms).await {
        tracing::error!(error = %e, "settings");
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The settings couldn't be saved");
    }
    let data = serde_json::to_string(&sources).unwrap_or_default();
    if let Err(e) = web.0.audit.append(&user.name, "settings.sources", Some("config/hub"), &data).await {
        tracing::error!(error = %e, "audit");
    }
    redirect("/settings")
}
