//! Audit (7.7.1, 12): the chain's state, with a critical banner when it doesn't verify, and the newest entries.

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};

use super::html;
use super::monitoring::when;
use crate::web::{Ctx, Web};

pub(super) struct Entry {
    pub seq: i64,
    pub at: String,
    pub actor: String,
    pub action: String,
    pub target: String,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditPage {
    broken: Option<String>,
    rows: usize,
    entries: Vec<Entry>,
}

pub(super) fn page(web: &Web, _ctx: &Ctx) -> Response<Body> {
    let (broken, rows) = match crate::audit::verify(web.0.db.readers()) {
        Ok(report) => (None, report.rows),
        Err(e) => (Some(e.to_string()), 0),
    };
    let entries = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT seq, at_ms, actor, action, coalesce(target, '') FROM audit_log ORDER BY seq DESC LIMIT 100",
            )?;
            s.query_map([], |r| {
                Ok(Entry {
                    seq: r.get(0)?,
                    at: when(r.get(1)?),
                    actor: r.get(2)?,
                    action: r.get(3)?,
                    target: r.get(4)?,
                })
            })?
            .collect()
        })
        .unwrap_or_default();
    html(StatusCode::OK, AuditPage { broken, rows, entries }.render())
}
