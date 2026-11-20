//! The pages for monitoring (7.7.1): site, machine (with its vitals refreshed by htmx), incidents, and Settings:
//! Notifiers with Send test.

use std::collections::BTreeMap;

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use rusqlite::OptionalExtension;

use super::{html, html_text, status};
use crate::web::{Ctx, Web};

pub(super) fn when(ms: i64) -> String {
    jiff::Timestamp::from_millisecond(ms).map(|t| t.to_string()).unwrap_or_default()
}

pub(super) struct IncidentView {
    pub id: String,
    pub machine: String,
    pub severity: String,
    pub state: String,
    pub title: String,
    pub opened: String,
}

const INCIDENT_COLUMNS: &str = "i.id, coalesce(m.name, 'hub'), i.severity, i.state, i.title, i.opened_at";

fn incident_view(r: &rusqlite::Row<'_>) -> rusqlite::Result<IncidentView> {
    Ok(IncidentView {
        id: r.get(0)?,
        machine: r.get(1)?,
        severity: r.get(2)?,
        state: r.get(3)?,
        title: r.get(4)?,
        opened: when(r.get(5)?),
    })
}

#[derive(Template)]
#[template(path = "machine.html")]
struct MachinePage {
    id: String,
    name: String,
    site: String,
    kind: String,
    os: String,
    access: String,
    state: String,
    capture: &'static str,
    silent_since: Option<String>,
    incidents: Vec<IncidentView>,
    services: Vec<(String, String)>,
    containers: Vec<(String, String)>,
}

fn capture(caps: &[i32]) -> &'static str {
    use rackhand_proto::probe::Capability;
    if caps.contains(&(Capability::Ebpf as i32)) {
        "eBPF"
    } else if caps.contains(&(Capability::Sampling as i32)) {
        "sampling"
    } else {
        "not reported"
    }
}

/// When a machine went silent, if its silence incident is open: its last report, or when the incident opened.
fn silent_since(web: &Web, id: &str) -> Option<String> {
    let opened: Option<i64> = web
        .0
        .db
        .readers()
        .with(|c| {
            c.query_row(
                "SELECT opened_at FROM incidents WHERE machine_id = ?1 AND kind = 'machine.silent' AND state != 'resolved'",
                [id],
                |r| r.get(0),
            )
            .optional()
        })
        .ok()
        .flatten();
    let opened = opened?;
    let last = web.0.ingest.as_ref().and_then(|i| i.last_seen(id));
    Some(when(last.unwrap_or(opened)))
}

pub(super) fn machine(web: &Web, ctx: &Ctx) -> Response<Body> {
    let id = ctx.path.strip_prefix("/machines/").unwrap_or("").to_string();
    let found = web.0.db.readers().with(|c| {
        c.query_row(
            "SELECT m.name, s.name, m.kind, coalesce(m.os, ''), m.access, m.state FROM machines m
             JOIN sites s ON s.id = m.site_id WHERE m.id = ?1",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .optional()
    });
    let (name, site, kind, os, access, state): (String, String, String, String, String, String) = match found {
        Ok(Some(row)) => row,
        Ok(None) => return status(StatusCode::NOT_FOUND, "No such machine"),
        Err(_) => return status(StatusCode::INTERNAL_SERVER_ERROR, "The database couldn't be read"),
    };
    let incidents = web
        .0
        .db
        .readers()
        .with(|c| {
            let sql = format!(
                "SELECT {INCIDENT_COLUMNS} FROM incidents i LEFT JOIN machines m ON m.id = i.machine_id
                 WHERE i.machine_id = ?1 AND i.state != 'resolved' ORDER BY i.opened_at DESC"
            );
            let mut s = c.prepare(&sql)?;
            s.query_map([&id], incident_view)?.collect()
        })
        .unwrap_or_default();
    let latest = web.0.ingest.as_ref().and_then(|i| i.latest(&id));
    let services = latest
        .as_ref()
        .map(|l| {
            l.services_json()
                .iter()
                .map(|s| (s["name"].as_str().unwrap_or("").into(), s["state"].as_str().unwrap_or("").into()))
                .collect()
        })
        .unwrap_or_default();
    let containers = latest
        .as_ref()
        .map(|l| l.containers.iter().map(|c| (c.name.clone(), c.state.clone())).collect())
        .unwrap_or_default();
    let caps = web.0.ingest.as_ref().map(|i| i.capabilities(&id)).unwrap_or_default();
    let page = MachinePage {
        silent_since: silent_since(web, &id),
        id,
        name,
        site,
        kind,
        os,
        access,
        state,
        capture: capture(&caps),
        incidents,
        services,
        containers,
    };
    html(StatusCode::OK, page.render())
}

pub(super) struct VitalRow {
    pub metric: &'static str,
    pub last: String,
    pub min: String,
    pub max: String,
    /// The SVG polyline's points, 300 by 40.
    pub line: String,
}

/// A line chart's points scaled into a 300 by 40 box.
fn polyline(points: &[(i64, f64)]) -> String {
    let (Some(first), Some(last)) = (points.first(), points.last()) else { return String::new() };
    let span_t = (last.0 - first.0).max(1) as f64;
    let lo = points.iter().map(|p| p.1).fold(f64::INFINITY, f64::min);
    let hi = points.iter().map(|p| p.1).fold(f64::NEG_INFINITY, f64::max);
    let span_v = if hi > lo { hi - lo } else { 1.0 };
    points
        .iter()
        .map(|(t, v)| format!("{:.1},{:.1}", (t - first.0) as f64 / span_t * 300.0, 38.0 - (v - lo) / span_v * 36.0))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Template)]
#[template(path = "vitals.html")]
struct Vitals {
    rows: Vec<VitalRow>,
}

const CHARTED: [&str; 4] = ["cpu.busy_pct", "mem.used_pct", "load.1m", "swap.used_pct"];

/// The machine's last hour of vitals: the htmx partial its page refreshes.
pub(super) fn vitals(web: &Web, ctx: &Ctx) -> Response<Body> {
    let id = ctx.path.strip_prefix("/machines/").and_then(|p| p.strip_suffix("/vitals")).unwrap_or("");
    let Some(ingest) = web.0.ingest.as_ref() else { return status(StatusCode::SERVICE_UNAVAILABLE, "No vitals yet") };
    let rows = CHARTED
        .iter()
        .filter_map(|metric| {
            let points =
                crate::query::vitals::vitals(ingest, id, metric, &BTreeMap::new(), ctx.now_ms - 3_600_000, ctx.now_ms);
            let last = points.last()?.1;
            let min = points.iter().map(|p| p.1).fold(f64::INFINITY, f64::min);
            let max = points.iter().map(|p| p.1).fold(f64::NEG_INFINITY, f64::max);
            Some(VitalRow {
                metric,
                last: format!("{last:.2}"),
                min: format!("{min:.2}"),
                max: format!("{max:.2}"),
                line: polyline(&points),
            })
        })
        .collect();
    html(StatusCode::OK, Vitals { rows }.render())
}

#[derive(Template)]
#[template(path = "incidents.html")]
struct IncidentsPage {
    open: Vec<IncidentView>,
    resolved: Vec<IncidentView>,
}

pub(super) fn incidents(web: &Web, ctx: &Ctx) -> Response<Body> {
    let list = |unresolved: bool| {
        web.0
            .db
            .readers()
            .with(|c| {
                let sql = format!(
                    "SELECT {INCIDENT_COLUMNS} FROM incidents i LEFT JOIN machines m ON m.id = i.machine_id
                     WHERE (i.state != 'resolved') = ?1 AND (?1 OR i.resolved_at >= ?2)
                     ORDER BY i.opened_at DESC LIMIT 500"
                );
                let mut s = c.prepare(&sql)?;
                s.query_map(rusqlite::params![unresolved, ctx.now_ms - 7 * 86_400_000], incident_view)?.collect()
            })
            .unwrap_or_default()
    };
    html(StatusCode::OK, IncidentsPage { open: list(true), resolved: list(false) }.render())
}

#[derive(Template)]
#[template(path = "incident.html")]
struct IncidentPage {
    incident: IncidentView,
    events: Vec<(String, String, String)>,
}

pub(super) fn incident(web: &Web, ctx: &Ctx) -> Response<Body> {
    let id = ctx.path.strip_prefix("/incidents/").unwrap_or("");
    let found = web.0.db.readers().with(|c| {
        let sql = format!(
            "SELECT {INCIDENT_COLUMNS} FROM incidents i LEFT JOIN machines m ON m.id = i.machine_id WHERE i.id = ?1"
        );
        let Some(incident) = c.query_row(&sql, [id], incident_view).optional()? else { return Ok(None) };
        let mut s =
            c.prepare("SELECT at_ms, kind, data FROM incident_events WHERE incident_id = ?1 ORDER BY at_ms, rowid")?;
        let events = s
            .query_map([id], |r| Ok((when(r.get(0)?), r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some((incident, events)))
    });
    match found {
        Ok(Some((incident, events))) => html(StatusCode::OK, IncidentPage { incident, events }.render()),
        Ok(None) => status(StatusCode::NOT_FOUND, "No such incident"),
        Err(_) => status(StatusCode::INTERNAL_SERVER_ERROR, "The database couldn't be read"),
    }
}

#[derive(Template)]
#[template(path = "site.html")]
struct SitePage {
    name: String,
    machines: Vec<(String, String, String)>,
}

pub(super) fn site(web: &Web, ctx: &Ctx) -> Response<Body> {
    let key = ctx.path.strip_prefix("/sites/").unwrap_or("");
    let found = web.0.db.readers().with(|c| {
        let Some((id, name)) = c
            .query_row("SELECT id, name FROM sites WHERE id = ?1 OR name = ?1", [key], |r| {
                Ok((r.get::<_, String>(0)?, r.get(1)?))
            })
            .optional()?
        else {
            return Ok(None);
        };
        let mut s = c.prepare("SELECT id, name, state FROM machines WHERE site_id = ?1 ORDER BY name")?;
        let machines =
            s.query_map([&id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some((name, machines)))
    });
    match found {
        Ok(Some((name, machines))) => html(StatusCode::OK, SitePage { name, machines }.render()),
        Ok(None) => status(StatusCode::NOT_FOUND, "No such site"),
        Err(_) => status(StatusCode::INTERNAL_SERVER_ERROR, "The database couldn't be read"),
    }
}

#[derive(Template)]
#[template(path = "notifiers.html")]
struct NotifiersPage<'a> {
    csrf: &'a str,
    names: Vec<String>,
}

pub(super) fn notifiers(web: &Web, ctx: &Ctx) -> Response<Body> {
    let names = web.0.notify.as_ref().map(|n| n.names()).unwrap_or_default();
    html(StatusCode::OK, NotifiersPage { csrf: &ctx.csrf, names }.render())
}

/// Settings: Notifiers, Send test: one message through every notifier.
pub(super) async fn notifier_test(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(notify) = web.0.notify.as_ref() else {
        return html_text(StatusCode::CONFLICT, "Notifiers", "No notifier is configured.", Some("/settings/notifiers"));
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
