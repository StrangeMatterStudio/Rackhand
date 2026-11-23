//! Overview (7.7.1): what needs attention (open incidents, approvals waiting), then every machine with its health.

use std::collections::BTreeMap;

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};

use super::monitoring::{self, IncidentView};
use super::{html, status};
use crate::web::ui::{self, Shell};
use crate::web::{Ctx, Web};

pub(super) struct MachineRow {
    pub id: String,
    pub site: String,
    pub name: String,
    pub kind: String,
    pub state: String,
    /// ok, warning, critical, silent, quarantined, pending or revoked.
    pub health: String,
    pub policy: String,
    pub cpu: String,
    pub memory: String,
    pub updates: String,
    pub last_seen: String,
}

pub(super) struct Counts {
    pub healthy: usize,
    pub total: usize,
    pub incidents: i64,
    pub critical: i64,
    pub updates: u32,
    pub security: u32,
}

#[derive(Template)]
#[template(path = "overview.html")]
struct Overview {
    shell: Shell,
    q: String,
    counts: Counts,
    incidents: Vec<IncidentView>,
    approvals: Vec<(String, String, String)>,
    machines: Vec<MachineRow>,
}

fn health(state: &str, quarantine: &str, silent: bool, worst: Option<&str>) -> &'static str {
    match (state, quarantine, silent, worst) {
        ("revoked", ..) => "revoked",
        ("pending", ..) => "pending",
        (_, q, ..) if q != "none" => "quarantined",
        (_, _, true, _) => "silent",
        (_, _, _, Some("critical")) => "critical",
        (_, _, _, Some("warning")) => "warning",
        _ => "ok",
    }
}

/// `4 s ago`, for a last report.
pub(super) fn ago(then: i64, now: i64) -> String {
    match (now - then).max(0) / 1000 {
        s @ 0..=89 => format!("{s} s ago"),
        s @ 90..=5399 => format!("{} min ago", s / 60),
        s @ 5400..=129_599 => format!("{} h ago", s / 3600),
        s => format!("{} days ago", s / 86_400),
    }
}

/// The machines (of one site, or all), each with its health and what it last reported.
pub(super) fn machines(web: &Web, now: i64, site: Option<&str>) -> rusqlite::Result<Vec<MachineRow>> {
    let mut rows = web.0.db.readers().with(|c| {
        let mut m = c.prepare(
            "SELECT m.id, s.name, m.name, m.kind, m.state, m.quarantine,
                    EXISTS (SELECT 1 FROM incidents i WHERE i.machine_id = m.id AND i.kind = 'machine.silent'
                            AND i.state != 'resolved'),
                    (SELECT max(CASE i.severity WHEN 'critical' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END)
                       FROM incidents i WHERE i.machine_id = m.id AND i.state != 'resolved'),
                    coalesce(p.name, '')
             FROM machines m JOIN sites s ON s.id = m.site_id LEFT JOIN policies p ON p.id = m.policy_id
             WHERE ?1 IS NULL OR m.site_id = ?1 ORDER BY s.name, m.name",
        )?;
        m.query_map([site], |r| {
            let worst: Option<i64> = r.get(7)?;
            let worst = match worst {
                Some(2) => Some("critical"),
                Some(1) => Some("warning"),
                _ => None,
            };
            let (state, quarantine): (String, String) = (r.get(4)?, r.get(5)?);
            Ok(MachineRow {
                id: r.get(0)?,
                site: r.get(1)?,
                name: r.get(2)?,
                kind: r.get(3)?,
                health: health(&state, &quarantine, r.get(6)?, worst).to_string(),
                state,
                policy: r.get(8)?,
                cpu: String::new(),
                memory: String::new(),
                updates: String::new(),
                last_seen: String::new(),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
    })?;
    let Some(ingest) = web.0.ingest.as_ref() else { return Ok(rows) };
    for r in &mut rows {
        let last = |metric: &str| {
            crate::query::vitals::vitals(ingest, &r.id, metric, &BTreeMap::new(), now - 120_000, now)
                .last()
                .map(|p| format!("{:.0} %", p.1))
                .unwrap_or_default()
        };
        let (cpu, memory) = (last("cpu.busy_pct"), last("mem.used_pct"));
        (r.cpu, r.memory) = (cpu, memory);
        r.last_seen = ingest.last_seen(&r.id).map(|t| ago(t, now)).unwrap_or_default();
        if let Some(u) = ingest.latest(&r.id).and_then(|l| l.updates) {
            r.updates =
                if u.security > 0 { format!("{}, {} security", u.pending, u.security) } else { u.pending.to_string() };
        }
    }
    Ok(rows)
}

impl MachineRow {
    pub fn matches(&self, q: &str) -> bool {
        ui::found(q, &[&self.name, &self.site, &self.kind, &self.health, &self.state, &self.policy])
    }
}

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Ok(all) = machines(web, ctx.now_ms, None) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The database couldn't be read");
    };
    let updates = |id: &str| web.0.ingest.as_ref().and_then(|i| i.latest(id)).and_then(|l| l.updates);
    let reported: Vec<_> = all.iter().filter_map(|m| updates(&m.id)).collect();
    let incidents = monitoring::open_incidents(web);
    let approvals = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT tool, coalesce(target, ''), requested_by FROM approvals
                 WHERE state = 'pending' AND expires_at > ?1 ORDER BY expires_at LIMIT 5",
            )?;
            s.query_map([ctx.now_ms], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
        })
        .unwrap_or_default();
    let counts = Counts {
        healthy: all.iter().filter(|m| m.health == "ok").count(),
        total: all.len(),
        incidents: incidents.len() as i64,
        critical: incidents.iter().filter(|i| i.severity == "critical").count() as i64,
        updates: reported.iter().map(|u| u.pending).sum(),
        security: reported.iter().map(|u| u.security).sum(),
    };
    let q = ui::query(ctx);
    let machines = all.into_iter().filter(|m| m.matches(&q)).collect();
    let shell = Shell::new(web, ctx, "Overview");
    let page = Overview { shell, q, counts, incidents: incidents.into_iter().take(5).collect(), approvals, machines };
    html(StatusCode::OK, page.render())
}
