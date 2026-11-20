//! Overview (7.7.1): sites, machines with their health, and the open incidents.

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};

use super::{html, status};
use crate::web::{Ctx, Web};

pub(super) struct MachineRow {
    pub id: String,
    pub site: String,
    pub name: String,
    pub kind: String,
    pub state: String,
    /// ok, warning, critical, silent, quarantined, pending or revoked.
    pub health: String,
}

#[derive(Template)]
#[template(path = "overview.html")]
struct Overview<'a> {
    user: &'a str,
    csrf: &'a str,
    sites: Vec<String>,
    machines: Vec<MachineRow>,
    open_incidents: i64,
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

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    let data = web.0.db.readers().with(|c| {
        let mut s = c.prepare("SELECT name FROM sites ORDER BY is_local DESC, name")?;
        let sites = s.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
        let mut m = c.prepare(
            "SELECT m.id, s.name, m.name, m.kind, m.state, m.quarantine,
                    EXISTS (SELECT 1 FROM incidents i WHERE i.machine_id = m.id AND i.kind = 'machine.silent'
                            AND i.state != 'resolved'),
                    (SELECT max(CASE i.severity WHEN 'critical' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END)
                       FROM incidents i WHERE i.machine_id = m.id AND i.state != 'resolved')
             FROM machines m JOIN sites s ON s.id = m.site_id ORDER BY s.name, m.name",
        )?;
        let machines = m
            .query_map([], |r| {
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
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let open: i64 = c.query_row("SELECT count(*) FROM incidents WHERE state != 'resolved'", [], |r| r.get(0))?;
        Ok((sites, machines, open))
    });
    let Ok((sites, machines, open_incidents)) = data else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The database couldn't be read");
    };
    let user = ctx.user.as_ref().map(|u| u.name.as_str()).unwrap_or("");
    html(StatusCode::OK, Overview { user, csrf: &ctx.csrf, sites, machines, open_incidents }.render())
}
