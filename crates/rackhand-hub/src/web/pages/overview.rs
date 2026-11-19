//! Overview (7.7.1): sites and machines. The pages for monitoring fill this in (T39).

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};

use super::{html, status};
use crate::web::{Ctx, Web};

pub(super) struct MachineRow {
    pub site: String,
    pub name: String,
    pub kind: String,
    pub state: String,
}

#[derive(Template)]
#[template(path = "overview.html")]
struct Overview<'a> {
    user: &'a str,
    sites: Vec<String>,
    machines: Vec<MachineRow>,
}

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    let data = web.0.db.readers().with(|c| {
        let mut s = c.prepare("SELECT name FROM sites ORDER BY is_local DESC, name")?;
        let sites = s.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
        let mut m = c.prepare(
            "SELECT s.name, m.name, m.kind, m.state FROM machines m JOIN sites s ON s.id = m.site_id ORDER BY s.name, m.name",
        )?;
        let machines = m
            .query_map([], |r| Ok(MachineRow { site: r.get(0)?, name: r.get(1)?, kind: r.get(2)?, state: r.get(3)? }))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((sites, machines))
    });
    let Ok((sites, machines)) = data else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The database couldn't be read");
    };
    let user = ctx.user.as_ref().map(|u| u.name.as_str()).unwrap_or("");
    html(StatusCode::OK, Overview { user, sites, machines }.render())
}
