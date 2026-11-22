//! Find: the header's search and the command palette, over the places someone can open, the machines and the incidents.

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};

use super::html;
use crate::web::ui::{self, Shell};
use crate::web::{Ctx, Web};

struct Found {
    href: String,
    name: String,
    what: String,
    icon: &'static str,
}

#[derive(Template)]
#[template(path = "find.html")]
struct FindPage {
    shell: Shell,
    q: String,
    found: Vec<Found>,
}

const MOST: usize = 30;

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    let q = ui::query(ctx);
    let shell = Shell::new(web, ctx, "Find");
    let mut found: Vec<Found> = shell
        .places
        .iter()
        .filter(|p| ui::found(&q, &[p.name]))
        .map(|p| Found { href: p.path.into(), name: p.name.into(), what: "Page".into(), icon: p.icon })
        .collect();
    found.extend(shell.sites.iter().filter(|s| ui::found(&q, &[s.as_str()])).map(|s| Found {
        href: format!("/sites/{s}"),
        name: s.clone(),
        what: "Site".into(),
        icon: "dns",
    }));
    if !q.is_empty() {
        let machines = super::overview::machines(web, ctx.now_ms, None).unwrap_or_default();
        found.extend(machines.into_iter().filter(|m| m.matches(&q)).take(MOST).map(|m| Found {
            href: format!("/machines/{}", m.id),
            name: m.name,
            what: format!("Machine at {}", m.site),
            icon: "computer",
        }));
        let incidents = super::monitoring::open_incidents(web);
        found.extend(incidents.into_iter().filter(|i| ui::found(&q, &[&i.title, &i.machine])).take(MOST).map(|i| Found {
            href: format!("/incidents/{}", i.id),
            name: i.title,
            what: format!("Incident on {}", i.machine),
            icon: "warning",
        }));
    }
    html(StatusCode::OK, FindPage { shell, q, found }.render())
}
