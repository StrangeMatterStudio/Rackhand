//! The pages for monitoring (7.7.1): site, machine (with its vitals refreshed by htmx) and incidents.

use std::collections::BTreeMap;

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use rusqlite::OptionalExtension;

use super::{html, status};
use crate::web::perms::{Permission, allowed};
use crate::web::ui::{self, Shell};
use crate::web::{Ctx, Web};

/// A moment as the pages show it, with its exact time in the element.
pub(super) fn when(ms: i64) -> String {
    ui::time(ms)
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
    shell: Shell,
    health: String,
    last_seen: String,
    policy: String,
    confirm: String,
    can_confirm: bool,
    /// The level the admin may change it to, and the form's token.
    change_to: Option<&'static str>,
    csrf: String,
    /// What went wrong with one of its buttons.
    notice: Option<String>,
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
    updates: Option<UpdatesView>,
    binding: Option<BindingView>,
    /// What it connected to in the last day, by container (7.7.1).
    connections: Vec<ConnGroup>,
    /// Quarantine, when the machine is in it: its state and who enforces it (D77).
    quarantine: Option<QuarantineView>,
}

/// One container's connections, or the machine's own.
struct ConnGroup {
    container: String,
    rows: Vec<ConnView>,
}

struct ConnView {
    program: String,
    destination: String,
    country: String,
    verdict: String,
    count: i64,
}

struct QuarantineView {
    state: String,
    /// Who stops the traffic, in words.
    by: &'static str,
}

/// How far back the Connections card looks.
const CONNECTIONS_WINDOW_MS: i64 = 86_400_000;
const CONNECTIONS_SHOWN: usize = 200;

fn connections(web: &Web, id: &str, now_ms: i64) -> Vec<ConnGroup> {
    type Row = (String, String, String, i64, String, String, i64);
    let rows: Vec<Row> = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT container, exe, dest_ip, dest_port, coalesce(dest_country, ''), coalesce(verdict, ''), sum(count)
                 FROM conn_records WHERE machine_id = ?1 AND bucket_ms > ?2
                 GROUP BY container, exe, dest_ip, dest_port, proto, verdict
                 ORDER BY container, 7 DESC LIMIT ?3",
            )?;
            s.query_map(rusqlite::params![id, now_ms - CONNECTIONS_WINDOW_MS, CONNECTIONS_SHOWN as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
            })?
            .collect()
        })
        .unwrap_or_default();
    let mut groups: Vec<ConnGroup> = Vec::new();
    for (container, exe, ip, port, country, verdict, count) in rows {
        let destination = if ip.contains(':') { format!("[{ip}]:{port}") } else { format!("{ip}:{port}") };
        let row = ConnView {
            program: exe.rsplit('/').next().unwrap_or(&exe).to_string(),
            destination,
            country,
            verdict,
            count,
        };
        match groups.iter_mut().find(|g| g.container == container) {
            Some(g) => g.rows.push(row),
            None => groups.push(ConnGroup { container, rows: vec![row] }),
        }
    }
    // the machine's own first (its container is empty, which sorts first), then each container by name
    groups
}

fn quarantine_view(web: &Web, id: &str, state: &str) -> Option<QuarantineView> {
    use crate::policy::quarantine::{Enforcement, State, enforcement, record};
    let state = State::parse(state).filter(|s| *s != State::None)?;
    let by = match record(&web.0.db, id).map(|r| enforcement(&r)) {
        Some(Enforcement::Hypervisor) => "Enforced by the hypervisor's firewall",
        Some(Enforcement::InGuest) => "Advisory: an attacker with root on the machine can undo it",
        None => "Not isolated yet",
    };
    Some(QuarantineView { state: state.as_str().to_string(), by })
}

/// The guest binding (7.3.12): its state and the guests the admin may confirm.
struct BindingView {
    state: String,
    guests: Vec<(String, String)>,
}

/// The question before a guest is confirmed as the machine's.
fn binding_dialog(csrf: &str, id: &str, guest: &(String, String)) -> String {
    let back = format!("/machines/{id}");
    format!(
        "{}<div class=\"d-b\"><p>{} becomes this machine's guest: its snapshots and rollbacks act on it.</p></div>\
         <form class=\"d-f\" method=\"post\" action=\"{back}/binding/confirm\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
         <input type=\"hidden\" name=\"guest\" value=\"{}\"><button type=\"submit\" class=\"primary\">Confirm this guest</button>\
         <a class=\"btn\" href=\"{back}\" data-close>Cancel</a></form></dialog>",
        ui::dialog("Confirm the guest", &back),
        ui::escape(&guest.0),
        ui::escape(csrf),
        ui::escape(&guest.1),
    )
}

/// `pve8 lxc vmid 100` for a `proxmox_ref`.
fn guest_label(reference: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(reference).unwrap_or_default();
    format!("{} {} vmid {}", v["node"].as_str().unwrap_or("?"), v["type"].as_str().unwrap_or("?"), v["vmid"])
}

struct UpdatesView {
    summary: String,
    reboot_required: bool,
    packages: String,
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
    let id = ctx.path.strip_prefix("/machines/").unwrap_or("");
    show_machine(web, ctx, id, StatusCode::OK, None)
}

/// The machine's page, with what went wrong with one of its buttons.
pub(super) fn show_machine(web: &Web, ctx: &Ctx, id: &str, code: StatusCode, notice: Option<&str>) -> Response<Body> {
    let id = id.to_string();
    let id_for_view = id.clone();
    let found = web.0.db.readers().with(|c| {
        c.query_row(
            "SELECT m.name, s.name, m.kind, coalesce(m.os, ''), m.access, m.state, m.proxmox_ref, m.proxmox_ref_state, m.quarantine
             FROM machines m JOIN sites s ON s.id = m.site_id WHERE m.id = ?1",
            [&id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                ))
            },
        )
        .optional()
    });
    type MachineRow = (String, String, String, String, String, String, Option<String>, String, String);
    let (name, site, kind, os, access, state, reference, binding_state, quarantined): MachineRow = match found {
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
    let updates = latest.as_ref().and_then(|l| l.updates.as_ref()).map(|u| UpdatesView {
        summary: format!("{} pending, {} security", u.pending, u.security),
        reboot_required: u.reboot_required,
        packages: u.packages.join(", "),
    });
    let caps = web.0.ingest.as_ref().map(|i| i.capabilities(&id)).unwrap_or_default();
    let binding = reference.map(|r| {
        let mut guests = vec![(guest_label(&r), r)];
        let seen = web.0.bindings.as_ref().and_then(|b| b.looks_like(&id));
        if let Some(seen) = seen.filter(|s| *s != guests[0].1) {
            guests.push((guest_label(&seen), seen));
        }
        BindingView { state: binding_state.clone(), guests }
    });
    let row =
        super::overview::machines(web, ctx.now_ms, None).ok().and_then(|all| all.into_iter().find(|m| m.id == id));
    let can_confirm = ctx.user.as_ref().is_some_and(|u| allowed(u.role, Permission::ConfirmBinding));
    let asked = ui::asked(ctx, "confirm").and_then(|c| c.strip_prefix("guest:"));
    let confirm = binding
        .as_ref()
        .filter(|_| can_confirm)
        .and_then(|b| b.guests.iter().find(|g| Some(g.1.as_str()) == asked))
        .map(|g| binding_dialog(&ctx.csrf, &id, g))
        .unwrap_or_default();
    let page = MachinePage {
        shell: Shell::at(web, ctx, &name, &format!("/machines/{id}")),
        health: row.as_ref().map(|r| r.health.clone()).unwrap_or_else(|| "ok".into()),
        last_seen: row.as_ref().map(|r| r.last_seen.clone()).unwrap_or_default(),
        policy: row.as_ref().map(|r| r.policy.clone()).unwrap_or_default(),
        confirm,
        can_confirm,
        change_to: ctx
            .user
            .as_ref()
            .filter(|u| allowed(u.role, Permission::Administer) && state == "enrolled" && kind != "appliance")
            .map(|_| if access == "monitor" { "managed" } else { "monitor" }),
        csrf: ctx.csrf.clone(),
        notice: notice.map(str::to_string),
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
        updates,
        binding,
        connections: connections(web, &id_for_view, ctx.now_ms),
        quarantine: quarantine_view(web, &id_for_view, &quarantined),
    };
    html(code, page.render())
}

pub(super) struct VitalRow {
    pub metric: &'static str,
    pub name: &'static str,
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

/// What a metric is called, and its unit.
fn metric_name(metric: &str) -> (&'static str, &'static str) {
    match metric {
        "cpu.busy_pct" => ("CPU", " %"),
        "mem.used_pct" => ("Memory", " %"),
        "load.1m" => ("Load, 1 min", ""),
        _ => ("Swap", " %"),
    }
}

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
                name: metric_name(metric).0,
                last: format!("{last:.2}{}", metric_name(metric).1),
                min: format!("{min:.2}"),
                max: format!("{max:.2}{}", metric_name(metric).1),
                line: polyline(&points),
            })
        })
        .collect();
    html(StatusCode::OK, Vitals { rows }.render())
}

#[derive(Template)]
#[template(path = "incidents.html")]
struct IncidentsPage {
    shell: Shell,
    q: String,
    open: Vec<IncidentView>,
    resolved: Vec<IncidentView>,
}

/// Every open incident, worst and newest first.
pub(super) fn open_incidents(web: &Web) -> Vec<IncidentView> {
    web.0
        .db
        .readers()
        .with(|c| {
            let sql = format!(
                "SELECT {INCIDENT_COLUMNS} FROM incidents i LEFT JOIN machines m ON m.id = i.machine_id
                 WHERE i.state != 'resolved'
                 ORDER BY CASE i.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, i.opened_at DESC"
            );
            let mut s = c.prepare(&sql)?;
            s.query_map([], incident_view)?.collect()
        })
        .unwrap_or_default()
}

pub(super) fn incidents(web: &Web, ctx: &Ctx) -> Response<Body> {
    let list = |unresolved: bool| -> Vec<IncidentView> {
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
    let q = ui::query(ctx);
    let fits = |i: &IncidentView| ui::found(&q, &[&i.title, &i.machine, &i.severity, &i.state]);
    let open = list(true).into_iter().filter(fits).collect();
    let resolved = list(false).into_iter().filter(fits).collect();
    html(
        StatusCode::OK,
        IncidentsPage { shell: Shell::new(web, ctx, "Incidents"), q: q.clone(), open, resolved }.render(),
    )
}

#[derive(Template)]
#[template(path = "incident.html")]
struct IncidentPage {
    shell: Shell,
    incident: IncidentView,
    events: Vec<(String, String, String)>,
    /// The assistant's jobs for it, with transcripts.
    jobs: Vec<super::assistant::JobView>,
    csrf: String,
    can_resume: bool,
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
        Ok(Some((incident, events))) => {
            let jobs = super::assistant::jobs_of(web, id, ctx.now_ms);
            let can_resume = ctx.user.as_ref().is_some_and(|u| allowed(u.role, Permission::Operate));
            html(
                StatusCode::OK,
                IncidentPage {
                    shell: Shell::new(web, ctx, &incident.title),
                    incident,
                    events,
                    jobs,
                    csrf: ctx.csrf.clone(),
                    can_resume,
                }
                .render(),
            )
        }
        Ok(None) => status(StatusCode::NOT_FOUND, "No such incident"),
        Err(_) => status(StatusCode::INTERNAL_SERVER_ERROR, "The database couldn't be read"),
    }
}

#[derive(Template)]
#[template(path = "site.html")]
struct SitePage {
    shell: Shell,
    q: String,
    machines: Vec<super::overview::MachineRow>,
}

pub(super) fn site(web: &Web, ctx: &Ctx) -> Response<Body> {
    let key = ctx.path.strip_prefix("/sites/").unwrap_or("");
    let found = web.0.db.readers().with(|c| {
        let Some((id, name)) = c
            .query_row("SELECT id, name FROM sites WHERE id = ?1 OR name = ?1", [key], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .optional()?
        else {
            return Ok(None);
        };
        Ok(Some((id, name)))
    });
    match found {
        Ok(Some((id, name))) => {
            let q = ui::query(ctx);
            let machines = super::overview::machines(web, ctx.now_ms, Some(&id)).unwrap_or_default();
            let machines = machines.into_iter().filter(|m| m.matches(&q)).collect();
            let shell = Shell::at(web, ctx, &name, &format!("/sites/{name}"));
            html(StatusCode::OK, SitePage { shell, q, machines }.render())
        }
        Ok(None) => super::peers::site(web, ctx, key).unwrap_or_else(|| status(StatusCode::NOT_FOUND, "No such site")),
        Err(_) => status(StatusCode::INTERNAL_SERVER_ERROR, "The database couldn't be read"),
    }
}
