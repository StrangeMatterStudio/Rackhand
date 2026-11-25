//! Peers and relays, and a peer's site page (7.7.1, 7.7.2, 7.3.4, 7.3.10): the hubs linked with this one and what they last
//! said, what each may ask and how much backup space it has, requests for a peer's machines (which are decided on the peer's
//! own dashboard), and the relay lists with how each fetch went.

use std::collections::BTreeMap;

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use prost::Message;
use rackhand_proto::peer::{ActionRequest, Health, SiteSummary, action_request_status};
use rackhand_store::{Row, RowUpdate, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;

use super::overview::ago;
use super::{html, html_text, see_other, status};
use crate::library::config;
use crate::peers::PeerState;
use crate::web::perms::{Permission, allowed};
use crate::web::ui::{self, Shell};
use crate::web::{Ctx, Web};

/// The queries a peer may be allowed, in the order they are stored and shown: the name stored, the label.
const QUERIES: [(&str, &str, &str); 4] = [
    ("vitals", "q_vitals", "Vitals (charts of its machines)"),
    ("machine", "q_machine", "Machine details"),
    ("incident", "q_incident", "Incident details"),
    ("job_log", "q_job_log", "Job logs (can hold credentials)"),
];
/// The most backup space one peer can be given, in GiB.
const MAX_QUOTA_GB: u64 = 100_000;
const GIB: u64 = 1 << 30;
/// Relay lists one hub follows.
const MAX_LISTS: usize = 20;

struct PeerRow {
    id: String,
    site: String,
    state: &'static str,
    last_heard: String,
    path: String,
    path_detail: String,
    machines: usize,
    incidents: usize,
    queries: Vec<(&'static str, &'static str, bool)>,
    quota_gb: String,
}

struct ListRow {
    url: String,
    status: String,
    error: String,
}

struct ListedRow {
    name: String,
    url: String,
    region: String,
    operator: String,
}

#[derive(Template)]
#[template(path = "peers.html")]
struct PeersPage {
    shell: Shell,
    csrf: String,
    can_edit: bool,
    peers: Vec<PeerRow>,
    lists_on: bool,
    lists: Vec<ListRow>,
    list_urls: String,
    listed: Vec<ListedRow>,
}

/// What a linked peer is, from the tables.
struct Linked {
    id: String,
    site: String,
    allowed: Vec<String>,
    quota: u64,
    added_at: i64,
    summary: Option<(i64, SiteSummary)>,
    /// When a peer is silent, from the settings (7.8.1).
    silent_after_ms: i64,
}

impl Linked {
    fn last_heard(&self) -> i64 {
        self.summary.as_ref().map_or(self.added_at, |s| s.0)
    }

    fn state(&self, now: i64) -> &'static str {
        match crate::peers::state(now - self.last_heard(), self.silent_after_ms) {
            PeerState::Ok => "peer_up",
            PeerState::Silent => "silent",
            PeerState::Down => "peer_down",
        }
    }
}

fn linked(web: &Web) -> Vec<Linked> {
    let silent_after_ms = config::hub_or_default(&web.0.db).peers.silent_after_ms();
    type R = (String, String, String, i64, i64, Option<(i64, Vec<u8>)>);
    let rows: Vec<R> = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT p.id, p.site, p.allowed_queries, p.backup_quota_bytes, p.added_at, s.received_at_ms, s.summary
                 FROM peers p LEFT JOIN peer_summaries s ON s.peer_id = p.id WHERE p.revoked_at IS NULL ORDER BY p.site",
            )?;
            s.query_map([], |r| {
                let at: Option<i64> = r.get(5)?;
                let blob: Option<Vec<u8>> = r.get(6)?;
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, at.zip(blob)))
            })?
            .collect()
        })
        .unwrap_or_default();
    rows.into_iter()
        .map(|(id, site, allowed, quota, added_at, summary)| Linked {
            id,
            site,
            allowed: serde_json::from_str(&allowed).unwrap_or_default(),
            quota: u64::try_from(quota).unwrap_or(0),
            added_at,
            summary: summary.and_then(|(at, blob)| Some((at, SiteSummary::decode(blob.as_slice()).ok()?))),
            silent_after_ms,
        })
        .collect()
}

fn health_word(code: i32) -> &'static str {
    match Health::try_from(code) {
        Ok(Health::Ok) => "ok",
        Ok(Health::Warning) => "warning",
        Ok(Health::Critical) => "critical",
        Ok(Health::Silent) => "silent",
        Ok(Health::Quarantined) => "quarantined",
        Ok(Health::Maintenance) => "maintenance",
        _ => "unknown",
    }
}

fn quota_text(bytes: u64) -> String {
    (bytes / GIB).to_string()
}

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return super::redirect("/sign-in") };
    let reach = web.0.peer_reach.as_ref();
    let peers = linked(web)
        .into_iter()
        .map(|p| {
            let path = reach.map(|r| r.path(&p.id));
            PeerRow {
                state: p.state(ctx.now_ms),
                last_heard: match &p.summary {
                    Some((at, _)) => ago(*at, ctx.now_ms),
                    None => "Nothing yet".into(),
                },
                path: path.as_ref().map(|x| x.label.to_string()).unwrap_or_default(),
                path_detail: path.and_then(|x| x.detail).unwrap_or_default(),
                machines: p.summary.as_ref().map_or(0, |s| s.1.machines.len()),
                incidents: p.summary.as_ref().map_or(0, |s| s.1.open_incidents.len()),
                queries: QUERIES
                    .iter()
                    .map(|(name, key, _)| (*key, label_of(key), p.allowed.iter().any(|a| a == name)))
                    .collect(),
                quota_gb: quota_text(p.quota),
                id: p.id,
                site: p.site,
            }
        })
        .collect();
    let settings = config::hub(&web.0.db).unwrap_or_default();
    let lists = web.0.relay_lists.as_ref().and_then(|l| l.lock().ok().map(|l| l.clone()));
    // the lists the hub follows now: what the fetcher holds, or the saved setting when nothing fetches
    let urls: Vec<String> = lists.as_ref().map_or_else(|| settings.relay_list_urls.clone(), |l| l.urls().to_vec());
    let list_rows = urls
        .iter()
        .map(|url| {
            let (status, error) = match lists.as_ref().and_then(|l| l.status(url)) {
                None => ("Not fetched yet".to_string(), String::new()),
                Some(s) => {
                    let mut said = format!("{} relay{} kept", s.kept, if s.kept == 1 { "" } else { "s" });
                    if s.skipped > 0 {
                        said.push_str(&format!(", {} skipped", s.skipped));
                    }
                    if s.ignored > 0 {
                        said.push_str(&format!(
                            ", {} past the first {}",
                            s.ignored,
                            crate::peers::relay_lists::MAX_ENTRIES
                        ));
                    }
                    said.push_str(&format!(", checked {}", ago(s.checked_ms, ctx.now_ms)));
                    (said, s.error.clone().unwrap_or_default())
                }
            };
            ListRow { url: url.clone(), status, error }
        })
        .collect();
    let listed = lists
        .map(|l| {
            l.listed()
                .into_iter()
                .map(|r| ListedRow { name: r.name, url: r.url, region: r.region, operator: r.operator })
                .collect()
        })
        .unwrap_or_default();
    let page = PeersPage {
        shell: Shell::new(web, ctx, "Peers and relays"),
        csrf: ctx.csrf.clone(),
        can_edit: allowed(user.role, Permission::Administer),
        peers,
        lists_on: settings.sources.relay_lists,
        lists: list_rows,
        list_urls: urls.join("\n"),
        listed,
    };
    html(StatusCode::OK, page.render())
}

fn label_of(key: &str) -> &'static str {
    QUERIES.iter().find(|(_, k, _)| *k == key).map_or("", |(_, _, label)| label)
}

// ---- the actions of the admin ---------------------------------------------------------------------------------------------

fn known(web: &Web, id: &str) -> Option<String> {
    web.0
        .db
        .readers()
        .with(|c| {
            c.query_row("SELECT site FROM peers WHERE id = ?1 AND revoked_at IS NULL", [id], |r| r.get::<_, String>(0))
                .optional()
        })
        .ok()
        .flatten()
}

fn peer_in_path<'a>(ctx: &'a Ctx, tail: &str) -> Option<&'a str> {
    ctx.path.strip_prefix("/peers/")?.strip_suffix(tail)
}

async fn audit(web: &Web, ctx: &Ctx, action: &str, target: &str, data: serde_json::Value) {
    let by = ctx.user.as_ref().map_or("unknown", |u| u.name.as_str());
    if let Err(e) = web.0.audit.append(by, action, Some(target), &data.to_string()).await {
        tracing::error!(error = %e, "audit");
    }
}

/// `POST /peers/{id}/settings`: which queries the peer may ask and how much backup space it has.
pub(super) async fn settings(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(id) = peer_in_path(ctx, "/settings") else { return status(StatusCode::NOT_FOUND, "No such peer") };
    let Some(site) = known(web, id) else { return status(StatusCode::NOT_FOUND, "No such peer") };
    let on = |k: &str| ctx.form.get(k).is_some_and(|v| v == "on");
    let chosen: Vec<&str> = QUERIES.iter().filter(|(_, key, _)| on(key)).map(|(name, _, _)| *name).collect();
    let quota = match ctx.form.get("quota_gb").map(|q| q.trim()).filter(|q| !q.is_empty()) {
        None => None,
        Some(q) => match q.parse::<u64>() {
            Ok(gb) if gb <= MAX_QUOTA_GB => Some(gb * GIB),
            _ => {
                return status(
                    StatusCode::BAD_REQUEST,
                    "Backup space is a whole number of gigabytes, from 0 (none) to 100000",
                );
            }
        },
    };
    let mut set = Row::from([("allowed_queries", Value::Text(serde_json::to_string(&chosen).unwrap_or_default()))]);
    if let Some(bytes) = quota {
        set.insert("backup_quota_bytes", Value::Integer(i64::try_from(bytes).unwrap_or(i64::MAX)));
    }
    let update = RowUpdate { table: "peers", key: ("id", Value::Text(id.to_string())), set };
    let change = rackhand_store::RegistryChange { updates: vec![update], ..Default::default() };
    if web.0.db.writer().send(WriteCmd::RegistryChange(change)).await.is_err() {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The change couldn't be saved");
    }
    audit(web, ctx, "peer.settings", id, serde_json::json!({ "site": site, "queries": chosen, "quota_bytes": quota }))
        .await;
    see_other("/peers")
}

/// `POST /peers/join`: joins the hub an invite names.
pub(super) async fn join(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return super::redirect("/sign-in") };
    let invite = ctx.form.get("invite").map(|i| i.trim()).unwrap_or("");
    if invite.is_empty() || invite.len() > 2048 || invite.chars().any(char::is_whitespace) {
        return status(StatusCode::BAD_REQUEST, "Paste the invite from the other hub's Add page, as one line");
    }
    let Some(reach) = web.0.peer_reach.as_ref() else {
        return status(StatusCode::SERVICE_UNAVAILABLE, "The hub isn't ready to link yet; try again in a minute");
    };
    match reach.join(invite, &user.name).await {
        Ok(site) => {
            audit(web, ctx, "peer.join_requested", &site, serde_json::json!({ "site": site })).await;
            see_other("/peers")
        }
        Err(why) => status(StatusCode::BAD_GATEWAY, &why),
    }
}

/// `POST /peers/{id}/unlink`.
pub(super) async fn unlink(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return super::redirect("/sign-in") };
    let Some(id) = peer_in_path(ctx, "/unlink") else { return status(StatusCode::NOT_FOUND, "No such peer") };
    if known(web, id).is_none() {
        return status(StatusCode::NOT_FOUND, "No such peer");
    }
    let Some(reach) = web.0.peer_reach.as_ref() else {
        return status(StatusCode::SERVICE_UNAVAILABLE, "The hub isn't ready to unlink yet; try again in a minute");
    };
    match reach.unlink(id, &user.name).await {
        Ok(()) => see_other("/peers"),
        Err(why) => status(StatusCode::BAD_GATEWAY, &why),
    }
}

/// `POST /peers/relay-lists`: the lists this hub follows, and whether it fetches them.
pub(super) async fn relay_lists(web: &Web, ctx: &Ctx) -> Response<Body> {
    let mut urls: Vec<String> = Vec::new();
    for line in ctx.form.get("urls").map_or("", String::as_str).lines().map(str::trim).filter(|l| !l.is_empty()) {
        let fine = line.starts_with("https://")
            && line.len() <= 512
            && !line.chars().any(|c| c.is_whitespace() || c.is_control());
        if !fine {
            return status(StatusCode::BAD_REQUEST, "A relay list address starts with https:// and has no spaces");
        }
        if !urls.iter().any(|u| u == line) {
            urls.push(line.to_string());
        }
    }
    if urls.len() > MAX_LISTS {
        return status(StatusCode::BAD_REQUEST, &format!("At most {MAX_LISTS} relay lists"));
    }
    let enabled = ctx.form.get("enabled").is_some_and(|v| v == "on");
    if let Some(lists) = web.0.relay_lists.as_ref()
        && let Ok(mut lists) = lists.lock()
    {
        lists.set_urls(urls.clone());
    }
    super::settings::change_to(web, ctx, "settings.relay_lists", "/peers", |c| {
        c.relay_list_urls = urls.clone();
        c.sources.relay_lists = enabled;
        serde_json::json!({ "lists": urls.len(), "enabled": enabled })
    })
    .await
}

// ---- a peer's site page ---------------------------------------------------------------------------------------------------

struct MachineView {
    id: String,
    name: String,
    kind: String,
    health: &'static str,
    last_seen: String,
}

struct IncidentLine {
    severity: String,
    title: String,
    machine: String,
    opened: String,
}

#[derive(Template)]
#[template(path = "peer_site.html")]
struct PeerSite {
    shell: Shell,
    csrf: String,
    peer: String,
    peer_id: String,
    state: &'static str,
    last_summary: String,
    version: String,
    can_ask: bool,
    machines: Vec<MachineView>,
    incidents: Vec<IncidentLine>,
}

fn ulid_text(bytes: &[u8]) -> Option<String> {
    let b: [u8; 16] = bytes.try_into().ok()?;
    Some(ulid::Ulid::from_bytes(b).to_string())
}

/// `/sites/{name}` for a linked peer: what it last said, and when. `None` when no peer has that name.
pub(super) fn site(web: &Web, ctx: &Ctx, key: &str) -> Option<Response<Body>> {
    let peer = linked(web).into_iter().find(|p| p.site == key || p.id == key)?;
    let can_ask = ctx.user.as_ref().is_some_and(|u| allowed(u.role, Permission::Operate));
    let state = peer.state(ctx.now_ms);
    let last_summary = match &peer.summary {
        Some((at, _)) => format!("Last summary {}", ago(*at, ctx.now_ms)),
        None => "No summary yet".to_string(),
    };
    let summary = peer.summary.as_ref().map(|s| &s.1);
    let names: BTreeMap<Vec<u8>, String> =
        summary.iter().flat_map(|s| s.machines.iter().map(|m| (m.id.clone(), m.name.clone()))).collect();
    let machines = summary
        .iter()
        .flat_map(|s| s.machines.iter())
        .filter_map(|m| {
            Some(MachineView {
                id: ulid_text(&m.id)?,
                name: m.name.clone(),
                kind: m.kind.clone(),
                health: health_word(m.health),
                last_seen: if m.last_seen_ms > 0 { ui::time(m.last_seen_ms) } else { String::new() },
            })
        })
        .collect();
    let incidents = summary
        .iter()
        .flat_map(|s| s.open_incidents.iter())
        .map(|i| IncidentLine {
            severity: i.severity.clone(),
            title: i.title.clone(),
            machine: names.get(&i.machine_id).cloned().unwrap_or_default(),
            opened: if i.opened_at_ms > 0 { ui::time(i.opened_at_ms) } else { String::new() },
        })
        .collect();
    let version = summary
        .and_then(|s| s.hub_health.as_ref())
        .and_then(|h| h.version.as_ref())
        .map(|v| v.version.clone())
        .unwrap_or_default();
    let page = PeerSite {
        shell: Shell::at(web, ctx, &peer.site, &format!("/sites/{}", peer.site)),
        csrf: ctx.csrf.clone(),
        peer: peer.site.clone(),
        peer_id: peer.id.clone(),
        state,
        last_summary,
        version,
        can_ask,
        machines,
        incidents,
    };
    Some(html(StatusCode::OK, page.render()))
}

/// What a request's first status says to the person who made it.
fn said(site: &str, s: &action_request_status::Status) -> String {
    use action_request_status::Status::*;
    match s {
        Queued(_) => format!("The request is queued on {site}."),
        NeedsApproval(_) => format!(
            "The request needs an approval on {site}. It waits on that hub's Approvals page, and nothing runs until someone there decides."
        ),
        RunningJob(_) => format!("The request is running on {site}."),
        Done(_) => format!("{site} ran the request and has finished."),
        Rejected(why) => format!("{site} refused the request: {why}"),
    }
}

/// Parameters as `key=value` lines.
fn params(text: &str) -> Option<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (k, v) = line.split_once('=')?;
        let (k, v) = (k.trim(), v.trim());
        let name =
            !k.is_empty() && k.len() <= 64 && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !name || v.len() > 256 || v.chars().any(char::is_control) || out.len() >= 20 {
            return None;
        }
        out.insert(k.to_string(), v.to_string());
    }
    Some(out)
}

/// `POST /peers/{id}/machines/{machine}/request`: asks the peer to run a runbook on one of its machines. The decision is on
/// the peer's own dashboard; nothing is started or approved here.
pub(super) async fn request(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return super::redirect("/sign-in") };
    let Some((id, machine)) = ctx
        .path
        .strip_prefix("/peers/")
        .and_then(|p| p.strip_suffix("/request"))
        .and_then(|p| p.split_once("/machines/"))
    else {
        return status(StatusCode::NOT_FOUND, "No such machine");
    };
    let Some(peer) = linked(web).into_iter().find(|p| p.id == id) else {
        return status(StatusCode::NOT_FOUND, "No such peer");
    };
    // only a machine the peer has told this hub about
    let target = peer
        .summary
        .as_ref()
        .and_then(|s| s.1.machines.iter().find(|m| ulid_text(&m.id).as_deref() == Some(machine)))
        .map(|m| m.id.clone());
    let Some(target) = target else { return status(StatusCode::NOT_FOUND, "That peer has no such machine") };
    let runbook = ctx.form.get("runbook").map(|r| r.trim()).unwrap_or("");
    let fine = !runbook.is_empty()
        && runbook.len() <= 64
        && runbook.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !fine {
        return status(StatusCode::BAD_REQUEST, "Name the runbook to run, as it is named on the peer");
    }
    let reason = ctx.form.get("reason").map(|r| r.trim()).unwrap_or("");
    if reason.is_empty() || reason.len() > 500 || reason.chars().any(|c| c.is_control() && c != '\n') {
        return status(StatusCode::BAD_REQUEST, "Say why, in a sentence: the approver on the other hub reads it");
    }
    let Some(params) = params(ctx.form.get("params").map_or("", String::as_str)) else {
        return status(StatusCode::BAD_REQUEST, "Parameters are lines of name=value, at most 20");
    };
    let Some(reach) = web.0.peer_reach.as_ref() else {
        return status(StatusCode::SERVICE_UNAVAILABLE, "The hub isn't ready to ask a peer yet; try again in a minute");
    };
    let here: String = web
        .0
        .db
        .readers()
        .with(|c| c.query_row("SELECT name FROM sites WHERE is_local = 1", [], |r| r.get(0)))
        .unwrap_or_else(|_| "hub".to_string());
    let request = ActionRequest {
        request_id: ulid::Ulid::new().to_bytes().to_vec(),
        requested_by: format!("{}@{here}", user.name),
        runbook: runbook.to_string(),
        target,
        params,
        reason: reason.to_string(),
    };
    let answer = reach.request(id, &request).await;
    let data = serde_json::json!({ "peer": peer.site, "machine": machine, "runbook": runbook });
    audit(web, ctx, "peer.request", id, data).await;
    match answer {
        Ok(first) => {
            let text =
                first.status.as_ref().map_or_else(|| "The peer took the request.".to_string(), |s| said(&peer.site, s));
            html_text(StatusCode::OK, "Request sent", &text, Some(&format!("/sites/{}", peer.site)))
        }
        Err(why) => status(StatusCode::BAD_GATEWAY, &format!("{} couldn't be asked: {why}", peer.site)),
    }
}

// ---- the overview's tiles --------------------------------------------------------------------------------------------------

pub(super) struct Tile {
    pub site: String,
    /// `3 of 4 healthy`.
    pub machines: String,
    pub incidents: usize,
    /// `peer_up`, `silent`, `peer_down`; empty for a site of this hub.
    pub state: &'static str,
    /// When the peer last said how it is.
    pub heard: String,
}

/// A tile for each site: those of this hub, then the linked peers (7.7.1). Only when a peer is linked: with none, the
/// overview is the one site's.
pub(super) fn tiles(web: &Web, now: i64, local: &[super::overview::MachineRow]) -> Vec<Tile> {
    let peers = linked(web);
    if peers.is_empty() {
        return Vec::new();
    }
    let mut sites: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for m in local {
        let e = sites.entry(m.site.as_str()).or_default();
        e.1 += 1;
        e.0 += usize::from(m.health == "ok");
    }
    let open: BTreeMap<String, usize> = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT s.name, count(*) FROM incidents i JOIN machines m ON m.id = i.machine_id
                 JOIN sites s ON s.id = m.site_id WHERE i.state != 'resolved' GROUP BY s.name",
            )?;
            s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?.collect()
        })
        .map(|rows: Vec<(String, i64)>| rows.into_iter().map(|(n, c)| (n, usize::try_from(c).unwrap_or(0))).collect())
        .unwrap_or_default();
    let mut tiles: Vec<Tile> = sites
        .into_iter()
        .map(|(site, (ok, total))| Tile {
            site: site.to_string(),
            machines: format!("{ok} of {total} healthy"),
            incidents: open.get(site).copied().unwrap_or(0),
            state: "",
            heard: String::new(),
        })
        .collect();
    for p in peers {
        let summary = p.summary.as_ref().map(|s| &s.1);
        let total = summary.map_or(0, |s| s.machines.len());
        let ok = summary.map_or(0, |s| s.machines.iter().filter(|m| m.health == Health::Ok as i32).count());
        tiles.push(Tile {
            machines: if summary.is_some() { format!("{ok} of {total} healthy") } else { "Nothing heard yet".into() },
            incidents: summary.map_or(0, |s| s.open_incidents.len()),
            state: p.state(now),
            heard: p.summary.as_ref().map(|(at, _)| format!("Last summary {}", ago(*at, now))).unwrap_or_default(),
            site: p.site,
        });
    }
    tiles
}
