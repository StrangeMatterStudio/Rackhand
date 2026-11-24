// The peer pages (7.7.1, 7.7.2, 7.3.4, 7.3.10): peers and relays, a peer's site page from its last summary, a request for a
// peer's machine, what a peer may ask and how much backup space it has, and the relay lists with their errors.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use prost::Message;
use rackhand_proto::peer::{
    ActionRequest, ActionRequestStatus, Health, HubHealth, IncidentSummary, MachineSummary, SiteSummary,
    action_request_status,
};

use super::super::shell::plain;
use super::*;
use crate::actions::runner::BoxFuture;
use crate::peers::path_status::PeerPath;
use crate::peers::relay_lists::{Fetch, RelayLists};
use crate::peers::PeerReach;

const PEER: &str = "01JPEERBETAAAAAAAAAAAAAAAA";
const WEB: &str = "01JMACH1NEAAAAAAAAAAAAAAAA";
const DB: &str = "01JMACH1NEBBBBBBBBBBBBBBBB";
const MIN: i64 = 60_000;

fn ulid_bytes(id: &str) -> Vec<u8> {
    ulid::Ulid::from_string(id).unwrap().to_bytes().to_vec()
}

/// What the owning hub would have been told: a machine that is fine, one that is not, and an open incident.
fn summary(site: &str) -> SiteSummary {
    SiteSummary {
        site: site.into(),
        generated_at_ms: 0,
        machines: vec![
            MachineSummary {
                id: ulid_bytes(WEB),
                name: "web".into(),
                kind: "linux".into(),
                health: Health::Ok as i32,
                last_seen_ms: 0,
            },
            MachineSummary {
                id: ulid_bytes(DB),
                name: "db".into(),
                kind: "linux".into(),
                health: Health::Critical as i32,
                last_seen_ms: 0,
            },
        ],
        open_incidents: vec![IncidentSummary {
            id: ulid_bytes("01J1NC1DENTAAAAAAAAAAAAAAA"),
            severity: "critical".into(),
            title: "postgres is down".into(),
            machine_id: ulid_bytes(DB),
            opened_at_ms: 0,
        }],
        hub_health: Some(HubHealth { db_ok: true, notifiers_ok: true, self_check_ok: true, ..HubHealth::default() }),
        peers_seen: Vec::new(),
        audit_head: Vec::new(),
    }
}

/// A linked peer `site`, last heard from `ago_ms` ago.
async fn peer(app: &App, id: &str, site: &str, ago_ms: i64) {
    let at = now_ms() - ago_ms;
    app.db
        .writer()
        .send(WriteCmd::Batch(vec![
            RowWrite::insert(
                "peers",
                Row::from([
                    ("id", Value::Text(id.into())),
                    ("site", Value::Text(site.into())),
                    ("endpoint_id", Value::Text(format!("endpoint-{site}"))),
                    ("added_at", Value::Integer(at - MIN)),
                    ("last_seen_ms", Value::Integer(at)),
                ]),
            ),
            RowWrite::insert(
                "peer_summaries",
                Row::from([
                    ("peer_id", Value::Text(id.into())),
                    ("received_at_ms", Value::Integer(at)),
                    ("summary", Value::Blob(summary(site).encode_to_vec())),
                ]),
            ),
        ]))
        .await
        .unwrap();
}

/// What the dashboard asked of the peers, and what it says back.
#[derive(Default)]
struct Fake {
    requests: Mutex<Vec<(String, ActionRequest)>>,
    joins: Mutex<Vec<String>>,
    unlinked: Mutex<Vec<String>>,
}

impl PeerReach for Fake {
    fn request<'a>(
        &'a self,
        peer_id: &'a str,
        request: &'a ActionRequest,
    ) -> BoxFuture<'a, Result<ActionRequestStatus, String>> {
        self.requests.lock().unwrap().push((peer_id.to_string(), request.clone()));
        Box::pin(async { Ok(ActionRequestStatus { status: Some(action_request_status::Status::NeedsApproval(true)) }) })
    }

    fn join<'a>(&'a self, invite: &'a str, _by: &'a str) -> BoxFuture<'a, Result<String, String>> {
        self.joins.lock().unwrap().push(invite.to_string());
        Box::pin(async { Ok("gamma".to_string()) })
    }

    fn unlink<'a>(&'a self, peer_id: &'a str, _by: &'a str) -> BoxFuture<'a, Result<(), String>> {
        self.unlinked.lock().unwrap().push(peer_id.to_string());
        Box::pin(async { Ok(()) })
    }

    fn path(&self, _peer_id: &str) -> PeerPath {
        PeerPath::unreachable(false)
    }
}

struct Canned(Vec<(&'static str, Result<String, String>)>);

impl Fetch for Canned {
    fn fetch<'a>(&'a self, url: &'a str) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        let body = self.0.iter().find(|(u, _)| *u == url).map(|(_, b)| b.clone()).unwrap_or(Err("not listed".into()));
        Box::pin(async move { body })
    }
}

async fn with_reach(name: &str) -> (App, std::sync::Arc<Fake>) {
    let fake = std::sync::Arc::new(Fake::default());
    let reach = fake.clone();
    let app = app_with(name, move |web| web.with_peer_reach(reach)).await;
    complete_first_run(&app, SETUP_CODE).await;
    (app, fake)
}

async fn page(app: &App, cookie: &str, path: &str) -> (StatusCode, String) {
    let resp = send(&app.router, get(path, cookie)).await;
    (resp.status(), text(resp).await)
}

async fn posted(app: &App, cookie: &str, path: &str, fields: &[(&str, &str)]) -> Response<Body> {
    let csrf = csrf_of(app, cookie).await;
    let mut all = vec![("csrf", csrf.as_str())];
    all.extend_from_slice(fields);
    send(&app.router, post(path, cookie, &all)).await
}

fn allowed_queries(app: &App, id: &str) -> (String, i64) {
    app.db
        .readers()
        .with(|c| {
            c.query_row("SELECT allowed_queries, backup_quota_bytes FROM peers WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
        })
        .unwrap()
}

fn count(app: &App, table: &str) -> i64 {
    app.db.readers().with(|c| c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_offline_shows_last_summary_time() {
    let (app, _) = with_reach("peer-offline").await;
    peer(&app, PEER, "beta", 45 * MIN).await;
    peer(&app, "01JPEERGAMMAAAAAAAAAAAAAAA", "gamma", 5_000).await;
    let viewer = session_for(&app.db, Role::Viewer).await;
    // the page of a peer that went quiet: what it last said, and when, not blank
    let (code, html) = page(&app, &viewer, "/sites/beta").await;
    assert_eq!(code, StatusCode::OK);
    let words = plain(&html);
    assert!(words.contains("Down"), "{words}");
    assert!(words.contains("Last summary 45 min ago") || words.contains("Last summary 46 min ago"), "{words}");
    for shown in ["web", "db", "postgres is down"] {
        assert!(words.contains(shown), "{shown}: {words}");
    }
    // a peer that is heard from is up and says so
    let (_, fresh) = page(&app, &viewer, "/sites/gamma").await;
    let fresh = plain(&fresh);
    assert!(fresh.contains("Up") && !fresh.contains("Down"), "{fresh}");
    // the overview has a tile for each site, local and peer, and the list of peers has both
    let (_, overview) = page(&app, &viewer, "/").await;
    let overview = plain(&overview);
    assert!(overview.contains("beta") && overview.contains("gamma"), "{overview}");
    let (_, peers) = page(&app, &viewer, "/peers").await;
    let peers = plain(&peers);
    assert!(peers.contains("beta") && peers.contains("Down") && peers.contains("gamma"), "{peers}");
    assert!(peers.contains("45 min ago") || peers.contains("46 min ago"), "the list says when each peer last spoke: {peers}");
    // an address that is neither a site nor a peer is still not found
    assert_eq!(page(&app, &viewer, "/sites/nowhere").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_machine_action_creates_action_request() {
    let (app, fake) = with_reach("peer-request").await;
    peer(&app, PEER, "beta", 5_000).await;
    let path = format!("/peers/{PEER}/machines/{WEB}/request");
    let fields = [("runbook", "restart-web"), ("reason", "the page is slow")];
    let (jobs, approvals) = (count(&app, "jobs"), count(&app, "approvals"));
    // a viewer can't ask
    let viewer = session_for(&app.db, Role::Viewer).await;
    assert_eq!(posted(&app, &viewer, &path, &fields).await.status(), StatusCode::FORBIDDEN);
    assert!(fake.requests.lock().unwrap().is_empty());
    // a responder's request goes to the peer, as the request the peer protocol defines
    let responder = session_for(&app.db, Role::Responder).await;
    let resp = posted(&app, &responder, &path, &fields).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let words = plain(&text(resp).await);
    assert!(words.contains("needs an approval on beta"), "{words}");
    let asked = fake.requests.lock().unwrap().clone();
    assert_eq!(asked.len(), 1);
    let (to, request) = &asked[0];
    assert_eq!(to, PEER);
    assert_eq!(request.runbook, "restart-web");
    assert_eq!(request.target, ulid_bytes(WEB));
    assert_eq!(request.reason, "the page is slow");
    assert_eq!(request.request_id.len(), 16, "an id the peer can retry with");
    assert!(request.requested_by.starts_with("responder-"), "{}", request.requested_by);
    // nothing ran or waits for approval here: the decision is on the peer's own dashboard
    assert_eq!((count(&app, "jobs"), count(&app, "approvals")), (jobs, approvals));
    // a machine the peer never listed, a missing runbook or reason, and a stranger ask nothing
    let strange = format!("/peers/{PEER}/machines/01JMACH1NECCCCCCCCCCCCCCCC/request");
    assert_eq!(posted(&app, &responder, &strange, &fields).await.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        posted(&app, &responder, &path, &[("runbook", ""), ("reason", "x")]).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        posted(&app, &responder, &path, &[("runbook", "restart-web"), ("reason", "")]).await.status(),
        StatusCode::BAD_REQUEST
    );
    let nobody = format!("/peers/nobody/machines/{WEB}/request");
    assert_eq!(posted(&app, &responder, &nobody, &fields).await.status(), StatusCode::NOT_FOUND);
    assert_eq!(fake.requests.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_allowed_queries_and_quota_editable_by_admin() {
    let (app, fake) = with_reach("peer-settings").await;
    peer(&app, PEER, "beta", 5_000).await;
    let path = format!("/peers/{PEER}/settings");
    let (before, quota) = allowed_queries(&app, PEER);
    assert_eq!((before.as_str(), quota), (r#"["vitals","machine","incident"]"#, 0));
    let fields = [("q_vitals", "on"), ("q_job_log", "on"), ("quota_gb", "50")];
    // a responder can look but not change
    let responder = session_for(&app.db, Role::Responder).await;
    assert_eq!(posted(&app, &responder, &path, &fields).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(allowed_queries(&app, PEER), (before.clone(), 0));
    // an admin can: the queries as ticked, the space in bytes, and the change is audited
    let admin = session_for(&app.db, Role::Admin).await;
    let resp = posted(&app, &admin, &path, &fields).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(allowed_queries(&app, PEER), (r#"["vitals","job_log"]"#.to_string(), 50 * 1024 * 1024 * 1024));
    let audited: i64 =
        app.db.readers().with(|c| c.query_row("SELECT count(*) FROM audit_log WHERE action = 'peer.settings'", [], |r| r.get(0))).unwrap();
    assert_eq!(audited, 1);
    // the page shows the choice back
    let (_, html) = page(&app, &admin, "/peers").await;
    assert!(html.contains("name=\"q_job_log\" checked") || html.contains("name=\"q_job_log\" value=\"on\" checked"), "{html}");
    assert!(html.contains("value=\"50\""), "{html}");
    // a quota that isn't a number or is below nothing changes nothing, and a stranger is not found
    for bad in ["abc", "-1", "1e9", "99999999"] {
        let resp = posted(&app, &admin, &path, &[("q_vitals", "on"), ("quota_gb", bad)]).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
    assert_eq!(allowed_queries(&app, PEER).1, 50 * 1024 * 1024 * 1024);
    assert_eq!(posted(&app, &admin, "/peers/nobody/settings", &fields).await.status(), StatusCode::NOT_FOUND);
    // unlinking and joining are the admin's, and go to the peers system
    assert_eq!(posted(&app, &responder, "/peers/join", &[("invite", "rackhand1:x#y")]).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(posted(&app, &admin, "/peers/join", &[("invite", "rackhand1:x#y")]).await.status(), StatusCode::SEE_OTHER);
    assert_eq!(fake.joins.lock().unwrap().as_slice(), ["rackhand1:x#y"]);
    assert_eq!(posted(&app, &responder, &format!("/peers/{PEER}/unlink"), &[]).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(posted(&app, &admin, &format!("/peers/{PEER}/unlink"), &[]).await.status(), StatusCode::SEE_OTHER);
    assert_eq!(fake.unlinked.lock().unwrap().as_slice(), [PEER]);
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_list_status_shows_errors() {
    const GOOD: &str = "https://lists.example.net/relays.toml";
    const BAD: &str = "https://broken.example.net/relays.toml";
    let mut lists = RelayLists::new(vec![GOOD.into(), BAD.into()]);
    let body = "[[relay]]\nurl = \"https://relay.example.org\"\nname = \"Example\"\n\n[[relay]]\nurl = \"http://insecure.example.org\"\nname = \"No TLS\"\n";
    lists.refresh(now_ms(), &Canned(vec![(GOOD, Ok(body.into())), (BAD, Ok("this is [not toml".into()))])).await;
    let shared = std::sync::Arc::new(Mutex::new(lists));
    let app = app_with("relay-lists", move |web| web.with_relay_lists(shared)).await;
    complete_first_run(&app, SETUP_CODE).await;
    let viewer = session_for(&app.db, Role::Viewer).await;
    let (code, html) = page(&app, &viewer, "/peers").await;
    assert_eq!(code, StatusCode::OK);
    let words = plain(&html);
    assert!(words.contains(GOOD) && words.contains("1 relay kept") && words.contains("1 skipped"), "{words}");
    assert!(words.contains(BAD) && words.contains("not TOML"), "{words}");
    assert!(words.contains("Relay lists are off") || words.contains("off"), "{words}");
    // the admin sets the lists: https only, and what is saved is the hub's setting
    let admin = session_for(&app.db, Role::Admin).await;
    let responder = session_for(&app.db, Role::Responder).await;
    let urls = [("urls", "https://one.example.net/r.toml\nhttps://two.example.net/r.toml")];
    assert_eq!(posted(&app, &responder, "/peers/relay-lists", &urls).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(posted(&app, &admin, "/peers/relay-lists", &urls).await.status(), StatusCode::SEE_OTHER);
    let saved = crate::library::config::hub(&app.db).unwrap();
    assert_eq!(saved.relay_list_urls, ["https://one.example.net/r.toml", "https://two.example.net/r.toml"]);
    assert_eq!(
        posted(&app, &admin, "/peers/relay-lists", &[("urls", "http://plain.example.net/r.toml")]).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(crate::library::config::hub(&app.db).unwrap().relay_list_urls.len(), 2, "a refused list changes nothing");
}
