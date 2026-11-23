//! The `rackhand/peer/1` contract (7.3.4, FR-18, AC28, AC69, E45) with a scripted peer: summaries, the query allow-list and its rate
//! limit, requests that wait for the owning hub's approval, idempotent retries, and unlinking.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr, TransportAddr};
use rackhand_hub::actions::Actions;
use rackhand_hub::actions::runner::{BoxFuture, StepCtx, StepOutcome, StepResult, StepRunner};
use rackhand_hub::audit::Audit;
use rackhand_hub::bus::Bus;
use rackhand_hub::ingest::{DiskSpace, Ingest};
use rackhand_hub::library::items::{Kind, Library};
use rackhand_hub::peers::{PeerLink, Peers};
use rackhand_hub::policy::approvals::{Approvals, Decider, Role};
use rackhand_hub::registry::Registry;
use rackhand_proto::alpn;
use rackhand_proto::peer::{
    ActionRequest, PeerQuery, SiteSummary, VitalsQuery, action_request_status, peer_answer, peer_query,
};
use rackhand_runbook::runbook::Step;
use rackhand_store::ids::now_ms;
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

const MACHINE: &str = "01JMACH1NEAAAAAAAAAAAAAAAA";
const RUNBOOK: &str = "name = \"restart-web\"\ndescription = \"t\"\nidentity = \"automation\"\nrisk = \"low\"\nautonomy = 1\n[[step]]\nid = \"tell\"\nkind = \"notify\"\nmessage = \"restarting\"\n";

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

#[derive(Debug)]
struct Works;

impl StepRunner for Works {
    fn run<'a>(&'a self, _c: &'a StepCtx, _s: &'a Step, _a: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async {
            StepResult {
                outcome: StepOutcome::Succeeded,
                command: None,
                exit_code: Some(0),
                stdout: b"ok\n".to_vec(),
                stderr: Vec::new(),
            }
        })
    }
}

#[derive(Debug)]
struct Roomy;

impl DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

/// The owning hub (site `alpha`), its linked peer `beta`, and a stranger `gamma`.
struct Env {
    db: Arc<Db>,
    peers: Peers,
    bus: Bus,
    registry: Arc<Registry>,
    addr: EndpointAddr,
    beta: Endpoint,
    gamma: Endpoint,
    _relay: iroh_relay::server::Server,
    _server: Endpoint,
}

fn ulid_bytes(id: &str) -> Vec<u8> {
    ulid::Ulid::from_string(id).unwrap().to_bytes().to_vec()
}

async fn env(name: &str) -> Env {
    let dir = std::env::temp_dir().join(format!("rackhand-peer-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let (relay, relay_url) = rackhand_net::testing::local_relay().await;
    let beta = rackhand_net::testing::endpoint(&relay_url, &[alpn::PEER]).await;
    let gamma = rackhand_net::testing::endpoint(&relay_url, &[alpn::PEER]).await;
    let writes = vec![
        RowWrite::insert("sites", Row::from([("id", t("s1")), ("name", t("alpha")), ("timezone", t("UTC"))])),
        RowWrite::insert(
            "machines",
            Row::from([
                ("id", t(MACHINE)),
                ("site_id", t("s1")),
                ("name", t("web")),
                ("kind", t("linux")),
                ("state", t("enrolled")),
            ]),
        ),
        RowWrite::insert(
            "incidents",
            Row::from([
                ("id", t("01J1NC1DENTAAAAAAAAAAAAAAA")),
                ("machine_id", t(MACHINE)),
                ("dedupe_key", t("k")),
                ("kind", t("service.not_active")),
                ("severity", t("warning")),
                ("state", t("human")),
                ("title", t("nginx is down")),
                ("opened_at", Value::Integer(now_ms())),
            ]),
        ),
        RowWrite::insert(
            "peers",
            Row::from([
                ("id", t("peer-beta")),
                ("site", t("beta")),
                ("endpoint_id", t(&beta.id().to_string())),
                ("added_at", Value::Integer(now_ms())),
            ]),
        ),
    ];
    db.writer().send(WriteCmd::Batch(writes)).await.unwrap();
    let audit = Audit::new(db.writer());
    let _ = audit.append("admin", "test", None, "{}").await;
    let (library, _) = Library::new(db.clone(), audit.clone());
    library.save(Kind::Runbook, "restart-web", RUNBOOK, "admin", 1).await.unwrap();
    let bus = Bus::new();
    let actions = Actions::new(db.clone(), audit.clone(), bus.clone(), Arc::new(Works));
    let ingest = Ingest::new(db.clone(), bus.clone(), Arc::new(Roomy));
    let registry = Registry::load(db.clone()).unwrap();
    let peers = Peers::new(db.clone(), audit, actions, ingest, "alpha", "0.1.0").with_registry(registry.clone());
    peers.clone().spawn(bus.subscribe("peers"));
    let server = rackhand_net::testing::endpoint(&relay_url, &[alpn::PEER]).await;
    let router = rackhand_net::router::Router::new(server.clone(), registry.clone()).route(alpn::PEER, peers.handler());
    tokio::spawn(router.serve());
    let mut addr = server.addr();
    addr.addrs.insert(TransportAddr::Relay(relay_url));
    Env { db, peers, bus, registry, addr, beta, gamma, _relay: relay, _server: server }
}

async fn link(env: &Env, from: &Endpoint) -> PeerLink {
    PeerLink::new(from.connect(env.addr.clone(), alpn::PEER).await.unwrap())
}

fn query_machine() -> PeerQuery {
    PeerQuery { kind: Some(peer_query::Kind::Machine(ulid_bytes(MACHINE))) }
}

fn denied(answer: &rackhand_proto::peer::PeerAnswer) -> Option<&str> {
    match &answer.kind {
        Some(peer_answer::Kind::Denied(why)) => Some(why.as_str()),
        _ => None,
    }
}

async fn eventually(mut f: impl FnMut() -> bool) {
    for _ in 0..100 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("never happened");
}

fn count(db: &Db, sql: &str) -> i64 {
    db.readers().with(|c| c.query_row(sql, [], |r| r.get(0))).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn invite_links_pairwise_only() {
    let env = env("pairwise").await;
    // beta is linked to alpha; gamma isn't, though gamma may be linked to beta: A to B and B to C don't link A and C
    let beta = link(&env, &env.beta).await;
    assert!(beta.query(&query_machine()).await.is_ok(), "the linked peer is answered");
    let stranger = env.gamma.connect(env.addr.clone(), alpn::PEER).await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), stranger.closed()).await.expect("closed");
    let code = rackhand_net::close_code(&closed);
    assert_eq!(
        code,
        Some(rackhand_proto::close::CloseCode::UnknownPeer),
        "a peer nobody linked is unknown: {closed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn summary_every_interval_with_audit_head() {
    let env = env("summary").await;
    let ours = env.peers.summary(now_ms());
    assert_eq!(ours.site, "alpha");
    assert_eq!(ours.machines.len(), 1);
    assert_eq!(ours.machines[0].name, "web");
    assert_eq!(ours.open_incidents.len(), 1, "{ours:?}");
    assert_eq!(ours.audit_head.len(), 32, "an external anchor for the audit chain");
    assert_eq!(ours.hub_health.as_ref().unwrap().version.as_ref().unwrap().version, "0.1.0");
    // a peer's summary, twice: one row, the latest
    let beta = link(&env, &env.beta).await;
    for (n, name) in ["first", "second"].iter().enumerate() {
        let summary = SiteSummary {
            site: "beta".into(),
            generated_at_ms: n as i64,
            audit_head: vec![n as u8; 32],
            machines: vec![rackhand_proto::peer::MachineSummary { name: name.to_string(), ..Default::default() }],
            ..Default::default()
        };
        beta.send_summary(&summary).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let db = env.db.clone();
    eventually(move || count(&db, "SELECT count(*) FROM peer_summaries") == 1).await;
    let db = env.db.clone();
    eventually(move || count(&db, "SELECT count(*) FROM peer_summaries WHERE instr(summary, 'second') > 0") == 1).await;
    assert_eq!(count(&env.db, "SELECT count(*) FROM peer_summaries"), 1, "only the latest per peer is kept");
    let (_, latest) = env.peers.latest_summary("peer-beta").unwrap();
    assert_eq!(latest.machines[0].name, "second");
    assert!(count(&env.db, "SELECT last_seen_ms FROM peers WHERE id = 'peer-beta'") > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn joblog_denied_by_default() {
    let env = env("joblog").await;
    // a job with one ordinary step and one sensitive diagnostic's
    let db = env.db.clone();
    db.writer()
        .send(WriteCmd::Batch(vec![
            RowWrite::insert(
                "jobs",
                Row::from([
                    ("id", t("01JJ0B0000000000000000000A")),
                    ("kind", t("runbook")),
                    ("name", t("restart-web")),
                    ("target", t(MACHINE)),
                    ("requested_by", t("user:admin")),
                    ("state", t("succeeded")),
                ]),
            ),
            RowWrite::insert(
                "job_steps",
                Row::from([
                    ("job_id", t("01JJ0B0000000000000000000A")),
                    ("step_id", t("restart")),
                    ("state", t("succeeded")),
                    ("stdout", Value::Blob(b"restarted nginx\n".to_vec())),
                    ("started_at", Value::Integer(1)),
                ]),
            ),
            RowWrite::insert(
                "job_steps",
                Row::from([
                    ("job_id", t("01JJ0B0000000000000000000A")),
                    ("step_id", t("diag-journal-01abc")),
                    ("state", t("succeeded")),
                    ("stdout", Value::Blob(b"password=hunter2\n".to_vec())),
                    ("started_at", Value::Integer(2)),
                ]),
            ),
        ]))
        .await
        .unwrap();
    let beta = link(&env, &env.beta).await;
    let ask = PeerQuery { kind: Some(peer_query::Kind::JobLog(ulid_bytes("01JJ0B0000000000000000000A"))) };
    let answer = beta.query(&ask).await.unwrap();
    assert_eq!(denied(&answer), Some("not allowed"), "E45: denied by default");
    // allowed by the admin: the log comes, and the sensitive step's output never does
    env.db
        .writer()
        .send(WriteCmd::RegistryChange(rackhand_store::RegistryChange {
            updates: vec![rackhand_store::RowUpdate {
                table: "peers",
                key: ("id", t("peer-beta")),
                set: Row::from([("allowed_queries", t("[\"vitals\",\"machine\",\"incident\",\"job_log\"]"))]),
            }],
            ..Default::default()
        }))
        .await
        .unwrap();
    let answer = beta.query(&ask).await.unwrap();
    let Some(peer_answer::Kind::JobLogChunk(chunk)) = answer.kind else { panic!("{answer:?}") };
    let log = String::from_utf8_lossy(&chunk.data).to_string();
    assert!(log.contains("restarted nginx") && chunk.last, "{log}");
    assert!(!log.contains("hunter2"), "sensitive_diagnostic_output_never_sent: {log}");
    assert!(log.contains("withheld"), "{log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn sensitive_diagnostic_output_never_sent() {
    // the answers to every other query hold nothing of a job's output either
    let env = env("sensitive").await;
    let beta = link(&env, &env.beta).await;
    for q in [
        query_machine(),
        PeerQuery { kind: Some(peer_query::Kind::Incident(ulid_bytes("01J1NC1DENTAAAAAAAAAAAAAAA"))) },
        PeerQuery {
            kind: Some(peer_query::Kind::Vitals(VitalsQuery {
                machine: ulid_bytes(MACHINE),
                metric: "cpu.busy_pct".into(),
                from_ms: 0,
                to_ms: now_ms(),
                ..Default::default()
            })),
        },
    ] {
        let answer = beta.query(&q).await.unwrap();
        assert!(denied(&answer).is_none(), "{answer:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn query_rate_over_10_per_second_limited() {
    let env = env("rate").await;
    let beta = link(&env, &env.beta).await;
    let mut answers = Vec::new();
    for _ in 0..13 {
        answers.push(beta.query(&query_machine()).await.unwrap());
    }
    let limited = answers.iter().filter(|a| denied(a) == Some("rate limited")).count();
    let served = answers.iter().filter(|a| denied(a).is_none()).count();
    assert_eq!((served, limited), (10, 3), "ten a second and the rest told so");
}

fn request(id: &str, requested_by: &str) -> ActionRequest {
    ActionRequest {
        request_id: ulid_bytes(id),
        requested_by: requested_by.into(),
        runbook: "restart-web".into(),
        target: ulid_bytes(MACHINE),
        params: Default::default(),
        reason: "nginx is down on the other site".into(),
    }
}

async fn next(statuses: &mut rackhand_hub::peers::Statuses) -> action_request_status::Status {
    tokio::time::timeout(Duration::from_secs(10), statuses.next())
        .await
        .expect("a status")
        .expect("a status")
        .status
        .unwrap()
}

fn approvals(db: &Db) -> Vec<(String, String, String)> {
    db.readers()
        .with(|c| {
            let mut s = c.prepare("SELECT id, requested_by, state FROM approvals ORDER BY rowid")?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
        })
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn action_request_needs_owner_approval() {
    let env = env("approval").await;
    let beta = link(&env, &env.beta).await;
    let mut statuses = beta.request(&request("01JREQ0000000000000000000A", "user:alice")).await.unwrap();
    assert_eq!(next(&mut statuses).await, action_request_status::Status::NeedsApproval(true));
    assert_eq!(count(&env.db, "SELECT count(*) FROM jobs WHERE name = 'restart-web'"), 0, "nothing runs without it");
    // a person on the owning hub approves
    let all = approvals(&env.db);
    assert_eq!(all.len(), 1);
    let admin = Decider { user: "admin".into(), role: Role::Admin, step_up_fresh: true };
    Approvals::new(env.db.clone()).decide(&all[0].0, &admin, true, now_ms()).await.unwrap();
    env.bus
        .publish(rackhand_hub::bus::BusEvent::ApprovalDecided {
            id: ulid_bytes(&all[0].0).try_into().unwrap(),
            approved: true,
        })
        .await;
    let mut seen = Vec::new();
    loop {
        let s = next(&mut statuses).await;
        let last = matches!(s, action_request_status::Status::Done(_));
        seen.push(s);
        if last {
            break;
        }
    }
    assert!(
        matches!(seen.last(), Some(action_request_status::Status::Done(d)) if *d == rackhand_proto::peer::JobOutcome::Succeeded as i32),
        "{seen:?}"
    );
    assert_eq!(count(&env.db, "SELECT count(*) FROM jobs WHERE name = 'restart-web' AND state = 'succeeded'"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn request_retry_same_id_idempotent() {
    let env = env("idempotent").await;
    let beta = link(&env, &env.beta).await;
    let mut first = beta.request(&request("01JREQ0000000000000000000B", "user:alice")).await.unwrap();
    assert_eq!(next(&mut first).await, action_request_status::Status::NeedsApproval(true));
    // the stream breaks and the requester asks again with the same id: the same request, not a second one
    drop(first);
    let mut again = beta.request(&request("01JREQ0000000000000000000B", "user:alice")).await.unwrap();
    assert_eq!(next(&mut again).await, action_request_status::Status::NeedsApproval(true));
    assert_eq!(approvals(&env.db).len(), 1, "one approval for the one request");
    // and approved once, one job only
    let admin = Decider { user: "admin".into(), role: Role::Admin, step_up_fresh: true };
    let id = approvals(&env.db)[0].0.clone();
    Approvals::new(env.db.clone()).decide(&id, &admin, true, now_ms()).await.unwrap();
    env.bus
        .publish(rackhand_hub::bus::BusEvent::ApprovalDecided {
            id: ulid_bytes(&id).try_into().unwrap(),
            approved: true,
        })
        .await;
    loop {
        if matches!(next(&mut again).await, action_request_status::Status::Done(_)) {
            break;
        }
    }
    let mut third = beta.request(&request("01JREQ0000000000000000000B", "user:alice")).await.unwrap();
    assert!(
        matches!(next(&mut third).await, action_request_status::Status::Done(_)),
        "a finished request says so again"
    );
    assert_eq!(count(&env.db, "SELECT count(*) FROM jobs WHERE name = 'restart-web'"), 1, "one job only");
}

#[tokio::test(flavor = "multi_thread")]
async fn requested_by_not_trusted_as_user() {
    let env = env("requested-by").await;
    let beta = link(&env, &env.beta).await;
    // the peer claims an admin asked: it still needs the owning hub's approval, and the approval isn't that admin's
    let mut statuses = beta.request(&request("01JREQ0000000000000000000C", "user:admin")).await.unwrap();
    assert_eq!(next(&mut statuses).await, action_request_status::Status::NeedsApproval(true));
    let all = approvals(&env.db);
    assert_eq!(all.len(), 1);
    assert!(all[0].1.starts_with("peer:beta:"), "asked by the peer, not by a user: {all:?}");
    assert!(!all[0].1.contains("admin"), "{all:?}");
    assert_eq!(count(&env.db, "SELECT count(*) FROM jobs"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_requests_auto_runs_without_an_approval_unless_high_risk() {
    let env = env("auto").await;
    env.db
        .writer()
        .send(WriteCmd::Batch(vec![RowWrite::insert(
            "policies",
            Row::from([("id", t("p1")), ("name", t("auto")), ("peer_requests", t("auto"))]),
        )]))
        .await
        .unwrap();
    env.db
        .writer()
        .send(WriteCmd::RegistryChange(rackhand_store::RegistryChange {
            updates: vec![rackhand_store::RowUpdate {
                table: "machines",
                key: ("id", t(MACHINE)),
                set: Row::from([("policy_id", t("p1"))]),
            }],
            ..Default::default()
        }))
        .await
        .unwrap();
    let beta = link(&env, &env.beta).await;
    let mut statuses = beta.request(&request("01JREQ0000000000000000000D", "user:alice")).await.unwrap();
    loop {
        if matches!(next(&mut statuses).await, action_request_status::Status::Done(_)) {
            break;
        }
    }
    assert!(approvals(&env.db).is_empty(), "the policy said auto for a low-risk runbook");
    assert_eq!(count(&env.db, "SELECT count(*) FROM jobs WHERE name = 'restart-web' AND state = 'succeeded'"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn unlinked_peer_gets_0x13() {
    let env = env("unlink").await;
    let beta = link(&env, &env.beta).await;
    assert!(beta.query(&query_machine()).await.is_ok());
    // the peer unlinks itself; the owner removes it, and its next connect is closed with 0x13
    beta.unlink("moving the hub").await.unwrap();
    let db = env.db.clone();
    eventually(move || count(&db, "SELECT count(*) FROM peers WHERE revoked_at IS NOT NULL") == 1).await;
    assert!(env.peers.peers().is_empty());
    let after = env.beta.connect(env.addr.clone(), alpn::PEER).await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), after.closed()).await.expect("closed");
    assert_eq!(rackhand_net::close_code(&closed), Some(rackhand_proto::close::CloseCode::Revoked), "{closed:?}");
    let _ = env.registry;
}
