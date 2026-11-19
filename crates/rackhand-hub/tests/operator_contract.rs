//! The `rackhand/operator/1` contract (7.3.5) with a scripted fake operator: offers in order, declines, tokens bound
//! to the accepting operator, disconnects, reattachment after a hub restart, and transcripts.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, TransportAddr};
use prost::Message;
use rackhand_hub::actions::Actions;
use rackhand_hub::actions::runner::{BoxFuture, StepCtx, StepResult, StepRunner};
use rackhand_hub::assist::{Assist, AssistRequest, AssistResult};
use rackhand_hub::audit::Audit;
use rackhand_hub::bus::{Bus, BusEvent, Delivery, JobOutcome};
use rackhand_hub::library::items::{Kind, Library};
use rackhand_hub::mcp::{Facts, Mcp, Observations, SeriesQuery};
use rackhand_hub::registry::Registry;
use rackhand_proto::alpn;
use rackhand_proto::operator::{
    HubToOperator, JobDone, JobEvent, JobEventKind, JobOffer, JobReply, OperatorHello, OperatorToHub, Outcome,
    hub_to_operator, job_reply, operator_to_hub,
};
use rackhand_runbook::runbook::Step;
use rackhand_store::ids::now_ms;
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;
use serde_json::json;

const PLAYBOOK: &str = "+++\nname = \"service-down\"\nincident_kinds = [\"service.down\"]\nautonomy = 1\nrisk = \"normal\"\ntools = [\"get_incident\", \"get_machine\", \"run_diagnostic\"]\nhosts = \"incident\"\nmax_runtime = \"30m\"\n+++\n## When\nA service is down.\n## Read first\n## Do\n## Done when\n## Stop and ask if\n";
const MACHINE: &str = "01JMACH1NEAAAAAAAAAAAAAAAA";

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

#[derive(Debug)]
struct Nothing;

impl Observations for Nothing {
    fn series(&self, _q: &SeriesQuery) -> Vec<(i64, f64)> {
        Vec::new()
    }
    fn facts(&self, _m: &str) -> Facts {
        Facts::default()
    }
}

#[derive(Debug)]
struct NoRunner;

impl StepRunner for NoRunner {
    fn run<'a>(&'a self, _c: &'a StepCtx, _s: &'a Step, _a: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async { StepResult::failed("unused") })
    }
}

struct Hub {
    pub db: Arc<Db>,
    pub addr: EndpointAddr,
    pub assist: Assist,
    pub bus: Bus,
    pub relay_url: iroh::RelayUrl,
    pub operators: Vec<Endpoint>,
    _relay: iroh_relay::server::Server,
    _server: Endpoint,
}

/// A hub with three operators in that order, and an open incident on one machine.
async fn hub(name: &str) -> Hub {
    let dir = std::env::temp_dir().join(format!("rackhand-operator-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let (relay, relay_url) = rackhand_net::testing::local_relay().await;
    let mut operators = Vec::new();
    for _ in 0..3 {
        operators.push(rackhand_net::testing::endpoint(&relay_url, &[]).await);
    }
    let mut writes = vec![
        RowWrite::insert("sites", Row::from([("id", t("s1")), ("name", t("home")), ("timezone", t("UTC"))])),
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
                ("dedupe_key", t("web/service.down")),
                ("kind", t("service.down")),
                ("severity", t("warning")),
                ("state", t("assistant")),
                ("title", t("nginx is down")),
                ("opened_at", Value::Integer(now_ms())),
            ]),
        ),
    ];
    for (n, op) in operators.iter().enumerate() {
        writes.push(RowWrite::insert(
            "operators",
            Row::from([
                ("id", t(&format!("op{}", n + 1))),
                ("name", t(&format!("operator-{}", n + 1))),
                ("endpoint_id", t(&op.id().to_string())),
                ("order", Value::Integer(n as i64)),
            ]),
        ));
    }
    db.writer().send(WriteCmd::Batch(writes)).await.unwrap();
    let audit = Audit::new(db.writer());
    let (library, _) = Library::new(db.clone(), audit.clone());
    library.save(Kind::Playbook, "service-down", PLAYBOOK, "admin", 1).await.unwrap();
    let bus = Bus::new();
    let actions = Actions::new(db.clone(), audit.clone(), bus.clone(), Arc::new(NoRunner));
    let assist = Assist::new(db.clone(), audit.clone(), actions.clone());
    let mcp = Mcp::new(db.clone(), audit, Arc::new(Nothing)).with_actions(actions);
    let server = rackhand_net::testing::endpoint(&relay_url, &[alpn::OPERATOR, alpn::MCP]).await;
    let registry = Registry::load(db.clone()).unwrap();
    let router = rackhand_net::router::Router::new(server.clone(), registry)
        .route(alpn::OPERATOR, assist.handler())
        .route(alpn::MCP, mcp.handler());
    tokio::spawn(router.serve());
    let mut addr = server.addr();
    addr.addrs.insert(TransportAddr::Relay(relay_url.clone()));
    Hub { db, addr, assist, bus, relay_url, operators, _relay: relay, _server: server }
}

/// A fake operator: one connection, one stream, frames each way.
struct FakeOperator {
    pub conn: Connection,
    send: SendStream,
    recv: RecvStream,
}

async fn write_frame(send: &mut SendStream, msg: &impl Message) {
    let body = msg.encode_to_vec();
    send.write_all(&(body.len() as u32).to_be_bytes()).await.unwrap();
    send.write_all(&body).await.unwrap();
}

impl FakeOperator {
    pub async fn connect(hub: &Hub, which: usize, running: Vec<Vec<u8>>, max_jobs: u32) -> FakeOperator {
        let conn = hub.operators[which].connect(hub.addr.clone(), alpn::OPERATOR).await.unwrap();
        let (mut send, recv) = conn.open_bi().await.unwrap();
        let hello = OperatorToHub {
            msg: Some(operator_to_hub::Msg::Hello(OperatorHello {
                operator_version: None,
                runners: vec![],
                max_jobs,
                running,
            })),
        };
        write_frame(&mut send, &hello).await;
        FakeOperator { conn, send, recv }
    }

    /// The next message from the hub, or `None` if none comes within a few seconds.
    pub async fn next(&mut self) -> Option<HubToOperator> {
        let mut len = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), self.recv.read_exact(&mut len)).await.ok()?.ok()?;
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        self.recv.read_exact(&mut body).await.ok()?;
        HubToOperator::decode(body.as_slice()).ok()
    }

    pub async fn offer(&mut self) -> Option<JobOffer> {
        match self.next().await?.msg? {
            hub_to_operator::Msg::Offer(o) => Some(o),
            _ => None,
        }
    }

    pub async fn reply(&mut self, accept: bool) {
        let reply = if accept { job_reply::Reply::Accepted(true) } else { job_reply::Reply::Declined("busy".into()) };
        let msg = OperatorToHub { msg: Some(operator_to_hub::Msg::Reply(JobReply { reply: Some(reply) })) };
        write_frame(&mut self.send, &msg).await;
    }

    pub async fn event(&mut self, job: &[u8], text: &str) {
        let ev =
            JobEvent { job_id: job.to_vec(), at_ms: now_ms(), kind: JobEventKind::Message as i32, text: text.into() };
        write_frame(&mut self.send, &OperatorToHub { msg: Some(operator_to_hub::Msg::Event(ev)) }).await;
    }

    pub async fn done(&mut self, job: &[u8], outcome: Outcome, summary: &str) {
        let done = JobDone { job_id: job.to_vec(), outcome: outcome as i32, summary: summary.into() };
        write_frame(&mut self.send, &OperatorToHub { msg: Some(operator_to_hub::Msg::Done(done)) }).await;
    }
}

fn request() -> AssistRequest {
    AssistRequest {
        incident_id: "01J1NC1DENTAAAAAAAAAAAAAAA".into(),
        playbook: "service-down".into(),
        brief: "nginx on web is down since 10:02".into(),
        hosts: vec![MACHINE.into()],
        deadline_ms: None,
        max_turns: None,
    }
}

fn ulid_text(bytes: &[u8]) -> String {
    ulid::Ulid::from_bytes(bytes.try_into().unwrap()).to_string()
}

fn job_state(db: &Db, job: &str) -> (String, Option<String>) {
    db.readers()
        .with(|c| c.query_row("SELECT state, outcome FROM jobs WHERE id = ?1", [job], |r| Ok((r.get(0)?, r.get(1)?))))
        .unwrap()
}

async fn wait_until(mut f: impl FnMut() -> bool) {
    for _ in 0..100 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("never happened");
}

#[tokio::test(flavor = "multi_thread")]
async fn offer_accept_events_done() {
    let hub = hub("accept").await;
    let mut events = hub.bus.subscribe("test");
    let mut op = FakeOperator::connect(&hub, 0, vec![], 2).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let assist = hub.assist.clone();
    let started = tokio::spawn(async move { assist.start(request()).await });
    let offer = op.offer().await.expect("an offer");
    op.reply(true).await;
    let AssistResult::Accepted { job_id, operator_id } = started.await.unwrap() else { panic!("not accepted") };
    assert_eq!((ulid_text(&offer.job_id), operator_id.as_str()), (job_id.clone(), "op1"));
    op.event(&offer.job_id, "looking at the journal").await;
    op.event(&offer.job_id, "nginx restarted").await;
    op.done(&offer.job_id, Outcome::Resolved, "restarted nginx").await;
    let db = hub.db.clone();
    let id = job_id.clone();
    wait_until(move || job_state(&db, &id).0 == "succeeded").await;
    let stored: Vec<String> = hub
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT text FROM assistant_transcripts WHERE job_id = ?1 ORDER BY seq")?;
            let rows = s.query_map([&job_id], |r| r.get(0))?;
            rows.collect()
        })
        .unwrap();
    assert_eq!(stored, ["looking at the journal", "nginx restarted"]);
    match tokio::time::timeout(Duration::from_secs(2), events.recv()).await.unwrap() {
        Some(Delivery::Event(BusEvent::JobFinished { outcome, .. })) => assert_eq!(outcome, JobOutcome::Succeeded),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn decline_tries_next_three_declines_go_human() {
    let hub = hub("decline").await;
    let mut ops = Vec::new();
    for n in 0..3 {
        ops.push(FakeOperator::connect(&hub, n, vec![], 1).await);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let assist = hub.assist.clone();
    let started = tokio::spawn(async move { assist.start(request()).await });
    // In the configured order, each declines in turn.
    for op in ops.iter_mut() {
        let _ = op.offer().await.expect("offered in order");
        op.reply(false).await;
    }
    match started.await.unwrap() {
        AssistResult::ToPerson { job_id: Some(job), reason } => {
            assert_eq!(reason, "declined");
            assert_eq!(job_state(&hub.db, &job), ("failed".to_string(), Some("declined".to_string())));
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn no_operator_goes_human() {
    let hub = hub("none").await;
    match hub.assist.start(request()).await {
        AssistResult::ToPerson { job_id: Some(job), reason } => {
            assert_eq!(reason, "no_operator");
            assert_eq!(job_state(&hub.db, &job).0, "failed");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn token_from_other_endpoint_refused() {
    let hub = hub("token").await;
    let mut op = FakeOperator::connect(&hub, 0, vec![], 1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let assist = hub.assist.clone();
    let started = tokio::spawn(async move { assist.start(request()).await });
    let offer = op.offer().await.unwrap();
    op.reply(true).await;
    assert!(matches!(started.await.unwrap(), AssistResult::Accepted { .. }));
    // The token from another operator's endpoint: refused with out_of_scope.
    let other = hub.operators[1].connect(hub.addr.clone(), alpn::MCP).await.unwrap();
    let (mut send, mut recv) = other.open_bi().await.unwrap();
    send.write_all(format!("{}\n", json!({ "auth": offer.job_token })).as_bytes()).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1 << 16)).await.unwrap().unwrap();
    let text = String::from_utf8_lossy(&reply);
    assert!(text.contains("out_of_scope"), "{text}");
    // From the accepting operator it works.
    let own = hub.operators[0].connect(hub.addr.clone(), alpn::MCP).await.unwrap();
    let (mut send, mut recv) = own.open_bi().await.unwrap();
    send.write_all(format!("{}\n", json!({ "auth": offer.job_token })).as_bytes()).await.unwrap();
    let init = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    send.write_all(format!("{init}\n").as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 65536];
    let n = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf)).await.unwrap().unwrap().unwrap();
    let line: serde_json::Value = serde_json::from_slice(buf[..n].split(|b| *b == b'\n').next().unwrap()).unwrap();
    let tools: Vec<&str> =
        line["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(tools, ["get_machine", "get_incident", "run_diagnostic"], "the playbook's tools");
    assert_eq!(offer.allowed_tools, ["get_incident", "get_machine", "run_diagnostic"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnect_fails_tools_then_failed_after_5_min() {
    let hub = hub("disconnect").await;
    let mut op = FakeOperator::connect(&hub, 0, vec![], 1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let assist = hub.assist.clone();
    let started = tokio::spawn(async move { assist.start(request()).await });
    let offer = op.offer().await.unwrap();
    op.reply(true).await;
    let AssistResult::Accepted { job_id, .. } = started.await.unwrap() else { panic!() };
    // The connection drops. The operator's tool calls fail with hub_unreachable meanwhile (its side); after 5 minutes
    // without the hub it stops the runner and reports `failed` when it reconnects.
    op.conn.close(0u32.into(), b"gone");
    drop(op);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(job_state(&hub.db, &job_id).0, "running", "the hub waits for the operator");
    let mut again = FakeOperator::connect(&hub, 0, vec![], 1).await;
    again.done(&offer.job_id, Outcome::Failed, "hub_unreachable for 5 minutes").await;
    let db = hub.db.clone();
    let id = job_id.clone();
    wait_until(move || job_state(&db, &id).0 == "failed").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hub_restart_reattaches_running_jobs() {
    let hub = hub("restart").await;
    let mut op = FakeOperator::connect(&hub, 0, vec![], 1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let assist = hub.assist.clone();
    let started = tokio::spawn(async move { assist.start(request()).await });
    let offer = op.offer().await.unwrap();
    op.reply(true).await;
    let AssistResult::Accepted { job_id, .. } = started.await.unwrap() else { panic!() };
    // A new hub process: a fresh Assist on the same database, with the operator's hello naming its running job.
    let audit = Audit::new(hub.db.writer());
    let actions = Actions::new(hub.db.clone(), audit.clone(), Bus::new(), Arc::new(NoRunner));
    let restarted = Assist::new(hub.db.clone(), audit, actions);
    let server = rackhand_net::testing::endpoint(&hub.relay_url, &[alpn::OPERATOR]).await;
    let router = rackhand_net::router::Router::new(server.clone(), Registry::load(hub.db.clone()).unwrap())
        .route(alpn::OPERATOR, restarted.handler());
    tokio::spawn(router.serve());
    let mut addr = server.addr();
    addr.addrs.insert(TransportAddr::Relay(hub.relay_url.clone()));
    let conn = hub.operators[0].connect(addr, alpn::OPERATOR).await.unwrap();
    let (mut send, recv) = conn.open_bi().await.unwrap();
    let hello = OperatorToHub {
        msg: Some(operator_to_hub::Msg::Hello(OperatorHello {
            operator_version: None,
            runners: vec![],
            max_jobs: 1,
            running: vec![offer.job_id.clone()],
        })),
    };
    write_frame(&mut send, &hello).await;
    let mut op = FakeOperator { conn, send, recv };
    let db = hub.db.clone();
    let assist2 = restarted.clone();
    let id = job_id.clone();
    wait_until(move || assist2.attached(&id) && job_state(&db, &id).0 == "running").await;
    op.event(&offer.job_id, "after the restart").await;
    op.done(&offer.job_id, Outcome::Resolved, "done").await;
    let db = hub.db.clone();
    let id = job_id.clone();
    wait_until(move || job_state(&db, &id).0 == "succeeded").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn transcript_capped_5mb_later_events_counted() {
    let hub = hub("transcript").await;
    let mut op = FakeOperator::connect(&hub, 0, vec![], 1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let assist = hub.assist.clone();
    let started = tokio::spawn(async move { assist.start(request()).await });
    let offer = op.offer().await.unwrap();
    op.reply(true).await;
    let AssistResult::Accepted { job_id, .. } = started.await.unwrap() else { panic!() };
    // Six 1 MB events: five fit in 5 MB, the sixth is only counted.
    let big = "x".repeat(1 << 20);
    for _ in 0..6 {
        op.event(&offer.job_id, &big).await;
    }
    op.done(&offer.job_id, Outcome::Resolved, "done").await;
    let db = hub.db.clone();
    let id = job_id.clone();
    wait_until(move || job_state(&db, &id).0 == "succeeded").await;
    let (rows, bytes): (i64, i64) = hub
        .db
        .readers()
        .with(|c| {
            c.query_row(
                "SELECT count(*), coalesce(sum(length(text)), 0) FROM assistant_transcripts WHERE job_id = ?1 AND kind = 'message'",
                [&job_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
        })
        .unwrap();
    assert!(bytes <= 5 * (1 << 20), "{bytes}");
    assert_eq!(rows, 5, "the events that fit in 5 MB");
    let note: String = hub
        .db
        .readers()
        .with(|c| {
            c.query_row(
                "SELECT text FROM assistant_transcripts WHERE job_id = ?1 AND kind = 'dropped'",
                [&job_id],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert!(note.contains("1 event"), "{note}");
}

mod assist {
    use super::*;
    use rackhand_hub::policy::approvals::{ApprovalError, ApprovalRequest, Approvals, Decider, Role, approval_hash};
    use rackhand_runbook::runbook::Risk;

    const RUNBOOK: &str = "name = \"restart-web\"\ndescription = \"Restart the web service\"\nidentity = \"automation\"\nrisk = \"low\"\nautonomy = 1\n[[step]]\nid = \"restart\"\nkind = \"ssh\"\ncmd = [\"sudo\", \"/usr/local/lib/rackhand/run\", \"/usr/bin/systemctl\", \"restart\", \"nginx.service\"]\n";

    #[tokio::test(flavor = "multi_thread")]
    async fn offer_has_scoped_token_hosts_tools_deadline() {
        let hub = hub("offer-fields").await;
        let mut op = FakeOperator::connect(&hub, 0, vec![], 1).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let before = now_ms();
        let assist = hub.assist.clone();
        let started = tokio::spawn(async move { assist.start(request()).await });
        let offer = op.offer().await.unwrap();
        op.reply(true).await;
        let AssistResult::Accepted { job_id, .. } = started.await.unwrap() else { panic!() };
        assert_eq!(ulid_text(&offer.incident_id), "01J1NC1DENTAAAAAAAAAAAAAAA");
        assert_eq!((offer.playbook.as_str(), offer.playbook_rev, offer.autonomy), ("service-down", 1, 1));
        assert_eq!(offer.brief_markdown, "nginx on web is down since 10:02");
        assert_eq!(offer.allowed_tools, ["get_incident", "get_machine", "run_diagnostic"]);
        assert_eq!(offer.hosts.iter().map(|h| ulid_text(h)).collect::<Vec<_>>(), [MACHINE]);
        assert!((before + 30 * 60_000..=now_ms() + 30 * 60_000).contains(&offer.deadline_ms), "30 minutes by default");
        assert_eq!(offer.max_turns, 60);
        // The token is bound to this operator, these hosts and tools, until the deadline.
        let (operator, hosts, tools, expires): (String, String, String, i64) = hub
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT operator_id, hosts, tools, expires_at FROM job_tokens WHERE job_id = ?1",
                    [&job_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
            })
            .unwrap();
        assert_eq!(operator, "op1");
        assert_eq!(serde_json::from_str::<Vec<String>>(&hosts).unwrap(), [MACHINE]);
        assert_eq!(serde_json::from_str::<Vec<String>>(&tools).unwrap(), offer.allowed_tools);
        assert_eq!(expires, offer.deadline_ms);
        // A deadline later than 2 hours is cut to 2 hours.
        let mut long = request();
        long.deadline_ms = Some(now_ms() + 5 * 3_600_000);
        let assist = hub.assist.clone();
        let mut op2 = FakeOperator::connect(&hub, 1, vec![], 1).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let started = tokio::spawn(async move { assist.start(long).await });
        // The first operator holds its one job, so the second is offered this one.
        let offer = op2.offer().await.unwrap();
        op2.reply(true).await;
        started.await.unwrap();
        assert!(offer.deadline_ms <= now_ms() + 2 * 3_600_000);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn daily_cap_routes_to_person_with_note() {
        let hub = hub("cap").await;
        // Twenty assistant jobs already today.
        let rows = (0..20)
            .map(|n| {
                RowWrite::insert(
                    "jobs",
                    Row::from([
                        ("id", t(&ulid::Ulid::new().to_string())),
                        ("kind", t("assistant")),
                        ("name", t(&format!("earlier-{n}"))),
                        ("requested_by", t("incidents")),
                        ("state", t("succeeded")),
                        ("started_at", Value::Integer(now_ms() - 1000)),
                    ]),
                )
            })
            .collect();
        hub.db.writer().send(WriteCmd::Batch(rows)).await.unwrap();
        let _op = FakeOperator::connect(&hub, 0, vec![], 1).await;
        match hub.assist.start(request()).await {
            AssistResult::ToPerson { job_id: None, reason } => assert_eq!(reason, "daily_cap"),
            other => panic!("{other:?}"),
        }
        let note: String = hub
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT data FROM incident_events WHERE incident_id = '01J1NC1DENTAAAAAAAAAAAAAAA' AND kind = 'note'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert!(note.contains("daily assistant cap (20)"), "{note}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn deadline_with_pending_approval_needs_human_and_resume() {
        let hub = hub("resume").await;
        let audit = Audit::new(hub.db.writer());
        let (library, _) = Library::new(hub.db.clone(), audit);
        library.save(Kind::Runbook, "restart-web", RUNBOOK, "admin", 1).await.unwrap();
        let mut op = FakeOperator::connect(&hub, 0, vec![], 2).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let assist = hub.assist.clone();
        let started = tokio::spawn(async move { assist.start(request()).await });
        let offer = op.offer().await.unwrap();
        op.reply(true).await;
        let AssistResult::Accepted { job_id, .. } = started.await.unwrap() else { panic!() };
        // The assistant asked to run a runbook; a person approved it just as the deadline came.
        let call = ApprovalRequest {
            requester: format!("job:{job_id}"),
            tool: "run_runbook".into(),
            target: Some(MACHINE.into()),
            args: json!({ "name": "restart-web", "params": {} }),
            runbook_rev: Some(1),
            risk: Risk::Low,
            step_up: false,
            reason: "restart".into(),
        };
        let approvals = Approvals::new(hub.db.clone());
        let id = approvals.create(&call, now_ms(), 3_600_000).await.unwrap();
        let admin = Decider { user: "admin".into(), role: Role::Admin, step_up_fresh: true };
        approvals.decide(&id, &admin, true, now_ms()).await.unwrap();
        op.done(&offer.job_id, Outcome::TimedOut, "deadline").await;
        let db = hub.db.clone();
        let jid = job_id.clone();
        wait_until(move || job_state(&db, &jid).0 != "running").await;
        assert_eq!(job_state(&hub.db, &job_id), ("failed".to_string(), Some("needs_human".to_string())));
        assert!(hub.assist.resumable(&job_id));
        // Resume: the approved call runs first, then a new job is offered.
        let assist = hub.assist.clone();
        let jid = job_id.clone();
        let resumed = tokio::spawn(async move { assist.resume(&jid).await });
        let next = op.offer().await.expect("a new offer");
        op.reply(true).await;
        let AssistResult::Accepted { job_id: new_job, .. } = resumed.await.unwrap().unwrap() else { panic!() };
        assert_ne!(new_job, job_id);
        assert_eq!(ulid_text(&next.job_id), new_job);
        let ran: String = hub
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT approval_id FROM jobs WHERE name = 'restart-web' AND approval_id IS NOT NULL",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(ran, id, "the approved call ran, with its approval");
        assert!(next.brief_markdown.contains("restart-web"), "the new brief says what ran: {}", next.brief_markdown);
        let used = approvals.check(&id, &format!("job:{job_id}"), &approval_hash(&call), now_ms());
        assert_eq!(used, Err(ApprovalError::Used));
    }
}
