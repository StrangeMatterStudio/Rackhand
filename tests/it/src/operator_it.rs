//! The operator binary (plan T77, 7.3.5): `rackhand operator join` against a real hub, and `rackhand operator run` with the
//! scripted runner against hubs in this process, so the offers, the bridge, the hub's MCP and the approvals are the real ones.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use rackhand_hub::actions::Actions;
use rackhand_hub::actions::runner::{BoxFuture, StepCtx, StepOutcome, StepResult, StepRunner};
use rackhand_hub::assist::{Assist, AssistRequest, AssistResult};
use rackhand_hub::audit::Audit;
use rackhand_hub::bus::Bus;
use rackhand_hub::library::items::{Kind, Library};
use rackhand_hub::mcp::{Facts, Mcp, Observations, SeriesQuery};
use rackhand_hub::policy::approvals::{Approvals, Decider, Role};
use rackhand_hub::registry::Registry;
use rackhand_runbook::runbook::Step;
use rackhand_store::ids::now_ms;
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use crate::probe_hub::Hub;
use crate::support::{binary, binary_with};

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rackhand-it-operator-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

mod operator {
    use super::*;

    /// The real hub: an operator invite, and `rackhand operator join` with it.
    #[test]
    fn join_registers_the_host_with_the_hub() {
        let mut hub = Hub::init("op-join");
        hub.start();
        hub.first_run();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let invite = rt.block_on(async {
            let db = Arc::new(Db::open(&hub.data.join("hub.db")).unwrap());
            let registry = Registry::load(db).unwrap();
            registry.invite_operator("admin", now_ms()).await.unwrap().as_str().to_string()
        });
        let dir = temp("join");
        let exe = binary("rackhand", "rackhand");
        let join = |invite: &str| {
            Command::new(&exe)
                .args(["operator", "join", "--ticket"])
                .arg(format!("rackhand1:{}@127.0.0.1:{}", hub.id_hex, hub.quic))
                .args(["--invite", invite, "--name", "lab-operator", "--dir"])
                .arg(&dir)
                .output()
                .unwrap()
        };
        let out = join(&invite);
        let said = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "{said}");
        assert!(said.contains("Joined the hub"), "{said}");
        let db = rusqlite::Connection::open(hub.data.join("hub.db")).unwrap();
        let (name, endpoint): (String, String) =
            db.query_row("SELECT name, endpoint_id FROM operators", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(name, "lab-operator");
        // the hub knows this host by the endpoint id of its node key, and the host remembers the hub
        let key = rackhand_net::key::load_or_create(&dir.join("node.key")).unwrap();
        assert_eq!(endpoint, key.public().to_string());
        let hubs = std::fs::read_to_string(dir.join("hubs.toml")).unwrap();
        assert!(hubs.contains(&hub.id_hex) && hubs.contains(&hub.quic.to_string()), "{hubs}");
        // an invite works once
        let again = join(&invite);
        assert!(!again.status.success(), "{}", String::from_utf8_lossy(&again.stderr));
        let operators: i64 = db.query_row("SELECT count(*) FROM operators", [], |r| r.get(0)).unwrap();
        assert_eq!(operators, 1);
    }

    // ---- hubs in this process --------------------------------------------------------------------------------------

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

    /// Every step of a runbook succeeds.
    #[derive(Debug)]
    struct Works;

    impl StepRunner for Works {
        fn run<'a>(&'a self, _c: &'a StepCtx, _s: &'a Step, _a: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
            Box::pin(async {
                StepResult {
                    outcome: StepOutcome::Succeeded,
                    command: None,
                    exit_code: Some(0),
                    stdout: b"done\n".to_vec(),
                    stderr: Vec::new(),
                }
            })
        }
    }

    const PLAYBOOK: &str = "+++\nname = \"service-down\"\nincident_kinds = [\"service.down\"]\nautonomy = 1\nrisk = \"normal\"\ntools = [\"list_machines\", \"get_approval\", \"run_runbook\", \"finish_job\"]\nhosts = \"incident\"\nmax_runtime = \"30m\"\n+++\n## When\nA service is down.\n## Read first\n## Do\n## Done when\n## Stop and ask if\n";

    fn runbook(name: &str) -> String {
        format!(
            "name = \"{name}\"\ndescription = \"test\"\nidentity = \"automation\"\nrisk = \"low\"\nautonomy = 1\n\
             [[step]]\nid = \"tell\"\nkind = \"notify\"\nmessage = \"{name}\"\n"
        )
    }

    struct InHub {
        db: Arc<Db>,
        assist: Assist,
        machine: String,
        ticket: rackhand_net::ticket::Ticket,
        _server: iroh::Endpoint,
    }

    /// A hub with one machine, an open incident, the playbook and two runbooks, and the operator at `operator_id`.
    async fn in_hub(name: &str, machine_name: &str, operator_id: &str) -> InHub {
        let dir = temp(name);
        let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
        let machine = format!("01JMACH{}", name.to_uppercase().replace('-', ""))
            .chars()
            .chain("AAAAAAAAAAAAAAAAAAAAAAAAAA".chars())
            .take(26)
            .collect::<String>();
        let incident = "01J1NC1DENTAAAAAAAAAAAAAAA";
        let writes = vec![
            RowWrite::insert("sites", Row::from([("id", t("s1")), ("name", t("home")), ("timezone", t("UTC"))])),
            RowWrite::insert(
                "machines",
                Row::from([
                    ("id", t(&machine)),
                    ("site_id", t("s1")),
                    ("name", t(machine_name)),
                    ("kind", t("linux")),
                    ("state", t("enrolled")),
                ]),
            ),
            RowWrite::insert(
                "incidents",
                Row::from([
                    ("id", t(incident)),
                    ("machine_id", t(&machine)),
                    ("dedupe_key", t("k")),
                    ("kind", t("service.down")),
                    ("severity", t("warning")),
                    ("state", t("assistant")),
                    ("title", t("nginx is down")),
                    ("opened_at", Value::Integer(now_ms())),
                ]),
            ),
            RowWrite::insert(
                "operators",
                Row::from([
                    ("id", t("op1")),
                    ("name", t("lab-operator")),
                    ("endpoint_id", t(operator_id)),
                    ("order", Value::Integer(0)),
                ]),
            ),
        ];
        db.writer().send(WriteCmd::Batch(writes)).await.unwrap();
        let audit = Audit::new(db.writer());
        let (library, _) = Library::new(db.clone(), audit.clone());
        library.save(Kind::Playbook, "service-down", PLAYBOOK, "admin", 1).await.unwrap();
        for rb in ["step-one", "step-two"] {
            library.save(Kind::Runbook, rb, &runbook(rb), "admin", 1).await.unwrap();
        }
        let actions = Actions::new(db.clone(), audit.clone(), Bus::new(), Arc::new(Works));
        let assist = Assist::new(db.clone(), audit.clone(), actions.clone());
        let mcp = Mcp::new(db.clone(), audit, Arc::new(Nothing)).with_actions(actions).with_library(library);
        let key = rackhand_net::key::load_or_create(&dir.join("hub.key")).unwrap();
        let config = rackhand_net::endpoint::EndpointConfig {
            relays: Default::default(),
            alpns: vec![rackhand_proto::alpn::OPERATOR.to_vec(), rackhand_proto::alpn::MCP.to_vec()],
            bind: Some("127.0.0.1:0".parse().unwrap()),
        };
        let server = rackhand_net::endpoint::bind(key, &config).await.unwrap();
        let registry = Registry::load(db.clone()).unwrap();
        let router = rackhand_net::router::Router::new(server.clone(), registry)
            .route(rackhand_proto::alpn::OPERATOR, assist.handler())
            .route(rackhand_proto::alpn::MCP, mcp.handler());
        tokio::spawn(router.serve());
        let addrs: Vec<std::net::SocketAddr> =
            server.addr().ip_addrs().copied().filter(|a| a.ip().is_loopback() || a.is_ipv4()).collect();
        let ticket = rackhand_net::ticket::Ticket { hub_id: *server.id().as_bytes(), addrs, relays: vec![] };
        InHub { db, assist, machine, ticket, _server: server }
    }

    struct OperatorProcess {
        child: Child,
        log: PathBuf,
    }

    impl Drop for OperatorProcess {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl OperatorProcess {
        fn log(&self) -> String {
            std::fs::read_to_string(&self.log).unwrap_or_default()
        }
    }

    /// An operator host: its directory and node key, whose endpoint id the hubs list.
    struct Host {
        dirs: rackhand_operator::state::Dirs,
        id: String,
        dir: PathBuf,
    }

    fn host(name: &str) -> Host {
        let dir = temp(name);
        let dirs = rackhand_operator::state::Dirs(dir.join("state"));
        let id = rackhand_net::key::load_or_create(&dirs.node_key()).unwrap().public().to_string();
        Host { dirs, id, dir }
    }

    /// `rackhand operator run` for the hubs the host joined, with the scripted runner.
    fn run_operator(host: &Host, hubs: &[(&InHub, &str)], script: &serde_json::Value) -> OperatorProcess {
        for (hub, site) in hubs {
            let entry = rackhand_operator::state::Hub {
                id: hub.ticket.hub_id.iter().map(|b| format!("{b:02x}")).collect(),
                site: site.to_string(),
                addrs: hub.ticket.addrs.iter().map(|a| a.to_string()).collect(),
                relays: vec![],
            };
            rackhand_operator::state::save(&host.dirs, entry).unwrap();
        }
        let script_path = host.dir.join("script.json");
        std::fs::write(&script_path, script.to_string()).unwrap();
        let log = host.dir.join("operator.log");
        let out = std::fs::File::create(&log).unwrap();
        let child = Command::new(binary_with("rackhand", "rackhand", "lab-build"))
            .args(["operator", "run", "--dir"])
            .arg(&host.dirs.0)
            .arg("--runner")
            .arg(format!("fake:{}", script_path.display()))
            .args(["--max-jobs", "2"])
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(out.try_clone().unwrap()))
            .stderr(Stdio::from(out))
            .spawn()
            .unwrap();
        OperatorProcess { child, log }
    }

    fn request(hub: &InHub) -> AssistRequest {
        AssistRequest {
            incident_id: "01J1NC1DENTAAAAAAAAAAAAAAA".into(),
            playbook: "service-down".into(),
            brief: "nginx on the machine is down".into(),
            hosts: vec![hub.machine.clone()],
            deadline_ms: None,
            max_turns: None,
        }
    }

    async fn until(limit: Duration, what: &str, mut f: impl FnMut() -> bool) {
        let start = std::time::Instant::now();
        while !f() {
            assert!(start.elapsed() < limit, "not within {limit:?}: {what}");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    async fn when_connected(hub: &InHub, op: &OperatorProcess) {
        until(Duration::from_secs(40), &format!("the operator connected: {}", op.log()), || {
            !hub.assist.connected_operators().is_empty()
        })
        .await;
    }

    fn job(db: &Db, id: &str) -> (String, Option<String>) {
        db.readers()
            .with(|c| {
                c.query_row("SELECT state, outcome FROM jobs WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))
            })
            .unwrap()
    }

    fn transcript(db: &Db, id: &str) -> Vec<String> {
        db.readers()
            .with(|c| {
                let mut s = c.prepare("SELECT text FROM assistant_transcripts WHERE job_id = ?1 ORDER BY seq")?;
                s.query_map([id], |r| r.get(0))?.collect()
            })
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_operator_two_hubs() {
        let host = host("two-hubs");
        let (alpha, beta) = (in_hub("hub-alpha", "alpha", &host.id).await, in_hub("hub-beta", "beta", &host.id).await);
        let script = serde_json::json!([
            { "say": "looking" },
            { "call": "list_machines", "args": {} },
            { "finish": { "outcome": "resolved", "summary": "done" } }
        ]);
        let op = run_operator(&host, &[(&alpha, "alpha"), (&beta, "beta")], &script);
        when_connected(&alpha, &op).await;
        when_connected(&beta, &op).await;
        let (a, b) = (alpha.assist.start(request(&alpha)).await, beta.assist.start(request(&beta)).await);
        let (AssistResult::Accepted { job_id: ja, .. }, AssistResult::Accepted { job_id: jb, .. }) = (a, b) else {
            panic!("a hub's job wasn't accepted: {}", op.log())
        };
        until(Duration::from_secs(60), &format!("both jobs succeeded: {}", op.log()), || {
            job(&alpha.db, &ja).0 == "succeeded" && job(&beta.db, &jb).0 == "succeeded"
        })
        .await;
        let (ta, tb) = (transcript(&alpha.db, &ja).join("\n"), transcript(&beta.db, &jb).join("\n"));
        assert!(ta.contains("looking") && ta.contains("list_machines") && ta.contains("alpha"), "{ta}");
        assert!(tb.contains("looking") && tb.contains("list_machines") && tb.contains("beta"), "{tb}");
        // each hub saw its own machines through the operator, and never the other's
        assert!(!ta.contains("beta") && !tb.contains("alpha"), "alpha: {ta}\nbeta: {tb}");
        assert_eq!(job(&alpha.db, &ja).1.as_deref(), Some("resolved"));
    }

    fn approvals(db: &Db) -> Vec<(String, String, String)> {
        db.readers()
            .with(|c| {
                let mut s =
                    c.prepare("SELECT id, json_extract(args, '$.name'), state FROM approvals ORDER BY rowid")?;
                s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
            })
            .unwrap()
    }

    /// AC34: each change the assistant wants waits for its own approval, in the order of the script; the next is not asked
    /// for before the one before it has been decided and has run.
    #[tokio::test(flavor = "multi_thread")]
    async fn guided_install_each_change_approved_in_order() {
        let host = host("guided");
        let hub = in_hub("hub-guided", "web", &host.id).await;
        let call = |name: &str| {
            serde_json::json!({ "call": "run_runbook", "wait_approval": true,
                "args": { "name": name, "target": hub.machine, "params": {}, "reason": "guided install" } })
        };
        let script = serde_json::json!([
            { "say": "two changes, one at a time" },
            call("step-one"),
            call("step-two"),
            { "finish": { "outcome": "resolved", "summary": "both done" } }
        ]);
        let op = run_operator(&host, &[(&hub, "home")], &script);
        when_connected(&hub, &op).await;
        let AssistResult::Accepted { job_id, .. } = hub.assist.start(request(&hub)).await else {
            panic!("not accepted: {}", op.log())
        };
        let admin = Decider { user: "admin".into(), role: Role::Admin, step_up_fresh: true };
        let decide = Approvals::new(hub.db.clone());
        for (n, runbook) in ["step-one", "step-two"].iter().enumerate() {
            until(Duration::from_secs(40), &format!("an approval for {runbook}: {}", op.log()), || {
                approvals(&hub.db).len() > n
            })
            .await;
            let all = approvals(&hub.db);
            assert_eq!(all.len(), n + 1, "the next change isn't asked for before this one is decided: {all:?}");
            assert_eq!(all[n].1, *runbook, "{all:?}");
            assert_eq!(all[n].2, "pending");
            // nothing of it has run yet
            let ran: i64 = hub
                .db
                .readers()
                .with(|c| c.query_row("SELECT count(*) FROM jobs WHERE name = ?1", [runbook], |r| r.get(0)))
                .unwrap();
            assert_eq!(ran, 0, "{runbook} ran without its approval");
            decide.decide(&all[n].0, &admin, true, now_ms()).await.unwrap();
        }
        until(Duration::from_secs(60), &format!("the job finished: {}", op.log()), || {
            job(&hub.db, &job_id).0 == "succeeded"
        })
        .await;
        let order: Vec<String> = hub
            .db
            .readers()
            .with(|c| {
                let mut s =
                    c.prepare("SELECT name FROM jobs WHERE name IN ('step-one', 'step-two') ORDER BY started_at, id")?;
                s.query_map([], |r| r.get(0))?.collect()
            })
            .unwrap();
        assert_eq!(order, ["step-one", "step-two"]);
        let states: Vec<String> = approvals(&hub.db).into_iter().map(|a| a.2).collect();
        assert_eq!(states, ["used", "used"], "each approval was used once, by the call it was for");
    }
}
