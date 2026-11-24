//! `rackhand-cli` against a hub (7.7.3, 7.3.6, 7.3.11, D59): a login with an invite and a status that follows it, a tunnel to a
//! machine by its name through `connect` and `forward`, a file sent with `send`, and a stdio MCP session through `mcp`.

#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rackhand_cli::commands;
use rackhand_cli::config::{self, Dirs};
use rackhand_cli::login::login;
use rackhand_hub::actions::runner::BoxFuture;
use rackhand_hub::audit::Audit;
use rackhand_hub::mcp::keys::{Scope, create_personal_key};
use rackhand_hub::mcp::{Facts, Mcp, Observations, SeriesQuery};
use rackhand_hub::peers::tunnel::{Network, Tunnels};
use rackhand_hub::peers::xfer::{Opener, Sink, Xfer};
use rackhand_hub::registry::Registry;
use rackhand_hub::registry::join_server::{HubInfo, JoinServer, ManagedSetupSource};
use rackhand_net::router::{Router, handler};
use rackhand_proto::alpn;
use rackhand_proto::common::ProbeConfig;
use rackhand_proto::join::ManagedSetup;
use rackhand_proto::tunnel::XferOffer;
use rackhand_store::ids::now_ms;
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;
use serde_json::{Value as Json, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

#[derive(Debug)]
struct Fixed;

impl Observations for Fixed {
    fn series(&self, _q: &SeriesQuery) -> Vec<(i64, f64)> {
        Vec::new()
    }

    fn facts(&self, _machine_id: &str) -> Facts {
        Facts {
            services: vec![json!({ "name": "nginx", "state": "running" })],
            containers: Vec::new(),
            updates: Vec::new(),
        }
    }
}

/// A destination that keeps what it is sent.
#[derive(Default)]
struct Keeps(Arc<Mutex<Vec<u8>>>);

struct KeepSink {
    data: Arc<Mutex<Vec<u8>>>,
    hash: Vec<u8>,
}

impl Sink for KeepSink {
    fn resume(&mut self) -> BoxFuture<'_, Result<u64, String>> {
        Box::pin(async { Ok(0) })
    }

    fn write<'a>(&'a mut self, _index: u64, data: &'a [u8]) -> BoxFuture<'a, Result<(), String>> {
        self.data.lock().unwrap().extend_from_slice(data);
        Box::pin(async { Ok(()) })
    }

    fn finish(self: Box<Self>) -> BoxFuture<'static, Result<(), String>> {
        Box::pin(async move {
            let ok = blake3::hash(&self.data.lock().unwrap()).as_bytes().as_slice() == self.hash.as_slice();
            if ok { Ok(()) } else { Err("the file doesn't match its hash".into()) }
        })
    }

    fn abandon(self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }
}

impl Opener for Keeps {
    fn open<'a>(
        &'a self,
        _caller: iroh::EndpointId,
        offer: &'a XferOffer,
    ) -> BoxFuture<'a, Result<Box<dyn Sink>, String>> {
        let sink = KeepSink { data: self.0.clone(), hash: offer.blake3.clone() };
        Box::pin(async move { Ok(Box::new(sink) as Box<dyn Sink>) })
    }
}

struct FixedSetup;

impl ManagedSetupSource for FixedSetup {
    fn managed_setup(&self, _machine_id: ulid::Ulid, _with_assistant: bool) -> ManagedSetup {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        ManagedSetup {
            automation_pubkey: "ssh-ed25519 AAAAautomation rackhand".into(),
            assistant_pubkey: None,
            sudoers: String::new(),
            commands: Some(rackhand_proto::signed::sign(&key, "commands", 1, now_ms(), now_ms() + 60_000, b"{}")),
        }
    }
}

struct Env {
    db: Arc<Db>,
    registry: Arc<Registry>,
    cli: Dirs,
    ticket: String,
    echo: SocketAddr,
    kept: Arc<Mutex<Vec<u8>>>,
    _relay: iroh_relay::server::Server,
}

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = tcp.read(&mut buf).await {
                    if n == 0 || tcp.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

async fn env(name: &str) -> Env {
    let dir = std::env::temp_dir().join(format!("rackhand-cli-contract-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let echo = echo_server().await;
    let ports = format!("[{}]", echo.port());
    let writes = vec![
        RowWrite::insert(
            "sites",
            Row::from([("id", t("s1")), ("name", t("home")), ("timezone", t("UTC")), ("is_local", Value::Integer(1))]),
        ),
        RowWrite::insert("sites", Row::from([("id", t("s2")), ("name", t("offsite")), ("timezone", t("UTC"))])),
        RowWrite::insert(
            "machines",
            Row::from([
                ("id", t("01J1FAR0000000000000000000")),
                ("site_id", t("s2")),
                ("name", t("far")),
                ("kind", t("linux")),
                ("address", t("127.0.0.1")),
                ("state", t("enrolled")),
            ]),
        ),
        RowWrite::insert("policies", Row::from([("id", t("p1")), ("name", t("open")), ("tunnel_ports", t(&ports))])),
        RowWrite::insert(
            "machines",
            Row::from([
                ("id", t("01J1WEB0000000000000000000")),
                ("site_id", t("s1")),
                ("name", t("web")),
                ("kind", t("linux")),
                ("os", t("Debian 12")),
                ("address", t("127.0.0.1")),
                ("state", t("enrolled")),
                ("policy_id", t("p1")),
            ]),
        ),
        RowWrite::insert(
            "users",
            Row::from([
                ("id", t("u-bob")),
                ("name", t("bob")),
                ("role", t("responder")),
                ("created_at", Value::Integer(1)),
            ]),
        ),
    ];
    db.writer().send(WriteCmd::Batch(writes)).await.unwrap();
    let registry = Registry::load(db.clone()).unwrap();
    let audit = Audit::new(db.writer());
    let (relay, relay_url) = rackhand_net::testing::local_relay().await;
    let hub = rackhand_net::testing::endpoint(&relay_url, &[alpn::JOIN, alpn::TUNNEL, alpn::XFER, alpn::MCP]).await;
    let info = HubInfo {
        site: "home".into(),
        version: "0.1.0".into(),
        relays: vec![relay_url.to_string()],
        hub_addrs: Vec::new(),
        probe_config: ProbeConfig::default(),
    };
    let (join, _joined) = JoinServer::new(registry.clone(), Arc::new(FixedSetup), info);
    let tunnels = Tunnels::new(db.clone(), audit.clone(), Arc::new(Network::new(hub.clone(), vec![relay_url.clone()])));
    let keeps = Keeps::default();
    let kept = keeps.0.clone();
    let xfer = Xfer::new(Arc::new(keeps));
    let mcp = Mcp::new(db.clone(), audit, Arc::new(Fixed));
    let j = join.clone();
    let router = Router::new(hub.clone(), registry.clone())
        .route(alpn::JOIN, handler(move |conn| j.clone().serve(conn)))
        .route(alpn::TUNNEL, tunnels.handler())
        .route(alpn::XFER, xfer.handler())
        .route(alpn::MCP, mcp.handler());
    tokio::spawn(router.serve());
    let hub_id: String = hub.id().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let ticket = format!("rackhand1:{hub_id}@!{relay_url}");
    Env { db, registry, cli: Dirs(dir.join("cli")), ticket, echo, kept, _relay: relay }
}

impl Env {
    /// An invite as the dashboard shows it, and the login that uses it.
    async fn enroll(&self) -> config::Hub {
        let invite = self.registry.invite_device("u-bob", "bob", now_ms()).await.unwrap();
        login(&self.cli, &format!("{}#{}", self.ticket, invite.as_str()), "laptop").await.unwrap()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn login_with_invite_then_status() {
    let env = env("login").await;
    let before = commands::status(&env.cli).await.unwrap();
    assert!(before.contains("isn't enrolled"), "{before}");
    let hub = env.enroll().await;
    assert_eq!((hub.site.as_str(), hub.user.as_str()), ("home", "bob"));
    assert_eq!(config::load(&env.cli), vec![hub.clone()]);
    let after = commands::status(&env.cli).await.unwrap();
    assert!(
        after.contains("home") && after.contains("user bob") && after.contains("enrolled and reachable"),
        "{after}"
    );
    // an invite works once; a second login with it is refused with what the hub said
    let invite = env.registry.invite_device("u-bob", "bob", now_ms()).await.unwrap();
    let text = format!("{}#{}", env.ticket, invite.as_str());
    let other = Dirs(env.cli.0.join("other"));
    login(&other, &text, "phone").await.unwrap();
    let again = login(&Dirs(env.cli.0.join("third")), &text, "tablet").await.unwrap_err();
    assert!(again.contains("refused the login"), "{again}");
    // a computer the hub doesn't know is told so by status
    let stranger = Dirs(env.cli.0.join("stranger"));
    config::save(&stranger, hub).unwrap();
    let state = commands::status(&stranger).await.unwrap();
    assert!(state.contains("doesn't know this device"), "{state}");
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_and_forward_reach_a_machine_by_its_name() {
    let env = env("connect").await;
    env.enroll().await;
    let port = env.echo.port();
    // `connect`: standard input and output are the tunnel
    let (mut input_tx, input_rx) = tokio::io::duplex(1024);
    let (output_tx, mut output_rx) = tokio::io::duplex(1024);
    let dirs = env.cli.clone();
    let task = tokio::spawn(async move { commands::connect(&dirs, "home/web", port, input_rx, output_tx).await });
    input_tx.write_all(b"ssh-2.0 through connect").await.unwrap();
    let mut got = vec![0u8; 23];
    tokio::time::timeout(Duration::from_secs(10), output_rx.read_exact(&mut got)).await.expect("the answer").unwrap();
    assert_eq!(got, b"ssh-2.0 through connect");
    drop(input_tx);
    task.await.unwrap().unwrap();
    // `forward`: a local port, on loopback, whose connections are tunnels
    let free = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let dirs = env.cli.clone();
    tokio::spawn(async move { commands::forward(&dirs, free, &format!("home/web:{port}")).await });
    let mut tcp = loop {
        match tokio::net::TcpStream::connect(("127.0.0.1", free)).await {
            Ok(s) => break s,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    };
    tcp.write_all(b"through forward").await.unwrap();
    let mut got = vec![0u8; 15];
    tokio::time::timeout(Duration::from_secs(10), tcp.read_exact(&mut got)).await.expect("the answer").unwrap();
    assert_eq!(got, b"through forward");
    // a machine of another site belongs to another hub: by its name here it is no machine of this one
    let (_, rx) = tokio::io::duplex(8);
    let (tx, _) = tokio::io::duplex(8);
    let e = commands::connect(&env.cli, "home/far", port, rx, tx).await.unwrap_err();
    assert!(e.contains("doesn't let this device reach"), "{e}");
    // a machine the hub doesn't have, and a port its policy doesn't allow, are refused and say why
    let (_, rx) = tokio::io::duplex(8);
    let (tx, _) = tokio::io::duplex(8);
    let e = commands::connect(&env.cli, "home/nowhere", port, rx, tx).await.unwrap_err();
    assert!(e.contains("doesn't let this device reach"), "{e}");
    let (_, rx) = tokio::io::duplex(8);
    let (tx, _) = tokio::io::duplex(8);
    let e = commands::connect(&env.cli, "home/web", port + 1, rx, tx).await.unwrap_err();
    assert!(e.contains("policy doesn't allow that port"), "{e}");
    // a hub this computer isn't enrolled to
    let (_, rx) = tokio::io::duplex(8);
    let (tx, _) = tokio::io::duplex(8);
    let e = commands::connect(&env.cli, "offsite/web", port, rx, tx).await.unwrap_err();
    assert!(e.contains("no hub is known for `offsite`"), "{e}");
    let audited: i64 = env
        .db
        .readers()
        .with(|c| {
            c.query_row(
                "SELECT count(*) FROM audit_log WHERE action = 'tunnel.opened' AND actor = 'user:bob'",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert!(audited >= 2, "each tunnel is audited: {audited}");
}

#[tokio::test(flavor = "multi_thread")]
async fn send_puts_a_file_where_the_hub_takes_it() {
    let env = env("send").await;
    env.enroll().await;
    let data: Vec<u8> = (0..2_500_000).map(|i| (i % 251) as u8).collect();
    let path = env.cli.0.join("payload.bin");
    std::fs::write(&path, &data).unwrap();
    commands::send(&env.cli, &path, "home/web:/var/lib/rackhand-run/incoming/payload.bin", true).await.unwrap();
    assert_eq!(*env.kept.lock().unwrap(), data);
    let e = commands::send(&env.cli, &env.cli.0.join("missing.bin"), "home/web:/x", true).await.unwrap_err();
    assert!(e.contains("missing.bin"), "{e}");
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_stdio_lists_tools_and_calls_get_machine() {
    let env = env("mcp").await;
    env.enroll().await;
    let key =
        create_personal_key(&env.db, "u-bob", &device_id(&env), Scope::Read, now_ms() + 3_600_000).await.unwrap().1;
    let (mut client_tx, input) = tokio::io::duplex(65536);
    let (output, client_rx) = tokio::io::duplex(65536);
    let dirs = env.cli.clone();
    tokio::spawn(async move { commands::mcp(&dirs, "home", &key, input, output).await });
    let mut lines = BufReader::new(client_rx).lines();
    let ask = |id: u64, method: &str, params: Json| {
        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        format!("{msg}\n")
    };
    client_tx
        .write_all(ask(1, "initialize", json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "t", "version": "0" } })).as_bytes())
        .await
        .unwrap();
    let init: Json = serde_json::from_str(
        &tokio::time::timeout(Duration::from_secs(10), lines.next_line()).await.unwrap().unwrap().unwrap(),
    )
    .unwrap();
    assert_eq!(init["result"]["serverInfo"]["name"], "rackhand");
    client_tx
        .write_all(format!("{}\n", json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).as_bytes())
        .await
        .unwrap();
    client_tx.write_all(ask(2, "tools/list", json!({})).as_bytes()).await.unwrap();
    let list: Json = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    let names: Vec<&str> =
        list["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"get_machine") && names.contains(&"list_machines"), "{names:?}");
    client_tx
        .write_all(
            ask(3, "tools/call", json!({ "name": "get_machine", "arguments": { "machine": "home/web" } })).as_bytes(),
        )
        .await
        .unwrap();
    let call: Json = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_ne!(call["result"]["isError"], true, "{call}");
    assert!(call["result"]["content"][0]["text"].as_str().unwrap().contains("nginx"), "{call}");
    // a key the hub doesn't know ends the session before any answer
    let (mut tx2, input2) = tokio::io::duplex(1024);
    let (output2, rx2) = tokio::io::duplex(1024);
    let dirs = env.cli.clone();
    let session = tokio::spawn(async move { commands::mcp(&dirs, "home", "rhk_not_a_key", input2, output2).await });
    tx2.write_all(ask(1, "initialize", json!({})).as_bytes()).await.unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), BufReader::new(rx2).read_to_end(&mut rest)).await;
    assert!(!String::from_utf8_lossy(&rest).contains("\"serverInfo\""), "no session for an unknown key");
    session.abort();
}

fn device_id(env: &Env) -> String {
    env.db.readers().with(|c| c.query_row("SELECT id FROM devices WHERE name = 'laptop'", [], |r| r.get(0))).unwrap()
}
