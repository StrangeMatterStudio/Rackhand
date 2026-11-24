//! The `rackhand/tunnel/1` contract (7.3.11, 7.3.2, FR-19, FR-21, D59, D60, D80, AC30, AC46): who may open a tunnel and to
//! which ports, a remote-mode probe that splices only from its pinned hub and only to its own SSH port, and a monitor
//! probe that accepts none.

#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, TransportAddr};
use prost::Message;
use rackhand_hub::audit::Audit;
use rackhand_hub::executor::RemoteReach;
use rackhand_hub::peers::tunnel::{Forwards, Network, Tunnels};
use rackhand_hub::registry::Registry;
use rackhand_net::frames;
use rackhand_proto::alpn;
use rackhand_proto::tunnel::{TunnelError, TunnelOpen, TunnelReply, tunnel_reply};
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn t(s: &str) -> Value {
    Value::Text(s.to_string())
}

/// A valid ULID that is a number.
fn id(n: u64) -> String {
    format!("01J1{n:022}")
}

fn bytes(id: &str) -> Vec<u8> {
    id.parse::<ulid::Ulid>().unwrap().to_bytes().to_vec()
}

/// Echoes every connection; its address stands in for a machine's SSH server.
async fn echo_server() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
    (addr, seen)
}

const WEB: u64 = 1;
const FAR: u64 = 2;
const QUIET: u64 = 3;
const ELSEWHERE: u64 = 4;

struct Env {
    db: Arc<Db>,
    hub: Endpoint,
    hub_addr: EndpointAddr,
    responder: Endpoint,
    viewer: Endpoint,
    /// The remote-mode probe of `far`, and where its "SSH server" is.
    probe: Endpoint,
    probe_addr: EndpointAddr,
    ssh: (SocketAddr, Arc<std::sync::atomic::AtomicUsize>),
    /// The machine `web`'s port (a local machine), which its policy allows.
    web: (SocketAddr, Arc<std::sync::atomic::AtomicUsize>),
    forwards: Arc<Forwards>,
    _relay: iroh_relay::server::Server,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

async fn env(name: &str) -> Env {
    let dir = std::env::temp_dir().join(format!("rackhand-tunnel-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let (relay, relay_url) = rackhand_net::testing::local_relay().await;
    let hub = rackhand_net::testing::endpoint(&relay_url, &[alpn::TUNNEL]).await;
    let responder = rackhand_net::testing::endpoint(&relay_url, &[]).await;
    let viewer = rackhand_net::testing::endpoint(&relay_url, &[]).await;
    // the probes accept a tunnel only if remote mode and managed (`alpns`): `far` does, `quiet` is a monitor probe
    let probe = rackhand_net::testing::endpoint(
        &relay_url,
        &rackhand_probe::remote::alpns(true, true).iter().map(Vec::as_slice).collect::<Vec<_>>(),
    )
    .await;
    let quiet_probe = rackhand_net::testing::endpoint(
        &relay_url,
        &rackhand_probe::remote::alpns(true, false).iter().map(Vec::as_slice).collect::<Vec<_>>(),
    )
    .await;
    let (ssh, web) = (echo_server().await, echo_server().await);
    let row = |table: &'static str, cols: Vec<(&'static str, Value)>| RowWrite::insert(table, Row::from_iter(cols));
    let machine =
        |n: u64, name: &str, site: &str, mode: &str, access: &str, probe: Option<&Endpoint>, policy: Option<&str>| {
            let mut cols = vec![
                ("id", t(&id(n))),
                ("site_id", t(site)),
                ("name", t(name)),
                ("kind", t("linux")),
                ("address", t("127.0.0.1")),
                ("mode", t(mode)),
                ("access", t(access)),
                ("state", t("enrolled")),
            ];
            if let Some(p) = probe {
                cols.push(("probe_endpoint_id", t(&p.id().to_string())));
            }
            if let Some(p) = policy {
                cols.push(("policy_id", t(p)));
            }
            row("machines", cols)
        };
    let web_ports = format!("[{}]", web.0.port());
    let writes = vec![
        row(
            "sites",
            vec![("id", t("s1")), ("name", t("alpha")), ("timezone", t("UTC")), ("is_local", Value::Integer(1))],
        ),
        row("sites", vec![("id", t("s2")), ("name", t("beta")), ("timezone", t("UTC"))]),
        row("policies", vec![("id", t("p-web")), ("name", t("web")), ("tunnel_ports", t(&web_ports))]),
        machine(WEB, "web", "s1", "local", "managed", None, Some("p-web")),
        machine(FAR, "far", "s1", "remote", "managed", Some(&probe), None),
        machine(QUIET, "quiet", "s1", "remote", "monitor", Some(&quiet_probe), None),
        machine(ELSEWHERE, "elsewhere", "s2", "local", "managed", None, None),
        row(
            "users",
            vec![
                ("id", t("u-resp")),
                ("name", t("riley")),
                ("role", t("responder")),
                ("created_at", Value::Integer(1)),
            ],
        ),
        row(
            "users",
            vec![("id", t("u-view")), ("name", t("vic")), ("role", t("viewer")), ("created_at", Value::Integer(1))],
        ),
        row(
            "devices",
            vec![
                ("id", t("d-resp")),
                ("user_id", t("u-resp")),
                ("name", t("laptop")),
                ("endpoint_id", t(&responder.id().to_string())),
                ("created_at", Value::Integer(1)),
            ],
        ),
        row(
            "devices",
            vec![
                ("id", t("d-view")),
                ("user_id", t("u-view")),
                ("name", t("phone")),
                ("endpoint_id", t(&viewer.id().to_string())),
                ("created_at", Value::Integer(1)),
            ],
        ),
    ];
    db.writer().send(WriteCmd::Batch(writes)).await.unwrap();
    let audit = Audit::new(db.writer());
    let _ = audit.append("admin", "test", None, "{}").await;
    let registry = Registry::load(db.clone()).unwrap();
    let relays = vec![relay_url.clone()];
    let network = Arc::new(Network::new(hub.clone(), relays));
    let tunnels = Tunnels::new(db.clone(), audit, network.clone());
    let router = rackhand_net::router::Router::new(hub.clone(), registry).route(alpn::TUNNEL, tunnels.handler());
    let mut tasks = vec![tokio::spawn(router.serve())];
    // the probe of `far` splices to this test's "SSH server" in place of 127.0.0.1:22
    tasks.push(rackhand_probe::remote::spawn(probe.clone(), hub.id(), bytes(&id(FAR)).try_into().unwrap(), ssh.0));
    let relay_only = |e: &Endpoint| {
        let mut a = e.addr();
        a.addrs.insert(TransportAddr::Relay(relay_url.clone()));
        a
    };
    let forwards = Arc::new(Forwards::new(db.clone(), network));
    Env {
        db,
        hub_addr: relay_only(&hub),
        probe_addr: relay_only(&probe),
        hub,
        responder,
        viewer,
        probe,
        ssh,
        web,
        forwards,
        _relay: relay,
        _tasks: tasks,
    }
}

/// Asks for a tunnel and returns the streams, or what the hub said.
async fn open(
    from: &Endpoint,
    to: &EndpointAddr,
    alpn: &[u8],
    target: &[u8],
    port: u32,
) -> Result<(SendStream, RecvStream), String> {
    let conn = from.connect(to.clone(), alpn).await.map_err(|e| format!("connect: {e}"))?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    let open = TunnelOpen { target: target.to_vec(), port, purpose: "test".into() };
    frames::write_msg(&mut send, &open).await.map_err(|e| e.to_string())?;
    let body = frames::read(&mut recv).await.map_err(|e| format!("closed: {e:?} {:?}", conn.close_reason()))?;
    let reply = TunnelReply::decode(body.as_slice()).unwrap();
    match reply.reply {
        Some(tunnel_reply::Reply::Opened(true)) => {
            // keep the connection alive with the streams
            std::mem::forget(conn);
            Ok((send, recv))
        }
        Some(tunnel_reply::Reply::Error(e)) => Err(format!("{:?}", TunnelError::try_from(e).unwrap())),
        other => Err(format!("{other:?}")),
    }
}

async fn round_trip(mut send: SendStream, mut recv: RecvStream, data: &[u8]) -> Vec<u8> {
    send.write_all(data).await.unwrap();
    let mut got = vec![0u8; data.len()];
    tokio::time::timeout(Duration::from_secs(10), recv.read_exact(&mut got)).await.expect("the answer").unwrap();
    got
}

fn count(db: &Db, sql: &str) -> i64 {
    db.readers().with(|c| c.query_row(sql, [], |r| r.get(0))).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn viewer_device_refused_responder_allowed() {
    let env = env("roles").await;
    let port = u32::from(env.web.0.port());
    let refused = open(&env.viewer, &env.hub_addr, alpn::TUNNEL, &bytes(&id(WEB)), port).await.err().unwrap();
    assert_eq!(refused, "OutOfScope", "a viewer can't open a tunnel (7.7.2)");
    let (send, recv) = open(&env.responder, &env.hub_addr, alpn::TUNNEL, &bytes(&id(WEB)), port).await.unwrap();
    assert_eq!(round_trip(send, recv, b"hello through the hub").await, b"hello through the hub");
    // a machine of another site belongs to another hub; a machine that doesn't exist isn't anyone's
    for target in [id(ELSEWHERE), id(99)] {
        let e = open(&env.responder, &env.hub_addr, alpn::TUNNEL, &bytes(&target), port).await.err().unwrap();
        assert_eq!(e, "OutOfScope", "{target}");
    }
    // each attempt is in the audit log, and the open one says who and what
    assert_eq!(count(&env.db, "SELECT count(*) FROM audit_log WHERE action = 'tunnel.refused'"), 3);
    assert_eq!(
        count(&env.db, "SELECT count(*) FROM audit_log WHERE action = 'tunnel.opened' AND actor = 'user:riley'"),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn port_not_in_policy_refused() {
    let env = env("ports").await;
    let other = u32::from(env.web.0.port()) + 1;
    let e = open(&env.responder, &env.hub_addr, alpn::TUNNEL, &bytes(&id(WEB)), other).await.err().unwrap();
    assert_eq!(e, "PortNotAllowed", "the policy of `web` allows only its own port");
    // a machine with no policy gets the default, 22: another port is refused there too
    let e = open(&env.responder, &env.hub_addr, alpn::TUNNEL, &bytes(&id(FAR)), 8080).await.err().unwrap();
    assert_eq!(e, "PortNotAllowed");
    // and a port that isn't a port at all
    let e = open(&env.responder, &env.hub_addr, alpn::TUNNEL, &bytes(&id(WEB)), 70_000).await.err().unwrap();
    assert_eq!(e, "PortNotAllowed");
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_probe_splices_only_to_local_22_from_pinned_hub() {
    let env = env("probe").await;
    let far = bytes(&id(FAR));
    // the pinned hub, straight to the probe: port 22 reaches the machine's SSH server
    let (send, recv) = open(&env.hub, &env.probe_addr, alpn::TUNNEL, &far, 22).await.unwrap();
    assert_eq!(round_trip(send, recv, b"ssh").await, b"ssh");
    assert_eq!(env.ssh.1.load(std::sync::atomic::Ordering::SeqCst), 1);
    // any other port is refused, and nothing was opened anywhere for it
    let e = open(&env.hub, &env.probe_addr, alpn::TUNNEL, &far, u32::from(env.web.0.port())).await.err().unwrap();
    assert_eq!(e, "PortNotAllowed");
    assert_eq!(env.web.1.load(std::sync::atomic::Ordering::SeqCst), 0, "another port is never opened");
    assert_eq!(env.ssh.1.load(std::sync::atomic::Ordering::SeqCst), 1);
    // another machine's id isn't this probe's to serve
    let e = open(&env.hub, &env.probe_addr, alpn::TUNNEL, &bytes(&id(WEB)), 22).await.err().unwrap();
    assert_eq!(e, "OutOfScope");
    // any other endpoint, even a registered device, is closed: only the pinned hub may open a tunnel
    let e = open(&env.responder, &env.probe_addr, alpn::TUNNEL, &far, 22).await.err().unwrap();
    assert!(e.contains("closed"), "{e}");
    assert_eq!(env.ssh.1.load(std::sync::atomic::Ordering::SeqCst), 1, "the other endpoint reached nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn monitor_remote_probe_accepts_no_tunnels() {
    let env = env("monitor").await;
    // the hub doesn't even try: a monitor machine has no account for it to use
    let e = open(&env.responder, &env.hub_addr, alpn::TUNNEL, &bytes(&id(QUIET)), 22).await.err().unwrap();
    assert_eq!(e, "Unsupported");
    // and the probe itself, asked directly, doesn't speak the protocol at all
    let quiet: iroh::EndpointId = env
        .db
        .readers()
        .with(|c| {
            c.query_row("SELECT probe_endpoint_id FROM machines WHERE name = 'quiet'", [], |r| r.get::<_, String>(0))
        })
        .unwrap()
        .parse()
        .unwrap();
    let mut addr = EndpointAddr::new(quiet);
    addr.addrs.extend(env.probe_addr.addrs.iter().filter(|a| matches!(a, TransportAddr::Relay(_))).cloned());
    let attempt = tokio::time::timeout(Duration::from_secs(10), env.hub.connect(addr, alpn::TUNNEL)).await;
    assert!(!matches!(attempt, Ok(Ok(_))), "a monitor probe accepts no tunnel connection");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_reaches_a_remote_machine_through_the_hub_and_the_probe() {
    let env = env("through").await;
    let (send, recv) = open(&env.responder, &env.hub_addr, alpn::TUNNEL, &bytes(&id(FAR)), 22).await.unwrap();
    assert_eq!(round_trip(send, recv, b"ssh-2.0 through two hops").await, b"ssh-2.0 through two hops");
    assert_eq!(env.ssh.1.load(std::sync::atomic::Ordering::SeqCst), 1, "it arrived at the probe's SSH port");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_hubs_own_ssh_to_a_remote_machine_goes_through_the_probe() {
    let env = env("reach").await;
    // a local machine isn't reached this way
    assert!(env.forwards.reach(&id(WEB)).is_none());
    assert!(env.forwards.reach(&id(99)).is_none());
    // a remote-mode one is: a loopback address the SSH client dials, spliced to the probe's SSH port
    let addr = env.forwards.reach(&id(FAR)).expect("remote mode").await.unwrap();
    assert!(addr.ip().is_loopback());
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"SSH-2.0-hub").await.unwrap();
    let mut got = [0u8; 11];
    tokio::time::timeout(Duration::from_secs(10), tcp.read_exact(&mut got)).await.expect("the answer").unwrap();
    assert_eq!(&got, b"SSH-2.0-hub");
    // the same address serves the next command
    let again = env.forwards.reach(&id(FAR)).expect("remote mode").await.unwrap();
    assert_eq!(again, addr);
    let _ = (&env.probe, &env.hub);
}
