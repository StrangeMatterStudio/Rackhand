//! Two hubs behind NATs (AC27, E26, AC31): direct when the NATs allow it, through the relay when they don't, and nothing at
//! all, with an explanation, when there is no relay either. The hubs here are bare endpoints: what the peer protocol says is
//! tested over any connection in `peer_contract`; these tests are about which path that connection takes.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr};
use rackhand_hub::peers::path_status::{PathStatus, PeerPath};
use rackhand_net::endpoint::{EndpointConfig, bind_trusting_relays};
use rackhand_net::paths::{self, PathKind};
use rackhand_net::relays::RelayConfig;
use rackhand_relay::admission::{CAPACITY, Mode};
use rackhand_relay::run::{Certificate, RelayRun, run};

use crate::topology::{A, B, FORWARDED_PORT, Lab, Nat, NsRuntime, RELAY, RELAY_IP};

const ALPN: &[u8] = b"rackhand/net-test/1";

fn relay_url() -> String {
    format!("https://{RELAY_IP}")
}

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// The relay in its namespace, with a certificate it made for itself, and the rate (none unless given).
async fn start_relay(rt: &NsRuntime, rate_bits: Option<u32>, mode: Mode) -> iroh_relay::server::Server {
    let dir = std::env::temp_dir().join(format!("rackhand-net-relay-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory");
    let cert = rcgen::generate_simple_self_signed(vec![RELAY_IP.to_string()]).expect("a certificate");
    std::fs::write(dir.join("cert.pem"), cert.cert.pem()).expect("cert");
    std::fs::write(dir.join("key.pem"), cert.signing_key.serialize_pem()).expect("key");
    let any = |port: u16| SocketAddr::from(([0, 0, 0, 0], port));
    let config = RelayRun {
        data_dir: dir.clone(),
        mode,
        http: any(80),
        https: any(443),
        quic: any(7842),
        certificate: Certificate::Files { cert: dir.join("cert.pem"), key: dir.join("key.pem") },
        rate_bits,
        capacity: CAPACITY,
    };
    let (server, _admission) = rt.run(async move { run(&config).await }).await.expect("the relay starts");
    server
}

/// A hub's endpoint in a namespace: with the relay or without one, on a fixed port or any.
async fn hub(rt: &NsRuntime, seed: u8, relay: bool, port: Option<u16>) -> Endpoint {
    let config = EndpointConfig {
        relays: RelayConfig { relays: if relay { vec![relay_url()] } else { Vec::new() }, ..RelayConfig::default() },
        alpns: vec![ALPN.to_vec()],
        bind: port.map(|p| SocketAddr::from(([0, 0, 0, 0], p))),
    };
    rt.run(async move { bind_trusting_relays(key(seed), &config).await.expect("an endpoint") }).await
}

/// Answers each bidirectional stream with what it was sent, or, in sink mode, with one byte once all of it has arrived.
fn serve(rt: &NsRuntime, endpoint: Endpoint, sink: bool) {
    rt.spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let Ok(data) = recv.read_to_end(8 << 20).await else { return };
                    let _ = send.write_all(if sink { b"k" } else { &data }).await;
                    let _ = send.finish();
                }
            });
        }
    });
}

fn via_relay(id: iroh::EndpointId) -> EndpointAddr {
    let mut addr = EndpointAddr::new(id);
    addr.addrs.insert(TransportAddr::Relay(relay_url().parse().expect("a relay URL")));
    addr
}

async fn round_trip(conn: &Connection, data: Vec<u8>) -> Vec<u8> {
    let (mut send, mut recv) = conn.open_bi().await.expect("a stream");
    send.write_all(&data).await.expect("written");
    send.finish().expect("finished");
    recv.read_to_end(8 << 20).await.expect("the answer")
}

#[tokio::test(flavor = "multi_thread")]
async fn full_cone_connects_direct() {
    crate::require_vm();
    let _lab = Lab::new(Nat::Symmetric, Nat::FullCone);
    let (rt_relay, rt_a, rt_b) = (NsRuntime::new(RELAY), NsRuntime::new(A), NsRuntime::new(B));
    let relay = start_relay(&rt_relay, Some(100_000_000), Mode::Public).await;
    let b = hub(&rt_b, 2, true, Some(FORWARDED_PORT)).await;
    let (b_id, a) = (b.id(), hub(&rt_a, 1, true, None).await);
    serve(&rt_b, b, false);
    let (direct, kind, echoed) = rt_a
        .run(async move {
            let conn = a.connect(via_relay(b_id), ALPN).await.expect("the hubs connect");
            let direct = paths::wait_direct(&conn, Duration::from_secs(30)).await;
            let echoed = round_trip(&conn, b"a vitals query".to_vec()).await;
            (direct, paths::kind(&conn), echoed)
        })
        .await;
    let took = direct.expect("a direct path through a NAT with the port forwarded");
    assert_eq!(kind, PathKind::Direct, "the connection settled on the direct path after {took:?}");
    assert_eq!(PeerPath::from_kind(kind, true).status, PathStatus::Direct);
    assert_eq!(echoed, b"a vitals query", "and carries the peer protocol");
    rt_relay.run(async move { relay.shutdown().await }).await.expect("the relay stops");
}

#[tokio::test(flavor = "multi_thread")]
async fn symmetric_connects_via_relay() {
    crate::require_vm();
    let _lab = Lab::new(Nat::Symmetric, Nat::Symmetric);
    let (rt_relay, rt_a, rt_b) = (NsRuntime::new(RELAY), NsRuntime::new(A), NsRuntime::new(B));
    let relay = start_relay(&rt_relay, Some(100_000_000), Mode::Public).await;
    let b = hub(&rt_b, 2, true, None).await;
    let (b_id, a) = (b.id(), hub(&rt_a, 1, true, None).await);
    serve(&rt_b, b, false);
    let (direct, kind, echoed) = rt_a
        .run(async move {
            let conn = a.connect(via_relay(b_id), ALPN).await.expect("the hubs connect through the relay");
            let direct = paths::wait_direct(&conn, Duration::from_secs(10)).await;
            let echoed = round_trip(&conn, b"summary".to_vec()).await;
            (direct, paths::kind(&conn), echoed)
        })
        .await;
    assert!(direct.is_err(), "two symmetric NATs don't hole punch (S3)");
    assert_eq!(kind, PathKind::Relay);
    let path = PeerPath::from_kind(kind, true);
    assert_eq!((path.status, path.label), (PathStatus::Relayed, "via relay"));
    assert_eq!(echoed, b"summary", "the relayed path carries the peer protocol");
    rt_relay.run(async move { relay.shutdown().await }).await.expect("the relay stops");
}

#[tokio::test(flavor = "multi_thread")]
async fn hard_nat_no_relay_unreachable_with_explanation() {
    crate::require_vm();
    let _lab = Lab::new(Nat::Symmetric, Nat::Symmetric);
    let (rt_a, rt_b) = (NsRuntime::new(A), NsRuntime::new(B));
    let b = hub(&rt_b, 2, false, None).await;
    let a = hub(&rt_a, 1, false, None).await;
    // all a can be given is b's own addresses, which are private
    let addr = b.addr();
    assert!(addr.addrs.iter().all(|a| !matches!(a, TransportAddr::Relay(_))), "b has no relay to be found by");
    serve(&rt_b, b, false);
    let connected =
        rt_a.run(async move { tokio::time::timeout(Duration::from_secs(20), a.connect(addr, ALPN)).await }).await;
    assert!(!matches!(connected, Ok(Ok(_))), "no path between two hubs behind NATs without a relay");
    let path = PeerPath::unreachable(false);
    assert_eq!((path.status, path.label), (PathStatus::Unreachable, "unreachable: no path"));
    let detail = path.detail.expect("an explanation");
    assert!(detail.contains("a relay is needed"), "the dashboard says so: {detail}");
}

#[tokio::test(flavor = "multi_thread")]
async fn public_unkeyed_limited_to_1_mbit() {
    crate::require_vm();
    let _lab = Lab::new(Nat::Symmetric, Nat::Symmetric);
    let (rt_relay, rt_a, rt_b) = (NsRuntime::new(RELAY), NsRuntime::new(A), NsRuntime::new(B));
    // a public relay with its default rate: 1 Mbit/s for every connection
    let relay = start_relay(&rt_relay, None, Mode::Public).await;
    let b = hub(&rt_b, 2, true, None).await;
    let (b_id, a) = (b.id(), hub(&rt_a, 1, true, None).await);
    serve(&rt_b, b, true);
    let bytes_per_second = rt_a
        .run(async move {
            let conn = a.connect(via_relay(b_id), ALPN).await.expect("the hubs connect through the relay");
            assert_eq!(paths::kind(&conn), PathKind::Relay);
            let data = vec![7u8; 1 << 20];
            let started = Instant::now();
            let answer = round_trip(&conn, data.clone()).await;
            assert_eq!(answer, b"k");
            data.len() as f64 / started.elapsed().as_secs_f64()
        })
        .await;
    assert!(
        (112_500.0..=137_500.0).contains(&bytes_per_second),
        "1 Mbit/s is 125 000 bytes a second, within 10%: {bytes_per_second:.0}"
    );
    rt_relay.run(async move { relay.shutdown().await }).await.expect("the relay stops");
}
