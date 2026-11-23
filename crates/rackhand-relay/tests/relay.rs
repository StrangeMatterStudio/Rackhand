#![allow(clippy::unwrap_used)] // a test fails by panicking
//! The relay as a server, on loopback with plain HTTP: what a client that connects is told (7.3.10, AC31, E27).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use iroh::dns::DnsResolver;
use iroh::{RelayUrl, SecretKey};
use iroh_relay::client::{Client, ClientBuilder};
use iroh_relay::server::Server;
use n0_future::StreamExt;
use rackhand_relay::admission::Mode;
use rackhand_relay::keys::{self, KeyBody, Priority};
use rackhand_relay::run::{Certificate, RelayRun, run, signing_key};

fn data_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rackhand-relay-it-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

async fn start(name: &str, mode: Mode) -> (Server, RelayUrl, PathBuf) {
    start_with(name, mode, rackhand_relay::admission::CAPACITY).await
}

async fn start_with(name: &str, mode: Mode, capacity: usize) -> (Server, RelayUrl, PathBuf) {
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let dir = data_dir(name);
    let config = RelayRun {
        data_dir: dir.clone(),
        mode,
        http: loopback,
        https: loopback,
        quic: loopback,
        certificate: Certificate::None,
        rate_bits: None,
        capacity,
    };
    let (server, _admission) = run(&config).await.expect("the relay starts");
    let url: RelayUrl = format!("http://{}", server.http_addr().expect("http address")).parse().expect("URL");
    (server, url, dir)
}

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

async fn connect(url: &RelayUrl, seed: u8, token: Option<&str>) -> Result<(), String> {
    connect_client(url, seed, token).await.map(drop)
}

async fn connect_client(url: &RelayUrl, seed: u8, token: Option<&str>) -> Result<Client, String> {
    let tls = iroh_relay::tls::CaTlsConfig::default()
        .client_config(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
        .expect("TLS client config");
    let mut client = ClientBuilder::new(url.clone(), key(seed), DnsResolver::new()).tls_client_config(tls);
    if let Some(token) = token {
        client = client.auth_token(token);
    }
    client.connect().await.map_err(|e| format!("{e:#}"))
}

fn token(dir: &std::path::Path, name: &str, priority: Priority, max: u32) -> String {
    let body = KeyBody { name: name.into(), priority, max_endpoints: max, expires_ms: i64::MAX };
    keys::create(&signing_key(dir).expect("the relay's key"), &body)
}

#[tokio::test]
async fn private_refuses_unkeyed_admits_keyed() {
    let (server, url, dir) = start("private", Mode::Private).await;
    let unkeyed = connect(&url, 1, None).await.unwrap_err();
    assert!(unkeyed.contains("only endpoints with a relay key"), "{unkeyed}");
    let keyed = token(&dir, "home", Priority::Normal, 1);
    connect(&url, 2, Some(&keyed)).await.expect("a keyed endpoint is admitted");
    // a key made by another relay, and one that has all its endpoints, are refused with what is wrong
    let foreign = keys::create(
        &ed25519_dalek::SigningKey::from_bytes(&[5; 32]),
        &KeyBody { name: "x".into(), priority: Priority::High, max_endpoints: 9, expires_ms: i64::MAX },
    );
    let forged = connect(&url, 3, Some(&foreign)).await.unwrap_err();
    assert!(forged.contains("isn't one of this relay's"), "{forged}");
    let third = connect(&url, 4, Some(&keyed)).await.unwrap_err();
    assert!(third.contains("most endpoints it allows"), "{third}");
    server.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn refused_client_sees_reason() {
    let (server, url, dir) = start("reason", Mode::Private).await;
    let expired = keys::create(
        &signing_key(&dir).unwrap(),
        &KeyBody { name: "old".into(), priority: Priority::Normal, max_endpoints: 1, expires_ms: 1 },
    );
    for (token, why) in
        [(None, "relay key"), (Some("rk1.e30.AAAA"), "isn't one of this relay's"), (Some(expired.as_str()), "expired")]
    {
        let e = connect(&url, 7, token).await.unwrap_err();
        assert!(e.contains("denied our authentication") && e.contains(why), "{token:?}: {e}");
    }
    server.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn public_admits_anyone_but_not_a_forged_key() {
    let (server, url, dir) = start("public", Mode::Public).await;
    connect(&url, 1, None).await.expect("anyone is admitted to a public relay");
    let e = connect(&url, 2, Some("rk1.e30.AAAA")).await.unwrap_err();
    assert!(e.contains("isn't one of this relay's"), "{e}");
    let keyed = token(&dir, "friend", Priority::High, 1);
    connect(&url, 3, Some(&keyed)).await.expect("a keyed endpoint is admitted too");
    server.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

/// Whether the relay has ended this client's connection (it is told nothing, only closed).
async fn ended(client: &mut Client) -> bool {
    matches!(tokio::time::timeout(std::time::Duration::from_millis(1500), client.next()).await, Ok(None | Some(Err(_))))
}

#[tokio::test]
async fn priority_admission_at_capacity() {
    let (server, url, dir) = start_with("capacity", Mode::Public, 2).await;
    let mut first = connect_client(&url, 1, None).await.unwrap();
    let mut second = connect_client(&url, 2, None).await.unwrap();
    let full = connect(&url, 3, None).await.unwrap_err();
    assert!(full.contains("the relay is full"), "an unkeyed endpoint is refused and told why: {full}");
    let high = token(&dir, "high", Priority::High, 1);
    let _keyed = connect_client(&url, 4, Some(&high)).await.expect("a keyed endpoint takes an unkeyed one's place");
    let closed = [ended(&mut first).await, ended(&mut second).await];
    assert_eq!(closed.iter().filter(|c| **c).count(), 1, "exactly one unkeyed endpoint was closed: {closed:?}");
    // the other unkeyed one is still there, and a second key of the same class finds nobody left to take
    let normal = token(&dir, "normal", Priority::Normal, 1);
    let _normal =
        connect_client(&url, 5, Some(&normal)).await.expect("the last unkeyed endpoint makes room for a normal key");
    let last = token(&dir, "last", Priority::Normal, 1);
    let e = connect(&url, 6, Some(&last)).await.unwrap_err();
    assert!(e.contains("the relay is full"), "a normal key can't take a high key's place: {e}");
    server.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(dir);
}
