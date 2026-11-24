//! A hub that moves (E35, 7.3.2, 7.3.3) and a VM that was cloned (E6): the probe is told where the hub is and has its SSH key lines
//! replaced for the new addresses, and one endpoint id from two boots is refused.

#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use data_encoding::BASE64;
use ed25519_dalek::SigningKey;
use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use rackhand_hub::actions::address_change::AddressChange;
use rackhand_hub::actions::runner::BoxFuture;
use rackhand_hub::bus::Bus;
use rackhand_hub::executor::HubSide;
use rackhand_hub::ingest::probe_server::{ProbeDirectory, ProbeServer, ServerSettings};
use rackhand_hub::ingest::{DiskSpace, Ingest};
use rackhand_hub::ssh::keys::{Identity, load_or_create};
use rackhand_hub::vault::Vault;
use rackhand_hub::vault::master_key::MasterKey;
use rackhand_net::endpoint::{EndpointConfig, bind};
use rackhand_net::registry::MemoryRegistry;
use rackhand_net::relays::RelayConfig;
use rackhand_probe::buffer::epoch::EpochState;
use rackhand_probe::buffer::segments::{Buffer, Limits};
use rackhand_probe::helper::keys::{Files, apply};
use rackhand_probe::link::{Incoming, Link, LinkConfig, Stop};
use rackhand_proto::alpn;
use rackhand_proto::common::LabelEntry;
use rackhand_proto::probe::{HubToProbe, Report, Sample, hub_to_probe};
use rackhand_store::ids::now_ms;
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

const M1: [u8; 16] = [1; 16];
const M2: [u8; 16] = [2; 16];

fn text(id: [u8; 16]) -> String {
    ulid::Ulid::from_bytes(id).to_string()
}

#[derive(Debug)]
struct Roomy;

impl DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

#[derive(Debug, Default)]
struct Directory(Mutex<HashMap<EndpointId, [u8; 16]>>);

impl ProbeDirectory for Directory {
    fn machine_of(&self, endpoint: &EndpointId) -> Option<[u8; 16]> {
        self.0.lock().unwrap().get(endpoint).copied()
    }
}

/// The hub's signing and its idea of where it connects from.
struct Hub {
    key: SigningKey,
    from: Mutex<Vec<String>>,
}

impl HubSide for Hub {
    fn signed_commands(&self, _now_ms: i64) -> Vec<u8> {
        Vec::new()
    }

    fn signed_keys(&self, now_ms: i64, body: &[u8]) -> Vec<u8> {
        let signed = rackhand_proto::signed::sign(&self.key, "keys", now_ms as u64, now_ms, now_ms + 600_000, body);
        prost::Message::encode_to_vec(&signed)
    }

    fn ssh_from(&self, _machine: &str) -> Vec<String> {
        self.from.lock().unwrap().clone()
    }

    fn managed(&self, _machine: &str) -> bool {
        true
    }

    fn revoke<'a>(&'a self, _machine: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
}

struct Env {
    db: Arc<Db>,
    registry: Arc<MemoryRegistry>,
    directory: Arc<Directory>,
    addr: EndpointAddr,
    relay_url: iroh::RelayUrl,
    dir: PathBuf,
    server: ProbeServer,
    change: AddressChange,
    hub: Arc<Hub>,
    _relay: iroh_relay::server::Server,
    _endpoint: Endpoint,
}

async fn env(name: &str) -> Env {
    let dir = std::env::temp_dir().join(format!("rackhand-address-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let t = |s: &str| Value::Text(s.into());
    db.writer()
        .send(WriteCmd::Batch(vec![
            RowWrite::insert(
                "sites",
                Row::from([
                    ("id", t("s1")),
                    ("name", t("home")),
                    ("timezone", t("UTC")),
                    ("is_local", Value::Integer(1)),
                ]),
            ),
            RowWrite::insert(
                "machines",
                Row::from([
                    ("id", t(&text(M1))),
                    ("site_id", t("s1")),
                    ("name", t("web")),
                    ("kind", t("linux")),
                    ("state", t("enrolled")),
                ]),
            ),
            RowWrite::insert(
                "machines",
                Row::from([
                    ("id", t(&text(M2))),
                    ("site_id", t("s1")),
                    ("name", t("nas")),
                    ("kind", t("linux")),
                    ("access", t("monitor")),
                    ("state", t("enrolled")),
                ]),
            ),
        ]))
        .await
        .unwrap();
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    let (relay, relay_url) = rackhand_net::testing::local_relay().await;
    let endpoint = rackhand_net::testing::endpoint(&relay_url, &[alpn::PROBE]).await;
    let registry = Arc::new(MemoryRegistry::default());
    let directory = Arc::new(Directory::default());
    let server = ProbeServer::new(ingest, directory.clone(), ServerSettings::default());
    tokio::spawn(
        rackhand_net::router::Router::new(endpoint.clone(), registry.clone())
            .route(alpn::PROBE, server.handler())
            .serve(),
    );
    let mut addr = endpoint.addr();
    addr.addrs.insert(TransportAddr::Relay(relay_url.clone()));
    let vault = Arc::new(Vault::new(MasterKey::from_bytes([5u8; 32]), db.clone()));
    load_or_create(&vault, Identity::Automation).await.unwrap();
    load_or_create(&vault, Identity::Assistant).await.unwrap();
    let hub = Arc::new(Hub { key: SigningKey::from_bytes(&[7u8; 32]), from: Mutex::new(vec!["192.0.2.10".into()]) });
    let change = AddressChange::new(db.clone(), vault, hub.clone(), server.clone());
    Env { db, registry, directory, addr, relay_url, dir, server, change, hub, _relay: relay, _endpoint: endpoint }
}

impl Env {
    fn link(&self, name: &str, endpoint: Endpoint, boot_id: &str) -> Link {
        self.link_as(name, endpoint, boot_id, M1)
    }

    fn link_as(&self, name: &str, endpoint: Endpoint, boot_id: &str, machine: [u8; 16]) -> Link {
        self.registry.allow(alpn::PROBE, endpoint.id());
        self.directory.0.lock().unwrap().insert(endpoint.id(), machine);
        let buffer = Buffer::open(&self.dir.join(format!("buffer-{name}")), Limits::default(), now_ms()).unwrap();
        let mut cfg = LinkConfig::new(self.addr.clone(), machine, "0.1.0");
        cfg.boot_id = boot_id.into();
        Link::new(endpoint, cfg, buffer, EpochState::start(None))
    }

    fn events(&self, kind: &str) -> Vec<String> {
        self.db
            .readers()
            .with(|c| {
                let mut s = c.prepare("SELECT severity FROM events WHERE kind = ?1")?;
                s.query_map([kind], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()
            })
            .unwrap()
    }
}

fn table() -> Vec<LabelEntry> {
    vec![LabelEntry { id: 0, labels: BTreeMap::new() }]
}

fn report(link: &mut Link) -> Report {
    Report {
        epoch: link.epoch(),
        seq: link.next_seq(),
        sampled_at_ms: now_ms(),
        vitals: vec![Sample { metric: 1, labels_id: 0, value: 1.0 }],
        ..Default::default()
    }
}

/// A managed machine of the probe's: the hub's two accounts, each with an old key and the old hub address.
struct Machine {
    files: Files,
    dir: PathBuf,
}

impl Machine {
    fn new(env: &Env) -> Machine {
        use std::os::unix::fs::MetadataExt;
        let dir = env.dir.join("machine");
        std::fs::create_dir_all(&dir).unwrap();
        let me = std::fs::metadata(&dir).unwrap();
        let hub_id: String = env.hub.key.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let files =
            Files { probe_toml: dir.join("probe.toml"), passwd: dir.join("passwd"), version: dir.join("keys.version") };
        std::fs::write(
            &files.probe_toml,
            format!("[hub]\nid = \"{hub_id}\"\n\n[machine]\nid = \"{}\"\naccess = \"managed\"\n", text(M1)),
        )
        .unwrap();
        let mut passwd = String::from("root:x:0:0::/root:/bin/sh\n");
        for user in ["rackhand", "rackhand-ai"] {
            let home = dir.join("home").join(user);
            std::fs::create_dir_all(home.join(".ssh")).unwrap();
            passwd.push_str(&format!("{user}:x:{}:{}::{}:/bin/sh\n", me.uid(), me.gid(), home.display()));
        }
        std::fs::write(&files.passwd, passwd).unwrap();
        Machine { files, dir }
    }

    fn authorized(&self, user: &str) -> String {
        std::fs::read_to_string(self.dir.join("home").join(user).join(".ssh/authorized_keys")).unwrap_or_default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hub_address_change_config_and_keys_update() {
    let env = env("moves").await;
    let machine = Machine::new(&env);
    let endpoint = rackhand_net::testing::endpoint(&env.relay_url, &[]).await;
    let mut link = env.link("a", endpoint, "boot-a");
    let mut s = link.connect(&table(), now_ms()).await.unwrap();
    assert!(s.welcome.config.as_ref().unwrap().hub_addrs.is_empty(), "the hub hasn't said where it is yet");
    // the hub is somewhere else now: it connects from 198.51.100.5, and says so
    *env.hub.from.lock().unwrap() = vec!["198.51.100.5".into()];
    let said =
        env.change.announce(&["198.51.100.5:7443".to_string()], &["https://relay.example.net".to_string()]).await;
    assert_eq!((said.configs.as_slice(), said.keys.as_slice()), (&[text(M1)][..], &[text(M1)][..]));
    // the probe gets the new addresses ...
    let msg: HubToProbe = tokio::time::timeout(Duration::from_secs(10), s.next_message()).await.unwrap().unwrap();
    let Incoming::Config(config) = link.on_message(msg).unwrap() else { panic!("a config update first") };
    assert_eq!(
        (config.hub_addrs.as_slice(), config.hub_relays.as_slice()),
        (&["198.51.100.5:7443".to_string()][..], &["https://relay.example.net".to_string()][..])
    );
    assert!(link.set_hub_addrs(&config.hub_addrs, &config.hub_relays), "it dials the new addresses from now on");
    assert!(!link.set_hub_addrs(&config.hub_addrs, &config.hub_relays), "and saying it again changes nothing");
    // ... and key lines that take its SSH from them, which its helper accepts: signed by the hub it pins
    let msg = tokio::time::timeout(Duration::from_secs(10), s.next_message()).await.unwrap().unwrap();
    let Some(hub_to_probe::Msg::KeysUpdate(update)) = msg.msg.clone() else { panic!("a key update next: {msg:?}") };
    let signed = update.keys.unwrap();
    let version =
        apply(&machine.files, &BASE64.encode(&signed.payload), &BASE64.encode(&signed.hub_signature), now_ms())
            .unwrap();
    assert!(version > 0);
    for user in ["rackhand", "rackhand-ai"] {
        let lines = machine.authorized(user);
        assert!(lines.contains("from=\"198.51.100.5\""), "{user}: {lines}");
        assert!(!lines.contains("192.0.2.10"), "{user}: the old address is gone: {lines}");
    }
    // a probe that connects after the change is told in its Welcome
    let again = rackhand_net::testing::endpoint(&env.relay_url, &[]).await;
    let mut other = env.link("b", again, "boot-a");
    let welcome = other.connect(&table(), now_ms()).await.unwrap();
    assert_eq!(welcome.welcome.config.as_ref().unwrap().hub_addrs, ["198.51.100.5:7443"]);
    let _ = (&env.server, report(&mut link));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_machine_that_isnt_managed_gets_the_addresses_and_no_keys() {
    let env = env("monitor").await;
    let endpoint = rackhand_net::testing::endpoint(&env.relay_url, &[]).await;
    let mut link = env.link_as("m", endpoint, "boot-m", M2);
    let _s = link.connect(&table(), now_ms()).await.unwrap();
    let said = env.change.announce(&["198.51.100.5:7443".to_string()], &[]).await;
    assert_eq!((said.configs.len(), said.keys.len()), (1, 0), "a monitor machine has no hub accounts to change");
}

#[tokio::test(flavor = "multi_thread")]
async fn same_endpoint_two_boot_ids_both_refused() {
    let env = env("clone").await;
    // one node key on two machines: the original and its clone
    let secret = iroh::SecretKey::from_bytes(&[9u8; 32]);
    let make = |secret: iroh::SecretKey| {
        let relay = env.relay_url.to_string();
        async move {
            let config = EndpointConfig {
                relays: RelayConfig { relays: vec![relay], ..Default::default() },
                alpns: Vec::new(),
                bind: None,
            };
            bind(secret, &config).await.unwrap()
        }
    };
    let mut original = env.link("orig", make(secret.clone()).await, "boot-original");
    let mut clone = env.link("clone", make(secret).await, "boot-clone");
    let mut s = original.connect(&table(), now_ms()).await.unwrap();
    // the original is reporting
    let first = report(&mut original);
    original.send_live(&mut s, first, now_ms()).await.unwrap();
    // the clone says hello with another boot id: it is refused, and the original is closed too
    let refused = clone.connect(&table(), now_ms()).await;
    assert!(matches!(refused, Err(Stop::IdentityMismatch)), "{refused:?}");
    // (an ack of its report may still arrive before the close)
    let ended = loop {
        let next = tokio::time::timeout(Duration::from_secs(10), s.next_message()).await.unwrap();
        if !matches!(&next, Ok(HubToProbe { msg: Some(hub_to_probe::Msg::Ack(_)) })) {
            break next;
        }
    };
    assert!(matches!(ended, Err(Stop::IdentityMismatch)), "{ended:?}");
    let events = env.events("probe.identity_conflict");
    assert_eq!(events, ["critical"], "one critical event");
    // and neither gets back in
    for link in [&mut original, &mut clone] {
        let again = link.connect(&table(), now_ms()).await;
        assert!(matches!(again, Err(Stop::IdentityMismatch)), "{again:?}");
    }
}
