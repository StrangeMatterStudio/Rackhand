//! Backups kept for peers (9, D58, 7.3.11): only peers given space may send one, one copy is kept, and an admin can export it to
//! restore on a new machine.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use iroh::{Endpoint, EndpointAddr, TransportAddr};
use rackhand_hub::audit::Audit;
use rackhand_hub::backup::peer::{PeerBackups, Sent, dir, export, send_latest};
use rackhand_hub::backup::{restore, take};
use rackhand_hub::peers::xfer::Xfer;
use rackhand_hub::vault::master_key::MasterKey;
use rackhand_net::registry::MemoryRegistry;
use rackhand_proto::alpn;
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

struct Env {
    root: PathBuf,
    db: Arc<Db>,
    addr: EndpointAddr,
    beta: Endpoint,
    gamma: Endpoint,
    stranger: Endpoint,
    _relay: iroh_relay::server::Server,
}

async fn env(name: &str, beta_quota: i64) -> Env {
    let root = std::env::temp_dir().join(format!("rackhand-peer-backup-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let db = Arc::new(Db::open(&root.join("hub.db")).unwrap());
    let (relay, relay_url) = rackhand_net::testing::local_relay().await;
    let server = rackhand_net::testing::endpoint(&relay_url, &[alpn::XFER]).await;
    let beta = rackhand_net::testing::endpoint(&relay_url, &[]).await;
    let gamma = rackhand_net::testing::endpoint(&relay_url, &[]).await;
    let stranger = rackhand_net::testing::endpoint(&relay_url, &[]).await;
    let peer = |id: &str, site: &str, e: &Endpoint, quota: i64| {
        RowWrite::insert(
            "peers",
            Row::from([
                ("id", t(id)),
                ("site", t(site)),
                ("endpoint_id", t(&e.id().to_string())),
                ("backup_quota_bytes", Value::Integer(quota)),
                ("added_at", Value::Integer(1)),
            ]),
        )
    };
    db.writer()
        .send(WriteCmd::Batch(vec![peer("p-beta", "beta", &beta, beta_quota), peer("p-gamma", "gamma", &gamma, 0)]))
        .await
        .unwrap();
    let registry = Arc::new(MemoryRegistry::default());
    for e in [&beta, &gamma, &stranger] {
        registry.allow(alpn::XFER, e.id());
    }
    let audit = Audit::new(db.writer());
    let backups = PeerBackups::new(db.clone(), audit, dir(&root));
    let xfer = Xfer::new(Arc::new(backups));
    tokio::spawn(rackhand_net::router::Router::new(server.clone(), registry).route(alpn::XFER, xfer.handler()).serve());
    let mut addr = server.addr();
    addr.addrs.insert(TransportAddr::Relay(relay_url));
    Env { root, db, addr, beta, gamma, stranger, _relay: relay }
}

/// A hub's own backups directory with one backup in it, taken at `at_ms`.
fn backup_at(sender: &Path, key: &MasterKey, at_ms: i64) -> PathBuf {
    std::fs::create_dir_all(sender).unwrap();
    let db = sender.join("hub.db");
    if !db.exists() {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch("CREATE TABLE sites (id TEXT, name TEXT); INSERT INTO sites VALUES ('s','from-the-sender');")
            .unwrap();
        std::fs::write(sender.join("node.key"), [9u8; 32]).unwrap();
    }
    take(&db, key, &sender.join("node.key"), &sender.join("backups"), at_ms).unwrap()
}

async fn send(from: &Endpoint, to: &EndpointAddr, backups: &Path) -> Sent {
    let conn = from.connect(to.clone(), alpn::XFER).await.unwrap();
    send_latest(&conn, backups, true, &|| 0, &mut || {}).await.unwrap()
}

fn kept(env: &Env) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir(&env.root))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    names
}

#[tokio::test(flavor = "multi_thread")]
async fn sent_only_to_peers_with_quota_one_copy_kept() {
    let env = env("quota", 10 << 20).await;
    let key = MasterKey::generate();
    let sender = env.root.join("sender");
    let first = backup_at(&sender, &key, 1_000);
    // a peer with no space is told so and nothing is kept; neither is a hub that isn't a peer
    for (who, e) in [("gamma", &env.gamma), ("stranger", &env.stranger)] {
        match send(e, &env.addr, &sender.join("backups")).await {
            Sent::Refused(why) => {
                assert!(why.contains("no backup space") || why.contains("not a linked peer"), "{who}: {why}")
            }
            other => panic!("{who}: {other:?}"),
        }
    }
    assert!(kept(&env).is_empty(), "nothing arrived for a peer without space: {:?}", kept(&env));
    // a peer with space has its backup kept, byte for byte
    assert_eq!(send(&env.beta, &env.addr, &sender.join("backups")).await, Sent::Sent);
    assert_eq!(kept(&env), vec!["beta.rhbk"]);
    assert_eq!(std::fs::read(dir(&env.root).join("beta.rhbk")).unwrap(), std::fs::read(&first).unwrap());
    // a newer backup replaces it: still one copy
    let second = backup_at(&sender, &key, 2_000);
    assert_ne!(first, second);
    assert_eq!(send(&env.beta, &env.addr, &sender.join("backups")).await, Sent::Sent);
    assert_eq!(kept(&env), vec!["beta.rhbk"], "one copy is kept");
    assert_eq!(std::fs::read(dir(&env.root).join("beta.rhbk")).unwrap(), std::fs::read(&second).unwrap());
    // a hub with nothing to send says so
    assert_eq!(send(&env.beta, &env.addr, &env.root.join("none")).await, Sent::NoBackup);
    // the offers are in the audit log, with how they went
    let refused: i64 = env
        .db
        .readers()
        .with(|c| {
            c.query_row(
                "SELECT count(*) FROM audit_log WHERE action = 'peer_backup.offered' AND data LIKE '%space%'",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(refused, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_backup_larger_than_the_space_given_is_refused_and_a_file_that_isnt_a_backup_too() {
    let env = env("size", 100).await;
    let key = MasterKey::generate();
    let sender = env.root.join("sender");
    backup_at(&sender, &key, 1_000);
    match send(&env.beta, &env.addr, &sender.join("backups")).await {
        Sent::Refused(why) => assert!(why.contains("larger than"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(kept(&env).is_empty());
    // a file that isn't a backup is turned away at its first chunk, even if the space is there
    env_with_quota(&env, 10 << 20).await;
    let junk = env.root.join("junk");
    std::fs::create_dir_all(junk.join("backups")).unwrap();
    std::fs::write(junk.join("backups").join("hub-1.rhbk"), vec![1u8; 5000]).unwrap();
    match send(&env.beta, &env.addr, &junk.join("backups")).await {
        Sent::Refused(why) => assert!(why.contains("isn't a Rackhand backup"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(kept(&env).iter().all(|n| !n.ends_with(".rhbk")));
}

/// Gives beta more space.
async fn env_with_quota(env: &Env, quota: i64) {
    let set = Row::from([("backup_quota_bytes", Value::Integer(quota))]);
    let update = rackhand_store::RowUpdate { table: "peers", key: ("id", t("p-beta")), set };
    let change = rackhand_store::RegistryChange { updates: vec![update], ..Default::default() };
    env.db.writer().send(WriteCmd::RegistryChange(change)).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn export_writes_restorable_file() {
    let env = env("export", 10 << 20).await;
    let key = MasterKey::generate();
    let sender = env.root.join("sender");
    backup_at(&sender, &key, 1_000);
    assert_eq!(send(&env.beta, &env.addr, &sender.join("backups")).await, Sent::Sent);
    // the hub that holds it can't read it, and an admin exports it
    let out = env.root.join("exported.rhbk");
    let bytes = export(&dir(&env.root), "beta", &out).unwrap();
    assert_eq!(bytes, std::fs::metadata(&out).unwrap().len());
    // a new machine restores it with the master key, as `hub restore` does
    let new = env.root.join("new-machine");
    std::fs::create_dir_all(&new).unwrap();
    restore(&out, &key, &new.join("hub.db"), &new.join("node.key")).unwrap();
    assert_eq!(std::fs::read(new.join("node.key")).unwrap(), [9u8; 32], "with the node key");
    let c = rusqlite::Connection::open(new.join("hub.db")).unwrap();
    let name: String = c.query_row("SELECT name FROM sites", [], |r| r.get(0)).unwrap();
    assert_eq!(name, "from-the-sender");
    // a site nothing is kept for, a name that is a path, and a kept file that isn't a backup
    assert!(export(&dir(&env.root), "nobody", &env.root.join("x")).unwrap_err().contains("no backup"));
    assert!(export(&dir(&env.root), "../etc", &env.root.join("x")).unwrap_err().contains("isn't a site name"));
    std::fs::write(dir(&env.root).join("fake.rhbk"), b"not a backup at all").unwrap();
    assert!(export(&dir(&env.root), "fake", &env.root.join("x")).unwrap_err().contains("isn't a Rackhand backup"));
    assert!(!env.root.join("x").exists());
}
