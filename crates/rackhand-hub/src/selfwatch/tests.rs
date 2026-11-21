use std::collections::BTreeMap;
use std::sync::Mutex;

use rackhand_proto::common::LabelEntry;
use rackhand_proto::probe::{Report, Sample};
use rackhand_store::Db;

use super::*;
use crate::bus::Bus;
use crate::ingest::{DiskSpace, Receipt, Stream};
use crate::notify::{BoxFuture, Message, SendError, Transport};

#[derive(Debug)]
struct Roomy;

impl DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

#[derive(Debug, Default)]
struct Sink(Mutex<Vec<Message>>);

impl Transport for Sink {
    fn name(&self) -> &str {
        "sink"
    }
    fn send<'a>(&'a self, msg: &'a Message) -> BoxFuture<'a, Result<(), SendError>> {
        self.0.lock().unwrap().push(msg.clone());
        Box::pin(async { Ok(()) })
    }
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rackhand-selfwatch-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Env {
    dir: PathBuf,
    db: Arc<Db>,
    ingest: Ingest,
    sink: Arc<Sink>,
    watch: SelfWatch,
}

fn env(name: &str, integrity: IntegrityCheck) -> Env {
    let dir = temp(name);
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    let sink = Arc::new(Sink::default());
    let notify = Notify::new(db.clone(), ingest.clone(), vec![sink.clone() as Arc<dyn Transport>]);
    std::fs::write(dir.join("rackhand"), b"the running binary").unwrap();
    let watch = SelfWatch {
        ingest: ingest.clone(),
        notify,
        db: db.clone(),
        integrity,
        exe: dir.join("rackhand"),
        exe_name: "rackhand-x86_64-unknown-linux-musl".into(),
        manifest: None,
        configs: Vec::new(),
    };
    Env { dir, db, ingest, sink, watch }
}

fn events(db: &Db, kind: &str) -> Vec<String> {
    db.readers()
        .with(|c| {
            let mut s = c.prepare("SELECT severity FROM events WHERE kind = ?1")?;
            s.query_map([kind], |r| r.get(0))?.collect()
        })
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn quick_check_failure_stops_writes_and_alerts() {
    let e = env("corrupt", Arc::new(|| Err("*** in database main *** page 12 is never used".into())));
    e.ingest.hello("m1", 1, &[LabelEntry { id: 0, labels: BTreeMap::new() }]).await.unwrap();
    let found = e.watch.daily(1_000).await;
    assert_eq!(found.iter().map(|f| f.kind).collect::<Vec<_>>(), ["hub.db_corrupt"]);
    // no acks: the report is held, not staged
    let report = Report {
        epoch: 1,
        seq: 1,
        sampled_at_ms: 1_000,
        vitals: vec![Sample { metric: 1, labels_id: 0, value: 5.0 }],
        ..Default::default()
    };
    let receipt = e.ingest.receive("m1", Stream::Live, vec![report], 100, 1_000).await.unwrap();
    assert_eq!(receipt, Receipt::Held);
    let staged: i64 =
        e.db.readers().with(|c| c.query_row("SELECT count(*) FROM report_staging", [], |r| r.get(0))).unwrap();
    assert_eq!(staged, 0, "nothing written");
    assert!(!e.ingest.latest_values().is_empty(), "the dashboard's values still come from memory");
    assert!(!e.ingest.accepting_jobs(), "no job starts");
    let sent = e.sink.0.lock().unwrap();
    assert_eq!(sent.len(), 1, "the alert goes straight to the notifiers");
    assert_eq!(sent[0].severity, "critical");
    assert!(events(&e.db, "hub.db_corrupt").is_empty(), "and isn't written as an event");
}

fn manifest(dir: &Path, name: &str, sha: &str, signer: u8, key_id: [u8; 8]) -> Manifest {
    let body = serde_json::json!({ "version": "0.1.0", "files": { name: sha } }).to_string();
    let key = ed25519_dalek::SigningKey::from_bytes(&[signer; 32]);
    let sig = rackhand_release::signing::sign(&key, key_id, body.as_bytes(), "file:manifest.json");
    std::fs::write(dir.join("manifest.json"), &body).unwrap();
    std::fs::write(dir.join("manifest.json.minisig"), sig).unwrap();
    Manifest { path: dir.join("manifest.json"), signature: dir.join("manifest.json.minisig") }
}

#[tokio::test(flavor = "multi_thread")]
async fn binary_hash_mismatch_is_critical() {
    // signed with the test release key (tests/keys, pinned in test builds)
    let mut e = env("binary", Arc::new(|| Ok(())));
    let actual = sha256_file(&e.watch.exe).unwrap();
    e.watch.manifest = Some(manifest(&e.dir, &e.watch.exe_name, &actual, 0x11, [1; 8]));
    assert!(e.watch.daily(1_000).await.iter().all(|f| f.kind != "hub.binary_changed"), "the release's own binary");
    e.watch.manifest = Some(manifest(&e.dir, &e.watch.exe_name, &"0".repeat(64), 0x11, [1; 8]));
    let found = e.watch.daily(2_000).await;
    assert!(found.iter().any(|f| f.kind == "hub.binary_changed" && f.detail.contains(&actual)), "{found:?}");
    assert_eq!(events(&e.db, "hub.binary_changed"), ["critical"]);
    // a manifest not signed by a pinned key proves nothing
    e.watch.manifest = Some(manifest(&e.dir, &e.watch.exe_name, &actual, 0x33, [3; 8]));
    let found = e.watch.daily(3_000).await;
    assert!(found.iter().any(|f| f.kind == "hub.binary_changed" && f.detail.contains("release manifest")), "{found:?}");
    assert!(!e.ingest.integrity_failed());
}

#[cfg(unix)]
#[test]
fn config_writable_by_others_is_exposed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp("config");
    let f = dir.join("hub.toml");
    std::fs::write(&f, "web = \"0.0.0.0:8443\"\n").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
    let me = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&f).unwrap());
    let finding = config_check(&f, 0o640, me).expect("group and others can write it");
    assert_eq!(finding.kind, "hub.config_exposed");
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(config_check(&f, 0o640, me), None, "its owner's, and no more than 640");
    assert!(config_check(&f, 0o640, me + 1).is_some(), "someone else's");
}
