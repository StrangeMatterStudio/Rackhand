//! The composition's wiring (7.2): what each system gets from the others.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rackhand_hub::audit::Audit;
use rackhand_hub::bus::Bus;
use rackhand_hub::ingest::{DiskSpace, Ingest, Stream};
use rackhand_hub::library::items::{Kind, Library};
use rackhand_hub::mcp::{Observations, SeriesQuery};
use rackhand_hub::vault::master_key::MasterKey;
use rackhand_hub::vault::{Secret, Vault};
use rackhand_store::Db;
use rackhand_store::ids::now_ms;

#[derive(Debug)]
struct Roomy;

impl DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

fn db(name: &str) -> Arc<Db> {
    let dir = std::env::temp_dir().join(format!("rackhand-composition-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Arc::new(Db::open(&dir.join("hub.db")).unwrap())
}

const M: &str = "01JD0000000000000000000001";

#[tokio::test(flavor = "multi_thread")]
async fn observations_wired_from_ingest() {
    let db = db("observations");
    let ingest = Ingest::new(db, Bus::new(), Arc::new(Roomy));
    ingest.hello(M, 1, &[rackhand_proto::common::LabelEntry::default()]).await.unwrap();
    let now = now_ms();
    let report = rackhand_proto::probe::Report {
        epoch: 1,
        seq: 1,
        sampled_at_ms: now,
        vitals: vec![rackhand_proto::probe::Sample { metric: 1, labels_id: 0, value: 12.5 }],
        services: vec![rackhand_proto::probe::ServiceState {
            name: "nginx".into(),
            status: 1,
            enabled: true,
            since_ms: 0,
        }],
        ..Default::default()
    };
    ingest.receive(M, Stream::Live, vec![report], 100, now).await.unwrap();
    let obs = crate::observations::FromIngest(ingest);
    assert_eq!(obs.facts(M).services[0]["name"], "nginx", "facts from the latest report");
    let q = SeriesQuery {
        machine_id: M.into(),
        metric: "cpu.busy_pct".into(),
        labels: Default::default(),
        from_ms: now - 3_600_000,
        // samples sit on the nearest 15 s tick, up to 7.5 s after they were taken
        to_ms: now + 15_000,
        step_ms: None,
    };
    let points = obs.series(&q);
    assert_eq!(points.len(), 1, "series from the recent window and the store");
    assert_eq!(points[0].1, 12.5);
}

#[tokio::test(flavor = "multi_thread")]
async fn notifiers_built_from_config() {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let hook = axum::Router::new().route(
        "/hook",
        axum::routing::post(move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::Relaxed);
                axum::http::StatusCode::NO_CONTENT
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, hook).await.unwrap() });

    let db = db("notifiers");
    let vault = Vault::new(MasterKey::from_bytes([4u8; 32]), db.clone());
    let (library, _) = Library::new(db.clone(), Audit::new(db.writer()));
    let config = r#"
[[discord]]
name = "ops"
webhook = "secret:discord_ops"

[[smtp]]
name = "mail"
host = "smtp.example.net"
port = 587
security = "starttls"
username = "hub@example.net"
password = "secret:smtp_password"
from = "hub@example.net"
to = ["ops@example.net"]
"#;
    library.save(Kind::Config, "notifiers", config, "admin", now_ms()).await.unwrap();
    // a missing secret is named
    let err = crate::hub_cmd::notifiers(&db, &vault, None).unwrap_err();
    assert!(err.contains("discord_ops"), "{err}");
    vault.put("discord_ops", &Secret::from(url.as_str())).await.unwrap();
    vault.put("smtp_password", &Secret::from("pw")).await.unwrap();
    let transports = crate::hub_cmd::notifiers(&db, &vault, Some("https://hub.example.net")).unwrap();
    let names: Vec<&str> = transports.iter().map(|t| t.name()).collect();
    assert_eq!(names, ["ops", "mail"]);
    // the Discord one delivers through the composition's Notify
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    let notify = rackhand_hub::notify::Notify::new(db.clone(), ingest, vec![transports[0].clone()]);
    notify.send_text("hello", now_ms()).await.unwrap();
    assert_eq!(hits.load(Ordering::Relaxed), 1);
}

/// Records what it is asked to send.
#[derive(Debug, Default)]
struct Recorder(std::sync::Mutex<Vec<rackhand_hub::notify::MessageKind>>);

impl rackhand_hub::notify::Transport for Recorder {
    fn name(&self) -> &str {
        "recorder"
    }
    fn send<'a>(
        &'a self,
        msg: &'a rackhand_hub::notify::Message,
    ) -> rackhand_hub::notify::BoxFuture<'a, Result<(), rackhand_hub::notify::SendError>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(msg.kind);
            Ok(())
        })
    }
}

async fn incident_event(db: &Db, kind: &str, state: &str, data: &str, at: i64) {
    use rackhand_store::{Row, RowWrite, WriteCmd};
    use rusqlite::types::Value;
    let t = |s: &str| Value::Text(s.into());
    let inc = Row::from([
        ("id", t("01JD00000000000000000000I1")),
        ("dedupe_key", t("k")),
        ("kind", t("disk.used")),
        ("severity", t("critical")),
        ("state", t(state)),
        ("title", t("disk.used_pct over 95")),
        ("opened_at", Value::Integer(at)),
    ]);
    let ev = Row::from([
        ("id", t(&rackhand_store::ids::new_id().to_string())),
        ("incident_id", t("01JD00000000000000000000I1")),
        ("at_ms", Value::Integer(at)),
        ("kind", t(kind)),
        ("data", t(data)),
    ]);
    db.writer()
        .send(WriteCmd::Batch(vec![RowWrite::upsert("incidents", "id", inc), RowWrite::insert("incident_events", ev)]))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn notify_state_survives_restart() {
    use rackhand_hub::notify::MessageKind;
    let db = db("notify-restart");
    let t0 = 1_795_068_000_000i64;
    let before = Arc::new(Recorder::default());
    {
        let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
        let notify = rackhand_hub::notify::Notify::new(db.clone(), ingest, vec![before.clone()]);
        incident_event(&db, "opened", "open", r#"{"severity":"critical","callout":true}"#, t0).await;
        notify.tick(t0).await.unwrap();
    }
    assert_eq!(*before.0.lock().unwrap(), [MessageKind::Callout]);
    // the hub restarts: the incident is still known as called out
    let after = Arc::new(Recorder::default());
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    let notify = rackhand_hub::notify::Notify::new(db.clone(), ingest, vec![after.clone()]);
    notify.tick(t0 + 6 * 3_600_000).await.unwrap();
    assert_eq!(*after.0.lock().unwrap(), [MessageKind::Callout], "the 6-hour re-send");
    incident_event(&db, "resolved", "resolved", r#"{"by":"condition"}"#, t0 + 7 * 3_600_000).await;
    notify.tick(t0 + 7 * 3_600_000).await.unwrap();
    assert_eq!(*after.0.lock().unwrap(), [MessageKind::Callout, MessageKind::Resolution], "and its resolution");
}

#[tokio::test(flavor = "multi_thread")]
async fn received_ranges_survive_restart() {
    let db = db("ranges-restart");
    let report =
        |seq: u64| rackhand_proto::probe::Report { epoch: 9, seq, sampled_at_ms: now_ms(), ..Default::default() };
    {
        let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
        for seq in 1..=3 {
            ingest.receive(M, Stream::Live, vec![report(seq)], 100, now_ms()).await.unwrap();
        }
        ingest.compact().await.unwrap();
        // one more, staged but not compacted when the hub stops
        ingest.receive(M, Stream::Live, vec![report(4)], 100, now_ms()).await.unwrap();
    }
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    ingest.start(now_ms()).await.unwrap();
    assert_eq!(ingest.received(M, 9), vec![(1, 4)], "what Welcome.received says after the restart");
    let again = ingest.receive(M, Stream::Live, vec![report(2)], 100, now_ms()).await.unwrap();
    assert_eq!(again, rackhand_hub::ingest::Receipt::Duplicate, "a resend is still a duplicate");
}
