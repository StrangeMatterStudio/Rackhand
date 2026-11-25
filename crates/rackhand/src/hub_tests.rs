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

#[tokio::test(flavor = "multi_thread")]
async fn probe_directory_from_registry() {
    use rackhand_hub::ingest::probe_server::{ProbeDirectory, ProbeServer, ServerSettings};
    use rackhand_store::{Row, RowWrite, WriteCmd};
    use rusqlite::types::Value;
    let db = db("probe-directory");
    let (relay, relay_url) = rackhand_net::testing::local_relay().await;
    let probe_endpoint = rackhand_net::testing::endpoint(&relay_url, &[]).await;
    let t = |s: &str| Value::Text(s.into());
    let machine_id = ulid::Ulid::new();
    let rows = vec![
        RowWrite::insert("sites", Row::from([("id", t("s1")), ("name", t("home")), ("timezone", t("UTC"))])),
        RowWrite::insert(
            "machines",
            Row::from([
                ("id", t(&machine_id.to_string())),
                ("site_id", t("s1")),
                ("name", t("web")),
                ("kind", t("linux")),
                ("state", t("enrolled")),
                ("probe_endpoint_id", t(&probe_endpoint.id().to_string())),
            ]),
        ),
    ];
    db.writer().send(WriteCmd::Batch(rows)).await.unwrap();
    // the directory is the machines table
    let directory = Arc::new(crate::hub_cmd::MachinesDirectory(db.clone()));
    assert_eq!(directory.machine_of(&probe_endpoint.id()), Some(machine_id.to_bytes()));
    let stranger = rackhand_net::testing::endpoint(&relay_url, &[]).await;
    assert_eq!(directory.machine_of(&stranger.id()), None);
    // D84: a managed machine reports while pending its SSH test; a revoked one doesn't
    let set_state = |state: &str| rackhand_store::RowUpdate {
        table: "machines",
        key: ("id", t(&machine_id.to_string())),
        set: Row::from([("state", t(state))]),
    };
    for (state, known) in [("pending", true), ("revoked", false), ("enrolled", true)] {
        let change = rackhand_store::RegistryChange { updates: vec![set_state(state)], ..Default::default() };
        db.writer().send(WriteCmd::RegistryChange(change)).await.unwrap();
        assert_eq!(directory.machine_of(&probe_endpoint.id()).is_some(), known, "{state}");
    }
    // and with the Registry's admission, an enrolled probe's report reaches Ingest
    let registry = rackhand_hub::registry::Registry::load(db.clone()).unwrap();
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    let hub = rackhand_net::testing::endpoint(&relay_url, &[rackhand_proto::alpn::PROBE]).await;
    let bindings = Arc::new(rackhand_hub::registry::guest_binding::GuestBindings::new(db.clone(), ingest.clone()));
    let server = ProbeServer::new(ingest.clone(), directory, ServerSettings::default()).with_bindings(bindings.clone());
    let router =
        rackhand_net::router::Router::new(hub.clone(), registry).route(rackhand_proto::alpn::PROBE, server.handler());
    tokio::spawn(router.serve());
    let mut addr = hub.addr();
    addr.addrs.insert(iroh::TransportAddr::Relay(relay_url.clone()));
    let dir = std::env::temp_dir().join(format!("rackhand-composition-probe-buffer-{}", std::process::id()));
    let buffer = rackhand_probe::buffer::segments::Buffer::open(&dir, Default::default(), now_ms()).unwrap();
    let mut cfg = rackhand_probe::link::LinkConfig::new(addr, machine_id.to_bytes(), "0.1.0");
    cfg.interfaces =
        vec![rackhand_proto::common::IfaceInfo { name: "eth0".into(), mac: "bc:24:11:82:f7:1a".into(), addrs: vec![] }];
    let mut link = rackhand_probe::link::Link::new(
        probe_endpoint,
        cfg,
        buffer,
        rackhand_probe::buffer::epoch::EpochState::start(None),
    );
    let mut session = link.connect(&[rackhand_proto::common::LabelEntry::default()], now_ms()).await.unwrap();
    let report = rackhand_proto::probe::Report {
        epoch: link.epoch(),
        seq: link.next_seq(),
        sampled_at_ms: now_ms(),
        ..Default::default()
    };
    link.send_live(&mut session, report, now_ms()).await.unwrap();
    link.read_acks(&mut session, |b| b.is_empty(), std::time::Duration::from_secs(10)).await.unwrap();
    assert_eq!(ingest.reports_total(), 1, "the report reached Ingest");
    // and the MACs its Hello gave reached guest binding (7.3.12)
    assert_eq!(bindings.reported_macs(&machine_id.to_string()), Some(vec!["bc:24:11:82:f7:1a".to_string()]));
    drop(relay);
}

/// A sleeper that doesn't wait (retention's pauses between batches).
struct NoWait;

impl rackhand_store::retention::Sleeper for NoWait {
    fn sleep(&self, _d: std::time::Duration) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rollup_and_retention_ticks_run() {
    let db = db("ticks");
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    ingest.start(0).await.unwrap();
    let incidents = rackhand_hub::incidents::Incidents::new(db.clone(), ingest.clone(), Bus::new());
    ingest.hello(M, 1, &[rackhand_proto::common::LabelEntry::default()]).await.unwrap();
    let t0 = 1_795_068_000_000i64; // the top of an hour
    let count = |sql: &str| -> i64 { db.readers().with(|c| c.query_row(sql, [], |r| r.get(0))).unwrap() };
    // a tier 0 row 3 days old, for retention to remove
    {
        let path =
            std::env::temp_dir().join(format!("rackhand-composition-ticks-{}", std::process::id())).join("hub.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO series_chunks (machine_id, metric_key_id, tier, start_ms, end_ms, count, closed, data)
             VALUES ('old', 99, 0, ?1, ?1, 1, 1, x'00')",
            [t0 - 3 * 86_400_000],
        )
        .unwrap();
    }
    let mut seq = 0u64;
    for minute in 0..60i64 {
        for k in 0..4 {
            seq += 1;
            let at = t0 + minute * 60_000 + k * 15_000;
            let r = rackhand_proto::probe::Report {
                epoch: 1,
                seq,
                sampled_at_ms: at,
                vitals: vec![rackhand_proto::probe::Sample { metric: 1, labels_id: 0, value: 30.0 }],
                ..Default::default()
            };
            ingest.receive(M, Stream::Live, vec![r], 100, at).await.unwrap();
        }
        // the scheduler's minute tick, just after the minute ends
        crate::hub_cmd::every_minute(&ingest, &incidents, &db, t0 + (minute + 1) * 60_000 + 1_000, &NoWait).await;
        if minute == 4 {
            assert_eq!(count("SELECT sum(count) FROM series_chunks WHERE tier = 1"), 5, "a tier 1 point a minute");
        }
    }
    assert_eq!(count("SELECT count(*) FROM series_chunks WHERE tier = 2"), 1, "the hour rolled up on the hour");
    assert!(count("SELECT count(*) FROM baseline_buckets") >= 2, "the baselines learned the hour");
    assert_eq!(count("SELECT count(*) FROM series_chunks WHERE machine_id = 'old'"), 0, "retention ran");
    assert_eq!(count("SELECT count(*) FROM report_staging"), 0, "compaction ran every 5 minutes");
}

/// The hourly retention run keeps tier 0 as long as the `[retention] tier0_h` setting says (7.8.1), not 48 hours.
#[tokio::test(flavor = "multi_thread")]
async fn retention_follows_the_tier_settings() {
    let db = db("tier-settings");
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    ingest.start(0).await.unwrap();
    let incidents = rackhand_hub::incidents::Incidents::new(db.clone(), ingest.clone(), Bus::new());
    let t0 = 1_795_068_000_000i64; // the top of an hour
    rackhand_hub::library::config::put(&db, "hub", "[retention]\ntier0_h = 12\n", "admin", t0).await.unwrap();
    let count = |sql: &str| -> i64 { db.readers().with(|c| c.query_row(sql, [], |r| r.get(0))).unwrap() };
    let path =
        std::env::temp_dir().join(format!("rackhand-composition-tier-settings-{}", std::process::id())).join("hub.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    for (machine, age_h) in [("old", 13), ("kept", 11)] {
        conn.execute(
            "INSERT INTO series_chunks (machine_id, metric_key_id, tier, start_ms, end_ms, count, closed, data)
             VALUES (?1, 99, 0, ?2, ?2, 1, 1, x'00')",
            rusqlite::params![machine, t0 - age_h * 3_600_000],
        )
        .unwrap();
    }
    drop(conn);
    crate::hub_cmd::every_minute(&ingest, &incidents, &db, t0 + 1_000, &NoWait).await;
    assert_eq!(count("SELECT count(*) FROM series_chunks WHERE machine_id = 'old'"), 0, "past the 12 hours");
    assert_eq!(count("SELECT count(*) FROM series_chunks WHERE machine_id = 'kept'"), 1, "inside them");
}
