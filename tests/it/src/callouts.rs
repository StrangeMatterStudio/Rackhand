//! AC5 through the real probe daemon and the hub's own systems, composed in this process as `hub run` composes them:
//! the probe reads a fixture root whose `/data` usage the test rewrites, and the hub's callouts go to a fake Discord
//! endpoint and an SMTP sink. In process because the hub binary trusts only the public roots for SMTP over TLS, so
//! it can't reach a test mail server (see the run's deviations).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rackhand_hub::bus::Bus;
use rackhand_hub::incidents::Incidents;
use rackhand_hub::ingest::probe_server::{ProbeDirectory, ProbeServer, ServerSettings};
use rackhand_hub::ingest::{DiskSpace, Ingest};
use rackhand_hub::notify::discord::{AMBER, Discord, GREEN, RED};
use rackhand_hub::notify::smtp::{Security, Smtp, SmtpConfig};
use rackhand_hub::notify::{Notify, Transport};
use rackhand_net::registry::MemoryRegistry;
use rackhand_probe::run::{Daemon, Options, Settings, SystemClock};
use rackhand_store::Db;

const MACHINE: [u8; 16] = [9; 16];

#[derive(Debug)]
struct Roomy;

impl DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

#[derive(Debug)]
struct One(iroh::EndpointId);

impl ProbeDirectory for One {
    fn machine_of(&self, endpoint: &iroh::EndpointId) -> Option<[u8; 16]> {
        (*endpoint == self.0).then_some(MACHINE)
    }
}

fn now_ms() -> i64 {
    rackhand_store::ids::now_ms()
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let target = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), target).unwrap();
        }
    }
}

/// The fixture machine with `/data` at `pct` percent used.
fn set_data_usage(root: &Path, pct: u64) {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/proc/rates/b/statvfs.txt");
    let mut text = std::fs::read_to_string(fixture).unwrap();
    let free = 100 - pct;
    text.push_str(&format!("/data 100000000000 {free}000000000 {free}000000000 1000000 900000\n"));
    let tmp = root.join("statvfs.txt.tmp");
    std::fs::write(&tmp, text).unwrap();
    std::fs::rename(tmp, root.join("statvfs.txt")).unwrap();
}

/// Discord messages: colour (red critical, amber warning, green resolution) and title.
#[derive(Debug, Default)]
struct Hook(Mutex<Vec<(u32, String)>>);

async fn fake_discord() -> (u16, Arc<Hook>) {
    let hook = Arc::new(Hook::default());
    let h = hook.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |body: String| {
            let h = h.clone();
            async move {
                let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                let color = v["embeds"][0]["color"].as_u64().unwrap_or(0) as u32;
                let title = v["embeds"][0]["title"].as_str().unwrap_or_default().to_string();
                h.0.lock().unwrap().push((color, title));
                axum::http::StatusCode::NO_CONTENT
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (port, hook)
}

async fn wait(limit: Duration, what: &str, f: impl Fn() -> bool) -> Duration {
    let start = Instant::now();
    while !f() {
        assert!(start.elapsed() < limit, "not within {limit:?}: {what}");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    start.elapsed()
}

#[tokio::test(flavor = "multi_thread")]
async fn disk_rule_callouts_and_resolution() {
    let dir = std::env::temp_dir().join(format!("rackhand-it-callouts-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let root: PathBuf = dir.join("root");
    copy_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/proc/rates/b"), &root);
    let mounts = root.join("proc/mounts");
    let mut m = std::fs::read_to_string(&mounts).unwrap();
    m.push_str("/dev/sdc1 /data ext4 rw,relatime 0 0\n");
    std::fs::write(&mounts, m).unwrap();
    // no failed units on this machine: only the disk rule should call out
    std::fs::write(root.join("units.txt"), "").unwrap();
    set_data_usage(&root, 96);

    // the hub's systems
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let site = "INSERT INTO sites (id, name, timezone, is_local) VALUES ('s', 'home', 'UTC', 1)";
    let machine = format!(
        "INSERT INTO machines (id, site_id, name, kind, state) VALUES ('{}', 's', 'web1', 'linux', 'enrolled')",
        ulid::Ulid::from_bytes(MACHINE)
    );
    {
        let c = rusqlite::Connection::open(dir.join("hub.db")).unwrap();
        c.execute(site, []).unwrap();
        c.execute(&machine, []).unwrap();
    }
    let bus = Bus::new();
    let ingest = Ingest::new(db.clone(), bus.clone(), Arc::new(Roomy));
    ingest.start(now_ms()).await.unwrap();
    let incidents = Incidents::new(db.clone(), ingest.clone(), bus.clone());
    let sink = rackhand_hub::notify::smtp_sink::Sink::start().await;
    let (port, hook) = fake_discord().await;
    let smtp = SmtpConfig {
        host: "localhost".into(),
        port: sink.port,
        security: Security::StartTls,
        username: Some("rackhand".into()),
        password: Some("sink".into()),
        from: "rackhand@hub.test".into(),
        to: vec!["ops@hub.test".into()],
        extra_roots: vec![sink.cert.clone()],
    };
    let transports: Vec<Arc<dyn Transport>> = vec![
        Arc::new(Discord::new("ops", &format!("http://127.0.0.1:{port}/hook"))),
        Arc::new(Smtp::new("mail", smtp)),
    ];
    let notify = Notify::new(db.clone(), ingest.clone(), transports);
    // the 15-second loop of `hub run`
    let (i, n) = (incidents.clone(), notify.clone());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            let _ = i.evaluate(now_ms()).await;
            let _ = n.tick(now_ms()).await;
        }
    });

    // the probe, over the mesh
    let (_relay, relay_url) = rackhand_net::testing::local_relay().await;
    let hub = rackhand_net::testing::endpoint(&relay_url, &[rackhand_proto::alpn::PROBE]).await;
    let probe = rackhand_net::testing::endpoint(&relay_url, &[]).await;
    let registry = Arc::new(MemoryRegistry::default());
    registry.allow(rackhand_proto::alpn::PROBE, probe.id());
    let server = ProbeServer::new(ingest.clone(), Arc::new(One(probe.id())), ServerSettings::default());
    let router = rackhand_net::router::Router::new(hub.clone(), registry.clone())
        .route(rackhand_proto::alpn::PROBE, server.handler());
    tokio::spawn(router.serve());
    let mut addr = hub.addr();
    addr.addrs.insert(iroh::TransportAddr::Relay(relay_url.clone()));
    let buffer =
        rackhand_probe::buffer::segments::Buffer::open(&dir.join("buffer"), Default::default(), now_ms()).unwrap();
    let link = rackhand_probe::link::Link::new(
        probe,
        rackhand_probe::link::LinkConfig::new(addr, MACHINE, "0.1.0"),
        buffer,
        rackhand_probe::buffer::epoch::EpochState::start(None),
    );
    let opts = Options {
        host: Arc::new(rackhand_probe::collect::RootHost::new(root.clone())),
        settings: Settings { interval: Duration::from_secs(5), ..Settings::default() },
        data_dir: dir.join("buffer"),
        state_file: None,
        version: "0.1.0".into(),
        clock: Arc::new(SystemClock::default()),
        jitter: Arc::new(|| 0.0),
        helper: None,
        capture: None,
    };
    tokio::spawn(Daemon::new(link, opts).unwrap().run());

    // 96% for 5 minutes: a critical to Discord and by mail within 60 s
    // messages about the disk only (the title names the incident)
    let count = |c: u32| hook.0.lock().unwrap().iter().filter(|(x, t)| *x == c && t.contains("isk")).count();
    let took = wait(Duration::from_secs(5 * 60 + 90), "a critical on Discord", || count(RED) >= 1).await;
    eprintln!("critical after {took:?}: {:?}", hook.0.lock().unwrap());
    // A machine with no history: the window matches at 80% of its 20 samples (7.6.1), the 16th, 15 intervals of 15 s
    // after the first; less the 5 s before the hub's interval reached the probe.
    assert!(took >= Duration::from_secs(15 * 15 - 5), "not before 16 samples: {took:?}");
    let mail = sink.received().await;
    assert!(mail.tls && mail.data.to_lowercase().contains("critical"), "the critical by mail: {mail:?}");
    // 70% for two samples: a resolution
    set_data_usage(&root, 70);
    let took = wait(Duration::from_secs(90), "a resolution on Discord", || count(GREEN) >= 1).await;
    eprintln!("resolution after {took:?}");
    // 86% for 5 minutes: a warning callout within 6 minutes (warnings join their site's 5-minute group). A falling
    // severity sends nothing (7.6: re-sent only when it rises), so the warning is checked on its own.
    set_data_usage(&root, 86);
    let took = wait(Duration::from_secs(11 * 60 + 30), "a warning on Discord", || {
        hook.0.lock().unwrap().iter().any(|(c, t)| *c == AMBER && (t.contains("isk") || t.contains("warning")))
    })
    .await;
    eprintln!("warning after {took:?}: {:?}", hook.0.lock().unwrap());
    // With the samples at 70% before it, every one of the window's has to be over: the whole 5 minutes, less the 15 s a
    // sample's time is rounded down by.
    assert!(took >= Duration::from_secs(5 * 60 - 15), "not before the 5 minutes: {took:?}");
    // within 6 minutes of the warning opening (86% held for 5 minutes; a resolved incident reopens with its id)
    let opened: i64 = rusqlite::Connection::open(dir.join("hub.db"))
        .unwrap()
        .query_row(
            "SELECT max(e.at_ms) FROM incident_events e JOIN incidents i ON i.id = e.incident_id              WHERE i.kind = 'disk.used' AND e.kind IN ('opened', 'reopened')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let late = now_ms() - opened;
    assert!(late <= 6 * 60_000, "the warning callout {late} ms after the incident opened");
}
