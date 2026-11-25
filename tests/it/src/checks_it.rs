//! Service checks from the hub binary (plan T46, AC10): an HTTP check of a service that stops, and a TLS check of a
//! certificate 10 days from expiry, against a container.

use std::time::Duration;

use crate::probe_hub::{Hub, within};
use crate::support::Container;

/// A self-signed certificate for `svc.lab.test` that expires in 10 days and an hour, in `dir`.
fn expiring_cert(dir: &std::path::Path) {
    let mut params = rcgen::CertificateParams::new(vec!["svc.lab.test".to_string()]).unwrap();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(10) + time::Duration::hours(1);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
}

fn results(hub: &Hub, check: &str) -> Vec<bool> {
    let db = hub.read_db();
    let mut s = db.prepare("SELECT ok FROM check_results WHERE check_id = ?1 ORDER BY at_ms").unwrap();
    s.query_map([check], |r| r.get::<_, i64>(0).map(|v| v != 0)).unwrap().map(Result::unwrap).collect()
}

#[test]
fn http_check_on_stopped_service_and_expiring_cert() {
    let mut hub = Hub::init("checks");
    let certs = hub.dir.join("certs");
    expiring_cert(&certs);
    let web = Container::start_with("web", &["-v", &format!("{}:/certs:ro", certs.display())]);
    let (ip, _) = web.ip_and_gateway();
    hub.config(
        "checks",
        &format!(
            "[[check]]\nname = \"web\"\nkind = \"http\"\ntarget = \"http://{ip}:8080/\"\ninterval_s = 15\n\
             [check.settings]\nbody_contains = \"up\"\n\n\
             [[check]]\nname = \"web-cert\"\nkind = \"tls\"\ntarget = \"{ip}:8443\"\ninterval_s = 15\n\
             [check.settings]\nserver_name = \"svc.lab.test\"\n"
        ),
    );
    hub.start();
    within(Duration::from_secs(60), "the HTTP check passes", || results(&hub, "web").contains(&true));
    // the certificate's 10 days give a warning (14 days warns, 3 is critical)
    let cert_warning = |hub: &Hub| hub.open_incidents().contains(&("cert.expiry".into(), "warning".into()));
    within(Duration::from_secs(60), "the certificate warning", || cert_warning(&hub));
    assert!(!hub.open_incidents().iter().any(|i| i.0 == "check.failing"), "{:?}", hub.open_incidents());
    // the service stops: a warning once 2 checks in a row have failed
    assert!(web.root("pkill -f '[s]erve.py web'").status.success());
    let failing = |hub: &Hub| hub.open_incidents().contains(&("check.failing".into(), "warning".into()));
    let stopped = std::time::Instant::now();
    while !failing(&hub) && stopped.elapsed() < Duration::from_secs(90) {
        std::thread::sleep(Duration::from_millis(500));
    }
    let took = stopped.elapsed();
    assert!(
        failing(&hub),
        "no warning within 90 s of the service stopping: results {:?}, open {:?}
{}",
        results(&hub, "web"),
        hub.open_incidents(),
        hub.log()
    );
    let runs = results(&hub, "web");
    let failed = runs.iter().rev().take_while(|ok| !**ok).count();
    assert!(failed >= 2, "opened after {failed} failures: {runs:?}");
    println!("check.failing warning {took:?} after the service stopped ({failed} failed runs)");
}

#[derive(Debug)]
struct One(iroh::EndpointId);

const MACHINE: [u8; 16] = [7; 16];

impl rackhand_hub::ingest::probe_server::ProbeDirectory for One {
    fn machine_of(&self, endpoint: &iroh::EndpointId) -> Option<[u8; 16]> {
        (*endpoint == self.0).then_some(MACHINE)
    }
}

#[derive(Debug)]
struct Roomy;

impl rackhand_hub::ingest::DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

/// An HTTP server on loopback whose `/health` answers 503.
async fn unhealthy() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = axum::Router::new()
        .route("/health", axum::routing::get(|| async { (axum::http::StatusCode::SERVICE_UNAVAILABLE, "starting") }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    port
}

/// `probe_check` (D115) through the real probe daemon: the hub's step sends `RunCheck` on stream 0, the probe runs
/// the check on its machine and answers `CheckResult`; the step fails with the first failing check, and the probe
/// refuses an address that isn't its machine's.
#[tokio::test(flavor = "multi_thread")]
async fn probe_check_step_runs_check_on_probe() {
    use rackhand_hub::actions::runner::{StepCtx, StepOutcome, StepRunner};
    use rackhand_hub::ingest::Ingest;
    use rackhand_hub::ingest::probe_server::{ProbeServer, ServerSettings};
    let dir = std::env::temp_dir().join(format!("rackhand-it-probe-check-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = std::sync::Arc::new(rackhand_store::Db::open(&dir.join("hub.db")).unwrap());
    let ingest = Ingest::new(db.clone(), rackhand_hub::bus::Bus::new(), std::sync::Arc::new(Roomy));
    let (_relay, relay_url) = rackhand_net::testing::local_relay().await;
    let hub = rackhand_net::testing::endpoint(&relay_url, &[rackhand_proto::alpn::PROBE]).await;
    let probe = rackhand_net::testing::endpoint(&relay_url, &[]).await;
    let registry = std::sync::Arc::new(rackhand_net::registry::MemoryRegistry::default());
    registry.allow(rackhand_proto::alpn::PROBE, probe.id());
    let server = ProbeServer::new(ingest.clone(), std::sync::Arc::new(One(probe.id())), ServerSettings::default());
    let router = rackhand_net::router::Router::new(hub.clone(), registry.clone())
        .route(rackhand_proto::alpn::PROBE, server.handler());
    tokio::spawn(router.serve());
    let mut addr = hub.addr();
    addr.addrs.insert(iroh::TransportAddr::Relay(relay_url.clone()));
    let buffer = rackhand_probe::buffer::segments::Buffer::open(&dir.join("buffer"), Default::default(), 0).unwrap();
    let link = rackhand_probe::link::Link::new(
        probe,
        rackhand_probe::link::LinkConfig::new(addr, MACHINE, "0.1.0"),
        buffer,
        rackhand_probe::buffer::epoch::EpochState::start(None),
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/proc/rates/b");
    let opts = rackhand_probe::run::Options {
        host: std::sync::Arc::new(rackhand_probe::collect::RootHost::new(root)),
        settings: rackhand_probe::run::Settings { interval: Duration::from_secs(5), ..Default::default() },
        data_dir: dir.join("buffer"),
        state_file: None,
        version: "0.1.0".into(),
        clock: std::sync::Arc::new(rackhand_probe::run::SystemClock::default()),
        jitter: std::sync::Arc::new(|| 0.0),
        helper: None,
        capture: None,
    };
    tokio::spawn(rackhand_probe::run::Daemon::new(link, opts).unwrap().run());
    let machine = ulid::Ulid::from_bytes(MACHINE).to_string();
    let started = std::time::Instant::now();
    while ingest.last_seen(&machine).is_none() {
        assert!(started.elapsed() < Duration::from_secs(30), "the probe never reported");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // on the probe's machine: a database port that accepts, a health page that isn't healthy yet
    let db_port = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pg = db_port.local_addr().unwrap().port();
    let health = unhealthy().await;
    let checks = server.probe_checks();
    let ctx = StepCtx {
        job_id: "j1".into(),
        machine_id: machine.clone(),
        machine_kind: "linux".into(),
        address: None,
        identity: rackhand_runbook::runbook::Identity::Automation,
        timeout: Duration::from_secs(10),
    };
    let step = |list: &str| -> rackhand_runbook::runbook::Step {
        toml::from_str(&format!("id = \"local\"\nkind = \"probe_check\"\nchecks = [{list}]\n")).unwrap()
    };
    let both = step(&format!("\"tcp:127.0.0.1:{pg}\", \"http:http://127.0.0.1:{health}/health\""));
    let r = checks.run(&ctx, &both, None).await;
    assert_eq!(r.outcome, StepOutcome::Failed(format!("http:http://127.0.0.1:{health}/health")));
    assert!(String::from_utf8_lossy(&r.stderr).contains("503"), "{}", String::from_utf8_lossy(&r.stderr));
    let fine = checks.run(&ctx, &step(&format!("\"tcp:127.0.0.1:{pg}\"")), None).await;
    assert_eq!(fine.outcome, StepOutcome::Succeeded);
    let away = checks.run(&ctx, &step("\"tcp:192.0.2.99:5432\""), None).await;
    assert_eq!(away.outcome, StepOutcome::Failed("tcp:192.0.2.99:5432".into()));
    assert!(String::from_utf8_lossy(&away.stderr).contains("isn't this machine's"));
}
