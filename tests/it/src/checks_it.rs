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
