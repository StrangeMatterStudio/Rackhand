//! `probe_check` on the probe (D115): only loopback and the machine's own addresses, the hub's TCP and HTTP syntax.

use std::net::IpAddr;
use std::time::Duration;

use super::*;

const T: Duration = Duration::from_secs(2);

fn to(ip: &str) -> impl Fn(&str) -> Vec<IpAddr> + Sync {
    let ip: IpAddr = ip.parse().unwrap();
    move |_| vec![ip]
}

#[tokio::test]
async fn only_this_machines_addresses() {
    let open = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = open.local_addr().unwrap().port();
    let ok = run_with(&format!("tcp:127.0.0.1:{port}"), T, &to("127.0.0.1")).await;
    assert!(ok.ok, "{}", ok.detail);
    assert!(ok.latency_ms >= 0.0);
    // a name is checked by what it resolves to: on this machine it runs, elsewhere it's refused
    let named = run_with(&format!("tcp:svc.lab.test:{port}"), T, &to("127.0.0.1")).await;
    assert!(named.ok, "{}", named.detail);
    let away = run_with("tcp:db.lab.test:5432", T, &to("192.0.2.99")).await;
    assert!(!away.ok && away.detail.contains("isn't this machine's"), "{}", away.detail);
    let literal = run_with("http:http://192.0.2.99:8080/health", T, &to("192.0.2.99")).await;
    assert!(!literal.ok && literal.detail.contains("isn't this machine's"), "{}", literal.detail);
    // a closed port fails as the hub's TCP check would
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let down = run_with(&format!("tcp:127.0.0.1:{closed}"), T, &to("127.0.0.1")).await;
    assert!(!down.ok);
    // only the tcp and http kinds, in their syntax
    for bad in ["dns:svc.lab.test", "tcp:", "http:ftp://127.0.0.1/", "nonsense"] {
        let r = run_with(bad, T, &to("127.0.0.1")).await;
        assert!(!r.ok, "{bad}: {}", r.detail);
    }
}

#[test]
fn own_addresses_are_loopback_or_bindable() {
    assert!(own("127.0.0.1".parse().unwrap()));
    assert!(own("::1".parse().unwrap()));
    assert!(!own("192.0.2.99".parse().unwrap()), "TEST-NET-1 isn't an address of this machine");
}
