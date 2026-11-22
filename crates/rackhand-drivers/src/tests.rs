//! The check drivers against local servers (plan T46).

use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

fn target(t: &str, settings: serde_json::Value) -> DriverTarget {
    DriverTarget { target: t.to_string(), settings, timeout: Duration::from_secs(3) }
}

fn metric(r: &DriverReading, name: &str) -> Option<f64> {
    r.metrics.iter().find(|(n, _)| n == name).map(|(_, v)| *v)
}

/// A tiny HTTP server: `/ok` 200 "all good", `/err` 500, `/moved` 302 to `/ok`.
async fn http_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, extra, body) = match path.as_str() {
                    "/ok" => ("200 OK", "", "all good"),
                    "/moved" => ("302 Found", "Location: /ok\r\n", ""),
                    _ => ("500 Internal Server Error", "", "broken"),
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn http_status_and_body_match() {
    let base = http_server().await;
    let http = Http::new();
    assert_eq!(http.kind(), DriverKind::Http);
    let ok = http.poll(&target(&format!("{base}/ok"), json!({ "body_contains": "good" }))).await.unwrap();
    assert!(ok.ok, "{}", ok.detail);
    assert_eq!(metric(&ok, "check.status_code"), Some(200.0));
    assert_eq!(metric(&ok, "check.up"), Some(1.0));
    assert!(ok.latency_ms.is_some_and(|l| l >= 0.0));
    let err = http.poll(&target(&format!("{base}/err"), json!({}))).await.unwrap();
    assert!(!err.ok && err.detail.contains("500"), "{}", err.detail);
    assert_eq!(metric(&err, "check.up"), Some(0.0));
    let body = http.poll(&target(&format!("{base}/ok"), json!({ "body_contains": "missing" }))).await.unwrap();
    assert!(!body.ok && body.detail.contains("body"), "{}", body.detail);
    // a redirect isn't followed: it is the answer
    let moved = http.poll(&target(&format!("{base}/moved"), json!({}))).await.unwrap();
    assert!(!moved.ok && moved.detail.contains("302"), "{}", moved.detail);
    let expected = http.poll(&target(&format!("{base}/moved"), json!({ "status": 302 }))).await.unwrap();
    assert!(expected.ok, "{}", expected.detail);
    // a setting it doesn't know is a configuration error, not a failing check
    assert!(matches!(
        http.poll(&target(&format!("{base}/ok"), json!({ "verify": false }))).await,
        Err(DriverError::Invalid(_))
    ));
}

/// A DNS stub that answers every A question for `svc.lab.test` with 192.0.2.44.
async fn dns_stub() -> String {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await.unwrap();
            let q = &buf[..n];
            // header: id, flags (response, recursion available), 1 question, 1 answer
            let mut r = vec![q[0], q[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
            r.extend_from_slice(&q[12..]);
            let name = super::dns::read_name(q, 12).map(|(n, _)| n).unwrap_or_default();
            if name == "svc.lab.test" {
                r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 44]);
            } else {
                r[3] = 0x83; // NXDOMAIN
                r[7] = 0;
            }
            sock.send_to(&r, from).await.unwrap();
        }
    });
    addr.to_string()
}

#[tokio::test]
async fn tcp_connect_and_dns_answer() {
    let tcp = Tcp::new();
    let open = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up = tcp.poll(&target(&open.local_addr().unwrap().to_string(), json!({}))).await.unwrap();
    assert!(up.ok && up.latency_ms.is_some(), "{}", up.detail);
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let down = tcp.poll(&target(&closed.to_string(), json!({}))).await.unwrap();
    assert!(!down.ok, "a closed port fails");
    assert_eq!(metric(&down, "check.up"), Some(0.0));

    let server = dns_stub().await;
    let dns = Dns::new();
    let found = dns.poll(&target("svc.lab.test", json!({ "server": server, "expect": "192.0.2.44" }))).await.unwrap();
    assert!(found.ok, "{}", found.detail);
    let wrong = dns.poll(&target("svc.lab.test", json!({ "server": server, "expect": "192.0.2.45" }))).await.unwrap();
    assert!(!wrong.ok && wrong.detail.contains("192.0.2.44"), "{}", wrong.detail);
    let missing = dns.poll(&target("nope.lab.test", json!({ "server": server }))).await.unwrap();
    assert!(!missing.ok, "NXDOMAIN fails");
}

/// An HTTPS server with a self-signed certificate answering 200 "all good", and the certificate's fingerprint.
async fn https_server() -> (String, String) {
    let (acceptor, fingerprint) = crate::pinned::test_server();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else { return };
                let mut buf = vec![0u8; 4096];
                let _ = s.read(&mut buf).await;
                let body = "all good";
                let resp =
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (format!("https://{addr}"), fingerprint)
}

/// Owner review (B1): an HTTPS check trusts the public roots, or, with `fingerprint`, exactly the certificate with that
/// SHA-256, for a self-signed internal service. A wrong one fails the check; the setting is for `https://` only.
#[tokio::test]
async fn https_check_pins_a_certificate_by_fingerprint() {
    let (base, fingerprint) = https_server().await;
    let http = Http::new();
    let url = format!("{base}/ok");
    let public = http.poll(&target(&url, json!({}))).await.unwrap();
    assert!(!public.ok && public.detail.contains("TLS"), "self-signed isn't publicly trusted: {}", public.detail);
    let pinned =
        http.poll(&target(&url, json!({ "fingerprint": fingerprint, "body_contains": "good" }))).await.unwrap();
    assert!(pinned.ok, "{}", pinned.detail);
    assert_eq!(metric(&pinned, "check.status_code"), Some(200.0));
    let lower = fingerprint.replace(':', "").to_lowercase();
    assert!(http.poll(&target(&url, json!({ "fingerprint": lower }))).await.unwrap().ok, "any case, colons optional");
    let other = crate::pinned::show(&[7u8; 32]);
    let wrong = http.poll(&target(&url, json!({ "fingerprint": other }))).await.unwrap();
    assert!(!wrong.ok && wrong.detail.contains("fingerprint"), "{}", wrong.detail);
    assert!(matches!(
        http.poll(&target(&url, json!({ "fingerprint": "not hex" }))).await,
        Err(DriverError::Invalid(_))
    ));
    let plain = http_server().await;
    assert!(
        matches!(
            http.poll(&target(&format!("{plain}/ok"), json!({ "fingerprint": fingerprint }))).await,
            Err(DriverError::Invalid(_))
        ),
        "a fingerprint on http:// is a configuration error"
    );
}

/// A TLS server whose self-signed certificate expires in `days` days and an hour.
async fn tls_server(days: i64) -> String {
    let mut params = rcgen::CertificateParams::new(vec!["svc.lab.test".to_string()]).unwrap();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(days) + time::Duration::hours(1);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let pk = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
    let config =
        rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der], pk)
            .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(s).await {
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    addr.to_string()
}

#[tokio::test]
async fn tls_days_to_expiry() {
    let addr = tls_server(10).await;
    let tls = Tls::new();
    // the certificate is read whoever signed it: its expiry is what's being watched
    let r = tls.poll(&target(&addr, json!({ "server_name": "svc.lab.test" }))).await.unwrap();
    assert!(r.ok, "{}", r.detail);
    assert_eq!(metric(&r, "check.cert_days"), Some(10.0), "{}", r.detail);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let down = tls.poll(&target(&closed.to_string(), json!({}))).await.unwrap();
    assert!(!down.ok);
}

#[tokio::test]
async fn icmp_uses_unprivileged_socket_or_cap_net_raw() {
    let icmp = Icmp::new();
    let r = icmp.poll(&target("127.0.0.1", json!({}))).await.unwrap();
    assert!(r.ok, "a ping to loopback without root: {}", r.detail);
    assert!(r.latency_ms.is_some());
    // an address nothing answers (TEST-NET-1 has no route here, or drops it) fails within the timeout
    let quiet = icmp
        .poll(&DriverTarget { target: "192.0.2.123".into(), settings: json!({}), timeout: Duration::from_millis(500) })
        .await
        .unwrap();
    assert!(!quiet.ok);
}

mod pinned_tls {
    use super::*;

    /// The certificate an appliance presents, read before it is pinned (7.3.12): the handshake only, nothing sent.
    #[tokio::test]
    async fn presented_is_the_servers_fingerprint_and_nothing_is_sent() {
        let (acceptor, fingerprint) = crate::pinned::test_server();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut s = acceptor.accept(tcp).await.unwrap();
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf).await;
            let _ = tx.send(buf.len());
        });
        let seen = crate::pinned::presented("127.0.0.1", port, Duration::from_secs(3)).await.unwrap();
        assert_eq!(seen, fingerprint);
        assert_eq!(rx.await.unwrap(), 0, "no request after the handshake");
        // nothing listening: a reason, not a fingerprint
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
        assert!(crate::pinned::presented("127.0.0.1", closed, Duration::from_secs(3)).await.is_err());
    }
}
