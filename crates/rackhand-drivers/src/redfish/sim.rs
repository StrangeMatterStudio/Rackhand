//! A Redfish BMC simulator for tests: HTTPS with its own certificate, the invented responses of
//! `tests/fixtures/redfish/`, Basic authentication (`rackhand` / `invented`), and every request logged.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A request: method, path, `Authorization` header.
type Logged = (String, String, String);

#[derive(Debug, Clone)]
pub struct Sim {
    pub url: String,
    pub fingerprint: String,
    requests: Arc<Mutex<Vec<Logged>>>,
}

fn resource(path: &str) -> Option<&'static str> {
    Some(match path {
        "/redfish/v1" | "/redfish/v1/" => "root",
        "/redfish/v1/Systems" => "systems",
        "/redfish/v1/Systems/1" => "system",
        "/redfish/v1/Chassis" => "chassis_list",
        "/redfish/v1/Chassis/1" => "chassis",
        "/redfish/v1/Chassis/1/Thermal" => "thermal",
        "/redfish/v1/Chassis/1/Power" => "power",
        _ => return None,
    })
}

impl Sim {
    pub async fn start() -> Sim {
        let (acceptor, fingerprint) = crate::pinned::test_server();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port");
        let url = format!("https://{}", listener.local_addr().expect("an address"));
        let requests: Arc<Mutex<Vec<Logged>>> = Arc::default();
        let log = requests.clone();
        let good = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("rackhand:invented"));
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let (acceptor, log, good) = (acceptor.clone(), log.clone(), good.clone());
                tokio::spawn(async move {
                    let Ok(mut s) = acceptor.accept(tcp).await else { return };
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 2048];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).to_string();
                    let mut first = head.lines().next().unwrap_or("").split_whitespace();
                    let (method, path) =
                        (first.next().unwrap_or("").to_string(), first.next().unwrap_or("").to_string());
                    let auth = head
                        .lines()
                        .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("authorization")))
                        .map(|(_, v)| v.trim().to_string())
                        .unwrap_or_default();
                    log.lock().unwrap_or_else(|e| e.into_inner()).push((method.clone(), path.clone(), auth.clone()));
                    let (status, body) = match (method.as_str(), resource(&path)) {
                        _ if auth != good => ("401 Unauthorized", "{}".to_string()),
                        ("GET", Some(name)) => {
                            let file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                                .join("tests/fixtures/redfish")
                                .join(format!("{name}.json"));
                            ("200 OK", std::fs::read_to_string(file).unwrap_or_else(|_| "{}".into()))
                        }
                        ("GET", None) => ("404 Not Found", "{}".to_string()),
                        _ => ("405 Method Not Allowed", "{}".to_string()),
                    };
                    let reply = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(reply.as_bytes()).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        Sim { url, fingerprint, requests }
    }

    pub fn requests(&self) -> Vec<Logged> {
        self.requests.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}
