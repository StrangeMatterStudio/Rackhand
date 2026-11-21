//! A TrueNAS simulator for tests: HTTPS with its own certificate, replaying the answers recorded in S9 over JSON-RPC
//! on the WebSocket at `/api/current` or, as an older release, REST at `/api/v2.0` only. It logs the methods called.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Every method the simulator answers: reads only.
pub const READS: &[&str] =
    &["auth.login_with_api_key", "pool.query", "disk.query", "disk.temperatures", "smart.test.results", "alert.list"];

const KEY: &str = "1-invented-api-key";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Api {
    WebSocket,
    Rest,
}

#[derive(Debug, Default)]
struct State {
    calls: Vec<String>,
    authorized: bool,
    /// A disk whose latest SMART test failed (the recording has only passes).
    failing_smart: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Sim {
    pub url: String,
    pub fingerprint: String,
    state: Arc<Mutex<State>>,
}

fn answer_of(api: Api, method: &str, failing_smart: Option<&str>) -> Value {
    let mut v = fixture(api, method);
    if let (Some(disk), "smart.test.results") = (failing_smart, method) {
        for d in v.as_array_mut().into_iter().flatten() {
            if d["disk"].as_str() == Some(disk) {
                if let Some(t) = d["tests"].as_array_mut().and_then(|t| t.iter_mut().find(|t| t["num"] == 0)) {
                    t["status"] = json!("FAILED");
                    t["status_verbose"] = json!("Completed: read failure");
                }
            }
        }
    }
    v
}

fn fixture(api: Api, method: &str) -> Value {
    let file = match method {
        "pool.query" => "pool",
        "disk.query" => "disk",
        "disk.temperatures" => "disk_temperatures",
        "smart.test.results" => "smart_results",
        "alert.list" => "alert_list",
        _ => return Value::Null,
    };
    let dir = if api == Api::WebSocket { "ws" } else { "rest" };
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/truenas").join(dir).join(format!("{file}.json"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap_or_default()).unwrap_or(Value::Null)
}

fn rest_method(verb: &str, path: &str) -> Option<&'static str> {
    match (verb, path) {
        ("GET", "/api/v2.0/pool") => Some("pool.query"),
        ("GET", "/api/v2.0/disk") => Some("disk.query"),
        ("POST", "/api/v2.0/disk/temperatures") => Some("disk.temperatures"),
        ("GET", "/api/v2.0/smart/test/results") => Some("smart.test.results"),
        ("GET", "/api/v2.0/alert/list") => Some("alert.list"),
        _ => None,
    }
}

impl Sim {
    pub async fn start(api: Api) -> Sim {
        let (acceptor, fingerprint) = crate::pinned::test_server();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port");
        let url = format!("https://{}", listener.local_addr().expect("an address"));
        let state = Arc::new(Mutex::new(State::default()));
        let shared = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let (acceptor, state) = (acceptor.clone(), shared.clone());
                tokio::spawn(async move {
                    let Ok(mut s) = acceptor.accept(tcp).await else { return };
                    serve(&mut s, api, &state).await;
                });
            }
        });
        Sim { url, fingerprint, state }
    }

    /// From now on `disk`'s latest SMART test failed.
    pub fn fail_smart(&self, disk: &str) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).failing_smart = Some(disk.to_string());
    }

    /// The methods called, in order.
    pub fn calls(&self) -> Vec<String> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).calls.clone()
    }

    /// Whether the API key was given (a JSON-RPC login, or REST's bearer token).
    pub fn authorized(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).authorized
    }
}

async fn serve<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: &mut S, api: Api, state: &Mutex<State>) {
    let Ok(head) = crate::ws::server::accept(s, api == Api::WebSocket).await else { return };
    match head {
        // a JSON-RPC session
        None => loop {
            let Ok(text) = crate::ws::server::recv(s).await else { return };
            let req: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let method = req["method"].as_str().unwrap_or("").to_string();
            let result: Option<Value> = {
                let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
                st.calls.push(method.clone());
                if method == "auth.login_with_api_key" {
                    st.authorized = req["params"][0] == KEY;
                    Some(json!(st.authorized))
                } else if st.authorized && READS.contains(&method.as_str()) {
                    Some(answer_of(api, &method, st.failing_smart.as_deref()))
                } else {
                    None
                }
            };
            let answer = match result {
                Some(r) => json!({ "jsonrpc": "2.0", "id": req["id"], "result": r }),
                None => {
                    json!({ "jsonrpc": "2.0", "id": req["id"], "error": { "code": -32601, "message": "not allowed" } })
                }
            };
            if crate::ws::server::send(s, &answer.to_string()).await.is_err() {
                return;
            }
        },
        // plain HTTP: REST, or a WebSocket asked of a release without one
        Some(head) => {
            let mut first = head.lines().next().unwrap_or("").split_whitespace();
            let (verb, path) = (first.next().unwrap_or(""), first.next().unwrap_or(""));
            let length: usize = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0))
                })
                .unwrap_or(0);
            let mut body = vec![0u8; length];
            let _ = s.read_exact(&mut body).await;
            let bearer = head.lines().any(|l| l.eq_ignore_ascii_case(&format!("authorization: Bearer {KEY}")));
            let (status, answer) = match rest_method(verb, path) {
                Some(method) => {
                    let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
                    st.calls.push(method.to_string());
                    st.authorized |= bearer;
                    if bearer {
                        ("200 OK", answer_of(api, method, st.failing_smart.as_deref()).to_string())
                    } else {
                        ("401 Unauthorized", "{}".to_string())
                    }
                }
                None => ("404 Not Found", "{}".to_string()),
            };
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                answer.len()
            );
            let _ = s.write_all(reply.as_bytes()).await;
            let _ = s.shutdown().await;
        }
    }
}
