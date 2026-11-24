//! A Proxmox VE API simulator for tests (plan T47): HTTPS with its own certificate, the answers recorded from the
//! lab's nodes (`tests/fixtures/proxmox/<version>/`, `cargo xtask lab record-proxmox`), the guests' firewall and
//! configuration kept as state so writes can be read back, and every request logged.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: String,
    pub authorization: String,
}

#[derive(Debug, Default)]
struct Guest {
    options: Map<String, Value>,
    rules: Vec<Value>,
    config: Map<String, Value>,
    /// Its snapshots (without `current`), as `{name, snaptime, description}`.
    snapshots: Vec<Value>,
    /// Its configuration doesn't load (a 500).
    broken: bool,
    /// A guest made through the API: its name, and whether it runs (the recorded two come from the fixtures).
    made: Option<(String, bool)>,
}

#[derive(Debug)]
struct State {
    dir: PathBuf,
    node: String,
    guests: BTreeMap<(String, u32), Guest>,
    /// Storages changed by a test: type, available and total bytes.
    storage: BTreeMap<String, (String, u64, u64)>,
    /// The cluster's nodes and their status, when a test sets them.
    nodes: Option<Vec<(String, String)>>,
    /// The datacenter firewall's `enable`, when a test sets it (the recorded options say off).
    datacenter_firewall: Option<bool>,
    /// Requests that fail once with a 500: the method and the end of the path.
    fail_once: Vec<(String, String)>,
    requests: Vec<Request>,
}

#[derive(Debug, Clone)]
pub struct Sim {
    pub url: String,
    /// The SHA-256 of its certificate, as `AA:BB:...`.
    pub fingerprint: String,
    state: Arc<Mutex<State>>,
}

fn fixture(dir: &std::path::Path, name: &str) -> Value {
    let text = std::fs::read_to_string(dir.join(format!("{name}.json"))).unwrap_or_else(|_| "{\"data\":null}".into());
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

fn form(body: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(body.as_bytes()).into_owned().collect()
}

impl Sim {
    /// A simulator of the recorded node `version` (`pve8` or `pve9`).
    pub async fn start(version: &str) -> Sim {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/proxmox").join(version);
        let node = std::fs::read_to_string(dir.join("node.txt")).expect("recorded fixtures").trim().to_string();
        let mut guests = BTreeMap::new();
        for (kind, vmid) in [("lxc", 100u32), ("qemu", 200u32)] {
            let mut g = Guest::default();
            if kind == "lxc" {
                g.options = fixture(&dir, "lxc_firewall_options")["data"].as_object().cloned().unwrap_or_default();
                g.rules = fixture(&dir, "lxc_firewall_rules")["data"].as_array().cloned().unwrap_or_default();
            }
            g.config = fixture(&dir, &format!("{kind}_config"))["data"].as_object().cloned().unwrap_or_default();
            g.snapshots = fixture(&dir, &format!("{kind}_snapshots"))["data"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|s| s["name"] != "current")
                .cloned()
                .collect();
            guests.insert((kind.to_string(), vmid), g);
        }
        let state = Arc::new(Mutex::new(State {
            dir,
            node,
            guests,
            storage: BTreeMap::new(),
            nodes: None,
            datacenter_firewall: None,
            fail_once: Vec::new(),
            requests: Vec::new(),
        }));
        let (acceptor, fingerprint) = crate::pinned::test_server();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port");
        let url = format!("https://{}", listener.local_addr().expect("an address"));
        let shared = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let (acceptor, state) = (acceptor.clone(), shared.clone());
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(tcp).await {
                        if let Some(req) = read_request(&mut tls).await {
                            let (status, body) = answer(&state, req);
                            let head = format!(
                                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = tls.write_all(head.as_bytes()).await;
                            let _ = tls.write_all(body.as_bytes()).await;
                            let _ = tls.shutdown().await;
                        }
                    }
                });
            }
        });
        Sim { url, fingerprint, state }
    }

    /// The nodes `GET /nodes` gives, as `(name, status)`.
    pub fn set_nodes(&self, nodes: &[(&str, &str)]) {
        let nodes = nodes.iter().map(|(n, s)| (n.to_string(), s.to_string())).collect();
        self.state.lock().unwrap_or_else(|e| e.into_inner()).nodes = Some(nodes);
    }

    pub fn requests(&self) -> Vec<Request> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).requests.clone()
    }

    /// From now on the configuration of guest `vmid` doesn't load.
    pub fn fail_config(&self, vmid: u32) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        for ((_, id), g) in s.guests.iter_mut() {
            if *id == vmid {
                g.broken = true;
            }
        }
    }

    /// From now on storage `name` reports this type and these sizes.
    pub fn set_storage(&self, name: &str, kind: &str, avail: u64, total: u64) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.storage.insert(name.to_string(), (kind.to_string(), avail, total));
    }

    /// The next request with this method whose path ends with `tail` fails with a 500.
    pub fn fail_once(&self, method: &str, tail: &str) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).fail_once.push((method.into(), tail.into()));
    }

    /// Turns the datacenter firewall on or off, as an admin would.
    pub fn set_datacenter_firewall(&self, on: bool) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).datacenter_firewall = Some(on);
    }

    /// A guest's own firewall: what it had before anything of ours.
    pub fn set_guest_firewall(&self, vmid: u32, options: Value, rules: Vec<Value>) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let g = s.guests.get_mut(&("lxc".to_string(), vmid)).expect("the guest");
        g.options = options.as_object().cloned().unwrap_or_default();
        g.rules = rules;
    }

    /// Someone changes one of the guest's firewall options.
    pub fn set_guest_option(&self, vmid: u32, key: &str, value: Value) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.guests.get_mut(&("lxc".to_string(), vmid)).expect("the guest").options.insert(key.into(), value);
    }

    /// What a quarantine does to a container's firewall (D104): policies DROP, a rule, the device's flag on.
    pub fn quarantine(&self, vmid: u32) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let g = s.guests.get_mut(&("lxc".to_string(), vmid)).expect("the guest");
        g.options.insert("enable".into(), json!(1));
        g.options.insert("policy_in".into(), json!("DROP"));
        g.options.insert("policy_out".into(), json!("DROP"));
        g.rules.insert(0, json!({ "type": "out", "action": "ACCEPT", "dest": "192.0.2.10", "enable": 1, "pos": 0 }));
        if let Some(Value::String(net)) = g.config.get_mut("net0") {
            *net = format!("{net},firewall=1");
        }
    }
}

async fn read_request<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Option<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let mut first = lines.next()?.split_whitespace();
    let (method, path) = (first.next()?.to_string(), first.next()?.to_string());
    let mut length = 0usize;
    let mut authorization = String::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => length = v.trim().parse().unwrap_or(0),
                "authorization" => authorization = v.trim().to_string(),
                _ => {}
            }
        }
    }
    while buf.len() < head_end + length {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&buf[head_end..(head_end + length).min(buf.len())]).to_string();
    Some(Request { method, path, body, authorization })
}

fn ok(data: Value) -> (&'static str, String) {
    ("200 OK", json!({ "data": data }).to_string())
}

fn answer(state: &Mutex<State>, req: Request) -> (&'static str, String) {
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    s.requests.push(req.clone());
    if !req.authorization.starts_with("PVEAPIToken=") {
        return ("401 Unauthorized", "{\"data\":null}".into());
    }
    let dir = s.dir.clone();
    let node = s.node.clone();
    let path = req.path.split('?').next().unwrap_or("").to_string();
    if let Some(i) = s.fail_once.iter().position(|(m, p)| *m == req.method && path.ends_with(p.as_str())) {
        s.fail_once.remove(i);
        return ("500 Internal Server Error", json!({ "data": null, "message": "injected failure" }).to_string());
    }
    let Some(rest) = path.strip_prefix("/api2/json") else { return ("404 Not Found", "{}".into()) };
    let parts: Vec<&str> = rest.trim_matches('/').split('/').collect();
    let data = |name: &str| fixture(&dir, name)["data"].clone();
    match (req.method.as_str(), parts.as_slice()) {
        ("GET", ["nodes"]) => match &s.nodes {
            Some(nodes) => {
                ok(nodes.iter().map(|(n, status)| json!({ "node": n, "status": status, "type": "node" })).collect())
            }
            None => ok(data("nodes")),
        },
        ("GET", ["cluster", "firewall", "options"]) => {
            let mut options = data("cluster_firewall_options");
            if let (Some(on), Some(m)) = (s.datacenter_firewall, options.as_object_mut()) {
                m.insert("enable".into(), json!(i64::from(on)));
            }
            ok(options)
        }
        ("GET", ["nodes", n, "status"]) if *n == node => ok(data("node_status")),
        ("GET", ["nodes", n, "storage"]) if *n == node => {
            let mut list = data("storage");
            for st in list.as_array_mut().into_iter().flatten() {
                let name = st["storage"].as_str().unwrap_or_default().to_string();
                if let Some((kind, avail, total)) = s.storage.get(&name) {
                    st["type"] = json!(kind);
                    st["avail"] = json!(avail);
                    st["total"] = json!(total);
                    st["used"] = json!(total.saturating_sub(*avail));
                }
            }
            ok(list)
        }
        ("GET", ["nodes", n, kind @ ("lxc" | "qemu")]) if *n == node => {
            let mut list = data(kind);
            for ((k, vmid), g) in &s.guests {
                if let (true, Some((name, running))) = (k == kind, &g.made) {
                    let status = if *running { "running" } else { "stopped" };
                    list.as_array_mut()
                        .into_iter()
                        .for_each(|l| l.push(json!({ "vmid": vmid, "name": name, "status": status })));
                }
            }
            ok(list)
        }
        ("POST", ["nodes", n, "lxc"]) if *n == node => {
            let f: BTreeMap<String, String> = form(&req.body).into_iter().collect();
            let vmid = f.get("vmid").and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
            let config = f.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
            let g = Guest {
                config,
                made: Some((f.get("hostname").cloned().unwrap_or_default(), false)),
                ..Guest::default()
            };
            s.guests.insert(("lxc".to_string(), vmid), g);
            ok(json!("UPID:sim:create"))
        }
        ("POST", ["nodes", n, "qemu", vmid, "clone"]) if *n == node => {
            let f: BTreeMap<String, String> = form(&req.body).into_iter().collect();
            let source =
                s.guests.get(&("qemu".to_string(), vmid.parse::<u32>().unwrap_or(0))).map(|g| g.config.clone());
            let newid = f.get("newid").and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
            let g = Guest {
                config: source.unwrap_or_default(),
                made: Some((f.get("name").cloned().unwrap_or_default(), false)),
                ..Guest::default()
            };
            s.guests.insert(("qemu".to_string(), newid), g);
            ok(json!("UPID:sim:clone"))
        }
        ("POST", ["nodes", n, kind @ ("lxc" | "qemu"), vmid, "status", action]) if *n == node => {
            let key = (kind.to_string(), vmid.parse::<u32>().unwrap_or(0));
            if let Some((_, running)) = s.guests.get_mut(&key).and_then(|g| g.made.as_mut()) {
                *running = *action == "start" || *action == "reboot";
            }
            ok(json!(format!("UPID:sim:{action}")))
        }
        ("GET", ["nodes", n, kind, _, "status", "current"]) if *n == node => ok(data(&format!("{kind}_status"))),
        ("GET", ["nodes", n, "tasks", upid, "status"]) if *n == node => {
            let upid = url::form_urlencoded::parse(format!("u={upid}").as_bytes()).next().map(|(_, v)| v.into_owned());
            let upid = upid.unwrap_or_default();
            if upid.starts_with("UPID:sim:") {
                return ok(json!({ "status": "stopped", "exitstatus": "OK", "upid": upid }));
            }
            let task = ["snapshot_create", "snapshot_rollback", "snapshot_delete", "failed_delete"]
                .into_iter()
                .find(|t| data(t).as_str() == Some(upid.as_str()))
                .map(|t| data(&format!("{t}_task")));
            match task {
                Some(t) => ok(t),
                None => ("500 Internal Server Error", json!({ "data": null, "message": "no such task" }).to_string()),
            }
        }
        ("POST", ["nodes", n, kind @ ("lxc" | "qemu"), vmid, "snapshot"]) if *n == node => {
            let name = form(&req.body).into_iter().find(|(k, _)| k == "snapname").map(|(_, v)| v);
            let key = (kind.to_string(), vmid.parse::<u32>().unwrap_or(0));
            if let (Some(g), Some(name)) = (s.guests.get_mut(&key), name) {
                let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
                g.snapshots.push(json!({ "name": name, "snaptime": at, "description": "" }));
            }
            ok(data("snapshot_create"))
        }
        ("POST", ["nodes", n, "lxc" | "qemu", _, "snapshot", _, "rollback"]) if *n == node => {
            ok(data("snapshot_rollback"))
        }
        ("DELETE", ["nodes", n, kind @ ("lxc" | "qemu"), vmid, "snapshot", name]) if *n == node => {
            let key = (kind.to_string(), vmid.parse::<u32>().unwrap_or(0));
            if let Some(g) = s.guests.get_mut(&key) {
                g.snapshots.retain(|x| x["name"] != *name);
            }
            ok(if *name == "rackhand-missing" { data("failed_delete") } else { data("snapshot_delete") })
        }
        (method, ["nodes", n, kind, vmid, tail @ ..]) if *n == node => {
            let key = (kind.to_string(), vmid.parse::<u32>().unwrap_or(0));
            let Some(g) = s.guests.get_mut(&key) else { return ("404 Not Found", "{}".into()) };
            match (method, tail) {
                ("GET", ["config"]) if g.broken => {
                    ("500 Internal Server Error", json!({ "data": null, "message": "config unreadable" }).to_string())
                }
                ("GET", ["config"]) => ok(Value::Object(g.config.clone())),
                ("GET", ["snapshot"]) => {
                    let mut list = g.snapshots.clone();
                    list.push(json!({ "name": "current", "description": "You are here!", "running": 1 }));
                    ok(Value::Array(list))
                }
                ("PUT", ["config"]) => {
                    for (k, v) in form(&req.body) {
                        g.config.insert(k, Value::String(v));
                    }
                    ok(Value::Null)
                }
                ("GET", ["firewall", "options"]) => ok(Value::Object(g.options.clone())),
                ("PUT", ["firewall", "options"]) => {
                    for (k, v) in form(&req.body) {
                        if k == "delete" {
                            for d in v.split(',') {
                                g.options.remove(d);
                            }
                        } else {
                            let v = v.parse::<i64>().map(Value::from).unwrap_or(Value::String(v));
                            g.options.insert(k, v);
                        }
                    }
                    ok(Value::Null)
                }
                ("GET", ["firewall", "rules"]) => {
                    let rules = g.rules.iter().enumerate().map(|(i, r)| {
                        let mut r = r.clone();
                        r["pos"] = json!(i);
                        r
                    });
                    ok(Value::Array(rules.collect()))
                }
                ("POST", ["firewall", "rules"]) => {
                    let mut rule = Map::new();
                    let mut pos = 0usize;
                    for (k, v) in form(&req.body) {
                        if k == "pos" {
                            pos = v.parse().unwrap_or(0);
                        } else {
                            // the API gives `enable` as a number and every other field (ports too) as text
                            let number = if k == "enable" { v.parse::<i64>().ok() } else { None };
                            rule.insert(k, number.map_or(Value::String(v), Value::from));
                        }
                    }
                    let at = pos.min(g.rules.len());
                    g.rules.insert(at, Value::Object(rule));
                    ok(Value::Null)
                }
                ("DELETE", ["firewall", "rules", pos]) => {
                    let pos: usize = pos.parse().unwrap_or(usize::MAX);
                    if pos < g.rules.len() {
                        g.rules.remove(pos);
                    }
                    ok(Value::Null)
                }
                _ => ("501 Not Implemented", "{\"data\":null}".into()),
            }
        }
        _ => ("501 Not Implemented", "{\"data\":null}".into()),
    }
}
