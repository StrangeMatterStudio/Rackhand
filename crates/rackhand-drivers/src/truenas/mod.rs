//! The TrueNAS driver (FR-10, 7.4.2, S9): pool health and use, disk temperatures, SMART status and alerts, read with an
//! API key over JSON-RPC 2.0 on the WebSocket at `/api/current`, or REST at `/api/v2.0` on a release without it.
//! Target `https://<host>[:port]`; settings `api_key` and `fingerprint` (the certificate's SHA-256, pinned).
//!
//! Series: `truenas.pool.healthy`, `.total_bytes`, `.used_bytes`, `.used_pct` (label `pool`); `truenas.disk.temp_c`
//! (a disk without a reading has none) and `truenas.disk.smart_ok` (its latest SMART test passed; label `disk`);
//! `truenas.alerts.critical` and `.warning`, the alerts not dismissed.

#[cfg(any(test, feature = "sim"))]
pub mod sim;

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::driver::{Driver, DriverError, DriverKind, DriverReading, DriverTarget, Point, settings, text};

const SETTINGS: &[&str] = &["api_key", "fingerprint"];
/// The reads, as JSON-RPC methods and their REST equivalents.
const READS: &[(&str, &str, &str)] = &[
    ("pool.query", "GET", "/api/v2.0/pool"),
    ("disk.query", "GET", "/api/v2.0/disk"),
    ("disk.temperatures", "POST", "/api/v2.0/disk/temperatures"),
    ("smart.test.results", "GET", "/api/v2.0/smart/test/results"),
    ("alert.list", "GET", "/api/v2.0/alert/list"),
];

#[derive(Debug, Default)]
pub struct TrueNas;

impl TrueNas {
    pub fn new() -> TrueNas {
        TrueNas
    }
}

struct Conn {
    host: String,
    port: u16,
    key: String,
    tls: tokio_rustls::TlsConnector,
}

/// Every read over the WebSocket: `Ok(None)` when the server has no `/api/current` (an older release).
async fn over_ws(c: &Conn) -> Result<Option<BTreeMap<&'static str, Value>>, String> {
    let mut s = crate::pinned::connect(&c.tls, &c.host, c.port).await?;
    if let Err(status) = crate::ws::connect(&mut s, &c.host, "/api/current").await {
        if status.contains(" 404 ") || status.contains(" 400 ") {
            return Ok(None);
        }
        return Err(format!("the WebSocket: {status}"));
    }
    let mut id = 0u64;
    let mut call = async |method: &str, params: Value| -> Result<Value, String> {
        id += 1;
        let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        crate::ws::send(&mut s, &req.to_string()).await?;
        loop {
            let answer: Value = serde_json::from_str(&crate::ws::recv(&mut s).await?).map_err(|e| e.to_string())?;
            if answer["id"].as_u64() != Some(id) {
                continue; // a notification
            }
            if let Some(e) = answer.get("error").filter(|e| !e.is_null()) {
                return Err(format!("{method}: {}", e["message"].as_str().unwrap_or("an error")));
            }
            return Ok(answer["result"].clone());
        }
    };
    if call("auth.login_with_api_key", json!([c.key])).await? != json!(true) {
        return Err("the API key was refused".into());
    }
    let mut out = BTreeMap::new();
    for (method, _, _) in READS {
        out.insert(*method, call(method, json!([])).await?);
    }
    Ok(Some(out))
}

/// Every read over REST.
async fn over_rest(c: &Conn) -> Result<BTreeMap<&'static str, Value>, String> {
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::body::Bytes;
    let mut out = BTreeMap::new();
    for (method, verb, path) in READS {
        let s = crate::pinned::connect(&c.tls, &c.host, c.port).await?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake::<_, Full<Bytes>>(hyper_util::rt::TokioIo::new(s))
                .await
                .map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        let body = if *verb == "POST" { Bytes::from_static(b"{}") } else { Bytes::new() };
        let req = hyper::Request::builder()
            .method(*verb)
            .uri(*path)
            .header(hyper::header::HOST, &c.host)
            .header(hyper::header::AUTHORIZATION, format!("Bearer {}", c.key))
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(body))
            .map_err(|e| e.to_string())?;
        let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let bytes = Limited::new(resp.into_body(), 16 << 20).collect().await.map_err(|e| e.to_string())?.to_bytes();
        if status != 200 {
            return Err(format!("{verb} {path}: {status}"));
        }
        out.insert(*method, serde_json::from_slice(&bytes).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn num(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

fn points(r: &BTreeMap<&'static str, Value>) -> Vec<Point> {
    let mut out = Vec::new();
    for pool in r["pool.query"].as_array().into_iter().flatten() {
        let Some(name) = pool["name"].as_str() else { continue };
        let l = [("pool", name)];
        out.push(Point::new("truenas.pool.healthy", &l, if pool["healthy"] == true { 1.0 } else { 0.0 }));
        if let (Some(size), Some(used)) = (num(&pool["size"]), num(&pool["allocated"])) {
            out.push(Point::new("truenas.pool.total_bytes", &l, size));
            out.push(Point::new("truenas.pool.used_bytes", &l, used));
            let pct = if size > 0.0 { (used / size * 10_000.0).round() / 100.0 } else { 0.0 };
            out.push(Point::new("truenas.pool.used_pct", &l, pct));
        }
    }
    for (disk, temp) in r["disk.temperatures"].as_object().into_iter().flatten() {
        if let Some(t) = num(temp).filter(|t| *t > 0.0) {
            out.push(Point::new("truenas.disk.temp_c", &[("disk", disk)], t));
        }
    }
    for d in r["smart.test.results"].as_array().into_iter().flatten() {
        let Some(disk) = d["disk"].as_str().or_else(|| d["name"].as_str()) else { continue };
        let latest = d["tests"].as_array().and_then(|t| t.iter().min_by_key(|t| t["num"].as_u64().unwrap_or(u64::MAX)));
        if let Some(t) = latest {
            let ok = if t["status"].as_str() == Some("SUCCESS") { 1.0 } else { 0.0 };
            out.push(Point::new("truenas.disk.smart_ok", &[("disk", disk)], ok));
        }
    }
    let open: Vec<&Value> =
        r["alert.list"].as_array().into_iter().flatten().filter(|a| a["dismissed"] != true).collect();
    let count = |level: &str| open.iter().filter(|a| a["level"].as_str() == Some(level)).count() as f64;
    out.push(Point::new("truenas.alerts.critical", &[], count("CRITICAL")));
    out.push(Point::new("truenas.alerts.warning", &[], count("WARNING")));
    out
}

#[async_trait::async_trait]
impl Driver for TrueNas {
    fn kind(&self) -> DriverKind {
        DriverKind::Truenas
    }

    fn known_settings(&self) -> &'static [&'static str] {
        SETTINGS
    }

    async fn poll(&self, target: &DriverTarget) -> Result<DriverReading, DriverError> {
        let s = settings(&target.settings, SETTINGS)?;
        let key =
            text(s, "api_key")?.ok_or_else(|| DriverError::Invalid("the API key (`api_key`)".into()))?.to_string();
        let tls = crate::pinned::connector(text(s, "fingerprint")?)?;
        let raw =
            if target.target.contains("://") { target.target.clone() } else { format!("https://{}", target.target) };
        let url = url::Url::parse(&raw).map_err(|e| DriverError::Invalid(format!("the address: {e}")))?;
        let host = url.host_str().ok_or_else(|| DriverError::Invalid("the address has no host".into()))?.to_string();
        let c = Conn { port: url.port().unwrap_or(443), host, key, tls };
        let started = std::time::Instant::now();
        let read = async {
            match over_ws(&c).await? {
                Some(r) => Ok::<_, String>((r, "JSON-RPC")),
                None => Ok((over_rest(&c).await?, "REST")),
            }
        };
        match tokio::time::timeout(target.timeout, read).await {
            Ok(Ok((r, api))) => {
                let mut reading = DriverReading::up(crate::driver::millis(started), format!("read over {api}"), vec![]);
                reading.points = points(&r);
                Ok(reading)
            }
            Ok(Err(e)) => Ok(DriverReading::down(e, vec![])),
            Err(_) => Ok(DriverReading::down(format!("no answer within {:?}", target.timeout), vec![])),
        }
    }
}

#[cfg(test)]
mod tests;
