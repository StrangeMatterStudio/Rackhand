//! The Redfish driver (FR-10, 7.4.2): each system's power state and health rollup, and each chassis's temperature and
//! fan readings and power supplies' status, read with GETs only, following the service's links from `/redfish/v1`
//! (the `Thermal` and `Power` resources). Target `https://<bmc>[:port]`; settings `username`, `password` (Basic
//! authentication) and `fingerprint` (the BMC certificate's SHA-256, pinned).
//!
//! Series, labelled `sensor`: `redfish.power_on` and `redfish.health` (0 OK, 1 Warning, 2 Critical) per system id;
//! `redfish.temp_c` and `redfish.fan_rpm` per sensor name (an absent sensor has none); `redfish.psu_ok` per supply.

#[cfg(any(test, feature = "sim"))]
pub mod sim;

use base64::Engine;
use serde_json::Value;

use crate::driver::{Driver, DriverError, DriverKind, DriverReading, DriverTarget, Point, settings, text};

const SETTINGS: &[&str] = &["username", "password", "fingerprint"];
/// The most links followed in one poll (systems and chassis), so a misbehaving service can't keep it going.
const MAX_RESOURCES: usize = 64;

#[derive(Debug, Default)]
pub struct Redfish;

impl Redfish {
    pub fn new() -> Redfish {
        Redfish
    }
}

struct Conn {
    host: String,
    port: u16,
    auth: String,
    tls: tokio_rustls::TlsConnector,
}

impl Conn {
    async fn get(&self, path: &str) -> Result<Value, String> {
        use http_body_util::{BodyExt, Empty, Limited};
        use hyper::body::Bytes;
        let s = crate::pinned::connect(&self.tls, &self.host, self.port).await?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(hyper_util::rt::TokioIo::new(s))
                .await
                .map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        let req = hyper::Request::get(path)
            .header(hyper::header::HOST, &self.host)
            .header(hyper::header::AUTHORIZATION, &self.auth)
            .header(hyper::header::ACCEPT, "application/json")
            .body(Empty::new())
            .map_err(|e| e.to_string())?;
        let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let bytes = Limited::new(resp.into_body(), 4 << 20).collect().await.map_err(|e| e.to_string())?.to_bytes();
        if status != 200 {
            return Err(format!("GET {path}: {status}"));
        }
        serde_json::from_slice(&bytes).map_err(|e| format!("GET {path}: {e}"))
    }

    /// The members of a collection the resource `v` links to under `field`.
    async fn members(&self, v: &Value, field: &str) -> Result<Vec<String>, String> {
        let Some(link) = v[field]["@odata.id"].as_str() else { return Ok(Vec::new()) };
        let list = self.get(link).await?;
        Ok(list["Members"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|m| m["@odata.id"].as_str().map(str::to_string))
            .take(MAX_RESOURCES)
            .collect())
    }
}

fn health(v: &Value) -> Option<f64> {
    match v.as_str()? {
        "OK" => Some(0.0),
        "Warning" => Some(1.0),
        "Critical" => Some(2.0),
        _ => None,
    }
}

fn present(v: &Value) -> bool {
    !matches!(v["Status"]["State"].as_str(), Some("Absent" | "Disabled"))
}

async fn read(c: &Conn) -> Result<Vec<Point>, String> {
    let mut out = Vec::new();
    let root = c.get("/redfish/v1").await?;
    for path in c.members(&root, "Systems").await? {
        let s = c.get(&path).await?;
        let id = s["Id"].as_str().unwrap_or(&path).to_string();
        let l = [("sensor", id.as_str())];
        if let Some(state) = s["PowerState"].as_str() {
            out.push(Point::new("redfish.power_on", &l, if state == "On" { 1.0 } else { 0.0 }));
        }
        let rollup = s["Status"]["HealthRollup"].clone();
        if let Some(h) = health(&rollup).or_else(|| health(&s["Status"]["Health"])) {
            out.push(Point::new("redfish.health", &l, h));
        }
    }
    for path in c.members(&root, "Chassis").await? {
        let chassis = c.get(&path).await?;
        if let Some(thermal) = chassis["Thermal"]["@odata.id"].as_str() {
            let t = c.get(thermal).await?;
            for s in t["Temperatures"].as_array().into_iter().flatten().filter(|s| present(s)) {
                if let (Some(name), Some(v)) = (s["Name"].as_str(), s["ReadingCelsius"].as_f64()) {
                    out.push(Point::new("redfish.temp_c", &[("sensor", name)], v));
                }
            }
            for f in t["Fans"].as_array().into_iter().flatten().filter(|f| present(f)) {
                let name = f["Name"].as_str().or_else(|| f["FanName"].as_str());
                if let (Some(name), Some(v)) = (name, f["Reading"].as_f64()) {
                    out.push(Point::new("redfish.fan_rpm", &[("sensor", name)], v));
                }
            }
        }
        if let Some(power) = chassis["Power"]["@odata.id"].as_str() {
            let p = c.get(power).await?;
            for s in p["PowerSupplies"].as_array().into_iter().flatten().filter(|s| present(s)) {
                if let Some(name) = s["Name"].as_str() {
                    let ok = if s["Status"]["Health"].as_str() == Some("OK") { 1.0 } else { 0.0 };
                    out.push(Point::new("redfish.psu_ok", &[("sensor", name)], ok));
                }
            }
        }
    }
    Ok(out)
}

#[async_trait::async_trait]
impl Driver for Redfish {
    fn kind(&self) -> DriverKind {
        DriverKind::Redfish
    }

    fn known_settings(&self) -> &'static [&'static str] {
        SETTINGS
    }

    async fn poll(&self, target: &DriverTarget) -> Result<DriverReading, DriverError> {
        let s = settings(&target.settings, SETTINGS)?;
        let user = text(s, "username")?.ok_or_else(|| DriverError::Invalid("the BMC account (`username`)".into()))?;
        let password = text(s, "password")?.unwrap_or("");
        let tls = crate::pinned::connector(text(s, "fingerprint")?)?;
        let raw =
            if target.target.contains("://") { target.target.clone() } else { format!("https://{}", target.target) };
        let url = url::Url::parse(&raw).map_err(|e| DriverError::Invalid(format!("the address: {e}")))?;
        let host = url.host_str().ok_or_else(|| DriverError::Invalid("the address has no host".into()))?.to_string();
        let auth = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}")));
        let c = Conn { port: url.port().unwrap_or(443), host, auth, tls };
        let started = std::time::Instant::now();
        match tokio::time::timeout(target.timeout, read(&c)).await {
            Ok(Ok(points)) => {
                let mut r =
                    DriverReading::up(crate::driver::millis(started), format!("{} readings", points.len()), vec![]);
                r.points = points;
                Ok(r)
            }
            Ok(Err(e)) => Ok(DriverReading::down(e, vec![])),
            Err(_) => Ok(DriverReading::down(format!("no answer within {:?}", target.timeout), vec![])),
        }
    }
}

#[cfg(test)]
mod tests;
