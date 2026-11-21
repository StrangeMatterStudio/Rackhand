//! The `Driver` trait (7.3.8) and what a poll reads. A check that runs and finds the service down is a reading with
//! `ok: false`; an error is for a check that couldn't run as configured.

use std::time::Duration;

use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DriverKind {
    Icmp,
    Tcp,
    Http,
    Dns,
    Tls,
    Proxmox,
    Truenas,
    Redfish,
    Snmp,
}

impl DriverKind {
    pub const ALL: [DriverKind; 9] = [
        DriverKind::Icmp,
        DriverKind::Tcp,
        DriverKind::Http,
        DriverKind::Dns,
        DriverKind::Tls,
        DriverKind::Proxmox,
        DriverKind::Truenas,
        DriverKind::Redfish,
        DriverKind::Snmp,
    ];

    pub fn name(self) -> &'static str {
        match self {
            DriverKind::Icmp => "icmp",
            DriverKind::Tcp => "tcp",
            DriverKind::Http => "http",
            DriverKind::Dns => "dns",
            DriverKind::Tls => "tls",
            DriverKind::Proxmox => "proxmox",
            DriverKind::Truenas => "truenas",
            DriverKind::Redfish => "redfish",
            DriverKind::Snmp => "snmp",
        }
    }

    pub fn parse(name: &str) -> Option<DriverKind> {
        DriverKind::ALL.into_iter().find(|k| k.name() == name)
    }
}

/// What to poll: an address (`host:port`, a URL or a host name, by kind), the check's settings and how long to wait.
#[derive(Debug, Clone, PartialEq)]
pub struct DriverTarget {
    pub target: String,
    pub settings: Value,
    pub timeout: Duration,
}

/// One poll's result: whether the check passed, how long it took, what was seen, and the readings as series
/// (`check.up`, `check.latency_ms`, `check.status_code`, `check.cert_days`).
#[derive(Debug, Clone, PartialEq)]
pub struct DriverReading {
    pub ok: bool,
    pub latency_ms: Option<f64>,
    pub detail: String,
    pub metrics: Vec<(String, f64)>,
}

impl DriverReading {
    pub fn up(latency_ms: f64, detail: impl Into<String>, mut metrics: Vec<(String, f64)>) -> DriverReading {
        metrics.insert(0, ("check.up".into(), 1.0));
        metrics.insert(1, ("check.latency_ms".into(), latency_ms));
        DriverReading { ok: true, latency_ms: Some(latency_ms), detail: detail.into(), metrics }
    }

    pub fn down(detail: impl Into<String>, mut metrics: Vec<(String, f64)>) -> DriverReading {
        metrics.insert(0, ("check.up".into(), 0.0));
        DriverReading { ok: false, latency_ms: None, detail: detail.into(), metrics }
    }

    /// The same reading, failed for `why` (the check answered, but not as expected).
    pub fn failed(mut self, why: impl Into<String>) -> DriverReading {
        self.ok = false;
        self.detail = why.into();
        if let Some(up) = self.metrics.iter_mut().find(|(n, _)| n == "check.up") {
            up.1 = 0.0;
        }
        self
    }
}

/// An operation on a managed system (snapshot, rollback, firewall rule, ...), for the API drivers.
#[derive(Debug, Clone, PartialEq)]
pub struct DriverOp {
    pub name: String,
    pub args: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DriverOpResult {
    pub output: Value,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum DriverError {
    #[error("check settings: {0}")]
    Invalid(String),
    #[error("the {0} driver has no operations")]
    Unsupported(&'static str),
    #[error("{0}")]
    Failed(String),
}

#[async_trait::async_trait]
pub trait Driver: Send + Sync {
    fn kind(&self) -> DriverKind;

    async fn poll(&self, target: &DriverTarget) -> Result<DriverReading, DriverError>;

    async fn call(&self, _target: &DriverTarget, _op: DriverOp) -> Result<DriverOpResult, DriverError> {
        Err(DriverError::Unsupported(self.kind().name()))
    }
}

/// The settings object, refusing keys the driver doesn't know (a typo shouldn't silently check something else).
pub(crate) fn settings<'a>(v: &'a Value, allowed: &[&str]) -> Result<Option<&'a Map<String, Value>>, DriverError> {
    let map = match v {
        Value::Null => return Ok(None),
        Value::Object(m) => m,
        _ => return Err(DriverError::Invalid("settings are a table".into())),
    };
    if let Some(k) = map.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(DriverError::Invalid(format!("unknown setting `{k}` (known: {})", allowed.join(", "))));
    }
    Ok(Some(map))
}

pub(crate) fn text<'a>(map: Option<&'a Map<String, Value>>, key: &str) -> Result<Option<&'a str>, DriverError> {
    match map.and_then(|m| m.get(key)) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(DriverError::Invalid(format!("`{key}` is a string"))),
    }
}

pub(crate) fn millis(since: std::time::Instant) -> f64 {
    (since.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0
}

/// The address of `host:port`, resolved (the first answer).
pub(crate) async fn resolve(addr: &str) -> Result<std::net::SocketAddr, String> {
    tokio::net::lookup_host(addr)
        .await
        .map_err(|e| format!("{addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("{addr}: no address"))
}
