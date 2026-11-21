//! The SNMP driver (FR-10, 7.4.2): v2c, or v3 with authPriv (HMAC-SHA-96 and AES-128), read only. The client sends
//! GET and GET-NEXT and nothing else: it has no write operation. Target `<host>[:161]`. Settings: `version` (`2c` or
//! `3`); for 2c `community`; for 3 `user`, `auth` (`sha`), `auth_password`, `priv` (`aes`), `priv_password`; `oids`,
//! more OIDs to read.
//!
//! Series: `snmp.sysuptime_s`; `snmp.if_in_octets`, `snmp.if_out_octets` and `snmp.if_oper_up` (`ifOperStatus` 1)
//! labelled `ifName` (`ifDescr` where there is no `ifName`); `snmp.oid` labelled `oid`, for each configured OID.

pub mod ber;
#[cfg(any(test, feature = "sim"))]
pub mod sim;
pub mod usm;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::driver::{Driver, DriverError, DriverKind, DriverReading, DriverTarget, Point, settings, text};
use ber::{Pdu, Value};

const SETTINGS: &[&str] = &["version", "community", "user", "auth", "auth_password", "priv", "priv_password", "oids"];
const SYS_UPTIME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
const IF_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 2];
const IF_OPER: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 8];
const IF_IN: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 10];
const IF_OUT: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 16];
const IF_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1];
/// The most rows one walk reads.
const MAX_ROWS: usize = 4096;

#[derive(Debug, Default)]
pub struct Snmp;

impl Snmp {
    pub fn new() -> Snmp {
        Snmp
    }
}

enum Security {
    Community(String),
    V3 { user: String, auth_password: String, priv_password: String },
}

/// The agent's engine, learnt by discovery, with the keys localized to it.
struct Engine {
    id: Vec<u8>,
    boots: u32,
    time: u32,
    at: Instant,
    auth: [u8; 20],
    privacy: [u8; 20],
}

struct Session {
    sock: tokio::net::UdpSocket,
    security: Security,
    engine: Option<Engine>,
    next_id: i64,
    timeout: Duration,
}

impl Session {
    async fn exchange(&self, msg: &[u8], id_of: impl Fn(&[u8]) -> Option<i64>, want: i64) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 65_535];
        for _ in 0..2 {
            self.sock.send(msg).await.map_err(|e| e.to_string())?;
            let deadline = tokio::time::Instant::now() + self.timeout / 2;
            while let Ok(got) = tokio::time::timeout_at(deadline, self.sock.recv(&mut buf)).await {
                let n = got.map_err(|e| e.to_string())?;
                if id_of(&buf[..n]) == Some(want) {
                    return Ok(buf[..n].to_vec());
                }
            }
        }
        Err("no answer from the agent".into())
    }

    /// v3 discovery: an unauthenticated request the agent answers with a Report naming its engine.
    async fn discover(&mut self) -> Result<(), String> {
        let Security::V3 { auth_password, priv_password, .. } = &self.security else { return Ok(()) };
        self.next_id += 1;
        let id = self.next_id;
        let probe = Pdu { kind: ber::GET, request_id: id, error_status: 0, varbinds: vec![] };
        let msg = usm::message(id, usm::REPORTABLE, &usm::Params::default(), &usm::scoped(&[], &probe));
        let answer = self.exchange(&msg, |m| usm::parse(m).ok().map(|p| p.msg_id), id).await?;
        let p = usm::parse(&answer)?;
        if p.params.engine.is_empty() {
            return Err("the agent named no engine".into());
        }
        let auth = usm::localized_key(auth_password, &p.params.engine);
        let privacy = usm::localized_key(priv_password, &p.params.engine);
        self.engine = Some(Engine {
            id: p.params.engine,
            boots: p.params.boots,
            time: p.params.time,
            at: Instant::now(),
            auth,
            privacy,
        });
        Ok(())
    }

    async fn request(&mut self, kind: u8, oid: &[u32]) -> Result<(Vec<u32>, Value), String> {
        self.next_id += 1;
        let id = self.next_id;
        let pdu = Pdu { kind, request_id: id, error_status: 0, varbinds: vec![(oid.to_vec(), Value::Null)] };
        let answer = match &self.security {
            Security::Community(c) => {
                let msg = ber::seq(&[ber::int(1), ber::octets(c.as_bytes()), ber::pdu(&pdu)]);
                let raw = self.exchange(&msg, |m| v2c_response(m).ok().map(|p| p.request_id), id).await?;
                v2c_response(&raw)?
            }
            Security::V3 { user, .. } => {
                let e = self.engine.as_ref().ok_or("no engine yet")?;
                let time = e.time + e.at.elapsed().as_secs() as u32;
                let mut salt = [0u8; 8];
                getrandom::fill(&mut salt).map_err(|err| err.to_string())?;
                let encrypted = usm::aes_cfb(&e.privacy, e.boots, time, &salt, &usm::scoped(&e.id, &pdu), false);
                let params = usm::Params {
                    engine: e.id.clone(),
                    boots: e.boots,
                    time,
                    user: user.clone(),
                    auth: vec![],
                    salt: salt.to_vec(),
                };
                let flags = usm::AUTH | usm::PRIV | usm::REPORTABLE;
                let msg = usm::signed(id, flags, &params, &ber::octets(&encrypted), &e.auth);
                let raw = self.exchange(&msg, |m| usm::parse(m).ok().map(|p| p.msg_id), id).await?;
                let p = usm::parse(&raw)?;
                if !usm::authentic(&raw, &p, &e.auth) {
                    return Err("the answer isn't authenticated with our key".into());
                }
                let salt: [u8; 8] = p.params.salt.as_slice().try_into().map_err(|_| "no privacy salt")?;
                let plain = usm::aes_cfb(&e.privacy, p.params.boots, p.params.time, &salt, &p.data, true);
                usm::parse_scoped(&plain)?
            }
        };
        if answer.kind == ber::REPORT {
            return Err("the agent refused the request (a report)".into());
        }
        if answer.error_status != 0 {
            return Err(format!("error status {}", answer.error_status));
        }
        answer.varbinds.into_iter().next().ok_or_else(|| "an empty answer".to_string())
    }

    async fn get(&mut self, oid: &[u32]) -> Result<Option<Value>, String> {
        let (_, v) = self.request(ber::GET, oid).await?;
        Ok(if matches!(v, Value::Missing(_)) { None } else { Some(v) })
    }

    /// Every row under `base`, by the last part of its OID (the interface index).
    async fn walk(&mut self, base: &[u32]) -> Result<BTreeMap<u32, Value>, String> {
        let mut out = BTreeMap::new();
        let mut at = base.to_vec();
        while out.len() < MAX_ROWS {
            let (oid, v) = self.request(ber::GET_NEXT, &at).await?;
            if !oid.starts_with(base) || oid.len() <= base.len() || matches!(v, Value::Missing(_)) || oid <= at {
                break;
            }
            out.insert(*oid.last().unwrap_or(&0), v);
            at = oid;
        }
        Ok(out)
    }
}

fn v2c_response(msg: &[u8]) -> Result<Pdu, String> {
    let mut outer = ber::Reader::new(msg);
    let mut m = ber::Reader::new(outer.expect(ber::SEQUENCE)?);
    let _version = m.int()?;
    let _community = m.octets()?;
    let (kind, pdu) = m.next_tlv()?;
    ber::parse_pdu(kind, pdu)
}

fn security(s: Option<&serde_json::Map<String, serde_json::Value>>) -> Result<Security, DriverError> {
    let need = |k: &str| -> Result<String, DriverError> {
        Ok(text(s, k)?.ok_or_else(|| DriverError::Invalid(format!("`{k}`")))?.to_string())
    };
    match text(s, "version")?.unwrap_or("2c") {
        "2c" => Ok(Security::Community(need("community")?)),
        "3" => {
            if text(s, "auth")?.unwrap_or("sha") != "sha" || text(s, "priv")?.unwrap_or("aes") != "aes" {
                return Err(DriverError::Invalid("v3 is auth sha with priv aes (authPriv)".into()));
            }
            let (auth_password, priv_password) = (need("auth_password")?, need("priv_password")?);
            if auth_password.len() < 8 || priv_password.len() < 8 {
                return Err(DriverError::Invalid("v3 passwords are at least 8 characters".into()));
            }
            Ok(Security::V3 { user: need("user")?, auth_password, priv_password })
        }
        other => Err(DriverError::Invalid(format!("version 2c or 3, not {other}"))),
    }
}

fn label_of(v: &Value) -> Option<String> {
    match v {
        Value::Bytes(b) => Some(String::from_utf8_lossy(b).trim_end_matches('\0').to_string()),
        _ => None,
    }
}

async fn read(sess: &mut Session, extra: &[Vec<u32>]) -> Result<Vec<Point>, String> {
    sess.discover().await?;
    let mut out = Vec::new();
    if let Some(Value::Unsigned(_, ticks)) = sess.get(SYS_UPTIME).await? {
        out.push(Point::new("snmp.sysuptime_s", &[], ticks as f64 / 100.0));
    }
    let mut names = sess.walk(IF_NAME).await?;
    if names.is_empty() {
        names = sess.walk(IF_DESCR).await?;
    }
    let (inn, outt, oper) = (sess.walk(IF_IN).await?, sess.walk(IF_OUT).await?, sess.walk(IF_OPER).await?);
    for (index, name) in &names {
        let Some(name) = label_of(name) else { continue };
        let l = [("ifName", name.as_str())];
        if let Some(v) = inn.get(index).and_then(Value::number) {
            out.push(Point::new("snmp.if_in_octets", &l, v));
        }
        if let Some(v) = outt.get(index).and_then(Value::number) {
            out.push(Point::new("snmp.if_out_octets", &l, v));
        }
        if let Some(v) = oper.get(index).and_then(Value::number) {
            out.push(Point::new("snmp.if_oper_up", &l, if v == 1.0 { 1.0 } else { 0.0 }));
        }
    }
    for oid in extra {
        if let Some(v) = sess.get(oid).await?.as_ref().and_then(Value::number) {
            let name = ber::dotted(oid);
            out.push(Point::new("snmp.oid", &[("oid", name.as_str())], v));
        }
    }
    Ok(out)
}

#[async_trait::async_trait]
impl Driver for Snmp {
    fn kind(&self) -> DriverKind {
        DriverKind::Snmp
    }

    fn known_settings(&self) -> &'static [&'static str] {
        SETTINGS
    }

    async fn poll(&self, target: &DriverTarget) -> Result<DriverReading, DriverError> {
        let s = settings(&target.settings, SETTINGS)?;
        let security = security(s)?;
        let extra: Vec<Vec<u32>> = match s.and_then(|m| m.get("oids")) {
            None => Vec::new(),
            Some(serde_json::Value::Array(list)) => list
                .iter()
                .map(|o| {
                    o.as_str().and_then(ber::from_dotted).ok_or_else(|| DriverError::Invalid(format!("an OID: {o}")))
                })
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(DriverError::Invalid("`oids` is a list".into())),
        };
        let addr = if target.target.contains(':') && !target.target.starts_with('[') {
            target.target.clone()
        } else {
            format!("{}:161", target.target)
        };
        let started = Instant::now();
        let agent = match crate::driver::resolve(&addr).await {
            Ok(a) => a,
            Err(e) => return Ok(DriverReading::down(e, vec![])),
        };
        let bind = if agent.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let sock = tokio::net::UdpSocket::bind(bind).await.map_err(|e| DriverError::Failed(e.to_string()))?;
        sock.connect(agent).await.map_err(|e| DriverError::Failed(e.to_string()))?;
        let mut sess =
            Session { sock, security, engine: None, next_id: 0, timeout: target.timeout.min(Duration::from_secs(5)) };
        match tokio::time::timeout(target.timeout * 4, read(&mut sess, &extra)).await {
            Ok(Ok(points)) => {
                let mut r =
                    DriverReading::up(crate::driver::millis(started), format!("{} readings", points.len()), vec![]);
                r.points = points;
                Ok(r)
            }
            Ok(Err(e)) => Ok(DriverReading::down(e, vec![])),
            Err(_) => Ok(DriverReading::down("no answer in time", vec![])),
        }
    }
}

#[cfg(test)]
mod tests;
