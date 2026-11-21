//! The `rackhand/join/1` server (7.3.1): one request and one response on one bidirectional stream. The only ALPN that
//! serves unregistered ids, so every failed attempt counts against a limit per remote address.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::{EndpointId, TransportAddr};
use prost::Message;
use rackhand_proto::common::{Access, ProbeConfig, ProbeMode, RelayUrl, SemVer, SshHostKey};
use rackhand_proto::frame;
use rackhand_proto::join::join_request::Kind as Req;
use rackhand_proto::join::join_response::Kind as Resp;
use rackhand_proto::join::{
    DeviceJoin, DeviceJoined, JoinError, JoinFailed, JoinRequest, JoinResponse, MachineJoin, MachineJoined,
    ManagedSetup, OperatorJoin, OperatorJoined, PeerJoin, PeerJoined,
};
use rackhand_store::ids::now_ms;
use rackhand_store::{ConsumeToken, RegistryChange, Row, RowWrite, StoreError, TokenRefusal, WriteCmd};
use rusqlite::types::Value;
use tokio::sync::mpsc;
use ulid::Ulid;

use super::Registry;
use super::machines::{access_name, mode_name};
use super::peers::valid_site_name;
use super::tokens::{self, StoredToken, Token, TokenKind};

const RATE_WINDOW_MS: i64 = 60_000;
const MAX_FAILURES: usize = 10;
/// Addresses tracked at once; the one idle longest is dropped first.
const MAX_TRACKED: usize = 4096;

/// What the installer needs for the hub's accounts: the SSH system's keys and the signed command list (7.3.7).
pub trait ManagedSetupSource: Send + Sync {
    fn managed_setup(&self, machine_id: Ulid, with_assistant: bool) -> ManagedSetup;
}

/// This hub, as join responses describe it.
#[derive(Debug, Clone)]
pub struct HubInfo {
    pub site: String,
    pub version: String,
    pub relays: Vec<String>,
    pub hub_addrs: Vec<String>,
    pub probe_config: ProbeConfig,
}

/// A successful join, for the systems that act on it: SSH pins the host keys of a managed machine.
#[derive(Debug, Clone, PartialEq)]
pub struct Joined {
    pub kind: TokenKind,
    pub id: String,
    pub endpoint_id: EndpointId,
    pub ssh_host_keys: Vec<SshHostKey>,
}

#[derive(Debug)]
struct Failure {
    code: JoinError,
    message: String,
}

impl Failure {
    fn new(code: JoinError, message: impl Into<String>) -> Failure {
        Failure { code, message: message.into() }
    }
}

impl From<StoreError> for Failure {
    fn from(e: StoreError) -> Failure {
        match e {
            StoreError::TokenRefused(r) => match r {
                TokenRefusal::Unknown => Failure::new(JoinError::Invalid, "unknown token"),
                TokenRefusal::Used => Failure::new(JoinError::Used, "the token has been used"),
                TokenRefusal::Expired => Failure::new(JoinError::Expired, "the token has expired"),
                TokenRefusal::WrongKind => Failure::new(JoinError::WrongKind, "the token is for another kind of join"),
            },
            StoreError::Sqlite(rusqlite::Error::SqliteFailure(f, _))
                if f.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Failure::new(JoinError::Invalid, "already registered")
            }
            other => {
                tracing::error!(error = %other, "join failed in the store");
                Failure::new(JoinError::Invalid, "the hub couldn't record the join")
            }
        }
    }
}

impl From<rusqlite::Error> for Failure {
    fn from(e: rusqlite::Error) -> Failure {
        StoreError::Sqlite(e).into()
    }
}

/// Failed attempts per remote address in the last minute.
#[derive(Debug, Default)]
struct RateLimiter {
    failures: HashMap<String, VecDeque<i64>>,
}

impl RateLimiter {
    fn prune(list: &mut VecDeque<i64>, now_ms: i64) {
        while list.front().is_some_and(|t| *t <= now_ms - RATE_WINDOW_MS) {
            list.pop_front();
        }
    }

    fn limited(&mut self, key: &str, now_ms: i64) -> bool {
        self.failures.get_mut(key).is_some_and(|l| {
            Self::prune(l, now_ms);
            l.len() >= MAX_FAILURES
        })
    }

    fn record(&mut self, key: &str, now_ms: i64) {
        if self.failures.len() >= MAX_TRACKED && !self.failures.contains_key(key) {
            self.failures.retain(|_, l| {
                Self::prune(l, now_ms);
                !l.is_empty()
            });
            if self.failures.len() >= MAX_TRACKED {
                let idle = self.failures.iter().min_by_key(|(_, l)| l.back().copied()).map(|(k, _)| k.clone());
                if let Some(k) = idle {
                    self.failures.remove(&k);
                }
            }
        }
        self.failures.entry(key.to_string()).or_default().push_back(now_ms);
    }
}

pub struct JoinServer {
    registry: Arc<Registry>,
    setup: Arc<dyn ManagedSetupSource>,
    hub: HubInfo,
    limiter: Mutex<RateLimiter>,
    joined: mpsc::UnboundedSender<Joined>,
}

impl std::fmt::Debug for JoinServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinServer").field("site", &self.hub.site).finish()
    }
}

/// The key a remote address is counted under: the IP of a direct caller (any port), the relay of a relayed one.
pub fn remote_key(conn: &Connection) -> String {
    let paths = conn.paths();
    let selected = paths.iter().find(|p| p.is_selected()).map(|p| p.remote_addr().clone());
    match selected {
        Some(TransportAddr::Ip(addr)) => format!("ip:{}", addr.ip()),
        Some(TransportAddr::Relay(url)) => format!("relay:{url}"),
        _ => format!("id:{}", conn.remote_id()),
    }
}

impl JoinServer {
    pub fn new(
        registry: Arc<Registry>,
        setup: Arc<dyn ManagedSetupSource>,
        hub: HubInfo,
    ) -> (Arc<JoinServer>, mpsc::UnboundedReceiver<Joined>) {
        let (joined, rx) = mpsc::unbounded_channel();
        (Arc::new(JoinServer { registry, setup, hub, limiter: Mutex::new(RateLimiter::default()), joined }), rx)
    }

    /// Serves one connection: one request, one response.
    pub async fn serve(self: Arc<Self>, conn: Connection) {
        let key = remote_key(&conn);
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(remote = %key, error = %e, "join: no request stream");
                return;
            }
        };
        let data = match recv.read_to_end(frame::MAX_FRAME + 4).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(remote = %key, error = %e, "join: the request couldn't be read");
                return;
            }
        };
        let request = frame::read_frame(&mut data.as_slice()).ok().and_then(|b| JoinRequest::decode(b.as_slice()).ok());
        let response = match request {
            Some(req) => self.handle(req, conn.remote_id(), &key, now_ms()).await,
            None => self.refuse(&key, now_ms(), Failure::new(JoinError::Invalid, "malformed request")),
        };
        if let Ok(bytes) = frame::encode(&response) {
            let _ = send.write_all(&bytes).await;
            let _ = send.finish();
        }
        // Let the caller read the response before the connection goes.
        let _ = tokio::time::timeout(Duration::from_secs(10), conn.closed()).await;
    }

    /// Handles one request from `caller`, counted under `remote_key`.
    pub async fn handle(&self, req: JoinRequest, caller: EndpointId, remote_key: &str, now_ms: i64) -> JoinResponse {
        if self.limiter.lock().map(|mut l| l.limited(remote_key, now_ms)).unwrap_or(true) {
            return failed(Failure::new(JoinError::RateLimited, "too many failed joins; try again in a minute"));
        }
        let result = match req.kind {
            Some(Req::Machine(m)) => self.machine(m, caller, now_ms).await,
            Some(Req::Device(d)) => self.device(d, caller, now_ms).await,
            Some(Req::Operator(o)) => self.operator(o, caller, now_ms).await,
            Some(Req::Peer(p)) => self.peer(p, caller, now_ms).await,
            None => Err(Failure::new(JoinError::Unsupported, "unknown kind of join")),
        };
        match result {
            Ok(kind) => JoinResponse { kind: Some(kind) },
            Err(f) => self.refuse(remote_key, now_ms, f),
        }
    }

    fn refuse(&self, remote_key: &str, now_ms: i64, f: Failure) -> JoinResponse {
        if let Ok(mut l) = self.limiter.lock() {
            l.record(remote_key, now_ms);
        }
        failed(f)
    }

    /// The stored token, if it exists, is of `kind`, unused and unexpired. The writer checks again as it uses it up.
    fn check(&self, token: &Token, kind: TokenKind, now_ms: i64) -> Result<StoredToken, Failure> {
        let stored = tokens::find(self.registry.db().readers(), token)?
            .ok_or_else(|| Failure::new(JoinError::Invalid, "unknown token"))?;
        if stored.kind != kind.as_str() {
            return Err(TokenRefusal::WrongKind.into_failure());
        }
        if stored.used_at.is_some() {
            return Err(TokenRefusal::Used.into_failure());
        }
        if stored.expires_at <= now_ms {
            return Err(TokenRefusal::Expired.into_failure());
        }
        Ok(stored)
    }

    async fn commit(
        &self,
        token: &Token,
        kind: TokenKind,
        now_ms: i64,
        mut change: RegistryChange,
    ) -> Result<(), Failure> {
        change.consume = Some(ConsumeToken { hash: tokens::hash(token).to_vec(), kind: kind.as_str().into(), now_ms });
        self.registry.db().writer().send(WriteCmd::RegistryChange(change)).await?;
        Ok(())
    }

    fn announce(&self, kind: TokenKind, id: &str, caller: EndpointId, ssh_host_keys: Vec<SshHostKey>) {
        self.registry.allow(kind, caller);
        let _ = self.joined.send(Joined { kind, id: id.into(), endpoint_id: caller, ssh_host_keys });
    }

    async fn machine(&self, m: MachineJoin, caller: EndpointId, now_ms: i64) -> Result<Resp, Failure> {
        let token = Token::parse(&m.token);
        let stored = self.check(&token, TokenKind::Machine, now_ms)?;
        let access = Access::try_from(m.access).ok().and_then(access_name);
        if access.is_none() || access != stored.bound.access.as_deref() {
            return Err(Failure::new(JoinError::Invalid, "the access level doesn't match the token"));
        }
        let access = access.unwrap_or_default();
        let mode = ProbeMode::try_from(m.mode)
            .ok()
            .and_then(mode_name)
            .ok_or_else(|| Failure::new(JoinError::Invalid, "probe mode"))?;
        let machine_id = stored
            .bound
            .machine_id
            .clone()
            .ok_or_else(|| Failure::new(JoinError::Invalid, "token without a machine"))?;
        let ulid: Ulid = machine_id.parse().map_err(|_| Failure::new(JoinError::Invalid, "token without a machine"))?;
        let previous = self.registry.machine_endpoint(&machine_id)?;
        let facts = m.facts.unwrap_or_default();
        let os = format!("{} {}", facts.os_name, facts.os_version).trim().to_string();
        let update = Registry::enroll_change(&machine_id, caller, access, mode, &os, previous.is_none(), now_ms);
        self.commit(&token, TokenKind::Machine, now_ms, RegistryChange { updates: vec![update], ..Default::default() })
            .await?;
        if let Some(old) = previous.filter(|p| *p != caller.to_string()).and_then(|p| p.parse::<EndpointId>().ok()) {
            self.registry.revoke(old);
        }
        let managed = access == "managed";
        // The hub role comes from the dashboard, not from what the machine reports (D62).
        let with_assistant = !stored.bound.roles.iter().any(|r| r == "hub");
        let setup = managed.then(|| self.setup.managed_setup(ulid, with_assistant));
        self.announce(TokenKind::Machine, &machine_id, caller, if managed { m.ssh_host_keys } else { Vec::new() });
        Ok(Resp::Machine(MachineJoined {
            machine_id: ulid.to_bytes().to_vec(),
            config: Some(self.hub.probe_config.clone()),
            access: m.access,
            managed: setup,
            hub_addrs: self.hub.hub_addrs.clone(),
        }))
    }

    async fn device(&self, d: DeviceJoin, caller: EndpointId, now_ms: i64) -> Result<Resp, Failure> {
        let token = Token::parse(&d.invite_secret);
        let stored = self.check(&token, TokenKind::Device, now_ms)?;
        let name = bounded_name(&d.device_name, "device name")?;
        let user_id = stored.bound.user_id.ok_or_else(|| Failure::new(JoinError::Invalid, "invite without a user"))?;
        let user = self
            .registry
            .user_name(&user_id)?
            .ok_or_else(|| Failure::new(JoinError::Invalid, "the user is disabled"))?;
        let id = Ulid::new().to_string();
        let row: Row = [
            ("id", Value::Text(id.clone())),
            ("user_id", Value::Text(user_id)),
            ("name", Value::Text(name)),
            ("endpoint_id", Value::Text(caller.to_string())),
            ("created_at", Value::Integer(now_ms)),
        ]
        .into_iter()
        .collect();
        let change = RegistryChange { writes: vec![RowWrite::insert("devices", row)], ..Default::default() };
        self.commit(&token, TokenKind::Device, now_ms, change).await?;
        self.announce(TokenKind::Device, &id, caller, Vec::new());
        Ok(Resp::Device(DeviceJoined { user, hub_site: self.hub.site.clone() }))
    }

    async fn operator(&self, o: OperatorJoin, caller: EndpointId, now_ms: i64) -> Result<Resp, Failure> {
        let token = Token::parse(&o.invite_secret);
        self.check(&token, TokenKind::Operator, now_ms)?;
        let name = bounded_name(&o.operator_name, "operator name")?;
        let runners: Vec<serde_json::Value> =
            o.runners.iter().map(|r| serde_json::json!({ "name": r.name, "version": r.version })).collect();
        let id = Ulid::new().to_string();
        let row: Row = [
            ("id", Value::Text(id.clone())),
            ("name", Value::Text(name)),
            ("endpoint_id", Value::Text(caller.to_string())),
            ("runners", Value::Text(serde_json::Value::Array(runners).to_string())),
            ("last_seen_ms", Value::Integer(now_ms)),
        ]
        .into_iter()
        .collect();
        let change = RegistryChange { writes: vec![RowWrite::insert("operators", row)], ..Default::default() };
        self.commit(&token, TokenKind::Operator, now_ms, change).await?;
        self.announce(TokenKind::Operator, &id, caller, Vec::new());
        Ok(Resp::Operator(OperatorJoined { hub_site: self.hub.site.clone() }))
    }

    async fn peer(&self, p: PeerJoin, caller: EndpointId, now_ms: i64) -> Result<Resp, Failure> {
        let token = Token::parse(&p.invite_secret);
        self.check(&token, TokenKind::Peer, now_ms)?;
        if !valid_site_name(&p.site) {
            return Err(Failure::new(JoinError::Invalid, "site names are 1 to 32 of a-z, 0-9 and -"));
        }
        let taken =
            || Failure::new(JoinError::SiteNameTaken, format!("site `{}` is already known to this hub", p.site));
        if self.registry.site_name_known(&p.site)? {
            return Err(taken());
        }
        let id = Ulid::new().to_string();
        let row: Row = [
            ("id", Value::Text(id.clone())),
            ("site", Value::Text(p.site.clone())),
            ("endpoint_id", Value::Text(caller.to_string())),
            ("added_at", Value::Integer(now_ms)),
        ]
        .into_iter()
        .collect();
        let change = RegistryChange { writes: vec![RowWrite::insert("peers", row)], ..Default::default() };
        match self.commit(&token, TokenKind::Peer, now_ms, change).await {
            // A peer with the same name joined in between.
            Err(f) if f.code == JoinError::Invalid && self.registry.site_name_known(&p.site)? => return Err(taken()),
            other => other?,
        }
        self.announce(TokenKind::Peer, &id, caller, Vec::new());
        Ok(Resp::Peer(PeerJoined {
            site: self.hub.site.clone(),
            hub_version: Some(SemVer { version: self.hub.version.clone() }),
            relays: self.hub.relays.iter().map(|url| RelayUrl { url: url.clone() }).collect(),
        }))
    }
}

trait IntoFailure {
    fn into_failure(self) -> Failure;
}

impl IntoFailure for TokenRefusal {
    fn into_failure(self) -> Failure {
        StoreError::TokenRefused(self).into()
    }
}

fn bounded_name(name: &str, what: &str) -> Result<String, Failure> {
    let name = name.trim();
    if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
        return Err(Failure::new(JoinError::Invalid, format!("{what}: 1 to 64 printable characters")));
    }
    Ok(name.to_string())
}

fn failed(f: Failure) -> JoinResponse {
    JoinResponse { kind: Some(Resp::Error(JoinFailed { code: f.code as i32, message: f.message })) }
}
