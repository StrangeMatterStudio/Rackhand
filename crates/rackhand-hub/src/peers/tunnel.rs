//! Tunnels (`rackhand/tunnel/1`, 7.3.11, FR-19, FR-21, D59, D60): a person's device opens a stream to a port of a machine at
//! this site, and the hub splices it to the machine. A machine in remote mode is reached through its probe, which splices to
//! its own `127.0.0.1:22` and nowhere else; the same path carries the hub's own SSH to such a machine (`RemoteReach`).
//!
//! The caller dials the hub that owns the machine. The hub lets through a device whose account here has the role responder
//! or admin, to a port the machine's policy allows (22 unless it says more).

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use prost::Message;
use rackhand_net::frames;
use rackhand_net::router::{Handler, handler};
use rackhand_proto::alpn;
use rackhand_proto::tunnel::{TunnelError, TunnelOpen, TunnelReply, tunnel_reply};
use rackhand_store::Db;
use rusqlite::OptionalExtension;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::actions::runner::BoxFuture;
use crate::audit::Audit;
use crate::executor::RemoteReach;

/// What a tunnel carries bytes through: a TCP connection, or a stream to a probe.
pub trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

/// A machine as the tunnel server needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub id: String,
    pub mode: String,
    pub access: String,
    pub address: Option<String>,
    pub probe_endpoint_id: Option<String>,
}

/// How a connection to a machine's port is made.
pub trait Backend: Send + Sync {
    fn open<'a>(&'a self, target: &'a Target, port: u16) -> BoxFuture<'a, Result<Box<dyn Io>, TunnelError>>;
}

/// A bidirectional QUIC stream that keeps its connection alive.
struct ProbeStream {
    _conn: Connection,
    recv: RecvStream,
    send: SendStream,
}

impl AsyncRead for ProbeStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProbeStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, buf).map_err(std::io::Error::other)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

fn error_of(reply: &TunnelReply) -> Option<TunnelError> {
    match reply.reply {
        Some(tunnel_reply::Reply::Opened(true)) => None,
        Some(tunnel_reply::Reply::Error(e)) => Some(TunnelError::try_from(e).unwrap_or(TunnelError::Unsupported)),
        _ => Some(TunnelError::Unsupported),
    }
}

/// The real connections: TCP to a local machine, and a tunnel stream to the probe of a remote-mode one.
#[derive(Debug, Clone)]
pub struct Network {
    endpoint: Arc<std::sync::OnceLock<Endpoint>>,
    /// Relays a probe may be reached through when no direct address is known.
    relays: Vec<iroh::RelayUrl>,
}

impl Network {
    pub fn new(endpoint: Endpoint, relays: Vec<iroh::RelayUrl>) -> Network {
        let network = Network::deferred(relays);
        network.bind(endpoint);
        network
    }

    /// A network whose endpoint comes later: the Executor is built before the hub's endpoint is.
    pub fn deferred(relays: Vec<iroh::RelayUrl>) -> Network {
        Network { endpoint: Arc::new(std::sync::OnceLock::new()), relays }
    }

    pub fn bind(&self, endpoint: Endpoint) {
        let _ = self.endpoint.set(endpoint);
    }

    /// The hub's endpoint, once it is bound.
    pub fn endpoint(&self) -> Option<Endpoint> {
        self.endpoint.get().cloned()
    }

    /// The relays a peer or probe may be reached through.
    pub fn relays(&self) -> &[iroh::RelayUrl] {
        &self.relays
    }

    async fn to_probe(&self, target: &Target, port: u16) -> Result<Box<dyn Io>, TunnelError> {
        // a probe at access level `monitor` has no account for the hub to use and accepts no tunnel (7.3.2)
        if target.access == "monitor" {
            return Err(TunnelError::Unsupported);
        }
        let id: EndpointId =
            target.probe_endpoint_id.as_deref().and_then(|i| i.parse().ok()).ok_or(TunnelError::MachineUnreachable)?;
        let machine = target.id.parse::<ulid::Ulid>().map_err(|_| TunnelError::OutOfScope)?;
        let mut addr = EndpointAddr::new(id);
        for relay in &self.relays {
            addr.addrs.insert(TransportAddr::Relay(relay.clone()));
        }
        let endpoint = self.endpoint.get().ok_or(TunnelError::MachineUnreachable)?;
        let work = async {
            let conn = endpoint.connect(addr, alpn::TUNNEL).await.map_err(|_| TunnelError::MachineUnreachable)?;
            let (mut send, mut recv) = conn.open_bi().await.map_err(|_| TunnelError::MachineUnreachable)?;
            let open = TunnelOpen { target: machine.to_bytes().to_vec(), port: u32::from(port), purpose: "ssh".into() };
            frames::write_msg(&mut send, &open).await.map_err(|_| TunnelError::MachineUnreachable)?;
            let body = frames::read(&mut recv).await.map_err(|_| TunnelError::MachineUnreachable)?;
            let reply = TunnelReply::decode(body.as_slice()).map_err(|_| TunnelError::MachineUnreachable)?;
            match error_of(&reply) {
                None => Ok(Box::new(ProbeStream { _conn: conn, recv, send }) as Box<dyn Io>),
                Some(e) => Err(e),
            }
        };
        tokio::time::timeout(Duration::from_secs(20), work).await.map_err(|_| TunnelError::MachineUnreachable)?
    }
}

fn socket_addr(address: &str, port: u16) -> Option<SocketAddr> {
    address.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, port)).or_else(|| {
        // an address stored with a port (`192.0.2.9:22`) names the machine; the port asked for replaces it
        address.parse::<SocketAddr>().ok().map(|a| SocketAddr::new(a.ip(), port))
    })
}

impl Backend for Network {
    fn open<'a>(&'a self, target: &'a Target, port: u16) -> BoxFuture<'a, Result<Box<dyn Io>, TunnelError>> {
        Box::pin(async move {
            if target.mode == "remote" {
                return self.to_probe(target, port).await;
            }
            let addr =
                target.address.as_deref().and_then(|a| socket_addr(a, port)).ok_or(TunnelError::MachineUnreachable)?;
            let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr))
                .await
                .map_err(|_| TunnelError::MachineUnreachable)?
                .map_err(|_| TunnelError::MachineUnreachable)?;
            Ok(Box::new(tcp) as Box<dyn Io>)
        })
    }
}

/// The loopback listeners, one for each remote-mode machine reached, kept for as long as the hub runs.
pub struct Forwards {
    db: Arc<Db>,
    backend: Arc<dyn Backend>,
    listeners: tokio::sync::Mutex<std::collections::HashMap<String, SocketAddr>>,
}

impl std::fmt::Debug for Forwards {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Forwards")
    }
}

impl Forwards {
    pub fn new(db: Arc<Db>, backend: Arc<dyn Backend>) -> Forwards {
        Forwards { db, backend, listeners: tokio::sync::Mutex::new(Default::default()) }
    }

    async fn listener(&self, target: Target) -> Result<SocketAddr, String> {
        let mut listeners = self.listeners.lock().await;
        if let Some(addr) = listeners.get(&target.id) {
            return Ok(*addr);
        }
        let tcp =
            tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.map_err(|e| e.to_string())?;
        let addr = tcp.local_addr().map_err(|e| e.to_string())?;
        let backend = self.backend.clone();
        let for_machine = target.clone();
        tokio::spawn(async move {
            while let Ok((mut local, _)) = tcp.accept().await {
                let (backend, target) = (backend.clone(), for_machine.clone());
                tokio::spawn(async move {
                    if let Ok(mut remote) = backend.open(&target, 22).await {
                        let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
                    }
                });
            }
        });
        listeners.insert(target.id, addr);
        Ok(addr)
    }
}

impl RemoteReach for Forwards {
    fn reach<'a>(&'a self, machine_id: &'a str) -> Option<BoxFuture<'a, Result<SocketAddr, String>>> {
        let target = target(&self.db, machine_id)?;
        if target.mode != "remote" {
            return None;
        }
        Some(Box::pin(async move { self.listener(target).await }))
    }
}

/// The machine a tunnel or transfer names: its 16-byte id, or its name at this hub's own site (what `rackhand-cli` says,
/// `<site>/<machine>` having been used to find this hub).
pub(crate) fn resolve_machine(db: &Db, named: &[u8]) -> Option<String> {
    if let Ok(id) = <[u8; 16]>::try_from(named) {
        return Some(ulid::Ulid::from_bytes(id).to_string());
    }
    let name = std::str::from_utf8(named).ok()?;
    db.readers()
        .with(|c| {
            c.query_row(
                "SELECT m.id FROM machines m JOIN sites s ON s.id = m.site_id
                 WHERE s.is_local = 1 AND m.name = ?1 AND m.state = 'enrolled'",
                [name],
                |r| r.get(0),
            )
            .optional()
        })
        .ok()
        .flatten()
}

/// A machine of this site that has enrolled.
pub(crate) fn target(db: &Db, machine_id: &str) -> Option<Target> {
    db.readers()
        .with(|c| {
            c.query_row(
                "SELECT m.id, m.mode, m.access, m.address, m.probe_endpoint_id FROM machines m
                 JOIN sites s ON s.id = m.site_id WHERE m.id = ?1 AND s.is_local = 1 AND m.state = 'enrolled'",
                [machine_id],
                |r| {
                    Ok(Target {
                        id: r.get(0)?,
                        mode: r.get(1)?,
                        access: r.get(2)?,
                        address: r.get(3)?,
                        probe_endpoint_id: r.get(4)?,
                    })
                },
            )
            .optional()
        })
        .ok()
        .flatten()
}

/// The tunnel ports a machine's policy allows: 22 unless it says otherwise.
pub(crate) fn policy_ports(db: &Db, machine_id: &str) -> Vec<u16> {
    let json: Option<String> = db
        .readers()
        .with(|c| {
            c.query_row(
                "SELECT p.tunnel_ports FROM machines m LEFT JOIN policies p ON p.id = m.policy_id WHERE m.id = ?1",
                [machine_id],
                |r| r.get(0),
            )
            .optional()
        })
        .ok()
        .flatten()
        .flatten();
    json.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_else(|| vec![22])
}

/// Who is asking: a device, and the account it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Person {
    pub(crate) user: String,
    pub(crate) device: String,
    pub(crate) role: String,
}

/// The account a device belongs to, if the device and the account are both in use.
pub(crate) fn person(db: &Db, caller: EndpointId) -> Option<Person> {
    db.readers()
        .with(|c| {
            c.query_row(
                "SELECT u.name, d.name, u.role FROM devices d JOIN users u ON u.id = d.user_id
                 WHERE d.endpoint_id = ?1 AND d.revoked_at IS NULL AND u.disabled_at IS NULL",
                [caller.to_string()],
                |r| Ok(Person { user: r.get(0)?, device: r.get(1)?, role: r.get(2)? }),
            )
            .optional()
        })
        .ok()
        .flatten()
}

pub struct Tunnels {
    db: Arc<Db>,
    audit: Audit,
    backend: Arc<dyn Backend>,
}

impl std::fmt::Debug for Tunnels {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Tunnels")
    }
}

impl Tunnels {
    pub fn new(db: Arc<Db>, audit: Audit, backend: Arc<dyn Backend>) -> Arc<Tunnels> {
        Arc::new(Tunnels { db, audit, backend })
    }

    /// The router's handler for `rackhand/tunnel/1`.
    pub fn handler(self: &Arc<Tunnels>) -> Handler {
        let this = self.clone();
        handler(move |conn| {
            let this = this.clone();
            async move { this.serve(conn).await }
        })
    }

    async fn serve(self: Arc<Tunnels>, conn: Connection) {
        let caller = conn.remote_id();
        while let Ok((send, recv)) = conn.accept_bi().await {
            tokio::spawn(self.clone().one(caller, send, recv));
        }
    }

    fn person(&self, caller: EndpointId) -> Option<Person> {
        person(&self.db, caller)
    }

    /// Whether this caller may open a tunnel to the machine and port, and the machine.
    fn authorize(&self, caller: EndpointId, open: &TunnelOpen) -> Result<(Person, Target, u16), TunnelError> {
        let person = self.person(caller).ok_or(TunnelError::OutOfScope)?;
        if !matches!(person.role.as_str(), "responder" | "admin") {
            return Err(TunnelError::OutOfScope);
        }
        let machine = resolve_machine(&self.db, &open.target).ok_or(TunnelError::OutOfScope)?;
        // a machine at another site belongs to another hub, which the caller dials directly
        let target = target(&self.db, &machine).ok_or(TunnelError::OutOfScope)?;
        let port = u16::try_from(open.port).map_err(|_| TunnelError::PortNotAllowed)?;
        if !policy_ports(&self.db, &machine).contains(&port) {
            return Err(TunnelError::PortNotAllowed);
        }
        Ok((person, target, port))
    }

    async fn record(&self, action: &str, who: &str, machine: &str, data: serde_json::Value) {
        let _ = self.audit.append(&format!("user:{who}"), action, Some(machine), &data.to_string()).await;
    }

    async fn one(self: Arc<Tunnels>, caller: EndpointId, mut send: SendStream, mut recv: RecvStream) {
        let Ok(body) = frames::read(&mut recv).await else { return };
        let Ok(open) = TunnelOpen::decode(body.as_slice()) else { return };
        let machine = resolve_machine(&self.db, &open.target).unwrap_or_default();
        let reply = |e: Option<TunnelError>| TunnelReply {
            reply: Some(match e {
                None => tunnel_reply::Reply::Opened(true),
                Some(e) => tunnel_reply::Reply::Error(e as i32),
            }),
        };
        let result = match self.authorize(caller, &open) {
            Ok((person, target, port)) => match self.backend.open(&target, port).await {
                Ok(stream) => Ok((person, port, stream)),
                Err(e) => {
                    self.record(
                        "tunnel.failed",
                        &person.user,
                        &machine,
                        serde_json::json!({ "device": person.device, "port": port, "error": format!("{e:?}") }),
                    )
                    .await;
                    Err(e)
                }
            },
            Err(e) => {
                let who = self.person(caller).map(|p| p.user).unwrap_or_else(|| caller.fmt_short().to_string());
                self.record(
                    "tunnel.refused",
                    &who,
                    &machine,
                    serde_json::json!({ "port": open.port, "error": format!("{e:?}") }),
                )
                .await;
                Err(e)
            }
        };
        match result {
            Err(e) => {
                let _ = frames::write_msg(&mut send, &reply(Some(e))).await;
                let _ = send.finish();
            }
            Ok((person, port, mut stream)) => {
                if frames::write_msg(&mut send, &reply(None)).await.is_err() {
                    return;
                }
                self.record(
                    "tunnel.opened",
                    &person.user,
                    &machine,
                    serde_json::json!({ "device": person.device, "port": port, "purpose": open.purpose }),
                )
                .await;
                let mut quic = tokio::io::join(recv, send);
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut quic).await;
                let _ = quic.into_inner().1.finish();
            }
        }
    }
}
