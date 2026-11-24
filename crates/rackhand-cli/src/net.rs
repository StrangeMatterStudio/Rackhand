//! Reaching the hub that owns a machine (7.3.11, D59): the caller dials that hub directly, with the device key it made for it.
//! `connect`, `forward` and `send` all begin here.

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr};
use prost::Message;
use rackhand_net::frames;
use rackhand_proto::tunnel::{TunnelError, TunnelOpen, TunnelReply, tunnel_reply};

use crate::config::{self, Dirs, Hub};

/// A connection to a hub on one protocol, with the endpoint it came from kept alive.
pub struct Link {
    pub endpoint: Endpoint,
    pub conn: Connection,
    pub hub: Hub,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Link({})", self.hub.site)
    }
}

pub fn hub_addr(hub: &Hub) -> Result<EndpointAddr, String> {
    hub.ticket()?.endpoint_addr()
}

pub async fn dial(dirs: &Dirs, site: &str, alpn: &[u8]) -> Result<Link, String> {
    let hub = config::find(dirs, site)?;
    let endpoint = config::endpoint(dirs, &hub.id, hub.relays.clone()).await?;
    let conn =
        endpoint.connect(hub_addr(&hub)?, alpn).await.map_err(|e| format!("can't reach the hub of `{site}`: {e}"))?;
    Ok(Link { endpoint, conn, hub })
}

fn why(e: TunnelError) -> &'static str {
    match e {
        TunnelError::OutOfScope => {
            "the hub doesn't let this device reach that machine (it needs a responder or admin account on the hub that owns it)"
        }
        TunnelError::PortNotAllowed => "the machine's policy doesn't allow that port",
        TunnelError::MachineUnreachable => "the hub can't reach the machine",
        TunnelError::Unsupported => "the machine can't take tunnels (it is at access level monitor)",
        TunnelError::Unspecified => "the hub refused",
    }
}

/// Opens a tunnel to `port` of the machine named `machine` at the hub's own site.
pub async fn open_tunnel(
    conn: &Connection,
    machine: &str,
    port: u16,
    purpose: &str,
) -> Result<(SendStream, RecvStream), String> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    // the hub takes a machine's name in place of its id
    let open = TunnelOpen { target: machine.as_bytes().to_vec(), port: u32::from(port), purpose: purpose.to_string() };
    frames::write_msg(&mut send, &open).await.map_err(|e| e.to_string())?;
    let body = frames::read(&mut recv)
        .await
        .map_err(|e| format!("the hub closed the connection: {e:?} ({:?})", conn.close_reason()))?;
    let reply = TunnelReply::decode(body.as_slice()).map_err(|e| e.to_string())?;
    match reply.reply {
        Some(tunnel_reply::Reply::Opened(true)) => Ok((send, recv)),
        Some(tunnel_reply::Reply::Error(e)) => {
            Err(why(TunnelError::try_from(e).unwrap_or(TunnelError::Unspecified)).to_string())
        }
        _ => Err("the hub's answer wasn't one".into()),
    }
}
