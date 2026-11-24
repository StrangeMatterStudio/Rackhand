//! Remote mode (7.3.2, 7.3.7, D60, D80): a probe on a machine at a site without a hub accepts `rackhand/tunnel/1` from its
//! pinned hub and splices each tunnel stream to the machine's own SSH server, `127.0.0.1:22`, and nowhere else. The hub's SSH
//! then arrives from localhost, which is what `from=` allows on a remote-mode machine. A probe at access level `monitor` has
//! no SSH account for the hub to use, so it accepts no tunnel at all.

use std::net::SocketAddr;
use std::sync::Arc;

use iroh::{Endpoint, EndpointId};
use prost::Message;
use rackhand_net::frames;
use rackhand_net::registry::{Admission, Registry};
use rackhand_net::router::{Router, handler};
use rackhand_proto::alpn;
use rackhand_proto::tunnel::{TunnelError, TunnelOpen, TunnelReply, tunnel_reply};
use tokio::net::TcpStream;

/// The only port a tunnel reaches.
pub const SSH_PORT: u16 = 22;

/// The ALPNs the probe's endpoint accepts: the tunnel in remote mode at access level `managed`, nothing otherwise (a probe
/// dials out; it has no inbound ports, 5).
pub fn alpns(remote: bool, managed: bool) -> Vec<Vec<u8>> {
    if remote && managed { vec![alpn::TUNNEL.to_vec()] } else { Vec::new() }
}

/// The pinned hub is the only id that may open a tunnel.
#[derive(Debug)]
struct PinnedHub(EndpointId);

impl Registry for PinnedHub {
    fn admission(&self, alpn: &[u8], id: &EndpointId) -> Admission {
        if alpn == rackhand_proto::alpn::TUNNEL && *id == self.0 { Admission::Allowed } else { Admission::Unknown }
    }
}

fn reply(error: Option<TunnelError>) -> TunnelReply {
    TunnelReply {
        reply: Some(match error {
            None => tunnel_reply::Reply::Opened(true),
            Some(e) => tunnel_reply::Reply::Error(e as i32),
        }),
    }
}

/// Where a tunnel stream goes: only the SSH port, only for this machine.
fn check(open: &TunnelOpen, machine: &[u8; 16]) -> Result<(), TunnelError> {
    if open.target.as_slice() != machine.as_slice() {
        return Err(TunnelError::OutOfScope);
    }
    if open.port != u32::from(SSH_PORT) {
        return Err(TunnelError::PortNotAllowed);
    }
    Ok(())
}

async fn one(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    machine: [u8; 16],
    ssh: SocketAddr,
) {
    let Ok(body) = frames::read(&mut recv).await else { return };
    let Ok(open) = TunnelOpen::decode(body.as_slice()) else { return };
    if let Err(e) = check(&open, &machine) {
        let _ = frames::write_msg(&mut send, &reply(Some(e))).await;
        let _ = send.finish();
        return;
    }
    let Ok(mut tcp) = TcpStream::connect(ssh).await else {
        let _ = frames::write_msg(&mut send, &reply(Some(TunnelError::MachineUnreachable))).await;
        let _ = send.finish();
        return;
    };
    if frames::write_msg(&mut send, &reply(None)).await.is_err() {
        return;
    }
    let mut stream = tokio::io::join(recv, send);
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
    let _ = stream.into_inner().1.finish();
}

/// Serves tunnels from `hub` to `ssh` (the machine's `127.0.0.1:22`) on the probe's endpoint.
pub fn spawn(endpoint: Endpoint, hub: EndpointId, machine: [u8; 16], ssh: SocketAddr) -> tokio::task::JoinHandle<()> {
    let router = Router::new(endpoint, Arc::new(PinnedHub(hub))).route(
        alpn::TUNNEL,
        handler(move |conn| async move {
            while let Ok((send, recv)) = conn.accept_bi().await {
                tokio::spawn(one(send, recv, machine, ssh));
            }
        }),
    );
    tokio::spawn(router.serve())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MACHINE: [u8; 16] = [7; 16];

    fn open(target: &[u8], port: u32) -> TunnelOpen {
        TunnelOpen { target: target.to_vec(), port, purpose: "ssh".into() }
    }

    #[test]
    fn only_this_machines_ssh_port() {
        assert_eq!(check(&open(&MACHINE, 22), &MACHINE), Ok(()));
        assert_eq!(check(&open(&MACHINE, 2222), &MACHINE), Err(TunnelError::PortNotAllowed));
        assert_eq!(check(&open(&MACHINE, 80), &MACHINE), Err(TunnelError::PortNotAllowed));
        assert_eq!(check(&open(&[8; 16], 22), &MACHINE), Err(TunnelError::OutOfScope));
        assert_eq!(check(&open(&[], 22), &MACHINE), Err(TunnelError::OutOfScope));
    }

    #[test]
    fn a_monitor_probe_and_a_local_probe_accept_no_tunnel() {
        assert_eq!(alpns(true, true), vec![alpn::TUNNEL.to_vec()]);
        assert!(alpns(true, false).is_empty(), "remote mode at access level monitor: no tunnel");
        assert!(alpns(false, true).is_empty(), "local mode has no inbound ports");
        assert!(alpns(false, false).is_empty());
    }

    #[test]
    fn only_the_pinned_hub_is_admitted() {
        let id = |n: u8| iroh::SecretKey::from_bytes(&[n; 32]).public();
        let registry = PinnedHub(id(1));
        assert_eq!(registry.admission(alpn::TUNNEL, &id(1)), Admission::Allowed);
        assert_eq!(registry.admission(alpn::TUNNEL, &id(2)), Admission::Unknown);
        assert_eq!(registry.admission(alpn::PROBE, &id(1)), Admission::Unknown, "and for no other protocol");
    }
}
