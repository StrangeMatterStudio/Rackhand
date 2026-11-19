//! The client's address (7.7.2): from the forwarding header only when the connection comes from a trusted proxy; a
//! source is an IPv4 address or an IPv6 /64.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;

/// The connection's peer, inserted by the listener.
#[derive(Debug, Clone, Copy)]
pub struct PeerAddr(pub SocketAddr);

pub type Trusted = [(IpAddr, u8)];

fn in_net(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let bits = u32::from(prefix.min(32));
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let bits = u32::from(prefix.min(128));
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

fn trusted(ip: IpAddr, list: &Trusted) -> bool {
    list.iter().any(|(net, prefix)| in_net(ip, *net, *prefix))
}

/// The client address: the peer, unless the peer is a trusted proxy, in which case the nearest untrusted address in
/// `X-Forwarded-For` (read from the right, so a client can't choose its own).
pub fn client_ip(peer: SocketAddr, headers: &HeaderMap, list: &Trusted) -> IpAddr {
    if !trusted(peer.ip(), list) {
        return peer.ip();
    }
    let forwarded: Vec<IpAddr> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|a| a.trim().parse().ok())
        .collect();
    forwarded.into_iter().rev().find(|ip| !trusted(*ip, list)).unwrap_or(peer.ip())
}

/// The key sign-in limits count under.
pub fn source_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}
