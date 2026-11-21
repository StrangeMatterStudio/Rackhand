//! ICMP checks: one echo request, answered within the timeout. Without root: an unprivileged ICMP socket where
//! `net.ipv4.ping_group_range` allows the user, else a raw socket, which the hub's unit grants with `CAP_NET_RAW` (7.1).
//! Target a host name or an address.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use socket2::{Domain, Protocol, Socket, Type};

use crate::driver::{Driver, DriverError, DriverKind, DriverReading, DriverTarget, millis, settings};

#[derive(Debug, Default)]
pub struct Icmp;

impl Icmp {
    pub fn new() -> Icmp {
        Icmp
    }
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn echo(v6: bool, id: u16, seq: u16) -> Vec<u8> {
    let mut p = vec![if v6 { 128 } else { 8 }, 0, 0, 0];
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(b"rackhand-check");
    if !v6 {
        let c = checksum(&p);
        p[2..4].copy_from_slice(&c.to_be_bytes());
    }
    p
}

/// A socket for echo requests: unprivileged when allowed, raw otherwise. Returns it and whether it is raw.
fn open(v6: bool) -> std::io::Result<(Socket, bool)> {
    let (domain, proto) = if v6 { (Domain::IPV6, Protocol::ICMPV6) } else { (Domain::IPV4, Protocol::ICMPV4) };
    match Socket::new(domain, Type::DGRAM, Some(proto)) {
        Ok(s) => Ok((s, false)),
        Err(_) => Socket::new(domain, Type::RAW, Some(proto)).map(|s| (s, true)),
    }
}

/// Whether `packet` is the reply to our request `seq` (a raw IPv4 socket hands over the IP header too).
fn is_reply(packet: &[u8], v6: bool, raw: bool, seq: u16) -> bool {
    let icmp = if raw && !v6 {
        packet.get(((packet.first().copied().unwrap_or(0) & 0x0f) as usize) * 4..)
    } else {
        Some(packet)
    };
    let Some(icmp) = icmp else { return false };
    icmp.len() >= 8 && icmp[0] == if v6 { 129 } else { 0 } && u16::from_be_bytes([icmp[6], icmp[7]]) == seq
}

#[async_trait::async_trait]
impl Driver for Icmp {
    fn kind(&self) -> DriverKind {
        DriverKind::Icmp
    }

    async fn poll(&self, target: &DriverTarget) -> Result<DriverReading, DriverError> {
        settings(&target.settings, &[])?;
        let ip: IpAddr = match target.target.parse() {
            Ok(ip) => ip,
            Err(_) => match crate::driver::resolve(&format!("{}:0", target.target)).await {
                Ok(a) => a.ip(),
                Err(e) => return Ok(DriverReading::down(e, vec![])),
            },
        };
        let v6 = ip.is_ipv6();
        let (socket, raw) = open(v6).map_err(|e| {
            DriverError::Failed(format!(
                "no ICMP socket ({e}): allow the group in net.ipv4.ping_group_range or grant CAP_NET_RAW"
            ))
        })?;
        socket.set_nonblocking(true).map_err(|e| DriverError::Failed(e.to_string()))?;
        let socket = tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(socket))
            .map_err(|e| DriverError::Failed(e.to_string()))?;
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().subsec_nanos();
        let seq = (nanos >> 8) as u16;
        let packet = echo(v6, std::process::id() as u16, seq);
        let started = Instant::now();
        let ask = async {
            socket.send_to(&packet, SocketAddr::new(ip, 0)).await.map_err(|e| format!("{ip}: {e}"))?;
            let mut buf = vec![0u8; 1500];
            loop {
                let (n, from) = socket.recv_from(&mut buf).await.map_err(|e| e.to_string())?;
                if from.ip() == ip && is_reply(&buf[..n], v6, raw, seq) {
                    return Ok::<_, String>(());
                }
            }
        };
        match tokio::time::timeout(target.timeout, ask).await {
            Ok(Ok(())) => Ok(DriverReading::up(millis(started), format!("{ip} answers"), vec![])),
            Ok(Err(e)) => Ok(DriverReading::down(e, vec![])),
            Err(_) => Ok(DriverReading::down(format!("{ip}: no answer within {:?}", target.timeout), vec![])),
        }
    }
}
