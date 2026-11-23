//! The kernel's connection tables (7.3.2, FR-4): `/proc/net/tcp`, `tcp6`, `udp` and `udp6`, as the sampling capture reads
//! them every 5 seconds where eBPF isn't available. A row has no process, only a socket inode and a uid; the helper says
//! who owns the inode.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::collect::Host;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    pub proto: Proto,
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
    /// The kernel's state number (`0A` is LISTEN, `01` ESTABLISHED).
    pub state: u8,
    pub inode: u64,
    pub uid: u32,
}

const TCP_ESTABLISHED: u8 = 0x01;
const TCP_SYN_SENT: u8 = 0x02;
const TCP_CLOSE_WAIT: u8 = 0x08;
const TCP_LISTEN: u8 = 0x0A;
const UDP_BOUND: u8 = 0x07;

impl Socket {
    /// A socket waiting for connections: a TCP listener, or a bound UDP socket with no peer.
    pub fn listening(&self) -> bool {
        match self.proto {
            Proto::Tcp => self.state == TCP_LISTEN,
            Proto::Udp => self.state == UDP_BOUND && self.remote_port == 0 && self.local_port != 0,
        }
    }

    /// A connection this machine opened or has open to another address: with a peer, an owner, and not a loopback or
    /// unspecified one.
    pub fn outbound(&self) -> bool {
        let live = match self.proto {
            Proto::Tcp => matches!(self.state, TCP_ESTABLISHED | TCP_SYN_SENT | TCP_CLOSE_WAIT),
            Proto::Udp => self.state == 0x01 || (self.state == UDP_BOUND && self.remote_port != 0),
        };
        live && self.inode != 0 && self.remote_port != 0 && !self.remote.is_unspecified() && !self.remote.is_loopback()
    }
}

/// `0100007F` as 127.0.0.1: IPv4 addresses are one little-endian word.
fn v4(hex: &str) -> Option<Ipv4Addr> {
    let w = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(w.swap_bytes()))
}

/// 32 hex digits: four words, each in the machine's byte order (little-endian here).
fn v6(hex: &str) -> Option<IpAddr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let w = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&w.swap_bytes().to_be_bytes());
    }
    let ip = Ipv6Addr::from(bytes);
    // an IPv4 peer of a dual-stack socket is the IPv4 address
    Some(ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4))
}

fn addr(field: &str, six: bool) -> Option<(IpAddr, u16)> {
    let (ip, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = if six { v6(ip)? } else { IpAddr::V4(v4(ip)?) };
    Some((ip, port))
}

/// The rows of one table.
pub fn parse(proto: Proto, six: bool, text: &str) -> Vec<Socket> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (local, local_port) = addr(f.get(1)?, six)?;
            let (remote, remote_port) = addr(f.get(2)?, six)?;
            Some(Socket {
                proto,
                local,
                local_port,
                remote,
                remote_port,
                state: u8::from_str_radix(f.get(3)?, 16).ok()?,
                uid: f.get(7)?.parse().ok()?,
                inode: f.get(9)?.parse().ok()?,
            })
        })
        .collect()
}

/// Every socket of the machine's four tables.
pub fn read(host: &dyn Host) -> Vec<Socket> {
    let mut out = Vec::new();
    for (path, proto, six) in [
        ("proc/net/tcp", Proto::Tcp, false),
        ("proc/net/tcp6", Proto::Tcp, true),
        ("proc/net/udp", Proto::Udp, false),
        ("proc/net/udp6", Proto::Udp, true),
    ] {
        if let Some(text) = host.read(path) {
            out.extend(parse(proto, six, &text));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

    #[test]
    fn parses_proc_net_tcp_udp_v4_v6() {
        let tcp = format!(
            "{HEAD}   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0 100 0 0 10 0\n\
             \x20  1: 0A00020F:A2C4 5DB8D822:01BB 01 00000000:00000000 02:000A7B7F 00000000  1000        0 22222 2 0 20 4 30 10 -1\n\
             \x20  2: 0A00020F:A2C5 5DB8D822:0050 02 00000000:00000000 00:00000000 00000000  1000        0 33333 2 0 20 4 30 10 -1\n"
        );
        let rows = parse(Proto::Tcp, false, &tcp);
        assert_eq!(rows.len(), 3);
        assert_eq!(
            (rows[0].local, rows[0].local_port, rows[0].state, rows[0].inode, rows[0].uid),
            ("127.0.0.1".parse::<IpAddr>().unwrap(), 8080, 0x0A, 11111, 0)
        );
        assert!(rows[0].listening() && !rows[0].outbound());
        let est = &rows[1];
        assert_eq!(est.remote, "34.216.184.93".parse::<IpAddr>().unwrap());
        assert_eq!((est.remote_port, est.uid), (443, 1000));
        assert!(est.outbound() && !est.listening());
        assert!(rows[2].outbound(), "a connection still being made is one too");

        // IPv6 as the kernel prints it: each 32-bit word of the address in the machine's byte order
        let hex6 = |ip: &str| -> String {
            let ip: std::net::Ipv6Addr = ip.parse().unwrap();
            ip.octets()
                .chunks(4)
                .map(|c| format!("{:08X}", u32::from_be_bytes([c[0], c[1], c[2], c[3]]).swap_bytes()))
                .collect()
        };
        let tcp6 = format!(
            "{HEAD}   0: {}:0016 {}:0000 0A 00000000:00000000 00:00000000 00000000     0        0 44444 1 0 100 0 0 10 0
                1: {}:C000 {}:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 55555 1 0 100 0 0 10 0
                2: {}:C001 {}:01BB 01 00000000:00000000 00:00000000 00000000     0        0 66666 1 0 100 0 0 10 0
",
            hex6("::1"),
            hex6("::"),
            hex6("::ffff:10.0.2.15"),
            hex6("::ffff:93.184.216.34"),
            hex6("2001:db8::1"),
            hex6("2001:db8::2"),
        );
        let rows = parse(Proto::Tcp, true, &tcp6);
        assert_eq!(rows[0].local, "::1".parse::<IpAddr>().unwrap());
        assert!(rows[0].listening());
        // an IPv4 peer on a dual-stack socket is an IPv4 address
        assert_eq!(rows[1].remote, "93.184.216.34".parse::<IpAddr>().unwrap(), "{:?}", rows[1]);
        assert_eq!(rows[1].local, "10.0.2.15".parse::<IpAddr>().unwrap());
        assert!(rows[1].outbound());
        assert_eq!(rows[2].remote, "2001:db8::2".parse::<IpAddr>().unwrap());
        assert!(rows[2].outbound());

        let udp = format!(
            "{HEAD}   0: 0A00020F:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 77777 2 0\n\
             \x20  1: 0A00020F:C350 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 88888 2 0\n"
        );
        let rows = parse(Proto::Udp, false, &udp);
        assert!(rows[0].listening() && !rows[0].outbound());
        assert!(rows[1].outbound() && rows[1].remote_port == 53);
        // nothing it can't read is a row
        assert!(parse(Proto::Tcp, false, "garbage\nmore garbage\n").is_empty());
        assert!(parse(Proto::Tcp, false, &format!("{HEAD}   0: ZZZZ:0050 00000000:0000 0A\n")).is_empty());
    }
}
