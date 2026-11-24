//! `GetExtendedTcpTable` and `GetExtendedUdpTable` (FR-4), as the tables they fill in: `MIB_TCPTABLE_OWNER_PID`,
//! `MIB_TCP6TABLE_OWNER_PID`, `MIB_UDPTABLE_OWNER_PID` and `MIB_UDP6TABLE_OWNER_PID`. A table is a row count and then the
//! rows, little-endian; a port is in network byte order in the low 16 bits of its field. A row becomes the same
//! [`Socket`] a Linux table does, with the owning pid where Linux has the socket inode (pid 0 is no process), so the
//! sampling capture that reads Linux tables reads these.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::security::conntable::{Proto, Socket};

const TCP4_ROW: usize = 24;
const TCP6_ROW: usize = 56;
const UDP4_ROW: usize = 12;
const UDP6_ROW: usize = 28;
/// What a UDP socket with no peer is in the tables Linux gives (`UDP_BOUND`).
const UDP_BOUND: u8 = 0x07;

fn u32_at(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn port_at(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b.get(at).copied().unwrap_or(0), b.get(at + 1).copied().unwrap_or(0)])
}

fn v4_at(b: &[u8], at: usize) -> IpAddr {
    let o = b.get(at..at + 4).unwrap_or(&[0; 4]);
    IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3]))
}

fn v6_at(b: &[u8], at: usize) -> IpAddr {
    let mut o = [0u8; 16];
    if let Some(s) = b.get(at..at + 16) {
        o.copy_from_slice(s);
    }
    IpAddr::V6(Ipv6Addr::from(o))
}

/// `MIB_TCP_STATE` as the kernel numbers Linux tables use.
fn state(mib: u32) -> u8 {
    match mib {
        2 => 0x0A,
        3 => 0x02,
        4 => 0x03,
        5 => 0x01,
        6 => 0x04,
        7 => 0x05,
        8 => 0x08,
        9 => 0x0B,
        10 => 0x09,
        11 => 0x06,
        _ => 0x07,
    }
}

/// The rows a table holds: its count, but never more than the bytes have room for.
fn rows(table: &[u8], width: usize) -> impl Iterator<Item = &[u8]> {
    let declared = u32_at(table, 0) as usize;
    let body = table.get(4..).unwrap_or(&[]);
    body.chunks_exact(width).take(declared)
}

pub fn tcp4(table: &[u8]) -> Vec<Socket> {
    rows(table, TCP4_ROW)
        .map(|r| Socket {
            proto: Proto::Tcp,
            local: v4_at(r, 4),
            local_port: port_at(r, 8),
            remote: v4_at(r, 12),
            remote_port: port_at(r, 16),
            state: state(u32_at(r, 0)),
            inode: u64::from(u32_at(r, 20)),
            uid: 0,
        })
        .collect()
}

pub fn tcp6(table: &[u8]) -> Vec<Socket> {
    rows(table, TCP6_ROW)
        .map(|r| Socket {
            proto: Proto::Tcp,
            local: v6_at(r, 0),
            local_port: port_at(r, 20),
            remote: v6_at(r, 24),
            remote_port: port_at(r, 44),
            state: state(u32_at(r, 48)),
            inode: u64::from(u32_at(r, 52)),
            uid: 0,
        })
        .collect()
}

pub fn udp4(table: &[u8]) -> Vec<Socket> {
    rows(table, UDP4_ROW)
        .map(|r| Socket {
            proto: Proto::Udp,
            local: v4_at(r, 0),
            local_port: port_at(r, 4),
            remote: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            remote_port: 0,
            state: UDP_BOUND,
            inode: u64::from(u32_at(r, 8)),
            uid: 0,
        })
        .collect()
}

pub fn udp6(table: &[u8]) -> Vec<Socket> {
    rows(table, UDP6_ROW)
        .map(|r| Socket {
            proto: Proto::Udp,
            local: v6_at(r, 0),
            local_port: port_at(r, 20),
            remote: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            remote_port: 0,
            state: UDP_BOUND,
            inode: u64::from(u32_at(r, 24)),
            uid: 0,
        })
        .collect()
}
