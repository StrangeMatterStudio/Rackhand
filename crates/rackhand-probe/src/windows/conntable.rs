//! The connection tables of this machine (FR-4, AC56): `GetExtendedTcpTable` and `GetExtendedUdpTable`, read every 5 seconds by the
//! sampling capture, for both address families. The bytes are parsed by [`super::parse::conntable`].

#![allow(unsafe_code)]

use std::ffi::c_void;

use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use super::parse::conntable;
use crate::security::conntable::Socket;

const NO_ERROR: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// A table, as the API fills it: asked for its size, then read into a buffer of that size, again if the table grew in between.
fn table(call: impl Fn(*mut c_void, *mut u32) -> u32) -> Vec<u8> {
    let mut size = 0u32;
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..8 {
        let at = if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr().cast() };
        match call(at, &mut size) {
            NO_ERROR => {
                buf.truncate(size as usize);
                return buf;
            }
            // room for the rows that appear while the call is made
            ERROR_INSUFFICIENT_BUFFER => buf = vec![0u8; size as usize + 1024],
            _ => return Vec::new(),
        }
    }
    Vec::new()
}

/// The TCP and UDP sockets of this machine, with the pid that owns each where a row has one.
pub fn read() -> Vec<Socket> {
    // SAFETY: each call is given a pointer to a buffer of at least the size it is told, and a pointer to that size
    let tcp = |family: u16| {
        table(|buf, size| unsafe { GetExtendedTcpTable(buf, size, 0, u32::from(family), TCP_TABLE_OWNER_PID_ALL, 0) })
    };
    let udp = |family: u16| {
        table(|buf, size| unsafe { GetExtendedUdpTable(buf, size, 0, u32::from(family), UDP_TABLE_OWNER_PID, 0) })
    };
    let mut sockets = conntable::tcp4(&tcp(AF_INET));
    sockets.extend(conntable::tcp6(&tcp(AF_INET6)));
    sockets.extend(conntable::udp4(&udp(AF_INET)));
    sockets.extend(conntable::udp6(&udp(AF_INET6)));
    sockets
}
