//! File descriptors on the helper socket (7.3.3, D196): the helper's answer to `EbpfCapture` carries the capture's map
//! descriptors as `SCM_RIGHTS` with its line, so the probe reads the maps without loading or attaching anything. An
//! answer with descriptors is the only one on its connection.

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};

use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer, SendAncillaryMessage,
    SendFlags,
};
use tokio::io::Interest;
use tokio::net::UnixStream;

/// The most descriptors one line carries (the capture passes three).
pub const MAX_FDS: usize = 8;

fn invalid(why: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, why.to_string())
}

/// Writes `bytes`, with `fds` attached to the first of them.
pub async fn send_line(stream: &UnixStream, bytes: &[u8], fds: &[BorrowedFd<'_>]) -> std::io::Result<()> {
    if fds.len() > MAX_FDS {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "too many descriptors for one line"));
    }
    let mut rest = bytes;
    let mut attach = !fds.is_empty();
    while !rest.is_empty() {
        let n = stream
            .async_io(Interest::WRITABLE, || {
                let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
                let mut control = SendAncillaryBuffer::new(&mut space);
                if attach && !control.push(SendAncillaryMessage::ScmRights(fds)) {
                    return Err(invalid("the descriptors don't fit"));
                }
                Ok(rustix::net::sendmsg(stream, &[IoSlice::new(rest)], &mut control, SendFlags::NOSIGNAL)?)
            })
            .await?;
        attach = false;
        rest = &rest[n..];
    }
    Ok(())
}

/// Reads up to and including the first newline, with the descriptors that came with it. More than `max` bytes
/// without a newline, more than [`MAX_FDS`] descriptors, or the end of the stream first, is an error.
pub async fn recv_line(stream: &UnixStream, max: usize) -> std::io::Result<(String, Vec<OwnedFd>)> {
    let mut line = Vec::new();
    let mut fds = Vec::new();
    loop {
        let mut buf = [0u8; 4096];
        let (n, got, cut) = stream
            .async_io(Interest::READABLE, || {
                let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
                let mut control = RecvAncillaryBuffer::new(&mut space);
                let msg = rustix::net::recvmsg(
                    stream,
                    &mut [IoSliceMut::new(&mut buf)],
                    &mut control,
                    RecvFlags::CMSG_CLOEXEC,
                )?;
                let mut got = Vec::new();
                for message in control.drain() {
                    if let RecvAncillaryMessage::ScmRights(received) = message {
                        got.extend(received);
                    }
                }
                Ok((msg.bytes, got, msg.flags.contains(ReturnFlags::CTRUNC)))
            })
            .await?;
        if cut {
            return Err(invalid("more descriptors than a line carries"));
        }
        fds.extend(got);
        if fds.len() > MAX_FDS {
            return Err(invalid("more descriptors than a line carries"));
        }
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed before the end of the line"));
        }
        line.extend_from_slice(&buf[..n]);
        if let Some(end) = line.iter().position(|b| *b == b'\n') {
            line.truncate(end + 1);
            return String::from_utf8(line).map(|l| (l, fds)).map_err(|_| invalid("not UTF-8"));
        }
        if line.len() > max {
            return Err(invalid("the line is too long"));
        }
    }
}

#[cfg(test)]
mod tests;
