//! Just enough WebSocket (RFC 6455) for TrueNAS's JSON-RPC API: the client handshake, masked text frames out, text
//! frames in (pings answered, a close ends it), over a stream the caller has secured; and the server side for the
//! simulator.

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC11B5A";
/// A frame bigger than this is refused (TrueNAS answers are a few hundred kilobytes at most).
const MAX_FRAME: u64 = 16 << 20;

fn accept_key(key: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, format!("{key}{GUID}").as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

/// Reads an HTTP head (up to the blank line).
async fn head<S: AsyncRead + Unpin>(s: &mut S) -> Result<String, String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if buf.len() > 16 * 1024 {
            return Err("an HTTP head over 16 KB".into());
        }
        if s.read(&mut byte).await.map_err(|e| e.to_string())? == 0 {
            return Err("the connection closed during the handshake".into());
        }
        buf.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()))
}

/// The client's opening handshake for `path` on `host`; an answer other than 101 is the error (its status line).
pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, host: &str, path: &str) -> Result<(), String> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
    let key = base64::engine::general_purpose::STANDARD.encode(nonce);
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    let answer = head(s).await?;
    let status = answer.lines().next().unwrap_or("").to_string();
    if !status.contains(" 101 ") {
        return Err(status);
    }
    if header(&answer, "Sec-WebSocket-Accept") != Some(accept_key(&key).as_str()) {
        return Err("the server's handshake answer doesn't match".into());
    }
    Ok(())
}

async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, opcode: u8, payload: &[u8], masked: bool) -> Result<(), String> {
    let mut frame = vec![0x80 | opcode];
    let mask_bit = if masked { 0x80 } else { 0 };
    match payload.len() {
        n if n < 126 => frame.push(mask_bit | n as u8),
        n if n <= u16::MAX as usize => {
            frame.push(mask_bit | 126);
            frame.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            frame.push(mask_bit | 127);
            frame.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    if masked {
        let mut mask = [0u8; 4];
        getrandom::fill(&mut mask).map_err(|e| e.to_string())?;
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    } else {
        frame.extend_from_slice(payload);
    }
    s.write_all(&frame).await.map_err(|e| e.to_string())
}

/// One frame: its opcode and payload (unmasked), whether it ends a message.
async fn read_frame<S: AsyncRead + Unpin>(s: &mut S) -> Result<(u8, bool, Vec<u8>), String> {
    let mut two = [0u8; 2];
    s.read_exact(&mut two).await.map_err(|e| e.to_string())?;
    let (fin, opcode, masked) = (two[0] & 0x80 != 0, two[0] & 0x0f, two[1] & 0x80 != 0);
    let len = match two[1] & 0x7f {
        126 => {
            let mut b = [0u8; 2];
            s.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            u64::from(u16::from_be_bytes(b))
        }
        127 => {
            let mut b = [0u8; 8];
            s.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            u64::from_be_bytes(b)
        }
        n => u64::from(n),
    };
    if len > MAX_FRAME {
        return Err(format!("a frame of {len} bytes"));
    }
    let mut mask = [0u8; 4];
    if masked {
        s.read_exact(&mut mask).await.map_err(|e| e.to_string())?;
    }
    let mut payload = vec![0u8; len as usize];
    s.read_exact(&mut payload).await.map_err(|e| e.to_string())?;
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Ok((opcode, fin, payload))
}

/// Sends a text message (masked, as a client must).
pub async fn send<S: AsyncWrite + Unpin>(s: &mut S, text: &str) -> Result<(), String> {
    write_frame(s, 1, text.as_bytes(), true).await
}

/// The next text message, pings answered on the way; a close is the error.
pub async fn recv<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Result<String, String> {
    recv_as(s, true).await
}

async fn recv_as<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, client: bool) -> Result<String, String> {
    let mut message = Vec::new();
    loop {
        let (opcode, fin, payload) = read_frame(s).await?;
        match opcode {
            0..=2 => {
                message.extend_from_slice(&payload);
                if fin {
                    return String::from_utf8(message).map_err(|_| "a text message that isn't UTF-8".into());
                }
            }
            8 => return Err("the server closed the connection".into()),
            9 => write_frame(s, 10, &payload, client).await?,
            _ => {}
        }
    }
}

/// The simulator's side: answers the handshake, then reads and writes messages.
#[cfg(any(test, feature = "sim"))]
pub mod server {
    use super::*;

    /// Reads the request; for a WebSocket upgrade answers 101 and returns `Ok(None)`, otherwise returns the head.
    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, upgrade: bool) -> Result<Option<String>, String> {
        let h = head(s).await?;
        let key = header(&h, "Sec-WebSocket-Key").map(str::to_string);
        match key {
            Some(key) if upgrade => {
                let answer = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                    accept_key(&key)
                );
                s.write_all(answer.as_bytes()).await.map_err(|e| e.to_string())?;
                Ok(None)
            }
            _ => Ok(Some(h)),
        }
    }

    pub async fn recv<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Result<String, String> {
        recv_as(s, false).await
    }

    pub async fn send<S: AsyncWrite + Unpin>(s: &mut S, text: &str) -> Result<(), String> {
        write_frame(s, 1, text.as_bytes(), false).await
    }
}
