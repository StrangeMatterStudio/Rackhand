//! Length-prefixed frames: a u32 big-endian length, then the body, at most 4 MB on the wire (7.3).

use std::io::{Read, Write};

/// The largest frame body accepted or sent.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame of {0} bytes is over the 4 MB limit")]
    TooLarge(usize),
    #[error("stream ended")]
    Closed,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn write_frame(w: &mut impl Write, body: &[u8]) -> Result<(), FrameError> {
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(body)?;
    Ok(())
}

/// Reads one frame. The length is checked before anything is allocated or read for the body.
pub fn read_frame(r: &mut impl Read) -> Result<Vec<u8>, FrameError> {
    let mut len = [0u8; 4];
    if let Err(e) = r.read_exact(&mut len) {
        return Err(if e.kind() == std::io::ErrorKind::UnexpectedEof { FrameError::Closed } else { e.into() });
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Encodes a message as a frame.
pub fn encode<M: prost::Message>(msg: &M) -> Result<Vec<u8>, FrameError> {
    let body = msg.encode_to_vec();
    let mut out = Vec::with_capacity(body.len() + 4);
    write_frame(&mut out, &body)?;
    Ok(out)
}
