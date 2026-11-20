//! Length-prefixed frames on QUIC streams (7.3): a u32 big-endian length, then at most 4 MB of body.

use iroh::endpoint::{RecvStream, SendStream};
use rackhand_proto::frame::{FrameError, MAX_FRAME};

/// Reads one frame; the length is checked before the body is read. A stream that ends before a frame starts is
/// [`FrameError::Closed`].
pub async fn read(recv: &mut RecvStream) -> Result<Vec<u8>, FrameError> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.map_err(|_| FrameError::Closed)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await.map_err(|_| FrameError::Closed)?;
    Ok(body)
}

pub async fn write(send: &mut SendStream, body: &[u8]) -> Result<(), FrameError> {
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    send.write_all(&out).await.map_err(|e| FrameError::Io(std::io::Error::other(e.to_string())))
}

pub async fn write_msg<M: prost::Message>(send: &mut SendStream, msg: &M) -> Result<(), FrameError> {
    write(send, &msg.encode_to_vec()).await
}
