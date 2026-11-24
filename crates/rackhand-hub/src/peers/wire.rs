//! Framing on a peer stream: one byte that says what it is, then length-prefixed protobuf frames.

use iroh::endpoint::{RecvStream, SendStream};
use prost::Message;
use rackhand_proto::frame::MAX_FRAME;

pub async fn read_kind(recv: &mut RecvStream) -> Option<u8> {
    let mut b = [0u8; 1];
    recv.read_exact(&mut b).await.ok()?;
    Some(b[0])
}

pub async fn read<M: Message + Default>(recv: &mut RecvStream) -> Option<M> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.ok()?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return None;
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await.ok()?;
    M::decode(body.as_slice()).ok()
}

pub async fn write<M: Message>(send: &mut SendStream, msg: &M) -> bool {
    let body = msg.encode_to_vec();
    send.write_all(&(body.len() as u32).to_be_bytes()).await.is_ok() && send.write_all(&body).await.is_ok()
}

pub async fn write_kind(send: &mut SendStream, kind: u8) -> bool {
    send.write_all(&[kind]).await.is_ok()
}
