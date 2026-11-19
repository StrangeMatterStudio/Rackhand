use std::time::Duration;

use rackhand_proto::alpn;
use rackhand_proto::close::CloseCode;

use crate::testing::Pair;

async fn closed_with(pair: &Pair, alpn: &[u8]) -> Option<CloseCode> {
    let conn = pair.client.connect(pair.server_addr(), alpn).await.ok()?;
    let reason = tokio::time::timeout(Duration::from_secs(10), conn.closed()).await.ok()?;
    crate::close_code(&reason)
}

#[tokio::test]
async fn unregistered_id_is_closed_with_0x10() {
    let pair = Pair::new(&[alpn::PROBE, alpn::JOIN]).await;
    assert_eq!(closed_with(&pair, alpn::PROBE).await, Some(CloseCode::UnknownPeer));
}

#[tokio::test]
async fn join_alpn_accepts_unregistered() {
    let pair = Pair::new(&[alpn::PROBE, alpn::JOIN]).await;
    let conn = pair.client.connect(pair.server_addr(), alpn::JOIN).await.expect("join connects");
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    let echoed = recv.read_to_end(64).await.unwrap();
    assert_eq!(echoed, b"ping", "the join handler ran for an unregistered id");
}

#[tokio::test]
async fn revoked_id_is_closed_with_0x13() {
    let pair = Pair::new(&[alpn::PROBE, alpn::JOIN]).await;
    pair.registry.allow(alpn::PROBE, pair.client.id());
    let conn = pair.client.connect(pair.server_addr(), alpn::PROBE).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"hi").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(64).await.unwrap(), b"hi", "registered id is served");
    conn.close(0u32.into(), b"done");
    pair.registry.revoke(pair.client.id());
    assert_eq!(closed_with(&pair, alpn::PROBE).await, Some(CloseCode::Revoked));
}

#[tokio::test]
async fn unknown_alpn_is_refused() {
    let pair = Pair::new(&[alpn::PROBE, alpn::JOIN]).await;
    pair.registry.allow(alpn::PEER, pair.client.id());
    let result =
        tokio::time::timeout(Duration::from_secs(10), pair.client.connect(pair.server_addr(), alpn::PEER)).await;
    assert!(matches!(result, Ok(Err(_))), "an ALPN the server doesn't serve can't connect");
}
