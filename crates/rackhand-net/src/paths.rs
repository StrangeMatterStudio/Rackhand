//! Which path a connection uses (7.3.4, 7.3.11, S3): a connection starts on the relay and moves to a direct path when the NATs
//! let a hole be punched. Bulk transfers wait for the direct path (`wait_direct`); the dashboard shows what is in use.

use std::time::{Duration, Instant};

use iroh::endpoint::Connection;

/// The path that carries application data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// An IP path between the two endpoints.
    Direct,
    /// Through a relay.
    Relay,
    /// No path is selected (the connection is closing, or hasn't opened one).
    None,
}

/// The selected path of a connection.
pub fn kind(conn: &Connection) -> PathKind {
    // a closed connection keeps its last snapshot, which says nothing about now
    if conn.close_reason().is_some() {
        return PathKind::None;
    }
    let paths = conn.paths();
    match paths.iter().find(|p| p.is_selected()) {
        Some(p) if p.is_ip() => PathKind::Direct,
        Some(p) if p.is_relay() => PathKind::Relay,
        _ => PathKind::None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no direct path within {0:?}")]
pub struct NoDirectPath(pub Duration);

/// Waits until a direct path is the selected one. Returns how long that took, or an error once `timeout` has passed.
pub async fn wait_direct(conn: &Connection, timeout: Duration) -> Result<Duration, NoDirectPath> {
    let started = Instant::now();
    if conn.close_reason().is_some() {
        return Err(NoDirectPath(timeout));
    }
    let mut paths = conn.paths_stream();
    let found = tokio::time::timeout(timeout, paths.wait_any(|p| p.is_ip() && p.is_selected())).await;
    match found {
        Ok(Some(_)) => Ok(started.elapsed()),
        _ => Err(NoDirectPath(timeout)),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::testing::Pair;

    use rackhand_proto::alpn;

    const ALPN: &[u8] = alpn::PEER;

    #[tokio::test]
    async fn two_endpoints_on_one_machine_reach_a_direct_path() {
        let pair = Pair::new(&[ALPN]).await;
        pair.registry.allow(ALPN, pair.client.id());
        let conn = pair.client.connect(pair.server_addr(), ALPN).await.expect("the connection opens");
        // it starts on whatever path came first and moves to the direct one
        let took = wait_direct(&conn, Duration::from_secs(10)).await.expect("a direct path on loopback");
        assert!(took < Duration::from_secs(10));
        assert_eq!(kind(&conn), PathKind::Direct);
    }

    #[tokio::test]
    async fn a_closed_connection_has_no_path_and_never_gets_a_direct_one() {
        let pair = Pair::new(&[ALPN]).await;
        pair.registry.allow(ALPN, pair.client.id());
        let conn = pair.client.connect(pair.server_addr(), ALPN).await.expect("the connection opens");
        conn.close(0u32.into(), b"done");
        let _ = conn.closed().await;
        assert_eq!(kind(&conn), PathKind::None);
        assert_eq!(wait_direct(&conn, Duration::from_millis(200)).await, Err(NoDirectPath(Duration::from_millis(200))));
    }
}
