//! iroh endpoint, relay config, ALPN routing, node key and registry checks (design 7.2, Net).
//!
//! Every Rackhand process has an Ed25519 node key that is its iroh endpoint id (7.1). The [`router::Router`] accepts a
//! connection only from ids registered for its ALPN, except on `rackhand/join/1`, and closes the rest with the codes
//! from 7.3.

pub mod endpoint;
pub mod frames;
pub mod key;
pub mod paths;
pub mod registry;
pub mod relays;
pub mod router;
#[cfg(feature = "testing")]
pub mod testing;
pub mod ticket;

use iroh::endpoint::ConnectionError;
use rackhand_proto::close::CloseCode;

/// Closes a connection with a Rackhand close code (7.3).
pub fn close(conn: &iroh::endpoint::Connection, code: CloseCode) {
    conn.close((code as u32).into(), code.reason());
}

/// The Rackhand close code the peer closed with, if any.
pub fn close_code(reason: &ConnectionError) -> Option<CloseCode> {
    match reason {
        ConnectionError::ApplicationClosed(close) => CloseCode::from_code(close.error_code.into_inner()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    mod key;
    mod relays;
    mod router;
}
