//! Building a node's iroh endpoint: its node key, its relays, its ALPNs, no address lookup services by default.

use std::net::SocketAddr;

use iroh::{Endpoint, SecretKey};

use crate::relays::RelayConfig;

#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error(transparent)]
    Relay(#[from] crate::relays::InvalidRelay),
    #[error("binding the endpoint: {0}")]
    Bind(String),
}

#[derive(Debug, Clone, Default)]
pub struct EndpointConfig {
    pub relays: RelayConfig,
    pub alpns: Vec<Vec<u8>>,
    /// A fixed UDP address to bind (hubs and relays); random when `None`.
    pub bind: Option<SocketAddr>,
}

/// iroh's QUIC settings without segmentation offload (GSO). A NIC without TX checksum offload (common for virtual
/// NICs) fails the first segmented send with EIO; the UDP layer then stops segmenting, but iroh keeps the segment count
/// a connection started with, so that connection's large sends (a join's answer, a big report) never arrive. Rackhand's
/// traffic is small, so sending one datagram at a time costs little.
pub fn transport() -> iroh::endpoint::QuicTransportConfig {
    iroh::endpoint::QuicTransportConfig::builder().enable_segmentation_offload(false).build()
}

pub async fn bind(key: SecretKey, config: &EndpointConfig) -> Result<Endpoint, EndpointError> {
    let mut builder = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(key)
        .transport_config(transport())
        .relay_mode(config.relays.relay_mode()?)
        .alpns(config.alpns.clone());
    if let Some(addr) = config.bind {
        builder = builder.bind_addr(addr).map_err(|e| EndpointError::Bind(e.to_string()))?;
    }
    builder.bind().await.map_err(|e| EndpointError::Bind(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segmentation_offload_is_off() {
        // On a NIC without TX checksum offload the first segmented send fails with EIO, and iroh keeps the segment
        // count it read when the connection started, so that connection's large sends never get through (plan L2).
        let ours = format!("{:?}", transport());
        assert!(ours.contains("enable_segmentation_offload: false"), "{ours}");
        let default = format!("{:?}", iroh::endpoint::QuicTransportConfig::default());
        assert!(default.contains("enable_segmentation_offload: true"), "iroh's default changed: {default}");
    }
}
