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

pub async fn bind(key: SecretKey, config: &EndpointConfig) -> Result<Endpoint, EndpointError> {
    let mut builder = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(key)
        .relay_mode(config.relays.relay_mode()?)
        .alpns(config.alpns.clone());
    if let Some(addr) = config.bind {
        builder = builder.bind_addr(addr).map_err(|e| EndpointError::Bind(e.to_string()))?;
    }
    builder.bind().await.map_err(|e| EndpointError::Bind(e.to_string()))
}
