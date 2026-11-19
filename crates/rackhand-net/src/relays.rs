//! Relay configuration: the hub's own relays first; n0's public relays and DNS discovery only when enabled (7.3.10,
//! D51, NG10).

use std::sync::Arc;

use iroh::{RelayMap, RelayMode, RelayUrl};

#[derive(Debug, Clone, Default)]
pub struct RelayConfig {
    /// The operator's own relays, in order.
    pub relays: Vec<String>,
    /// Use n0's public relays (off by default).
    pub n0_relays: bool,
    /// Use n0's DNS discovery (off by default).
    pub n0_discovery: bool,
    /// Auth token presented to keyed relays (spike S2).
    pub auth_token: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid relay URL `{0}`")]
pub struct InvalidRelay(String);

impl RelayConfig {
    pub fn relay_mode(&self) -> Result<RelayMode, InvalidRelay> {
        if self.relays.is_empty() {
            return Ok(if self.n0_relays { RelayMode::Default } else { RelayMode::Disabled });
        }
        let map = RelayMap::empty();
        for url in &self.relays {
            let parsed: RelayUrl = url.parse().map_err(|_| InvalidRelay(url.clone()))?;
            let mut config = iroh::RelayConfig::from(parsed.clone());
            if let Some(token) = &self.auth_token {
                config = config.with_auth_token(token.clone());
            }
            map.insert(parsed, Arc::new(config));
        }
        Ok(RelayMode::Custom(map))
    }
}
