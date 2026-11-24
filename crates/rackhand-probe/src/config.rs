//! `/etc/rackhand-probe/probe.toml` (7.3.3, D91): root-owned, written by the installer and `set-hub` only. It pins the
//! hub (its endpoint id, which is also the key that signs command lists and key updates), says where to reach it,
//! and names this machine and its access level. The wrapper and the daemon both read it through this module.

use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;

#[cfg(unix)]
pub const PATH: &str = "/etc/rackhand-probe/probe.toml";
/// Where the Windows probe keeps its files (7.3.3): ACLs allow only SYSTEM, Administrators and the probe service.
#[cfg(windows)]
pub const PATH: &str = r"C:\ProgramData\Rackhand\probe\probe.toml";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("probe.toml: {0}")]
    Read(String),
    #[error("probe.toml: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeToml {
    pub hub: HubSection,
    #[serde(default)]
    pub machine: Option<MachineSection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubSection {
    /// The hub's node key (its endpoint id), 64 hex characters.
    pub id: String,
    /// Direct addresses of the hub's QUIC endpoint, from the join.
    #[serde(default)]
    pub addrs: Vec<SocketAddr>,
    /// Relay URLs, from the join.
    #[serde(default)]
    pub relays: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSection {
    /// This machine's id at the hub (a ULID), from the join.
    pub id: String,
    /// `managed` or `monitor` (7.3.12).
    #[serde(default = "managed")]
    pub access: String,
    /// `local` or `remote` (D60).
    #[serde(default = "local")]
    pub mode: String,
}

fn managed() -> String {
    "managed".into()
}

fn local() -> String {
    "local".into()
}

impl ProbeToml {
    pub fn parse(text: &str) -> Result<ProbeToml, ConfigError> {
        let cfg: ProbeToml = toml::from_str(text).map_err(|e| ConfigError::Invalid(e.to_string()))?;
        cfg.hub_key()?;
        if let Some(m) = &cfg.machine {
            cfg.machine_id()?;
            if !["managed", "monitor"].contains(&m.access.as_str()) {
                return Err(ConfigError::Invalid(format!("machine.access {:?} isn't managed or monitor", m.access)));
            }
            if !["local", "remote"].contains(&m.mode.as_str()) {
                return Err(ConfigError::Invalid(format!("machine.mode {:?} isn't local or remote", m.mode)));
            }
        }
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<ProbeToml, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Read(format!("{}: {e}", path.display())))?;
        ProbeToml::parse(&text)
    }

    /// The pinned hub key's 32 bytes.
    pub fn hub_key(&self) -> Result<[u8; 32], ConfigError> {
        let id = self.hub.id.trim();
        if id.len() != 64 {
            return Err(ConfigError::Invalid("hub.id isn't 64 hex characters".into()));
        }
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&id[2 * i..2 * i + 2], 16)
                .map_err(|_| ConfigError::Invalid("hub.id isn't hex".into()))?;
        }
        Ok(bytes)
    }

    /// This machine's id, once the machine has joined.
    pub fn machine_id(&self) -> Result<[u8; 16], ConfigError> {
        let m = self.machine.as_ref().ok_or_else(|| ConfigError::Invalid("no [machine] section".into()))?;
        let id: ulid::Ulid = m.id.parse().map_err(|_| ConfigError::Invalid("machine.id isn't a ULID".into()))?;
        Ok(id.to_bytes())
    }
}
