//! Hub configuration stored with revisions (7.8: edited in the dashboard, stored with revisions, mirrored to git as
//! `config/<name>.toml`). Kept as library items of kind `config`, beside runbooks and playbooks.

use std::sync::Arc;

use rackhand_store::{Db, Row, RowWrite, StoreError, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;
use serde::{Deserialize, Serialize};

pub const HUB: &str = "hub";

/// The outside sources (7.8.5), each on or off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sources {
    pub feodo: bool,
    pub spamhaus: bool,
    pub dbip: bool,
    /// Air-gapped mode: the hub makes no outside request at all (D65).
    #[serde(default)]
    pub airgapped: bool,
    /// Off unless enabled: MaxMind GeoLite2 (own license key), online reputation lookups (send destinations out), relay
    /// lists (URLs the admin adds) and n0's public relays and DNS discovery (7.8.5).
    #[serde(default)]
    pub maxmind: bool,
    #[serde(default)]
    pub reputation: bool,
    #[serde(default)]
    pub relay_lists: bool,
    #[serde(default)]
    pub n0_relays: bool,
}

impl Default for Sources {
    fn default() -> Self {
        Sources {
            feodo: true,
            spamhaus: true,
            dbip: true,
            airgapped: false,
            maxmind: false,
            reputation: false,
            relay_lists: false,
            n0_relays: false,
        }
    }
}

/// `config/hub.toml`: the settings edited in the dashboard.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubConfig {
    #[serde(default)]
    pub sources: Sources,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_mirror: Option<GitMirror>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<Oidc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<ProbeSettings>,
    #[serde(default, skip_serializing_if = "AssistantSettings::is_default")]
    pub assistant: AssistantSettings,
    /// A URL a hub with no peers calls every 5 minutes, for a service outside the site that notices when it goes quiet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadman_url: Option<String>,
}

/// The assistant's settings (7.7.1): how many jobs a day the hub starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantSettings {
    #[serde(default = "daily_cap")]
    pub daily_cap: u32,
}

fn daily_cap() -> u32 {
    crate::assist::DEFAULT_DAILY_CAP
}

impl Default for AssistantSettings {
    fn default() -> Self {
        AssistantSettings { daily_cap: daily_cap() }
    }
}

impl AssistantSettings {
    fn is_default(&self) -> bool {
        *self == AssistantSettings::default()
    }
}

/// What every probe is told (7.8.1): its interval, the connection tuples per report, and its buffer's cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeSettings {
    #[serde(default = "interval_s")]
    pub interval_s: u32,
    #[serde(default = "connection_tuples")]
    pub connection_tuples: u32,
    #[serde(default = "buffer_max_mb")]
    pub buffer_max_mb: u32,
}

fn interval_s() -> u32 {
    15
}
fn connection_tuples() -> u32 {
    500
}
fn buffer_max_mb() -> u32 {
    64
}

impl Default for ProbeSettings {
    fn default() -> ProbeSettings {
        ProbeSettings {
            interval_s: interval_s(),
            connection_tuples: connection_tuples(),
            buffer_max_mb: buffer_max_mb(),
        }
    }
}

impl ProbeSettings {
    /// The ranges of 7.8.1; the buffer is at most 64 MB (5).
    pub fn check(&self) -> Result<(), String> {
        if !(5..=300).contains(&self.interval_s) {
            return Err(format!("probe.interval_s {}: 5 to 300", self.interval_s));
        }
        if !(100..=5000).contains(&self.connection_tuples) {
            return Err(format!("probe.connection_tuples {}: 100 to 5000", self.connection_tuples));
        }
        if !(1..=64).contains(&self.buffer_max_mb) {
            return Err(format!("probe.buffer_max_mb {}: 1 to 64", self.buffer_max_mb));
        }
        Ok(())
    }
}

/// OIDC sign-in (7.7.2). The client secret is in the Vault; `client_secret` names it (`secret:<name>`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Oidc {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// The hub's callback as registered with the provider: `https://<hub>/sign-in/oidc/callback`.
    pub redirect_url: String,
}

/// The library's git mirror (7.3.13). The deploy key is in the Vault, never here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitMirror {
    pub url: String,
    #[serde(default = "main_branch")]
    pub branch: String,
    /// The server's SHA-256 host key, learned on the first push.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_fingerprint: Option<String>,
}

fn main_branch() -> String {
    "main".into()
}

impl HubConfig {
    pub fn to_toml(&self) -> String {
        toml::to_string(self).unwrap_or_default()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("config/{0}.toml: {1}")]
    Parse(String, String),
}

/// The rows of a config item's first revision, to include in another command's transaction (first run).
pub fn first_revision_rows(name: &str, content: &str, author: &str, now_ms: i64) -> Vec<RowWrite> {
    let item: Row = [
        ("name", Value::Text(name.into())),
        ("kind", Value::Text("config".into())),
        ("origin", Value::Text("user".into())),
        ("rev", Value::Integer(1)),
    ]
    .into_iter()
    .collect();
    let rev: Row = [
        ("name", Value::Text(name.into())),
        ("kind", Value::Text("config".into())),
        ("rev", Value::Integer(1)),
        ("content", Value::Text(content.into())),
        ("author", Value::Text(author.into())),
        ("created_at", Value::Integer(now_ms)),
    ]
    .into_iter()
    .collect();
    vec![RowWrite::insert("library_items", item), RowWrite::insert("library_revisions", rev)]
}

/// Stores a new revision; returns its number.
pub async fn put(db: &Arc<Db>, name: &str, content: &str, author: &str, now_ms: i64) -> Result<i64, ConfigError> {
    let row: Row = [
        ("kind", Value::Text("config".into())),
        ("name", Value::Text(name.into())),
        ("content", Value::Text(content.into())),
        ("author", Value::Text(author.into())),
        ("created_at", Value::Integer(now_ms)),
    ]
    .into_iter()
    .collect();
    let ack = db.writer().send(WriteCmd::PutLibraryRevision(row)).await?;
    Ok(ack.rows as i64)
}

/// The current revision's content.
pub fn current(db: &Db, name: &str) -> Result<Option<String>, ConfigError> {
    Ok(db.readers().with(|c| {
        c.query_row(
            "SELECT r.content FROM library_items i JOIN library_revisions r ON r.kind = i.kind AND r.name = i.name AND r.rev = i.rev
             WHERE i.kind = 'config' AND i.name = ?1",
            [name],
            |r| r.get(0),
        )
        .optional()
    })?)
}

/// The hub settings, defaults if none are stored yet.
pub fn hub(db: &Db) -> Result<HubConfig, ConfigError> {
    match current(db, HUB)? {
        Some(text) => parse_hub(&text),
        None => Ok(HubConfig::default()),
    }
}

/// `config/hub.toml`, with its values in their ranges.
pub fn parse_hub(text: &str) -> Result<HubConfig, ConfigError> {
    let cfg: HubConfig = toml::from_str(text).map_err(|e| ConfigError::Parse(HUB.into(), e.to_string()))?;
    if let Some(p) = &cfg.probe {
        p.check().map_err(|e| ConfigError::Parse(HUB.into(), e))?;
    }
    Ok(cfg)
}
