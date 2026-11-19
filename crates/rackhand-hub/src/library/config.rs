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
}

impl Default for Sources {
    fn default() -> Self {
        Sources { feodo: true, spamhaus: true, dbip: true }
    }
}

/// `config/hub.toml`: the settings edited in the dashboard.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubConfig {
    #[serde(default)]
    pub sources: Sources,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_mirror: Option<GitMirror>,
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
        Some(text) => toml::from_str(&text).map_err(|e| ConfigError::Parse(HUB.into(), e.to_string())),
        None => Ok(HubConfig::default()),
    }
}
