//! One-time join tokens and invite secrets (7.3.1): 128-bit random, single use, bound to a kind, stored only as a
//! SHA-256 hash. Machine tokens last 60 minutes; device, operator and peer invites 24 hours.

use rackhand_proto::alpn;
use rackhand_store::{Row, RowWrite};
use rusqlite::types::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vault::master_key::crockford;

const MIN_MS: i64 = 60_000;
pub const MACHINE_TTL_MS: i64 = 60 * MIN_MS;
pub const INVITE_TTL_MS: i64 = 24 * 60 * MIN_MS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    Machine,
    Device,
    Operator,
    Peer,
}

impl TokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenKind::Machine => "machine",
            TokenKind::Device => "device",
            TokenKind::Operator => "operator",
            TokenKind::Peer => "peer",
        }
    }

    pub fn ttl_ms(self) -> i64 {
        if self == TokenKind::Machine { MACHINE_TTL_MS } else { INVITE_TTL_MS }
    }

    /// The ALPNs an id that joined with this kind may use (7.3.2, 7.3.4 to 7.3.6, 7.3.11).
    pub fn alpns(self) -> &'static [&'static [u8]] {
        match self {
            TokenKind::Machine => &[alpn::PROBE],
            // A person's device: tunnels, transfers, and MCP with their personal key (7.3.6).
            TokenKind::Device => &[alpn::TUNNEL, alpn::XFER, alpn::MCP],
            TokenKind::Operator => &[alpn::OPERATOR, alpn::MCP],
            TokenKind::Peer => &[alpn::PEER, alpn::XFER],
        }
    }
}

/// A token as shown once to the admin. It is never stored or logged.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(redacted)")
    }
}

impl Token {
    fn generate() -> Result<Token, getrandom::Error> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes)?;
        Ok(Token(crockford(&bytes)))
    }

    /// A token as typed or pasted; case and surrounding space don't matter.
    pub fn parse(text: &str) -> Token {
        Token(text.trim().to_ascii_uppercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The stored form of a token.
pub fn hash(token: &Token) -> [u8; 32] {
    Sha256::digest(token.as_str().to_ascii_uppercase().as_bytes()).into()
}

/// What a token is bound to (`join_tokens.bound`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bound {
    /// Machine tokens: the access level chosen in the dashboard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    /// Machine tokens: the machine the join enrolls (a new one, or an enrolled one changing level).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub level_change: bool,
    /// Device invites: the user the device belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

/// A new token and the row that stores its hash.
pub(crate) fn issue(
    kind: TokenKind,
    site_id: Option<&str>,
    bound: &Bound,
    created_by: &str,
    now_ms: i64,
) -> Result<(Token, RowWrite), IssueError> {
    let token = Token::generate()?;
    let mut row: Row = [
        ("id", Value::Text(ulid::Ulid::new().to_string())),
        ("kind", Value::Text(kind.as_str().into())),
        ("hash", Value::Blob(hash(&token).to_vec())),
        ("created_by", Value::Text(created_by.into())),
        ("expires_at", Value::Integer(now_ms + kind.ttl_ms())),
        ("bound", Value::Text(serde_json::to_string(bound)?)),
    ]
    .into_iter()
    .collect();
    if let Some(site) = site_id {
        row.insert("site_id", Value::Text(site.into()));
    }
    Ok((token, RowWrite::insert("join_tokens", row)))
}

#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    #[error("no randomness: {0}")]
    Random(#[from] getrandom::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// A stored token, looked up by hash.
#[derive(Debug, Clone)]
pub(crate) struct StoredToken {
    pub kind: String,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub bound: Bound,
}

pub(crate) fn find(readers: &rackhand_store::reader::ReadPool, token: &Token) -> rusqlite::Result<Option<StoredToken>> {
    use rusqlite::OptionalExtension;
    let h = hash(token);
    readers.with(|c| {
        c.query_row("SELECT kind, expires_at, used_at, bound FROM join_tokens WHERE hash = ?1", [h.as_slice()], |r| {
            let bound: Option<String> = r.get(3)?;
            Ok(StoredToken {
                kind: r.get(0)?,
                expires_at: r.get(1)?,
                used_at: r.get(2)?,
                bound: bound.and_then(|b| serde_json::from_str(&b).ok()).unwrap_or_default(),
            })
        })
        .optional()
    })
}
