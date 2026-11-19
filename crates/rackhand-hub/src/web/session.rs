//! Sessions (7.7.2): a random cookie whose SHA-256 is the stored id; 12 hours absolute, 2 hours idle.

use std::sync::Arc;

use rackhand_store::{Db, Row, StoreError, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;
use sha2::{Digest, Sha256};

use super::perms::{Role, parse_role};

pub const COOKIE: &str = "rh_session";
pub const ANON_COOKIE: &str = "rh_anon";
pub const ABSOLUTE_MS: i64 = 12 * 3_600_000;
pub const IDLE_MS: i64 = 2 * 3_600_000;

/// `Secure; HttpOnly; SameSite=Strict` on every cookie the hub sets.
pub fn cookie(name: &str, value: &str, max_age_s: i64) -> String {
    format!("{name}={value}; Path=/; Max-Age={max_age_s}; Secure; HttpOnly; SameSite=Strict")
}

pub(crate) fn random_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub(crate) fn hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("no randomness: {0}")]
    Random(#[from] getrandom::Error),
}

/// Starts a session for the user and returns the cookie value.
pub async fn create(db: &Arc<Db>, user_id: &str, now_ms: i64) -> Result<String, SessionError> {
    let token = random_token()?;
    let row: Row = [
        ("id_hash", Value::Blob(hash(&token).to_vec())),
        ("user_id", Value::Text(user_id.into())),
        ("created_at", Value::Integer(now_ms)),
        ("last_seen_at", Value::Integer(now_ms)),
        ("expires_at", Value::Integer(now_ms + ABSOLUTE_MS)),
    ]
    .into_iter()
    .collect();
    db.writer().send(WriteCmd::PutSession(row)).await?;
    Ok(token)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionUser {
    pub id_hash: [u8; 32],
    pub user_id: String,
    pub name: String,
    pub role: Role,
    pub step_up_at: Option<i64>,
}

/// The session's user, if the session exists, hasn't expired or gone idle, and the user is enabled.
pub fn lookup(db: &Db, token: &str, now_ms: i64) -> rusqlite::Result<Option<SessionUser>> {
    let h = hash(token);
    let row: Option<(String, String, String, Option<i64>)> = db.readers().with(|c| {
        c.query_row(
            "SELECT u.id, u.name, u.role, s.step_up_at FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.id_hash = ?1 AND s.expires_at > ?2 AND s.last_seen_at > ?3 AND u.disabled_at IS NULL",
            rusqlite::params![h.as_slice(), now_ms, now_ms - IDLE_MS],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
    })?;
    Ok(row.and_then(|(user_id, name, role, step_up_at)| {
        Some(SessionUser { id_hash: h, user_id, name, role: parse_role(&role)?, step_up_at })
    }))
}
