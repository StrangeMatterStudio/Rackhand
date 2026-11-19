//! MCP credentials (7.3.6, 7.7.2): personal keys bound to a person's device, scope `read` or `read_request`, 90 days by
//! default and at most a year; job tokens bound to the operator that accepted the job, with its hosts and tools. Only
//! a SHA-256 hash of either is stored; the token is shown once.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use rackhand_store::ids::now_ms;
use rackhand_store::{Db, Row, StoreError, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;
use sha2::{Digest, Sha256};

pub const DEFAULT_KEY_MS: i64 = 90 * 86_400_000;
pub const MAX_KEY_MS: i64 = 365 * 86_400_000;
/// Personal keys and job tokens look different, so each is only ever looked up where it belongs.
pub const KEY_PREFIX: &str = "rk_";
pub const JOB_PREFIX: &str = "rj_";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Read,
    ReadRequest,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::ReadRequest => "read_request",
        }
    }

    pub fn parse(s: &str) -> Option<Scope> {
        match s {
            "read" => Some(Scope::Read),
            "read_request" => Some(Scope::ReadRequest),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("{0}")]
    Invalid(&'static str),
}

pub fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn token(prefix: &str) -> Result<String, KeyError> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| KeyError::Invalid("no randomness"))?;
    Ok(format!("{prefix}{}", B64.encode(b)))
}

/// A personal key for `user_id`'s device: returns its id and the token, shown once.
pub async fn create_personal_key(
    db: &Db,
    user_id: &str,
    device_id: &str,
    scope: Scope,
    expires_at: i64,
) -> Result<(String, String), KeyError> {
    if expires_at > now_ms() + MAX_KEY_MS {
        return Err(KeyError::Invalid("a key lasts at most a year"));
    }
    let owned: Option<i64> = db.readers().with(|c| {
        c.query_row(
            "SELECT 1 FROM devices WHERE id = ?1 AND user_id = ?2 AND revoked_at IS NULL",
            [device_id, user_id],
            |r| r.get(0),
        )
        .optional()
    })?;
    if owned.is_none() {
        return Err(KeyError::Invalid("the device isn't one of the user's"));
    }
    let id = ulid::Ulid::new().to_string();
    let secret = token(KEY_PREFIX)?;
    let row: Row = [
        ("id", Value::Text(id.clone())),
        ("user_id", Value::Text(user_id.into())),
        ("device_id", Value::Text(device_id.into())),
        ("scope", Value::Text(scope.as_str().into())),
        ("hash", Value::Blob(hash(&secret))),
        ("expires_at", Value::Integer(expires_at)),
    ]
    .into_iter()
    .collect();
    db.writer().send(WriteCmd::PutMcpKey(row)).await?;
    Ok((id, secret))
}

pub async fn revoke_personal_key(db: &Db, key_id: &str, now_ms: i64) -> Result<(), KeyError> {
    let row: Row = [("id", Value::Text(key_id.into())), ("revoked_at", Value::Integer(now_ms))].into_iter().collect();
    db.writer().send(WriteCmd::PutMcpKey(row)).await?;
    Ok(())
}

/// A new token for the job, bound to another operator (the next one offered the job); the old token stops working.
pub async fn rebind_job_token(db: &Db, job_id: &str, operator_id: &str) -> Result<String, KeyError> {
    let secret = token(JOB_PREFIX)?;
    let row: Row = [
        ("job_id", Value::Text(job_id.into())),
        ("operator_id", Value::Text(operator_id.into())),
        ("hash", Value::Blob(hash(&secret))),
    ]
    .into_iter()
    .collect();
    db.writer().send(WriteCmd::PutJobToken(row)).await?;
    Ok(secret)
}

/// A job's token for the operator that accepted it (Assist, T76): its hosts and its playbook's tools.
pub async fn issue_job_token(
    db: &Db,
    job_id: &str,
    operator_id: &str,
    hosts: &[&str],
    tools: &[&str],
    expires_at: i64,
) -> Result<String, KeyError> {
    let secret = token(JOB_PREFIX)?;
    let row: Row = [
        ("job_id", Value::Text(job_id.into())),
        ("operator_id", Value::Text(operator_id.into())),
        ("hash", Value::Blob(hash(&secret))),
        ("hosts", Value::Text(serde_json::to_string(hosts).unwrap_or_else(|_| "[]".into()))),
        ("tools", Value::Text(serde_json::to_string(tools).unwrap_or_else(|_| "[]".into()))),
        ("expires_at", Value::Integer(expires_at)),
    ]
    .into_iter()
    .collect();
    db.writer().send(WriteCmd::PutJobToken(row)).await?;
    Ok(secret)
}
