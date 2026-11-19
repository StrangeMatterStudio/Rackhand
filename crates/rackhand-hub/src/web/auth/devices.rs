//! Device cookies (7.7.2): a browser that has signed in to an account carries a cookie that gives it its own sign-in
//! limit for that account.

use rackhand_store::{Db, Row, StoreError, WriteCmd};
use rusqlite::types::Value;

use crate::web::session::{hash, random_token};

pub const DEVICE_COOKIE: &str = "rh_device";
pub const MAX_AGE_S: i64 = 365 * 24 * 3600;

#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("no randomness: {0}")]
    Random(#[from] getrandom::Error),
}

pub fn hash_hex(token: &str) -> String {
    hash(token).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn is_known(db: &Db, user_id: &str, token: &str) -> bool {
    db.readers()
        .with(|c| {
            c.query_row(
                "SELECT EXISTS (SELECT 1 FROM known_devices WHERE user_id = ?1 AND cookie_hash = ?2)",
                rusqlite::params![user_id, hash(token).as_slice()],
                |r| r.get(0),
            )
        })
        .unwrap_or(false)
}

/// Remembers the browser for the account after a sign-in; returns a new cookie value if it had none for it.
pub async fn remember(
    db: &Db,
    user_id: &str,
    current: Option<&str>,
    now_ms: i64,
) -> Result<Option<String>, DeviceError> {
    let (token, new) = match current.filter(|t| is_known(db, user_id, t)) {
        Some(t) => (t.to_string(), false),
        None => (random_token()?, true),
    };
    let row: Row = [
        ("user_id", Value::Text(user_id.into())),
        ("cookie_hash", Value::Blob(hash(&token).to_vec())),
        ("first_seen_at", Value::Integer(now_ms)),
        ("last_seen_at", Value::Integer(now_ms)),
    ]
    .into_iter()
    .collect();
    db.writer().send(WriteCmd::PutKnownDevice(row)).await?;
    Ok(new.then_some(token))
}
