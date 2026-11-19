//! Local accounts and their credentials.

use std::sync::Arc;

use rackhand_store::{Db, Row, RowWrite, StoreError, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;

use super::password;
use crate::policy::approvals::Role;
use crate::vault::{Secret, Vault};
use crate::web::perms::{parse_role, role_name};

#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("{0}")]
    Invalid(String),
}

/// What sign-in needs about an account.
#[derive(Debug, Clone)]
pub struct Account {
    pub id: String,
    pub name: String,
    pub role: Role,
    pub password_hash: Option<String>,
    /// The TOTP credential's id, its Vault name and the newest step accepted.
    pub totp: Option<(String, String, Option<i64>)>,
}

pub fn find(db: &Db, name: &str) -> Result<Option<Account>, UserError> {
    let found: Option<(String, String, String)> = db.readers().with(|c| {
        c.query_row(
            "SELECT id, name, role FROM users WHERE name = ?1 AND disabled_at IS NULL AND auth = 'local'",
            [name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
    })?;
    let Some((id, name, role)) = found else { return Ok(None) };
    let Some(role) = parse_role(&role) else { return Ok(None) };
    let creds: Vec<(String, String, Vec<u8>, Option<i64>)> = db.readers().with(|c| {
        let mut s = c.prepare("SELECT id, kind, data, last_totp_step FROM credentials WHERE user_id = ?1")?;
        let rows = s.query_map([&id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        rows.collect()
    })?;
    let mut account = Account { id, name, role, password_hash: None, totp: None };
    for (cid, kind, data, step) in creds {
        let text = String::from_utf8_lossy(&data).into_owned();
        match kind.as_str() {
            "password" => account.password_hash = Some(text),
            "totp" => account.totp = text.strip_prefix("vault:").map(|v| (cid, v.to_string(), step)),
            _ => {}
        }
    }
    Ok(Some(account))
}

/// Creates a local account with a password and, normally, a TOTP secret (sealed in the Vault).
pub async fn create_local(
    db: &Arc<Db>,
    vault: &Vault,
    name: &str,
    role: Role,
    password: &str,
    totp_secret: Option<&[u8]>,
    now_ms: i64,
) -> Result<String, UserError> {
    if password.chars().count() < password::MIN_LENGTH {
        return Err(UserError::Invalid("the password needs at least 12 characters".into()));
    }
    let hash = password::hash(password).map_err(UserError::Invalid)?;
    let id = ulid::Ulid::new().to_string();
    let user: Row = [
        ("id", Value::Text(id.clone())),
        ("name", Value::Text(name.into())),
        ("role", Value::Text(role_name(role).into())),
        ("auth", Value::Text("local".into())),
        ("created_at", Value::Integer(now_ms)),
    ]
    .into_iter()
    .collect();
    let mut writes = vec![RowWrite::insert("users", user), credential(&id, "password", hash.into_bytes(), now_ms)];
    if let Some(secret) = totp_secret {
        let vault_name = format!("totp:{id}");
        vault.put(&vault_name, &Secret::new(secret.to_vec())).await.map_err(|e| UserError::Invalid(e.to_string()))?;
        writes.push(credential(&id, "totp", format!("vault:{vault_name}").into_bytes(), now_ms));
    }
    db.writer().send(WriteCmd::Batch(writes)).await?;
    Ok(id)
}

pub(crate) fn credential(user_id: &str, kind: &str, data: Vec<u8>, now_ms: i64) -> RowWrite {
    let row: Row = [
        ("id", Value::Text(ulid::Ulid::new().to_string())),
        ("user_id", Value::Text(user_id.into())),
        ("kind", Value::Text(kind.into())),
        ("data", Value::Blob(data)),
        ("created_at", Value::Integer(now_ms)),
    ]
    .into_iter()
    .collect();
    RowWrite::insert("credentials", row)
}

/// Records that a TOTP step was used, if no later step has been: a code (or its step) works once.
pub async fn use_totp_step(db: &Db, credential_id: &str, step: i64) -> Result<bool, UserError> {
    let row: Row =
        [("id", Value::Text(credential_id.into())), ("last_totp_step", Value::Integer(step))].into_iter().collect();
    match db.writer().send(WriteCmd::PutCredential(row)).await {
        Ok(_) => Ok(true),
        Err(StoreError::Conflict(_)) => Ok(false),
        Err(e) => Err(e.into()),
    }
}
