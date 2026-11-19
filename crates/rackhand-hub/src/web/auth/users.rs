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

/// A stored passkey and its credential row.
#[derive(Debug, Clone)]
pub struct StoredPasskey {
    pub credential_id: String,
    pub created_at: i64,
    pub passkey: webauthn_rs::prelude::Passkey,
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
    pub passkeys: Vec<StoredPasskey>,
}

impl Account {
    /// A TOTP or a passkey: what sign-in's second step and step-up need (7.7.2).
    pub fn has_local_factor(&self) -> bool {
        self.totp.is_some() || !self.passkeys.is_empty()
    }
}

/// A local account by name, for the password step.
pub fn find(db: &Db, name: &str) -> Result<Option<Account>, UserError> {
    load(db, "name = ?1 AND auth = 'local'", name)
}

/// Any enabled account by id (local or OIDC), for step-up and passkeys.
pub fn find_by_id(db: &Db, id: &str) -> Result<Option<Account>, UserError> {
    load(db, "id = ?1", id)
}

struct CredentialRow {
    id: String,
    kind: String,
    data: Vec<u8>,
    step: Option<i64>,
    created_at: i64,
}

fn load(db: &Db, filter: &str, value: &str) -> Result<Option<Account>, UserError> {
    let sql = format!("SELECT id, name, role FROM users WHERE {filter} AND disabled_at IS NULL");
    let found: Option<(String, String, String)> =
        db.readers().with(|c| c.query_row(&sql, [value], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional())?;
    let Some((id, name, role)) = found else { return Ok(None) };
    let Some(role) = parse_role(&role) else { return Ok(None) };
    let creds: Vec<CredentialRow> = db.readers().with(|c| {
        let mut s =
            c.prepare("SELECT id, kind, data, last_totp_step, created_at FROM credentials WHERE user_id = ?1")?;
        let rows = s.query_map([&id], |r| {
            Ok(CredentialRow {
                id: r.get(0)?,
                kind: r.get(1)?,
                data: r.get(2)?,
                step: r.get(3)?,
                created_at: r.get(4)?,
            })
        })?;
        rows.collect()
    })?;
    let mut account = Account { id, name, role, password_hash: None, totp: None, passkeys: Vec::new() };
    for c in creds {
        match c.kind.as_str() {
            "password" => account.password_hash = Some(String::from_utf8_lossy(&c.data).into_owned()),
            "totp" => {
                let text = String::from_utf8_lossy(&c.data).into_owned();
                account.totp = text.strip_prefix("vault:").map(|v| (c.id, v.to_string(), c.step));
            }
            "passkey" => match serde_json::from_slice(&c.data) {
                Ok(passkey) => {
                    account.passkeys.push(StoredPasskey { credential_id: c.id, created_at: c.created_at, passkey })
                }
                Err(e) => tracing::warn!(error = %e, "unreadable passkey"),
            },
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

/// How a new account signs in.
#[derive(Debug, Clone, Copy)]
pub enum NewUser<'a> {
    Local {
        password: &'a str,
    },
    /// Through the OIDC provider, matched by its `sub` claim.
    Oidc {
        subject: &'a str,
    },
}

/// Creates an account with its TOTP secret (sealed in the Vault). Local accounts also get their password.
pub async fn create(
    db: &Arc<Db>,
    vault: &Vault,
    name: &str,
    role: Role,
    new: NewUser<'_>,
    totp_secret: &[u8],
    now_ms: i64,
) -> Result<String, UserError> {
    let subject = match new {
        NewUser::Local { password } => {
            return create_local(db, vault, name, role, password, Some(totp_secret), now_ms).await;
        }
        NewUser::Oidc { subject } => subject,
    };
    let id = ulid::Ulid::new().to_string();
    let user: Row = [
        ("id", Value::Text(id.clone())),
        ("name", Value::Text(name.into())),
        ("role", Value::Text(role_name(role).into())),
        ("auth", Value::Text("oidc".into())),
        ("oidc_subject", Value::Text(subject.into())),
        ("created_at", Value::Integer(now_ms)),
    ]
    .into_iter()
    .collect();
    let vault_name = format!("totp:{id}");
    vault.put(&vault_name, &Secret::new(totp_secret.to_vec())).await.map_err(|e| UserError::Invalid(e.to_string()))?;
    let writes = vec![
        RowWrite::insert("users", user),
        credential(&id, "totp", format!("vault:{vault_name}").into_bytes(), now_ms),
    ];
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
