//! Encrypted secrets (design 7.2, Vault; 7.4.1; 10). Values are sealed with XChaCha20-Poly1305 under the master key,
//! which never enters the database, so the database file alone reveals nothing (AC54).

pub mod master_key;

use std::sync::Arc;

use rackhand_store::Db;
use rackhand_store::ids::now_ms;
use rackhand_store::writer::{Row, StoreError, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;
use zeroize::Zeroizing;

use master_key::{MasterKey, Sealed};

/// A secret value in memory. It is wiped on drop and never printed.
#[derive(Clone)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Secret {
        Secret(Zeroizing::new(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Secret {
        Secret::new(s.as_bytes().to_vec())
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(redacted)")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("no master key (the hub needs its master.key credential)")]
    NoMasterKey,
    #[error("secret `{0}` doesn't exist")]
    NotFound(String),
    #[error("secret `{0}` can't be decrypted with this master key")]
    Decrypt(String),
    #[error("encryption failed")]
    Encrypt,
    #[error("the recovery code is not valid")]
    BadRecoveryCode,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

#[derive(Debug)]
pub struct Vault {
    key: MasterKey,
    db: Arc<Db>,
}

impl Vault {
    pub fn new(key: MasterKey, db: Arc<Db>) -> Vault {
        Vault { key, db }
    }

    pub async fn put(&self, name: &str, value: &Secret) -> Result<(), VaultError> {
        let sealed = self.key.seal(name, value.expose())?;
        let mut row = Row::new();
        row.insert("name", Value::Text(name.into()));
        row.insert("nonce", Value::Blob(sealed.nonce.to_vec()));
        row.insert("ciphertext", Value::Blob(sealed.ciphertext));
        row.insert("created_at", Value::Integer(now_ms()));
        self.db.writer().send(WriteCmd::PutSecret(row)).await?;
        Ok(())
    }

    /// `value` sealed as `name`, as a write to make in the same transaction as the change it belongs to.
    pub fn sealed(&self, name: &str, value: &Secret, now_ms: i64) -> Result<rackhand_store::RowWrite, VaultError> {
        let sealed = self.key.seal(name, value.expose())?;
        let mut row = Row::new();
        row.insert("name", Value::Text(name.into()));
        row.insert("nonce", Value::Blob(sealed.nonce.to_vec()));
        row.insert("ciphertext", Value::Blob(sealed.ciphertext));
        row.insert("created_at", Value::Integer(now_ms));
        Ok(rackhand_store::RowWrite::upsert("secrets", "name", row))
    }

    pub fn get(&self, name: &str) -> Result<Secret, VaultError> {
        let found: Option<(Vec<u8>, Vec<u8>)> = self.db.readers().with(|c| {
            c.query_row("SELECT nonce, ciphertext FROM secrets WHERE name = ?1", [name], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()
        })?;
        let (nonce, ciphertext) = found.ok_or_else(|| VaultError::NotFound(name.to_string()))?;
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| VaultError::Decrypt(name.to_string()))?;
        self.key.open(name, &Sealed { nonce, ciphertext })
    }

    /// Every stored value, for the git mirror's pre-push scan (7.3.13). Values that don't open are skipped.
    pub fn all_values(&self) -> Vec<Secret> {
        let names: Vec<String> = self
            .db
            .readers()
            .with(|c| {
                let mut s = c.prepare("SELECT name FROM secrets")?;
                let rows = s.query_map([], |r| r.get(0))?;
                rows.collect()
            })
            .unwrap_or_default();
        names.iter().filter_map(|n| self.get(n).ok()).collect()
    }
}

#[cfg(test)]
mod tests;
