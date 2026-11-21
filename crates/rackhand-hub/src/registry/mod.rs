//! Sites, machines, devices, operators, peers, tags and enrollment tokens (7.2, Registry; 7.3.1; 7.3.12).
//!
//! Admission (which endpoint ids may use which ALPN) is answered from memory: loaded from the tables at start and
//! updated by every join and revocation, so the router never waits on the database.

pub mod agentless;
pub mod devices;
pub mod guest_binding;
pub mod join_server;
pub mod machines;
pub mod operators;
pub mod peers;
pub mod tokens;

use std::str::FromStr;
use std::sync::Arc;

use iroh::EndpointId;
use rackhand_net::registry::{Admission, MemoryRegistry, Registry as Admit};
use rackhand_store::{Db, StoreError};

use tokens::{IssueError, TokenKind};

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Issue(#[from] IssueError),
    #[error("{0}")]
    Invalid(String),
}

#[derive(Debug)]
pub struct Registry {
    db: Arc<Db>,
    admission: MemoryRegistry,
}

impl Registry {
    /// Loads admission from the tables: enrolled machines, and devices, operators and peers not revoked.
    pub fn load(db: Arc<Db>) -> Result<Arc<Registry>, RegistryError> {
        let registry = Registry { db, admission: MemoryRegistry::default() };
        let queries: [(&str, TokenKind); 4] = [
            (
                "SELECT probe_endpoint_id, state = 'revoked' FROM machines WHERE probe_endpoint_id IS NOT NULL",
                TokenKind::Machine,
            ),
            ("SELECT endpoint_id, revoked_at IS NOT NULL FROM devices", TokenKind::Device),
            ("SELECT endpoint_id, revoked_at IS NOT NULL FROM operators", TokenKind::Operator),
            ("SELECT endpoint_id, revoked_at IS NOT NULL FROM peers", TokenKind::Peer),
        ];
        for (sql, kind) in queries {
            let rows: Vec<(String, bool)> = registry.db.readers().with(|c| {
                let mut stmt = c.prepare(sql)?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                rows.collect()
            })?;
            for (id, revoked) in rows {
                let Ok(id) = EndpointId::from_str(&id) else {
                    tracing::warn!(%id, "unreadable endpoint id in the registry");
                    continue;
                };
                if revoked { registry.admission.revoke(id) } else { registry.allow(kind, id) }
            }
        }
        Ok(Arc::new(registry))
    }

    pub(crate) fn db(&self) -> &Arc<Db> {
        &self.db
    }

    pub(crate) fn allow(&self, kind: TokenKind, id: EndpointId) {
        for alpn in kind.alpns() {
            self.admission.allow(alpn, id);
        }
    }

    /// Removes the id from every ALPN; its next connection is closed with `0x13`.
    pub fn revoke(&self, id: EndpointId) {
        self.admission.revoke(id);
    }
}

impl Admit for Registry {
    fn admission(&self, alpn: &[u8], id: &EndpointId) -> Admission {
        self.admission.admission(alpn, id)
    }
}

#[cfg(test)]
mod tests;
