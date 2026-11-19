//! Which endpoint ids may use which ALPN (7.1, 7.3). The hub's Registry system implements [`Admission`] over its
//! tables; [`MemoryRegistry`] is the in-memory version used by probes, relays and tests.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use iroh::EndpointId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Allowed,
    Unknown,
    Revoked,
}

pub trait Registry: Send + Sync + std::fmt::Debug {
    fn admission(&self, alpn: &[u8], id: &EndpointId) -> Admission;
}

#[derive(Debug, Default)]
pub struct MemoryRegistry {
    allowed: RwLock<HashMap<Vec<u8>, HashSet<EndpointId>>>,
    revoked: RwLock<HashSet<EndpointId>>,
}

impl MemoryRegistry {
    pub fn allow(&self, alpn: &[u8], id: EndpointId) {
        if let Ok(mut map) = self.allowed.write() {
            map.entry(alpn.to_vec()).or_default().insert(id);
        }
        if let Ok(mut revoked) = self.revoked.write() {
            revoked.remove(&id);
        }
    }

    /// Removes the id from every ALPN; its next connection is closed with `0x13`.
    pub fn revoke(&self, id: EndpointId) {
        if let Ok(mut map) = self.allowed.write() {
            for ids in map.values_mut() {
                ids.remove(&id);
            }
        }
        if let Ok(mut revoked) = self.revoked.write() {
            revoked.insert(id);
        }
    }
}

impl Registry for MemoryRegistry {
    fn admission(&self, alpn: &[u8], id: &EndpointId) -> Admission {
        if self.revoked.read().map(|r| r.contains(id)).unwrap_or(false) {
            return Admission::Revoked;
        }
        let allowed = self.allowed.read().map(|m| m.get(alpn).is_some_and(|ids| ids.contains(id))).unwrap_or(false);
        if allowed { Admission::Allowed } else { Admission::Unknown }
    }
}
