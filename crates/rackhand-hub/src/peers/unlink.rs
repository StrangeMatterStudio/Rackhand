//! Unlinking (7.3.4): either side sends `PeerUnlink` (or just removes the peer); both remove the other's endpoint id. A removed
//! peer gets `0x13` on its next connect, because admission no longer lists it.

use rackhand_store::ids::now_ms;
use rackhand_store::{Row, RowUpdate};
use rusqlite::types::Value;

use super::{PeerRow, Peers};

impl Peers {
    /// Removes the peer from this hub: it is revoked, and its summary goes with it.
    pub async fn remove_peer(&self, peer: &PeerRow, by: &str, why: &str) -> Result<(), rackhand_store::StoreError> {
        let update = RowUpdate {
            table: "peers",
            key: ("id", Value::Text(peer.id.clone())),
            set: Row::from([("revoked_at", Value::Integer(now_ms()))]),
        };
        let change = rackhand_store::RegistryChange { updates: vec![update], ..Default::default() };
        self.inner.db.writer().send(rackhand_store::WriteCmd::RegistryChange(change)).await?;
        if let (Some(registry), Ok(id)) =
            (self.inner.registry.lock().ok().and_then(|r| r.clone()), peer.endpoint_id.parse::<iroh::EndpointId>())
        {
            registry.revoke(id);
        }
        let data = serde_json::json!({ "site": peer.site, "why": why }).to_string();
        let _ = self.inner.audit.append(by, "peer.unlinked", Some(&peer.id), &data).await;
        Ok(())
    }

    /// The peer unlinked itself.
    pub(super) async fn unlinked_by(&self, peer: &PeerRow, reason: &str) {
        if let Err(e) = self.remove_peer(peer, &format!("peer:{}", peer.site), reason).await {
            tracing::warn!(error = %e, peer = %peer.site, "unlinking a peer");
        }
    }
}
