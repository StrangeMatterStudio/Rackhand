//! A hub whose address changes (E35, 7.3.2, 7.3.3): probes still reach it by endpoint id through a relay, and the hub tells each
//! connected probe the new addresses (`ConfigUpdate`) and, on managed machines, replaces the hub's SSH key lines with ones that
//! take the SSH from the new addresses (`KeysUpdate`, which the probe hands to its helper). A machine that can't reach the hub at
//! all, at a LAN-only site without a relay, is fixed on the machine with `rackhand-probe set-hub <ticket>`.

use std::sync::Arc;

use prost::Message;
use rackhand_proto::common::SignedPayload;
use rackhand_proto::probe::{ConfigUpdate, HubToProbe, KeysUpdate, hub_to_probe};
use rackhand_store::Db;
use rackhand_store::ids::now_ms;

use crate::executor::HubSide;
use crate::ingest::probe_server::ProbeServer;
use crate::ssh::keys::{Identity, load_for};
use crate::vault::Vault;

/// What one announcement did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Announced {
    /// Probes that were told the new addresses.
    pub configs: Vec<String>,
    /// Managed machines whose key lines were replaced with ones for the new addresses.
    pub keys: Vec<String>,
}

pub struct AddressChange {
    db: Arc<Db>,
    vault: Arc<Vault>,
    hub: Arc<dyn HubSide>,
    probes: ProbeServer,
}

impl std::fmt::Debug for AddressChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AddressChange")
    }
}

impl AddressChange {
    pub fn new(db: Arc<Db>, vault: Arc<Vault>, hub: Arc<dyn HubSide>, probes: ProbeServer) -> AddressChange {
        AddressChange { db, vault, hub, probes }
    }

    /// Whether a managed machine has the hub's accounts, and which: no assistant account on a machine with role `hub`.
    fn accounts(&self, machine: &str) -> Vec<Identity> {
        let row: Option<(String, String)> = self
            .db
            .readers()
            .with(|c| {
                use rusqlite::OptionalExtension;
                c.query_row("SELECT access, roles FROM machines WHERE id = ?1 AND state = 'enrolled'", [machine], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()
            })
            .ok()
            .flatten();
        let Some((access, roles)) = row else { return Vec::new() };
        if access != "managed" {
            return Vec::new();
        }
        let roles: Vec<String> = serde_json::from_str(&roles).unwrap_or_default();
        if roles.iter().any(|r| r == "hub") {
            vec![Identity::Automation]
        } else {
            vec![Identity::Automation, Identity::Assistant]
        }
    }

    /// The key update for a managed machine: each account's current key, from the hub's current addresses.
    async fn keys_for(&self, machine: &str) -> Option<KeysUpdate> {
        let identities = self.accounts(machine);
        if identities.is_empty() {
            return None;
        }
        let mut keys = serde_json::Map::new();
        for id in identities {
            let key = load_for(&self.vault, id, machine).await.ok()?;
            keys.insert(id.user().to_string(), serde_json::json!([key.public_key().to_openssh().ok()?]));
        }
        let body = serde_json::json!({ "from": self.hub.ssh_from(machine), "keys": keys });
        let signed = self.hub.signed_keys(now_ms(), body.to_string().as_bytes());
        let signed = SignedPayload::decode(signed.as_slice()).ok()?;
        Some(KeysUpdate { keys: Some(signed) })
    }

    /// What every Welcome says from now on, without telling the probes already connected.
    pub fn learn(&self, addrs: &[String], relays: &[String]) {
        self.probes.set_hub_addresses(addrs.to_vec(), relays.to_vec());
    }

    /// Tells every connected probe the hub's addresses, and the managed ones their new key lines.
    pub async fn announce(&self, addrs: &[String], relays: &[String]) -> Announced {
        self.probes.set_hub_addresses(addrs.to_vec(), relays.to_vec());
        let mut config = self.probes.config().clone();
        config.hub_addrs = addrs.to_vec();
        config.hub_relays = relays.to_vec();
        let mut done = Announced::default();
        for machine in self.probes.connected() {
            let update = ConfigUpdate { config: Some(config.clone()), config_rev: self.probes.config_rev() + 1 };
            let msg = HubToProbe { msg: Some(hub_to_probe::Msg::ConfigUpdate(update)) };
            if self.probes.send_to(&machine, msg).await {
                done.configs.push(machine.clone());
            }
            if let Some(keys) = self.keys_for(&machine).await {
                let msg = HubToProbe { msg: Some(hub_to_probe::Msg::KeysUpdate(keys)) };
                if self.probes.send_to(&machine, msg).await {
                    done.keys.push(machine.clone());
                }
            }
        }
        done
    }
}
