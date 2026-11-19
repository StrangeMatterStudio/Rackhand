//! Host key pinning (7.3.7, E8): a machine's host keys come only from its authenticated join. A key that differs
//! blocks every connection and raises `ssh.host_key_changed` (critical); the offered key is held until an admin
//! accepts it with step-up.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use rackhand_proto::common::SshHostKey;
use rackhand_store::{Db, Row, StoreError, WriteCmd};
use rusqlite::types::Value;
use russh::keys::{HashAlg, PublicKey};
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyError {
    /// No key for the machine from a join.
    NotPinned,
    /// The machine offered a key that isn't the pinned one.
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyAlert {
    Changed { machine_id: String, key_type: String, offered: String },
}

impl HostKeyAlert {
    pub fn kind(&self) -> &'static str {
        "ssh.host_key_changed"
    }
    pub fn severity(&self) -> &'static str {
        "critical"
    }
}

pub fn fingerprint(key: &PublicKey) -> Option<String> {
    Some(key.fingerprint(HashAlg::Sha256).to_string())
}

fn key_type(key: &PublicKey) -> String {
    key.algorithm().as_str().to_string()
}

#[derive(Debug)]
pub struct HostKeys {
    db: Arc<Db>,
    /// machine id -> key type -> fingerprint, as stored.
    pinned: Mutex<HashMap<String, BTreeMap<String, String>>>,
    /// The key each machine offered instead, waiting for an admin.
    offered: Mutex<HashMap<String, (String, String)>>,
    alerts: mpsc::UnboundedSender<HostKeyAlert>,
}

impl HostKeys {
    pub fn new(db: Arc<Db>) -> (Arc<HostKeys>, mpsc::UnboundedReceiver<HostKeyAlert>) {
        let rows: Vec<(String, String, String)> = db
            .readers()
            .with(|c| {
                let mut s = c.prepare("SELECT machine_id, key_type, fingerprint FROM ssh_host_keys")?;
                let rows = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
                rows.collect()
            })
            .unwrap_or_default();
        let mut pinned: HashMap<String, BTreeMap<String, String>> = HashMap::new();
        for (m, t, f) in rows {
            pinned.entry(m).or_default().insert(t, f);
        }
        let (tx, rx) = mpsc::unbounded_channel();
        (Arc::new(HostKeys { db, pinned: Mutex::new(pinned), offered: Mutex::new(HashMap::new()), alerts: tx }), rx)
    }

    /// Whether the key a machine presents may be trusted.
    pub fn check(&self, machine_id: &str, key: &PublicKey) -> Result<(), HostKeyError> {
        let (Some(fp), kt) = (fingerprint(key), key_type(key)) else { return Err(HostKeyError::Changed) };
        let pinned = self.pinned.lock().map_err(|_| HostKeyError::NotPinned)?;
        let Some(keys) = pinned.get(machine_id).filter(|k| !k.is_empty()) else { return Err(HostKeyError::NotPinned) };
        if keys.get(&kt) == Some(&fp) {
            return Ok(());
        }
        drop(pinned);
        // One alert per offered key, not one per connection attempt.
        let offer = (kt.clone(), fp.clone());
        let first =
            self.offered.lock().map(|mut o| o.insert(machine_id.into(), offer.clone()) != Some(offer)).unwrap_or(true);
        if first {
            let _ =
                self.alerts.send(HostKeyAlert::Changed { machine_id: machine_id.into(), key_type: kt, offered: fp });
        }
        Err(HostKeyError::Changed)
    }

    /// Replaces the machine's pinned keys as a whole (`PutHostKey`: the machine and its keys as JSON).
    async fn store(
        &self,
        machine_id: &str,
        keys: &[(String, String)],
        by: &str,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        let list: Vec<serde_json::Value> = keys
            .iter()
            .map(|(t, f)| serde_json::json!({ "key_type": t, "fingerprint": f, "accepted_at": now_ms, "accepted_by": by }))
            .collect();
        let row: Row = [
            ("machine_id", Value::Text(machine_id.into())),
            ("keys", Value::Text(serde_json::Value::Array(list).to_string())),
        ]
        .into_iter()
        .collect();
        self.db.writer().send(WriteCmd::PutHostKey(row)).await?;
        if let Ok(mut p) = self.pinned.lock() {
            p.insert(machine_id.into(), keys.iter().cloned().collect());
        }
        Ok(())
    }

    /// Pins the keys a machine sent with its join.
    pub async fn pin_from_join(&self, machine_id: &str, keys: &[PublicKey], now_ms: i64) -> Result<(), StoreError> {
        let pairs: Vec<(String, String)> = keys.iter().filter_map(|k| Some((key_type(k), fingerprint(k)?))).collect();
        self.store(machine_id, &pairs, "join", now_ms).await
    }

    /// The same, from the join message's keys.
    pub async fn pin_join_message(&self, machine_id: &str, keys: &[SshHostKey], now_ms: i64) -> Result<(), StoreError> {
        let parsed: Vec<PublicKey> = keys
            .iter()
            .filter_map(|k| PublicKey::from_openssh(&format!("{} {}", k.algorithm, k.public_key)).ok())
            .collect();
        self.pin_from_join(machine_id, &parsed, now_ms).await
    }

    /// The key waiting for acceptance, if any.
    pub fn offered(&self, machine_id: &str) -> Option<(String, String)> {
        self.offered.lock().ok()?.get(machine_id).cloned()
    }

    /// An admin (after step-up) accepts the offered key in place of the pinned ones.
    pub async fn accept_offered(&self, machine_id: &str, by: &str, now_ms: i64) -> Result<bool, StoreError> {
        let Some(offer) = self.offered.lock().ok().and_then(|mut o| o.remove(machine_id)) else { return Ok(false) };
        self.store(machine_id, &[offer], by, now_ms).await?;
        Ok(true)
    }
}
