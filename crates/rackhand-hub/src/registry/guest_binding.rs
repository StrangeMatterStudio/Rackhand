//! Guest binding (7.3.12, D93, E50): which Proxmox guest a machine is. The hub compares the MAC addresses a machine's
//! probe reports with the guests' configured ones: with no binding, the one guest that matches is proposed; an admin
//! confirms a binding (`proxmox_ref`: `cluster`, the hypervisor machine; `node`, `vmid`, `type`), and from then on
//! reports never change it. A confirmed machine that reports another guest's MAC, or none of its own guest's, is
//! `mismatch` (one `machine.guest_binding_mismatch` warning), which blocks hypervisor-side actions until an admin
//! confirms a binding again: the one it had, or the guest it now looks like.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rackhand_store::{Db, RegistryChange, Row, RowUpdate, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;

use crate::ingest::{Event, Ingest, Severity};

/// A guest and the MACs of its network devices, as its hypervisor's configuration gives them.
#[derive(Debug, Clone, PartialEq)]
pub struct GuestMacs {
    /// The hypervisor machine.
    pub host: String,
    pub node: String,
    pub vmid: u64,
    /// `lxc` or `qemu`.
    pub kind: String,
    pub macs: Vec<String>,
}

impl GuestMacs {
    /// The binding that names this guest, as `proxmox_ref` holds it.
    pub fn reference(&self) -> String {
        serde_json::json!({ "cluster": self.host, "node": self.node, "vmid": self.vmid, "type": self.kind }).to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Unchanged,
    Proposed,
    Mismatch,
}

#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error(transparent)]
    Store(#[from] rackhand_store::StoreError),
    #[error(transparent)]
    Read(#[from] rusqlite::Error),
}

pub struct GuestBindings {
    db: Arc<Db>,
    ingest: Ingest,
    /// The guest a mismatched machine now looks like, offered to the admin (until confirmed or a restart).
    seen: Mutex<HashMap<String, String>>,
}

impl std::fmt::Debug for GuestBindings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestBindings").finish_non_exhaustive()
    }
}

/// A MAC as hex digits, whatever its case and separators.
fn norm(mac: &str) -> String {
    mac.chars().filter(char::is_ascii_hexdigit).collect::<String>().to_ascii_uppercase()
}

impl GuestBindings {
    pub fn new(db: Arc<Db>, ingest: Ingest) -> GuestBindings {
        GuestBindings { db, ingest, seen: Mutex::new(HashMap::new()) }
    }

    fn seen(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn current(&self, machine: &str) -> Result<Option<(Option<String>, String)>, BindingError> {
        Ok(self.db.readers().with(|c| {
            c.query_row("SELECT proxmox_ref, proxmox_ref_state FROM machines WHERE id = ?1", [machine], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()
        })?)
    }

    async fn set(
        &self,
        machine: &str,
        reference: Option<&str>,
        state: &str,
        by: Option<&str>,
    ) -> Result<(), BindingError> {
        let mut set = Row::from([("proxmox_ref_state", Value::Text(state.into()))]);
        if let Some(r) = reference {
            set.insert("proxmox_ref", Value::Text(r.into()));
        }
        if let Some(by) = by {
            set.insert("proxmox_ref_confirmed_by", Value::Text(by.into()));
        }
        let update = RowUpdate { table: "machines", key: ("id", Value::Text(machine.into())), set };
        let change = RegistryChange { consume: None, writes: vec![], updates: vec![update] };
        self.db.writer().send(WriteCmd::RegistryChange(change)).await?;
        Ok(())
    }

    /// What a machine's report says about its binding, given the guests' configured MACs.
    pub async fn observe(
        &self,
        machine: &str,
        reported: &[String],
        guests: &[GuestMacs],
        now_ms: i64,
    ) -> Result<Outcome, BindingError> {
        let Some((bound, state)) = self.current(machine)? else { return Ok(Outcome::Unchanged) };
        let reported: Vec<String> = reported.iter().map(|m| norm(m)).filter(|m| !m.is_empty()).collect();
        let matches = |g: &GuestMacs| g.macs.iter().any(|m| reported.contains(&norm(m)));
        let matching: Vec<&GuestMacs> = guests.iter().filter(|g| matches(g)).collect();
        // a MAC on two guests' configs proves nothing
        let looks_like = if matching.len() == 1 { Some(matching[0]) } else { None };
        match state.as_str() {
            "confirmed" => {
                let Some(own) = guests.iter().find(|g| Some(g.reference()) == bound) else {
                    return Ok(Outcome::Unchanged); // its host's configuration isn't known now: nothing to judge
                };
                if matches(own) && looks_like.is_none_or(|g| g == own) {
                    return Ok(Outcome::Unchanged);
                }
                let seen = looks_like.map(GuestMacs::reference);
                if let Some(s) = &seen {
                    self.seen().insert(machine.to_string(), s.clone());
                }
                self.set(machine, None, "mismatch", None).await?;
                let parse =
                    |s: &Option<String>| s.as_deref().and_then(|v| serde_json::from_str::<serde_json::Value>(v).ok());
                let data = serde_json::json!({ "bound": parse(&bound), "seen": parse(&seen), "reported": reported });
                let event = Event {
                    at_ms: now_ms,
                    ..Event::machine(machine, "machine.guest_binding_mismatch", Severity::Warning, data)
                };
                if let Err(e) = self.ingest.raise_event(event).await {
                    tracing::warn!(error = %e, "raising machine.guest_binding_mismatch");
                }
                Ok(Outcome::Mismatch)
            }
            "mismatch" => {
                if let Some(g) = looks_like {
                    self.seen().insert(machine.to_string(), g.reference());
                }
                Ok(Outcome::Unchanged)
            }
            // none or proposed: the one matching guest is the proposal
            _ => match looks_like {
                Some(g) if bound.as_deref() != Some(g.reference().as_str()) || state != "proposed" => {
                    self.set(machine, Some(&g.reference()), "proposed", None).await?;
                    Ok(Outcome::Proposed)
                }
                _ => Ok(Outcome::Unchanged),
            },
        }
    }

    /// An admin confirms `reference` as the machine's guest: the proposal or the binding it has, or after a mismatch
    /// the guest it now looks like. Returns false for any other.
    pub async fn confirm(&self, machine: &str, reference: &str, by: &str, _now_ms: i64) -> Result<bool, BindingError> {
        let Some((bound, _)) = self.current(machine)? else { return Ok(false) };
        let seen = self.seen().get(machine).cloned();
        if bound.as_deref() != Some(reference) && seen.as_deref() != Some(reference) {
            return Ok(false);
        }
        self.set(machine, Some(reference), "confirmed", Some(by)).await?;
        self.seen().remove(machine);
        Ok(true)
    }

    /// The guest a mismatched machine now looks like, if one.
    pub fn looks_like(&self, machine: &str) -> Option<String> {
        self.seen().get(machine).cloned()
    }
}

#[cfg(test)]
mod tests;
