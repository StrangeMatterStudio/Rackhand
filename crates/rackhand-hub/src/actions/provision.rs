//! Provisioning a guest (7.3.12, FR-23): the hub's side of `provision-vm` and `provision-lxc`. The runbook makes the
//! machine as the dashboard's Add would (pending, with a 60-minute token), has the hypervisor create the guest, has the
//! guest enroll itself with that token, and binds it: the runbook that created the guest confirms its binding, since no
//! probe has said anything about it yet.

use rackhand_proto::common::{Access, ProbeMode};
use rackhand_store::{Db, RegistryChange, Row, RowUpdate, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;
use ulid::Ulid;

use crate::registry::Registry;
use crate::registry::machines::AddMachine;
use crate::registry::tokens::Token;

#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("the hypervisor isn't a machine of this hub")]
    NoHost,
    #[error("a machine of that name is already here")]
    NameTaken,
    #[error("no such machine made by a provisioning run")]
    NoMachine,
    #[error("the machine is bound to a guest already")]
    AlreadyBound,
    #[error("{0}")]
    Other(String),
}

fn other(e: impl std::fmt::Display) -> ProvisionError {
    ProvisionError::Other(e.to_string())
}

fn site_of(db: &Db, machine: &str) -> Result<Option<String>, ProvisionError> {
    db.readers()
        .with(|c| c.query_row("SELECT site_id FROM machines WHERE id = ?1", [machine], |r| r.get(0)).optional())
        .map_err(other)
}

/// The machine for a guest about to be made, on its hypervisor's site, and the token its installer joins with.
pub async fn pending_guest(
    registry: &Registry,
    host: &str,
    name: &str,
    by: &str,
    now_ms: i64,
) -> Result<(Ulid, Token), ProvisionError> {
    let site_id = site_of(registry.db(), host)?.ok_or(ProvisionError::NoHost)?;
    if named(registry.db(), &site_id, name).is_some() {
        return Err(ProvisionError::NameTaken);
    }
    let add = AddMachine {
        site_id,
        name: name.into(),
        kind: "linux".into(),
        access: Access::Managed,
        mode: ProbeMode::Local,
        roles: vec![],
    };
    registry.add_machine(&add, by, now_ms).await.map_err(other)
}

/// The machine of that name on a site: its id and state.
fn named(db: &Db, site_id: &str, name: &str) -> Option<(String, String)> {
    db.readers()
        .with(|c| {
            c.query_row("SELECT id, state FROM machines WHERE site_id = ?1 AND name = ?2", [site_id, name], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()
        })
        .ok()
        .flatten()
}

/// The machine `name` on `host`'s site, if it exists: its id and state.
pub fn machine_named(db: &Db, host: &str, name: &str) -> Option<(String, String)> {
    named(db, &site_of(db, host).ok()??, name)
}

/// Whether the machine has enrolled: its probe joined and, for a managed one, the hub's SSH test passed (D84).
pub fn is_enrolled(db: &Db, host: &str, name: &str) -> bool {
    machine_named(db, host, name).is_some_and(|(_, state)| state == "enrolled")
}

/// Binds the machine to the guest the runbook made, confirmed: only a machine of the host's site that has no binding.
pub async fn bind_guest(
    db: &Db,
    host: &str,
    node: &str,
    machine: &str,
    kind: &str,
    vmid: u64,
    by: &str,
) -> Result<(), ProvisionError> {
    if !["qemu", "lxc"].contains(&kind) {
        return Err(ProvisionError::Other("a guest is qemu or lxc".into()));
    }
    let found: Option<(String, String)> = db
        .readers()
        .with(|c| {
            c.query_row("SELECT kind, proxmox_ref_state FROM machines WHERE id = ?1", [machine], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()
        })
        .map_err(other)?;
    let (machine_kind, state) = found.ok_or(ProvisionError::NoMachine)?;
    let (machine_site, host_site) = (site_of(db, machine)?, site_of(db, host)?);
    if machine_site.is_none() || machine_site != host_site || machine == host || machine_kind == "hypervisor" {
        return Err(ProvisionError::NoMachine);
    }
    if state != "none" {
        return Err(ProvisionError::AlreadyBound);
    }
    let reference = serde_json::json!({ "cluster": host, "node": node, "vmid": vmid, "type": kind }).to_string();
    let set = Row::from([
        ("proxmox_ref", Value::Text(reference)),
        ("proxmox_ref_state", Value::Text("confirmed".into())),
        ("proxmox_ref_confirmed_by", Value::Text(by.into())),
    ]);
    let update = RowUpdate { table: "machines", key: ("id", Value::Text(machine.into())), set };
    let change = RegistryChange { updates: vec![update], ..Default::default() };
    db.writer().send(WriteCmd::RegistryChange(change)).await.map_err(other)?;
    Ok(())
}

#[cfg(test)]
#[path = "provision_tests.rs"]
mod tests;
