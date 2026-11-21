//! Agentless machines (7.3.12): an appliance, or a Proxmox host's API, added through a dashboard form per driver. The
//! form is a join of its own: its address first, which creates the pending machine (or names the enrolled machine the
//! API belongs to) and a one-time `agentless` token bound to the driver, the address and the certificate shown; then
//! the accepted certificate and the credentials, which use the token up in the same transaction that stores the
//! credentials in the Vault and enrolls the machine. The row keeps the settings with each credential as a `secret:`
//! reference.

use rackhand_store::{ConsumeToken, RegistryChange, Row, RowUpdate, RowWrite, StoreError, TokenRefusal, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;
use ulid::Ulid;

use super::tokens::{self, Bound, StoredToken, Token, TokenKind};
use super::{Registry, RegistryError};

/// The first half of an appliance form.
#[derive(Debug, Clone)]
pub struct AddAppliance {
    pub site_id: String,
    /// The new machine's name; unused when `attach` names the machine.
    pub name: String,
    /// The driver's name: `proxmox`, `truenas`, `redfish` or `snmp`.
    pub driver: String,
    pub address: String,
    /// The certificate fingerprint shown to the admin, for the HTTPS drivers.
    pub fingerprint: Option<String>,
    /// An enrolled machine the API belongs to (a Proxmox host that runs a probe), instead of a new machine.
    pub attach: Option<String>,
}

/// An appliance form waiting for its second half.
#[derive(Debug, Clone)]
pub struct ApplianceForm {
    pub machine_id: String,
    pub driver: String,
    pub address: String,
    pub fingerprint: Option<String>,
}

/// The settings' credentials, each replaced by the reference to the Vault entry that holds them all.
pub fn referenced(settings: &serde_json::Value, secrets: &[&str], vault_name: &str) -> serde_json::Value {
    let mut shown = settings.clone();
    if let Some(m) = shown.as_object_mut() {
        for (k, v) in m.iter_mut() {
            if secrets.contains(&k.as_str()) {
                *v = serde_json::Value::String(format!("secret:{vault_name}"));
            }
        }
    }
    shown
}

/// The Vault entry that holds an agentless machine's driver settings, credentials included.
pub fn vault_name(machine_id: &str) -> String {
    format!("driver.{machine_id}")
}

impl Registry {
    /// Creates the pending machine (unless the form attaches to one) and the form's one-time token.
    pub async fn add_appliance(
        &self,
        add: &AddAppliance,
        created_by: &str,
        now_ms: i64,
    ) -> Result<(String, Token), RegistryError> {
        let mut writes = Vec::new();
        let machine_id = match &add.attach {
            Some(id) => {
                let state: Option<String> = self.db().readers().with(|c| {
                    c.query_row("SELECT state FROM machines WHERE id = ?1 AND site_id = ?2", [id, &add.site_id], |r| {
                        r.get(0)
                    })
                    .optional()
                })?;
                if state.as_deref() != Some("enrolled") {
                    return Err(RegistryError::Invalid("the machine isn't an enrolled machine here".into()));
                }
                id.clone()
            }
            None => {
                let id = Ulid::new().to_string();
                let kind = if add.driver == "proxmox" { "hypervisor" } else { "appliance" };
                let row: Row = [
                    ("id", Value::Text(id.clone())),
                    ("site_id", Value::Text(add.site_id.clone())),
                    ("name", Value::Text(add.name.clone())),
                    ("kind", Value::Text(kind.into())),
                    ("address", Value::Text(add.address.clone())),
                    ("driver", Value::Text(add.driver.clone())),
                    ("state", Value::Text("pending".into())),
                ]
                .into_iter()
                .collect();
                writes.push(RowWrite::insert("machines", row));
                id
            }
        };
        let bound = Bound {
            machine_id: Some(machine_id.clone()),
            driver: Some(add.driver.clone()),
            address: Some(add.address.clone()),
            fingerprint: add.fingerprint.clone(),
            ..Bound::default()
        };
        let (token, row) = tokens::issue(TokenKind::Agentless, Some(&add.site_id), &bound, created_by, now_ms)?;
        writes.push(row);
        self.db().writer().send(WriteCmd::Batch(writes)).await?;
        Ok((machine_id, token))
    }

    /// The form a token opens, if it is an unused, unexpired appliance form.
    pub fn appliance_form(&self, token: &Token, now_ms: i64) -> Result<ApplianceForm, RegistryError> {
        let refused = |r| RegistryError::Store(StoreError::TokenRefused(r));
        let StoredToken { kind, expires_at, used_at, bound } =
            tokens::find(self.db().readers(), token)?.ok_or_else(|| refused(TokenRefusal::Unknown))?;
        if kind != TokenKind::Agentless.as_str() {
            return Err(refused(TokenRefusal::WrongKind));
        }
        if used_at.is_some() {
            return Err(refused(TokenRefusal::Used));
        }
        if expires_at <= now_ms {
            return Err(refused(TokenRefusal::Expired));
        }
        let (Some(machine_id), Some(driver), Some(address)) = (bound.machine_id, bound.driver, bound.address) else {
            return Err(RegistryError::Invalid("the form's token is incomplete".into()));
        };
        Ok(ApplianceForm { machine_id, driver, address, fingerprint: bound.fingerprint })
    }

    /// Completes the form: the token used up, the credentials sealed into the Vault (`secret`, a write from
    /// [`crate::vault::Vault::sealed`]) and the machine given its driver, settings and, if new, enrolled, all at once.
    /// A used or expired token changes nothing.
    pub async fn complete_appliance(
        &self,
        token: &Token,
        form: &ApplianceForm,
        shown_settings: &serde_json::Value,
        secret: RowWrite,
        now_ms: i64,
    ) -> Result<(), RegistryError> {
        let pending: Option<String> = self.db().readers().with(|c| {
            c.query_row("SELECT state FROM machines WHERE id = ?1", [&form.machine_id], |r| r.get(0)).optional()
        })?;
        let mut set: Row = [
            ("driver", Value::Text(form.driver.clone())),
            ("address", Value::Text(form.address.clone())),
            ("driver_settings", Value::Text(shown_settings.to_string())),
        ]
        .into_iter()
        .collect();
        if pending.as_deref() == Some("pending") {
            set.insert("state", Value::Text("enrolled".into()));
            set.insert("enrolled_at", Value::Integer(now_ms));
        }
        let change = RegistryChange {
            consume: Some(ConsumeToken {
                hash: tokens::hash(token).to_vec(),
                kind: TokenKind::Agentless.as_str().into(),
                now_ms,
            }),
            writes: vec![secret],
            updates: vec![RowUpdate { table: "machines", key: ("id", Value::Text(form.machine_id.clone())), set }],
        };
        self.db().writer().send(WriteCmd::RegistryChange(change)).await?;
        Ok(())
    }
}
