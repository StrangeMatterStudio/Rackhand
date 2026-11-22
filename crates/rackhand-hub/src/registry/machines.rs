//! Machines: "Add machine" creates the pending row and its token; the join enrolls it (7.3.12).

use iroh::EndpointId;
use rackhand_proto::common::{Access, ProbeMode};
use rackhand_store::{Row, RowUpdate, RowWrite, WriteCmd};
use rusqlite::types::Value;
use ulid::Ulid;

use super::tokens::{self, Bound, Token, TokenKind};
use super::{Registry, RegistryError};

/// The dashboard's "Add machine" form.
#[derive(Debug, Clone)]
pub struct AddMachine {
    pub site_id: String,
    pub name: String,
    /// `linux`, `alpine`, `windows`, `appliance` or `hypervisor`.
    pub kind: String,
    pub access: Access,
    pub mode: ProbeMode,
    pub roles: Vec<String>,
}

pub(crate) fn access_name(access: Access) -> Option<&'static str> {
    match access {
        Access::Managed => Some("managed"),
        Access::Monitor => Some("monitor"),
        Access::Unspecified => None,
    }
}

pub(crate) fn mode_name(mode: ProbeMode) -> Option<&'static str> {
    match mode {
        ProbeMode::Local => Some("local"),
        ProbeMode::Remote => Some("remote"),
        ProbeMode::Unspecified => None,
    }
}

impl Registry {
    /// Creates the machine as `pending` and returns its id and a 60-minute token for the install command.
    pub async fn add_machine(
        &self,
        add: &AddMachine,
        created_by: &str,
        now_ms: i64,
    ) -> Result<(Ulid, Token), RegistryError> {
        let access = access_name(add.access).ok_or_else(|| RegistryError::Invalid("access level".into()))?;
        let mode = mode_name(add.mode).ok_or_else(|| RegistryError::Invalid("probe mode".into()))?;
        let id = Ulid::new();
        let machine: Row = [
            ("id", Value::Text(id.to_string())),
            ("site_id", Value::Text(add.site_id.clone())),
            ("name", Value::Text(add.name.clone())),
            ("kind", Value::Text(add.kind.clone())),
            ("mode", Value::Text(mode.into())),
            ("access", Value::Text(access.into())),
            ("roles", Value::Text(serde_json::to_string(&add.roles).map_err(tokens::IssueError::from)?)),
            ("state", Value::Text("pending".into())),
        ]
        .into_iter()
        .collect();
        let bound = Bound {
            access: Some(access.into()),
            machine_id: Some(id.to_string()),
            roles: add.roles.clone(),
            ..Bound::default()
        };
        let (token, token_row) = tokens::issue(TokenKind::Machine, Some(&add.site_id), &bound, created_by, now_ms)?;
        self.db().writer().send(WriteCmd::Batch(vec![RowWrite::insert("machines", machine), token_row])).await?;
        Ok((id, token))
    }

    /// A one-time token that changes an enrolled machine's access level; the join keeps its id and history.
    pub async fn level_change_token(
        &self,
        machine_id: Ulid,
        access: Access,
        created_by: &str,
        now_ms: i64,
    ) -> Result<Token, RegistryError> {
        let access = access_name(access).ok_or_else(|| RegistryError::Invalid("access level".into()))?;
        let id = machine_id.to_string();
        let (site_id, roles): (String, String) = self.db().readers().with(|c| {
            c.query_row("SELECT site_id, roles FROM machines WHERE id = ?1 AND state = 'enrolled'", [&id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
        })?;
        let bound = Bound {
            access: Some(access.into()),
            machine_id: Some(id),
            roles: serde_json::from_str(&roles).unwrap_or_default(),
            level_change: true,
            ..Bound::default()
        };
        let (token, row) = tokens::issue(TokenKind::Machine, Some(&site_id), &bound, created_by, now_ms)?;
        self.db().writer().send(WriteCmd::Batch(vec![row])).await?;
        Ok(token)
    }

    /// The enrolling update of a machine's join-owned columns. Everything else on the row (policy, tags, roles,
    /// guest binding) is left as it is. A managed machine's first join leaves it `pending` until the hub's SSH test
    /// passes (D84); a monitor machine, or a machine joining again, is `enrolled`.
    pub(crate) fn enroll_change(
        machine_id: &str,
        endpoint: EndpointId,
        access: &str,
        mode: &str,
        os: &str,
        first_enrollment: bool,
        now_ms: i64,
    ) -> RowUpdate {
        let state = if first_enrollment && access == "managed" { "pending" } else { "enrolled" };
        let mut set: Row = [
            ("probe_endpoint_id", Value::Text(endpoint.to_string())),
            ("access", Value::Text(access.into())),
            ("mode", Value::Text(mode.into())),
            ("os", Value::Text(os.into())),
            ("state", Value::Text(state.into())),
        ]
        .into_iter()
        .collect();
        if first_enrollment {
            set.insert("enrolled_at", Value::Integer(now_ms));
        }
        RowUpdate { table: "machines", key: ("id", Value::Text(machine_id.into())), set }
    }

    /// Whether a driver is attached to the machine, so its `address` names the driver's API.
    pub(crate) fn machine_has_driver(&self, machine_id: &str) -> rusqlite::Result<bool> {
        self.db()
            .readers()
            .with(|c| c.query_row("SELECT driver IS NOT NULL FROM machines WHERE id = ?1", [machine_id], |r| r.get(0)))
    }

    /// The machine's current probe endpoint id, if it has enrolled before.
    pub(crate) fn machine_endpoint(&self, machine_id: &str) -> rusqlite::Result<Option<String>> {
        use rusqlite::OptionalExtension;
        self.db()
            .readers()
            .with(|c| {
                c.query_row("SELECT probe_endpoint_id FROM machines WHERE id = ?1", [machine_id], |r| r.get(0))
                    .optional()
            })
            .map(Option::flatten)
    }
}
