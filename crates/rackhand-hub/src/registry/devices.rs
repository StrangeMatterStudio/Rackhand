//! Devices: a person's laptop or phone, joined with an invite bound to their user (7.3.12).

use std::str::FromStr;

use iroh::EndpointId;
use rackhand_store::{RegistryChange, Row, RowUpdate, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;

use super::tokens::{self, Bound, Token, TokenKind};
use super::{Registry, RegistryError};

/// A device as the settings page lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    pub id: String,
    pub name: String,
    pub user: String,
    pub created_at: i64,
    pub last_seen_ms: Option<i64>,
    pub revoked_at: Option<i64>,
}

impl Registry {
    /// A 24-hour invite for one of `user_id`'s devices.
    pub async fn invite_device(&self, user_id: &str, created_by: &str, now_ms: i64) -> Result<Token, RegistryError> {
        let bound = Bound { user_id: Some(user_id.into()), ..Bound::default() };
        let (token, row) = tokens::issue(TokenKind::Device, None, &bound, created_by, now_ms)?;
        self.db().writer().send(WriteCmd::Batch(vec![row])).await?;
        Ok(token)
    }

    pub(crate) fn user_name(&self, user_id: &str) -> rusqlite::Result<Option<String>> {
        self.db().readers().with(|c| {
            c.query_row("SELECT name FROM users WHERE id = ?1 AND disabled_at IS NULL", [user_id], |r| r.get(0))
                .optional()
        })
    }

    pub fn devices(&self) -> rusqlite::Result<Vec<DeviceRow>> {
        self.db().readers().with(|c| {
            let mut s = c.prepare(
                "SELECT d.id, d.name, u.name, d.created_at, d.last_seen_ms, d.revoked_at
                 FROM devices d JOIN users u ON u.id = d.user_id ORDER BY d.created_at",
            )?;
            let rows = s.query_map([], |r| {
                Ok(DeviceRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    user: r.get(2)?,
                    created_at: r.get(3)?,
                    last_seen_ms: r.get(4)?,
                    revoked_at: r.get(5)?,
                })
            })?;
            rows.collect()
        })
    }

    /// Revokes a device: recorded first, then its endpoint id leaves admission, so its next connection is closed with
    /// `0x13`. Returns false for a device that doesn't exist or is already revoked.
    pub async fn revoke_device(&self, device_id: &str, now_ms: i64) -> Result<bool, RegistryError> {
        let found: Option<(String, Option<i64>)> = self.db().readers().with(|c| {
            c.query_row("SELECT endpoint_id, revoked_at FROM devices WHERE id = ?1", [device_id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()
        })?;
        let Some((endpoint, None)) = found else { return Ok(false) };
        let update = RowUpdate {
            table: "devices",
            key: ("id", Value::Text(device_id.into())),
            set: Row::from([("revoked_at", Value::Integer(now_ms))]),
        };
        let change = RegistryChange { updates: vec![update], ..Default::default() };
        self.db().writer().send(WriteCmd::RegistryChange(change)).await?;
        if let Ok(id) = EndpointId::from_str(&endpoint) {
            self.revoke(id);
        }
        Ok(true)
    }
}
