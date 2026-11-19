//! Policies and maintenance windows as stored (7.8, D33): the rows Policy owns, and `config/policies.toml`, the
//! revisioned copy the git mirror carries. Every change writes both.

use std::str::FromStr;
use std::sync::Arc;

use rackhand_store::{Db, Row, StoreError, WriteCmd};
use rusqlite::types::Value;
use serde::Serialize;

use crate::library::config;
use crate::scheduler::rrule::Recurrence;

pub const CONFIG_NAME: &str = "policies";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyRow {
    pub id: String,
    pub name: String,
    pub patch: String,
    pub auto_reboot: bool,
    pub auto_rollback: bool,
    pub snapshot: String,
    pub quarantine: String,
    pub peer_requests: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowRow {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    pub rrule: String,
    pub timezone: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Config(#[from] config::ConfigError),
}

fn one_of(field: &str, value: &str, allowed: &[&str]) -> Result<(), PolicyError> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(PolicyError::Invalid(format!("`{field}` is one of {}", allowed.join(", "))))
    }
}

pub fn policies(db: &Db) -> Result<Vec<PolicyRow>, PolicyError> {
    Ok(db.readers().with(|c| {
        let mut s = c.prepare(
            "SELECT id, name, patch, auto_reboot, auto_rollback, snapshot, quarantine, peer_requests FROM policies ORDER BY name",
        )?;
        let rows = s.query_map([], |r| {
            Ok(PolicyRow {
                id: r.get(0)?,
                name: r.get(1)?,
                patch: r.get(2)?,
                auto_reboot: r.get(3)?,
                auto_rollback: r.get(4)?,
                snapshot: r.get(5)?,
                quarantine: r.get(6)?,
                peer_requests: r.get(7)?,
            })
        })?;
        rows.collect()
    })?)
}

pub fn windows(db: &Db) -> Result<Vec<WindowRow>, PolicyError> {
    Ok(db.readers().with(|c| {
        let mut s = c.prepare("SELECT id, machine_id, tag, rrule, timezone FROM windows ORDER BY id")?;
        let rows = s.query_map([], |r| {
            Ok(WindowRow {
                id: r.get(0)?,
                machine_id: r.get(1)?,
                tag: r.get(2)?,
                rrule: r.get(3)?,
                timezone: r.get(4)?,
            })
        })?;
        rows.collect()
    })?)
}

#[derive(Serialize)]
struct File {
    policy: Vec<PolicyRow>,
    window: Vec<WindowRow>,
}

/// `config/policies.toml` for the current rows.
pub fn render(db: &Db) -> Result<String, PolicyError> {
    let file = File { policy: policies(db)?, window: windows(db)? };
    toml::to_string(&file).map_err(|e| PolicyError::Invalid(e.to_string()))
}

async fn revision(db: &Arc<Db>, by: &str, now_ms: i64) -> Result<(), PolicyError> {
    config::put(db, CONFIG_NAME, &render(db)?, by, now_ms).await?;
    Ok(())
}

/// Adds or changes a policy (by name), then stores the new revision of the config file.
pub async fn put_policy(db: &Arc<Db>, p: &PolicyRow, by: &str, now_ms: i64) -> Result<String, PolicyError> {
    if p.name.is_empty() || p.name.len() > 64 {
        return Err(PolicyError::Invalid("a policy has a name of 1 to 64 characters".into()));
    }
    one_of("patch", &p.patch, &["auto", "approve-only", "hold"])?;
    one_of("snapshot", &p.snapshot, &["required", "optional"])?;
    one_of("quarantine", &p.quarantine, &["approval", "never"])?;
    one_of("peer_requests", &p.peer_requests, &["approval", "auto"])?;
    let existing = policies(db)?.into_iter().find(|e| e.name == p.name).map(|e| e.id);
    let id = existing.unwrap_or_else(|| ulid::Ulid::new().to_string());
    let row: Row = [
        ("id", Value::Text(id.clone())),
        ("name", Value::Text(p.name.clone())),
        ("patch", Value::Text(p.patch.clone())),
        ("auto_reboot", Value::Integer(i64::from(p.auto_reboot))),
        ("auto_rollback", Value::Integer(i64::from(p.auto_rollback))),
        ("snapshot", Value::Text(p.snapshot.clone())),
        ("quarantine", Value::Text(p.quarantine.clone())),
        ("peer_requests", Value::Text(p.peer_requests.clone())),
    ]
    .into_iter()
    .collect();
    db.writer().send(WriteCmd::PutPolicy(row)).await?;
    revision(db, by, now_ms).await?;
    Ok(id)
}

/// Adds a maintenance window for one machine or a tag (7.5.3), then stores the new revision of the config file.
pub async fn put_window(
    db: &Arc<Db>,
    machine_id: Option<&str>,
    tag: Option<&str>,
    rule: &str,
    timezone: &str,
    by: &str,
    now_ms: i64,
) -> Result<String, PolicyError> {
    if machine_id.is_some() == tag.is_some() {
        return Err(PolicyError::Invalid("a window is for one machine or for a tag".into()));
    }
    Recurrence::from_str(rule).map_err(|e| PolicyError::Invalid(format!("the rule: {e:?}")))?;
    jiff::tz::TimeZone::get(timezone).map_err(|_| PolicyError::Invalid(format!("no timezone `{timezone}`")))?;
    let id = ulid::Ulid::new().to_string();
    let row: Row = [
        ("id", Value::Text(id.clone())),
        ("machine_id", machine_id.map_or(Value::Null, |m| Value::Text(m.into()))),
        ("tag", tag.map_or(Value::Null, |t| Value::Text(t.into()))),
        ("kind", Value::Text("maintenance".into())),
        ("rrule", Value::Text(rule.into())),
        ("timezone", Value::Text(timezone.into())),
    ]
    .into_iter()
    .collect();
    db.writer().send(WriteCmd::PutWindow(row)).await?;
    revision(db, by, now_ms).await?;
    Ok(id)
}
