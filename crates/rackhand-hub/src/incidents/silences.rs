//! Silences (7.5.2): for a machine or a tag, and a rule or kind (or every one), until an end at most 30 days away.

use rackhand_store::ids::new_id;
use rackhand_store::{Row, WriteCmd};
use rusqlite::types::Value;

use super::{Incidents, IncidentsError};

pub const MAX_SILENCE_MS: i64 = 30 * 86_400_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SilenceTarget {
    Machine(String),
    Tag(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Silence {
    pub target: SilenceTarget,
    /// A rule id (condition incidents) or an event kind; `None` silences every one.
    pub rule_or_kind: Option<String>,
    pub until_ms: i64,
    pub created_by: String,
    pub reason: String,
}

impl Incidents {
    pub async fn silence(&self, s: Silence, now_ms: i64) -> Result<String, IncidentsError> {
        if s.until_ms - now_ms > MAX_SILENCE_MS {
            return Err(IncidentsError::SilenceTooLong);
        }
        if s.until_ms <= now_ms {
            return Err(IncidentsError::SilenceEnded);
        }
        let id = new_id().to_string();
        let (machine, tag) = match &s.target {
            SilenceTarget::Machine(m) => (Value::Text(m.clone()), Value::Null),
            SilenceTarget::Tag(t) => (Value::Null, Value::Text(t.clone())),
        };
        let row = Row::from([
            ("id", Value::Text(id.clone())),
            ("machine_id", machine),
            ("tag", tag),
            ("kind", s.rule_or_kind.map(Value::Text).unwrap_or(Value::Null)),
            ("until_ms", Value::Integer(s.until_ms)),
            ("created_by", Value::Text(s.created_by)),
            ("reason", Value::Text(s.reason)),
        ]);
        self.inner.db.writer().send(WriteCmd::PutSilence(row)).await?;
        Ok(id)
    }

    /// Whether a silence covers a new incident of `kind` (a rule id or event kind) on `machine` now.
    pub(crate) fn silenced(&self, machine: &str, kind: &str, now_ms: i64) -> Result<bool, IncidentsError> {
        Ok(self.inner.db.readers().with(|c| {
            c.query_row(
                "SELECT EXISTS (SELECT 1 FROM silences WHERE until_ms > ?3
                   AND (kind IS NULL OR kind = ?2 OR rule_id = ?2)
                   AND (machine_id = ?1 OR tag IN (SELECT value FROM json_each(
                         (SELECT coalesce(tags, '[]') FROM machines WHERE id = ?1)))))",
                rusqlite::params![machine, kind, now_ms],
                |r| r.get(0),
            )
        })?)
    }
}
