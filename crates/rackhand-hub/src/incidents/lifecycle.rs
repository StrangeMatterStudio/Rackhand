//! Incident states and their changes (7.5.2). Each change and its `incident_events` row commit together.

use rackhand_detect::rules::Severity;
use rackhand_store::ids::new_id;
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;

use super::{Incidents, IncidentsError};
use crate::bus::BusEvent;

/// A resolved incident with the same dedupe key reopens within this time.
pub const REOPEN_MS: i64 = 30 * 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Open,
    Automation,
    Assistant,
    Human,
    Resolved,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Open => "open",
            State::Automation => "automation",
            State::Assistant => "assistant",
            State::Human => "human",
            State::Resolved => "resolved",
        }
    }

    fn parse(s: &str) -> State {
        match s {
            "automation" => State::Automation,
            "assistant" => State::Assistant,
            "human" => State::Human,
            "resolved" => State::Resolved,
            _ => State::Open,
        }
    }
}

pub(crate) fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "critical",
    }
}

pub(crate) fn parse_severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "warning" => Severity::Warning,
        _ => Severity::Info,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IncidentRow {
    pub id: String,
    pub machine_id: Option<String>,
    pub rule_id: Option<String>,
    pub dedupe_key: String,
    pub kind: String,
    pub severity: Severity,
    pub state: State,
    pub title: String,
    pub opened_at: i64,
    pub acked_at: Option<i64>,
    pub acked_by: Option<String>,
    pub resolved_at: Option<i64>,
    pub resolved_by: Option<String>,
}

fn opt_text(v: &Option<String>) -> Value {
    v.clone().map(Value::Text).unwrap_or(Value::Null)
}

fn opt_int(v: Option<i64>) -> Value {
    v.map(Value::Integer).unwrap_or(Value::Null)
}

impl IncidentRow {
    fn to_row(&self) -> Row {
        Row::from([
            ("id", Value::Text(self.id.clone())),
            ("machine_id", opt_text(&self.machine_id)),
            ("rule_id", opt_text(&self.rule_id)),
            ("dedupe_key", Value::Text(self.dedupe_key.clone())),
            ("kind", Value::Text(self.kind.clone())),
            ("severity", Value::Text(severity_str(self.severity).into())),
            ("state", Value::Text(self.state.as_str().into())),
            ("title", Value::Text(self.title.clone())),
            ("opened_at", Value::Integer(self.opened_at)),
            ("acked_at", opt_int(self.acked_at)),
            ("acked_by", opt_text(&self.acked_by)),
            ("resolved_at", opt_int(self.resolved_at)),
            ("resolved_by", opt_text(&self.resolved_by)),
        ])
    }
}

const COLUMNS: &str = "id, machine_id, rule_id, dedupe_key, kind, severity, state, title, opened_at, acked_at, acked_by, resolved_at, resolved_by";

fn from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<IncidentRow> {
    Ok(IncidentRow {
        id: r.get(0)?,
        machine_id: r.get(1)?,
        rule_id: r.get(2)?,
        dedupe_key: r.get(3)?,
        kind: r.get(4)?,
        severity: parse_severity(&r.get::<_, String>(5)?),
        state: State::parse(&r.get::<_, String>(6)?),
        title: r.get(7)?,
        opened_at: r.get(8)?,
        acked_at: r.get(9)?,
        acked_by: r.get(10)?,
        resolved_at: r.get(11)?,
        resolved_by: r.get(12)?,
    })
}

/// The newest incident with this dedupe key.
pub(crate) fn by_key(db: &Db, key: &str) -> Result<Option<IncidentRow>, IncidentsError> {
    let sql = format!("SELECT {COLUMNS} FROM incidents WHERE dedupe_key = ?1 ORDER BY opened_at DESC, id DESC LIMIT 1");
    Ok(db.readers().with(|c| c.query_row(&sql, [key], from_row).optional())?)
}

pub(crate) fn by_id(db: &Db, id: &str) -> Result<IncidentRow, IncidentsError> {
    let sql = format!("SELECT {COLUMNS} FROM incidents WHERE id = ?1");
    db.readers().with(|c| c.query_row(&sql, [id], from_row).optional())?.ok_or(IncidentsError::NoSuchIncident)
}

/// What opening an incident needs.
#[derive(Debug, Clone)]
pub(crate) struct Opening {
    pub machine_id: Option<String>,
    pub rule_id: Option<String>,
    pub dedupe_key: String,
    pub kind: String,
    pub severity: Severity,
    pub title: String,
}

impl Incidents {
    /// Writes the incident and one event about the change, in one transaction, then tells the bus.
    pub(crate) async fn write(
        &self,
        inc: &IncidentRow,
        event: &str,
        data: serde_json::Value,
        at_ms: i64,
    ) -> Result<(), IncidentsError> {
        let ev = Row::from([
            ("id", Value::Text(new_id().to_string())),
            ("incident_id", Value::Text(inc.id.clone())),
            ("at_ms", Value::Integer(at_ms)),
            ("kind", Value::Text(event.into())),
            ("data", Value::Text(data.to_string())),
        ]);
        let batch = vec![RowWrite::upsert("incidents", "id", inc.to_row()), RowWrite::insert("incident_events", ev)];
        self.inner.db.writer().send(WriteCmd::Batch(batch)).await?;
        if let Ok(id) = inc.id.parse::<ulid::Ulid>() {
            self.inner.bus.publish(BusEvent::IncidentChanged { id: id.to_bytes() }).await;
        }
        Ok(())
    }

    /// Opens an incident, or reopens the same dedupe key's incident if it was resolved within 30 minutes. An
    /// unresolved one is left as it is. A new incident a silence covers isn't opened: returns `None` then.
    pub(crate) async fn open(&self, o: Opening, now_ms: i64) -> Result<Option<IncidentRow>, IncidentsError> {
        let existing = by_key(&self.inner.db, &o.dedupe_key)?;
        if let Some(inc) = existing.clone().filter(|i| i.state != State::Resolved) {
            // still open (a rule's state was lost in a restart): keep it, at the severity now matching
            if inc.severity != o.severity {
                self.change_severity(inc.clone(), o.severity, now_ms).await?;
            }
            return Ok(Some(inc));
        }
        if let Some(mut inc) = existing.filter(|i| i.resolved_at.is_some_and(|r| now_ms - r <= REOPEN_MS)) {
            inc.state = State::Open;
            inc.severity = o.severity;
            inc.resolved_at = None;
            inc.resolved_by = None;
            let data = serde_json::json!({ "severity": severity_str(o.severity), "callout": true });
            self.write(&inc, "reopened", data, now_ms).await?;
            return Ok(Some(inc));
        }
        self.open_new(o, now_ms).await
    }

    /// A new incident, unless a silence covers it.
    pub(crate) async fn open_new(&self, o: Opening, now_ms: i64) -> Result<Option<IncidentRow>, IncidentsError> {
        if let Some(machine) = &o.machine_id {
            if self.silenced(machine, &o.kind, now_ms)? {
                return Ok(None);
            }
        }
        let inc = IncidentRow {
            id: new_id().to_string(),
            machine_id: o.machine_id,
            rule_id: o.rule_id,
            dedupe_key: o.dedupe_key,
            kind: o.kind,
            severity: o.severity,
            state: State::Open,
            title: o.title,
            opened_at: now_ms,
            acked_at: None,
            acked_by: None,
            resolved_at: None,
            resolved_by: None,
        };
        let data = serde_json::json!({ "severity": severity_str(inc.severity), "callout": true });
        self.write(&inc, "opened", data, now_ms).await?;
        Ok(Some(inc))
    }

    /// A rise calls out again; a fall doesn't (7.5.2).
    pub(crate) async fn change_severity(
        &self,
        mut inc: IncidentRow,
        to: Severity,
        now_ms: i64,
    ) -> Result<(), IncidentsError> {
        if inc.severity == to {
            return Ok(());
        }
        let from = inc.severity;
        inc.severity = to;
        let data = serde_json::json!({ "from": severity_str(from), "to": severity_str(to), "callout": to > from });
        self.write(&inc, "severity", data, now_ms).await
    }

    pub(crate) async fn resolve(&self, mut inc: IncidentRow, by: &str, now_ms: i64) -> Result<(), IncidentsError> {
        inc.state = State::Resolved;
        inc.resolved_at = Some(now_ms);
        inc.resolved_by = Some(by.into());
        self.write(&inc, "resolved", serde_json::json!({ "by": by }), now_ms).await
    }

    /// A person resolves an incident (the only way an event incident resolves at levels 0 and 1).
    pub async fn resolve_by(&self, id: &str, by: &str, now_ms: i64) -> Result<(), IncidentsError> {
        let inc = by_id(&self.inner.db, id)?;
        self.resolve(inc, by, now_ms).await
    }

    /// Stops re-notification; the state is unchanged (7.5.2).
    pub async fn acknowledge(&self, id: &str, by: &str, now_ms: i64) -> Result<(), IncidentsError> {
        let mut inc = by_id(&self.inner.db, id)?;
        inc.acked_at = Some(now_ms);
        inc.acked_by = Some(by.into());
        self.write(&inc, "acknowledged", serde_json::json!({ "by": by }), now_ms).await
    }

    /// Moves an incident to another state (routing).
    pub async fn set_state(&self, id: &str, state: State, now_ms: i64) -> Result<(), IncidentsError> {
        let mut inc = by_id(&self.inner.db, id)?;
        let from = inc.state;
        inc.state = state;
        let data = serde_json::json!({ "from": from.as_str(), "to": state.as_str() });
        self.write(&inc, "state", data, now_ms).await
    }
}
