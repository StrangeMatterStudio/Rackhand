//! Events (7.3.8): every system raises its events through Ingest, the only writer of `events`.

use rackhand_store::ids::{new_id, now_ms};
use rackhand_store::{Row, WriteCmd};
use rusqlite::types::Value;

use super::{Ingest, IngestError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub machine_id: Option<String>,
    pub at_ms: i64,
    pub kind: String,
    pub severity: Severity,
    pub subject: Option<String>,
    pub data: serde_json::Value,
    /// The job running when it happened, if any.
    pub job_id: Option<String>,
}

impl Event {
    /// An event about a machine, now.
    pub fn machine(machine_id: &str, kind: &str, severity: Severity, data: serde_json::Value) -> Event {
        Event { machine_id: Some(machine_id.to_string()), ..Event::hub(kind, severity, data) }
    }

    /// An event about the hub itself, now.
    pub fn hub(kind: &str, severity: Severity, data: serde_json::Value) -> Event {
        Event { machine_id: None, at_ms: now_ms(), kind: kind.to_string(), severity, subject: None, data, job_id: None }
    }
}

fn opt(v: Option<String>) -> Value {
    v.map(Value::Text).unwrap_or(Value::Null)
}

impl Ingest {
    pub async fn raise_event(&self, event: Event) -> Result<(), IngestError> {
        self.raise_events(vec![event]).await
    }

    pub async fn raise_events(&self, events: Vec<Event>) -> Result<(), IngestError> {
        if events.is_empty() {
            return Ok(());
        }
        let rows = events
            .into_iter()
            .map(|e| {
                Row::from([
                    ("id", Value::Text(new_id().to_string())),
                    ("machine_id", opt(e.machine_id)),
                    ("at_ms", Value::Integer(e.at_ms)),
                    ("kind", Value::Text(e.kind)),
                    ("severity", Value::Text(e.severity.as_str().into())),
                    ("subject", opt(e.subject)),
                    ("data", Value::Text(e.data.to_string())),
                    ("job_id", opt(e.job_id)),
                ])
            })
            .collect();
        self.inner.writer.send(WriteCmd::PutEvents(rows)).await?;
        Ok(())
    }
}
