//! Notes on an incident (7.3.6 `add_incident_note`, the dashboard): an `incident_events` row of kind `note`.

use rackhand_store::{Db, Row, StoreError, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;

/// The longest note kept.
pub const MAX_NOTE: usize = 4000;

#[derive(Debug, thiserror::Error)]
pub enum NoteError {
    #[error("no such incident")]
    Unknown,
    #[error("a note is 1 to 4000 characters")]
    Length,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

/// Adds a note by `by` (a person, `job:<id>` or `key:<id>`); returns its id.
pub async fn add_note(db: &Db, incident_id: &str, text: &str, by: &str, now_ms: i64) -> Result<String, NoteError> {
    let text = text.trim();
    if text.is_empty() || text.chars().count() > MAX_NOTE {
        return Err(NoteError::Length);
    }
    let exists: Option<i64> = db
        .readers()
        .with(|c| c.query_row("SELECT 1 FROM incidents WHERE id = ?1", [incident_id], |r| r.get(0)).optional())?;
    if exists.is_none() {
        return Err(NoteError::Unknown);
    }
    let id = ulid::Ulid::new().to_string();
    let row: Row = [
        ("id", Value::Text(id.clone())),
        ("incident_id", Value::Text(incident_id.into())),
        ("at_ms", Value::Integer(now_ms)),
        ("kind", Value::Text("note".into())),
        ("data", Value::Text(serde_json::json!({ "text": text, "by": by }).to_string())),
    ]
    .into_iter()
    .collect();
    db.writer().send(WriteCmd::AppendIncidentEvent(row)).await?;
    Ok(id)
}
