//! Appending audit rows and retention checkpoints.

use rackhand_store::ids::now_ms;
use rackhand_store::writer::{Row, StoreError, StoreWriter, WriteCmd};
use rusqlite::types::Value;

#[derive(Debug, Clone)]
pub struct Audit {
    writer: StoreWriter,
}

impl Audit {
    pub fn new(writer: StoreWriter) -> Audit {
        Audit { writer }
    }

    /// Appends one entry. `data` is a JSON object; it never holds secrets or command output (10).
    pub async fn append(&self, actor: &str, action: &str, target: Option<&str>, data: &str) -> Result<(), StoreError> {
        let mut row = Row::new();
        row.insert("at_ms", Value::Integer(now_ms()));
        row.insert("actor", Value::Text(actor.into()));
        row.insert("action", Value::Text(action.into()));
        if let Some(t) = target {
            row.insert("target", Value::Text(t.into()));
        }
        row.insert("data", Value::Text(data.into()));
        self.writer.send(WriteCmd::AppendAudit(row)).await.map(|_| ())
    }

    /// Writes a checkpoint with the hash of row `seq`, then removes every row up to it, in one transaction.
    pub async fn checkpoint_and_remove_through(&self, seq: i64) -> Result<usize, StoreError> {
        let mut row = Row::new();
        row.insert("at_ms", Value::Integer(now_ms()));
        row.insert("removed_through_seq", Value::Integer(seq));
        self.writer.send(WriteCmd::AppendAuditCheckpoint(row)).await.map(|a| a.rows)
    }
}
