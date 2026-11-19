//! `rackhand hub audit verify`: checks the whole chain (12).

use rackhand_store::audit::{AuditFields, GENESIS, hex, row_hash};
use rackhand_store::reader::ReadPool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyReport {
    pub rows: usize,
    pub first_seq: i64,
    pub last_seq: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("row {seq}: hash doesn't match its contents (changed)")]
    HashMismatch { seq: i64 },
    #[error("row {seq}: doesn't link to the row before it")]
    BrokenLink { seq: i64 },
    #[error("rows missing between {after} and {next}")]
    Gap { after: i64, next: i64 },
    #[error("the chain starts at row {first} with no checkpoint for the removed rows")]
    MissingStart { first: i64 },
    #[error("reading the audit log: {0}")]
    Read(String),
}

struct AuditRow {
    seq: i64,
    at_ms: i64,
    actor: String,
    action: String,
    target: Option<String>,
    data: String,
    prev_hash: Vec<u8>,
    hash: Vec<u8>,
    checkpoint: bool,
}

pub fn verify(readers: &ReadPool) -> Result<VerifyReport, VerifyError> {
    let rows: Vec<AuditRow> = readers
        .with(|c| {
            let mut stmt = c.prepare(
                "SELECT seq, at_ms, actor, action, target, data, prev_hash, hash, checkpoint FROM audit_log ORDER BY seq",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(AuditRow {
                    seq: r.get(0)?,
                    at_ms: r.get(1)?,
                    actor: r.get(2)?,
                    action: r.get(3)?,
                    target: r.get(4)?,
                    data: r.get(5)?,
                    prev_hash: r.get(6)?,
                    hash: r.get(7)?,
                    checkpoint: r.get(8)?,
                })
            })?;
            rows.collect()
        })
        .map_err(|e| VerifyError::Read(e.to_string()))?;
    let Some(first) = rows.first() else { return Ok(VerifyReport { rows: 0, first_seq: 0, last_seq: 0 }) };

    if first.seq == 1 {
        if first.prev_hash != GENESIS {
            return Err(VerifyError::BrokenLink { seq: 1 });
        }
    } else {
        let want = format!("{{\"removed_through_seq\":{},\"hash\":\"{}\"}}", first.seq - 1, hex(&first.prev_hash));
        if !rows.iter().any(|r| r.checkpoint && r.data == want) {
            return Err(VerifyError::MissingStart { first: first.seq });
        }
    }
    let mut prev: Option<&AuditRow> = None;
    for row in &rows {
        if let Some(p) = prev {
            if row.seq != p.seq + 1 {
                return Err(VerifyError::Gap { after: p.seq, next: row.seq });
            }
            if row.prev_hash != p.hash {
                return Err(VerifyError::BrokenLink { seq: row.seq });
            }
        }
        let fields = AuditFields {
            seq: row.seq,
            at_ms: row.at_ms,
            actor: &row.actor,
            action: &row.action,
            target: row.target.as_deref(),
            data: &row.data,
            checkpoint: row.checkpoint,
        };
        if row_hash(&row.prev_hash, &fields).as_slice() != row.hash.as_slice() {
            return Err(VerifyError::HashMismatch { seq: row.seq });
        }
        prev = Some(row);
    }
    Ok(VerifyReport { rows: rows.len(), first_seq: first.seq, last_seq: rows.last().map(|r| r.seq).unwrap_or(0) })
}
