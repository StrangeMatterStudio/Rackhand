//! The audit chain's row hash (7.4.1): SHA-256 over the previous row's hash and this row's fields. Shared by the
//! writer (which appends) and `rackhand hub audit verify` (which checks).

use sha2::{Digest, Sha256};

pub const GENESIS: [u8; 32] = [0; 32];

#[derive(Debug, Clone, Copy)]
pub struct AuditFields<'a> {
    pub seq: i64,
    pub at_ms: i64,
    pub actor: &'a str,
    pub action: &'a str,
    pub target: Option<&'a str>,
    pub data: &'a str,
    pub checkpoint: bool,
}

pub fn row_hash(prev: &[u8], row: &AuditFields<'_>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"rackhand-audit-v1\0");
    h.update(prev);
    h.update(row.seq.to_be_bytes());
    h.update(row.at_ms.to_be_bytes());
    for field in [row.actor, row.action, row.target.unwrap_or("\u{0}none"), row.data] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field.as_bytes());
    }
    h.update([u8::from(row.checkpoint)]);
    h.finalize().into()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
