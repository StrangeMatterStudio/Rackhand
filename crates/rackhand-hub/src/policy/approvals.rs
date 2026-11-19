//! Approvals (7.3.6, 7.6.8, 7.7.2): an approval binds who asked, the tool, the target, the arguments and the runbook
//! revision by a SHA-256 hash; it expires, is used once, and the first decision wins.

use std::sync::Arc;

use rackhand_runbook::runbook::Risk;
use rackhand_store::{Db, Row, StoreError, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Responder,
    Admin,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalRequest {
    /// `job:<id>`, `key:<id>`, `peer:<site>` or `user:<name>`.
    pub requester: String,
    pub tool: String,
    pub target: Option<String>,
    pub args: serde_json::Value,
    pub runbook_rev: Option<i64>,
    pub risk: Risk,
    pub step_up: bool,
    pub reason: String,
}

/// The person deciding, from their dashboard session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decider {
    pub user: String,
    pub role: Role,
    /// Stepped up in the last 5 minutes.
    pub step_up_fresh: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalError {
    #[error("no such approval")]
    Unknown,
    #[error("approval_mismatch: the call or the caller differs from what was approved")]
    Mismatch,
    #[error("the approval hasn't been decided")]
    NotApproved,
    #[error("approval_rejected")]
    Rejected,
    #[error("the approval has been used")]
    Used,
    #[error("the approval has expired")]
    Expired,
    #[error("already decided")]
    AlreadyDecided,
    #[error("this role can't approve this risk")]
    NotPermitted,
    #[error("high risk needs a step-up first")]
    StepUpRequired,
    #[error("store: {0}")]
    Store(String),
}

impl From<StoreError> for ApprovalError {
    fn from(e: StoreError) -> Self {
        ApprovalError::Store(e.to_string())
    }
}

impl From<rusqlite::Error> for ApprovalError {
    fn from(e: rusqlite::Error) -> Self {
        ApprovalError::Store(e.to_string())
    }
}

fn risk_name(r: Risk) -> &'static str {
    match r {
        Risk::Low => "low",
        Risk::Normal => "normal",
        Risk::High => "high",
    }
}

/// The hash of everything an approval binds. Fields are length-prefixed; argument keys are sorted.
pub fn approval_hash(req: &ApprovalRequest) -> [u8; 32] {
    let rev = req.runbook_rev.map(|r| r.to_string()).unwrap_or_default();
    let target = req.target.as_deref().map(|t| format!("={t}")).unwrap_or_default();
    let args = req.args.to_string();
    let mut h = Sha256::new();
    for field in [req.requester.as_str(), req.tool.as_str(), target.as_str(), args.as_str(), rev.as_str()] {
        h.update((field.len() as u64).to_le_bytes());
        h.update(field.as_bytes());
    }
    h.finalize().into()
}

/// Who may approve what (7.7.2). A person may approve their own request.
pub fn can_approve(role: Role, risk: Risk, step_up_fresh: bool) -> Result<(), ApprovalError> {
    match (role, risk) {
        (Role::Viewer, _) | (Role::Responder, Risk::High) => Err(ApprovalError::NotPermitted),
        (Role::Admin, Risk::High) if !step_up_fresh => Err(ApprovalError::StepUpRequired),
        _ => Ok(()),
    }
}

#[derive(Debug, Clone)]
pub struct Approvals {
    db: Arc<Db>,
}

struct Stored {
    risk: String,
    requester: String,
    hash: Vec<u8>,
    state: String,
    expires_at: i64,
}

impl Approvals {
    pub fn new(db: Arc<Db>) -> Approvals {
        Approvals { db }
    }

    fn get(&self, id: &str) -> Result<Stored, ApprovalError> {
        self.db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT risk, requested_by, args_hash, state, expires_at FROM approvals WHERE id = ?1",
                    [id],
                    |r| {
                        Ok(Stored {
                            risk: r.get(0)?,
                            requester: r.get(1)?,
                            hash: r.get(2)?,
                            state: r.get(3)?,
                            expires_at: r.get(4)?,
                        })
                    },
                )
                .optional()
            })?
            .ok_or(ApprovalError::Unknown)
    }

    /// Creates a pending approval that expires `ttl_ms` from now.
    pub async fn create(&self, req: &ApprovalRequest, now_ms: i64, ttl_ms: i64) -> Result<String, ApprovalError> {
        let id = ulid::Ulid::new().to_string();
        let row: Row = [
            ("id", Value::Text(id.clone())),
            ("tool", Value::Text(req.tool.clone())),
            ("target", req.target.clone().map_or(Value::Null, Value::Text)),
            ("args", Value::Text(req.args.to_string())),
            ("runbook_rev", req.runbook_rev.map_or(Value::Null, Value::Integer)),
            ("args_hash", Value::Blob(approval_hash(req).to_vec())),
            ("risk", Value::Text(risk_name(req.risk).into())),
            ("step_up", Value::Integer(i64::from(req.step_up))),
            ("requested_by", Value::Text(req.requester.clone())),
            ("reason", Value::Text(req.reason.clone())),
            ("state", Value::Text("pending".into())),
            ("expires_at", Value::Integer(now_ms + ttl_ms)),
        ]
        .into_iter()
        .collect();
        self.db.writer().send(WriteCmd::CreateApproval(row)).await?;
        Ok(id)
    }

    /// Approves or rejects. The first decision wins; a later one gets `AlreadyDecided`.
    pub async fn decide(&self, id: &str, by: &Decider, approve: bool, now_ms: i64) -> Result<(), ApprovalError> {
        let stored = self.get(id)?;
        let risk = match stored.risk.as_str() {
            "high" => Risk::High,
            "normal" => Risk::Normal,
            _ => Risk::Low,
        };
        can_approve(by.role, risk, by.step_up_fresh)?;
        if stored.state != "pending" {
            return Err(ApprovalError::AlreadyDecided);
        }
        if stored.expires_at <= now_ms {
            return Err(ApprovalError::Expired);
        }
        let row: Row = [
            ("id", Value::Text(id.into())),
            ("state", Value::Text(if approve { "approved" } else { "rejected" }.into())),
            ("decided_by", Value::Text(by.user.clone())),
            ("decided_at", Value::Integer(now_ms)),
        ]
        .into_iter()
        .collect();
        match self.db.writer().send(WriteCmd::DecideApproval(row)).await {
            Ok(_) => Ok(()),
            Err(StoreError::Conflict(_)) => Err(ApprovalError::AlreadyDecided),
            Err(e) => Err(e.into()),
        }
    }

    /// Uses an approval for the repeated call: same caller, same hash, approved, unexpired, unused.
    pub async fn use_approval(&self, id: &str, caller: &str, hash: &[u8], now_ms: i64) -> Result<(), ApprovalError> {
        let stored = self.get(id)?;
        if stored.requester != caller || stored.hash != hash {
            return Err(ApprovalError::Mismatch);
        }
        match stored.state.as_str() {
            "approved" => {}
            "pending" => return Err(ApprovalError::NotApproved),
            "rejected" => return Err(ApprovalError::Rejected),
            "used" => return Err(ApprovalError::Used),
            _ => return Err(ApprovalError::Expired),
        }
        if stored.expires_at <= now_ms {
            return Err(ApprovalError::Expired);
        }
        match self.db.writer().send(WriteCmd::UseApproval(id.into())).await {
            Ok(_) => Ok(()),
            Err(StoreError::Conflict(_)) => Err(ApprovalError::Used),
            Err(e) => Err(e.into()),
        }
    }
}
