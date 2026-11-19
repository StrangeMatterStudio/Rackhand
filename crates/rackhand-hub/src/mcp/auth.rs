//! Who is calling (7.3.6): the auth line's token, checked against the endpoint the session arrived from. A personal
//! key works only from its device, a job token only from the operator that accepted the job, and a key's scope never
//! goes past its user's role (7.7.2): `read_request` on a viewer's account works as `read`.

use iroh::EndpointId;
use rackhand_store::Db;
use rusqlite::OptionalExtension;

use super::keys::{self, Scope};
use crate::policy::approvals::Role;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    Job { job_id: String, hosts: Vec<String>, tools: Vec<String> },
    Key { key_id: String, user_id: String, role: Role, scope: Scope },
}

impl Caller {
    /// The audit log's actor, and what approvals name as the requester.
    pub fn actor(&self) -> String {
        match self {
            Caller::Job { job_id, .. } => format!("job:{job_id}"),
            Caller::Key { key_id, .. } => format!("key:{key_id}"),
        }
    }
}

struct KeyRow {
    id: String,
    user_id: String,
    scope: String,
    expires_at: i64,
    revoked: bool,
    endpoint: String,
    device_revoked: bool,
    role: String,
    disabled: bool,
}

struct JobRow {
    job_id: String,
    hosts: String,
    tools: String,
    expires_at: i64,
    revoked: bool,
    endpoint: String,
    operator_revoked: bool,
    state: String,
}

fn personal(db: &Db, token: &str, peer: &EndpointId, now_ms: i64) -> Option<Caller> {
    let k: KeyRow = db
        .readers()
        .with(|c| {
            c.query_row(
                "SELECT k.id, k.user_id, k.scope, k.expires_at, k.revoked_at IS NOT NULL, d.endpoint_id,
                        d.revoked_at IS NOT NULL, u.role, u.disabled_at IS NOT NULL
                 FROM mcp_keys k JOIN devices d ON d.id = k.device_id JOIN users u ON u.id = k.user_id
                 WHERE k.hash = ?1",
                [keys::hash(token)],
                |r| {
                    Ok(KeyRow {
                        id: r.get(0)?,
                        user_id: r.get(1)?,
                        scope: r.get(2)?,
                        expires_at: r.get(3)?,
                        revoked: r.get(4)?,
                        endpoint: r.get(5)?,
                        device_revoked: r.get(6)?,
                        role: r.get(7)?,
                        disabled: r.get(8)?,
                    })
                },
            )
            .optional()
        })
        .ok()??;
    if k.revoked || k.device_revoked || k.disabled || now_ms >= k.expires_at || k.endpoint != peer.to_string() {
        return None;
    }
    let role = parse_role(&k.role)?;
    let scope = match (Scope::parse(&k.scope)?, role) {
        (_, Role::Viewer) => Scope::Read,
        (s, _) => s,
    };
    Some(Caller::Key { key_id: k.id, user_id: k.user_id, role, scope })
}

fn job(db: &Db, token: &str, peer: &EndpointId, now_ms: i64) -> Result<Caller, &'static str> {
    job_row(db, token).ok_or("unauthorized").and_then(|j| {
        if j.revoked || j.operator_revoked || now_ms >= j.expires_at || j.state != "running" {
            return Err("unauthorized");
        }
        // A live token from another endpoint than the operator that accepted the job (7.3.5).
        if j.endpoint != peer.to_string() {
            return Err("out_of_scope");
        }
        Ok(Caller::Job {
            job_id: j.job_id,
            hosts: serde_json::from_str(&j.hosts).unwrap_or_default(),
            tools: serde_json::from_str(&j.tools).unwrap_or_default(),
        })
    })
}

fn job_row(db: &Db, token: &str) -> Option<JobRow> {
    db.readers()
        .with(|c| {
            c.query_row(
                "SELECT t.job_id, t.hosts, t.tools, t.expires_at, t.revoked_at IS NOT NULL, o.endpoint_id,
                        o.revoked_at IS NOT NULL, j.state
                 FROM job_tokens t JOIN operators o ON o.id = t.operator_id JOIN jobs j ON j.id = t.job_id
                 WHERE t.hash = ?1",
                [keys::hash(token)],
                |r| {
                    Ok(JobRow {
                        job_id: r.get(0)?,
                        hosts: r.get(1)?,
                        tools: r.get(2)?,
                        expires_at: r.get(3)?,
                        revoked: r.get(4)?,
                        endpoint: r.get(5)?,
                        operator_revoked: r.get(6)?,
                        state: r.get(7)?,
                    })
                },
            )
            .optional()
        })
        .ok()
        .flatten()
}

/// The caller for an auth line's token, or why not: `out_of_scope` for a job token used from another endpoint than
/// its operator's, `unauthorized` otherwise. The session is closed then.
pub fn check(db: &Db, token: &str, peer: &EndpointId, now_ms: i64) -> Result<Caller, &'static str> {
    if token.starts_with(keys::KEY_PREFIX) {
        personal(db, token, peer, now_ms).ok_or("unauthorized")
    } else if token.starts_with(keys::JOB_PREFIX) {
        job(db, token, peer, now_ms)
    } else {
        Err("unauthorized")
    }
}

pub fn authenticate(db: &Db, token: &str, peer: &EndpointId, now_ms: i64) -> Option<Caller> {
    check(db, token, peer, now_ms).ok()
}

fn parse_role(s: &str) -> Option<Role> {
    match s {
        "viewer" => Some(Role::Viewer),
        "responder" => Some(Role::Responder),
        "admin" => Some(Role::Admin),
        _ => None,
    }
}
