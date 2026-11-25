//! Action requests from a peer (7.3.4, AC28): treated like a local request at level 1. The owning hub always asks its own
//! people for an approval, unless the target's policy says `peer_requests = "auto"` and the runbook isn't high risk. The
//! status goes back on the request's stream each time it changes until it is final; a requester whose stream broke asks again
//! with the same `request_id` and takes up the same request. `requested_by` is information and never a user.

use std::collections::BTreeMap;
use std::time::Duration;

use iroh::endpoint::SendStream;
use rackhand_proto::peer::{ActionRequest, ActionRequestStatus, JobOutcome as WireOutcome, action_request_status};
use rackhand_runbook::runbook::Runbook;
use rackhand_store::ids::now_ms;

use super::{PeerRow, Peers, wire};
use crate::actions::{JobKind, StartJob};
use crate::bus::{BusEvent, Delivery, Subscription};
use crate::library::items::{Kind, Library};
use crate::policy::approvals::{ApprovalRequest, Approvals};
use crate::policy::decide::{Access, Action, Decision, Request, Requester, Target, decide};

/// How often a request's status is looked at.
const STATUS_EVERY: Duration = Duration::from_millis(500);
/// How long an approved request may wait for its job to start before it is called not started.
const START_WAIT_MS: i64 = 60_000;

fn status(s: action_request_status::Status) -> ActionRequestStatus {
    ActionRequestStatus { status: Some(s) }
}

fn rejected(why: impl Into<String>) -> ActionRequestStatus {
    status(action_request_status::Status::Rejected(why.into()))
}

/// Whether a status is the last one.
pub fn is_final(s: &ActionRequestStatus) -> bool {
    matches!(s.status, Some(action_request_status::Status::Done(_)) | Some(action_request_status::Status::Rejected(_)))
}

impl Peers {
    fn key(peer: &PeerRow, request_id: &[u8]) -> Option<String> {
        let id: [u8; 16] = request_id.try_into().ok()?;
        Some(format!("peer:{}:{}", peer.site, ulid::Ulid::from_bytes(id)))
    }

    /// Takes up a request: the same one again if it was made before, else a new job, or an approval that will start one.
    /// `Err` is why it was refused.
    pub async fn handle_request(&self, peer: &PeerRow, req: &ActionRequest) -> Result<String, String> {
        let key = Peers::key(peer, &req.request_id).ok_or("the request id isn't an id")?;
        let known: Option<i64> = self.one(
            "SELECT 1 WHERE EXISTS (SELECT 1 FROM approvals WHERE requested_by = ?1) OR EXISTS (SELECT 1 FROM jobs WHERE requested_by = ?1)",
            [&key],
        );
        if known.is_some() {
            return Ok(key);
        }
        let db = &self.inner.db;
        let (rev, source) = Library::current_in(db, Kind::Runbook, &req.runbook)
            .ok()
            .flatten()
            .ok_or_else(|| format!("no runbook `{}`", req.runbook))?;
        let runbook = Runbook::parse(&source).map_err(|e| format!("the runbook doesn't validate: {e}"))?;
        let target =
            ulid::Ulid::from_bytes(req.target.as_slice().try_into().map_err(|_| "the target isn't an id")?).to_string();
        type M = (String, String, String, Option<String>);
        let machine: M = db
            .readers()
            .with(|c| {
                use rusqlite::OptionalExtension;
                c.query_row(
                    "SELECT m.access, m.roles, m.tags, p.peer_requests FROM machines m LEFT JOIN policies p ON p.id = m.policy_id
                     WHERE m.id = ?1 AND m.state = 'enrolled'",
                    [&target],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()
            })
            .ok()
            .flatten()
            .ok_or("no such machine")?;
        let (access, roles, tags, policy) = machine;
        let roles: Vec<String> = serde_json::from_str(&roles).unwrap_or_default();
        let tags: Vec<String> = serde_json::from_str(&tags).unwrap_or_default();
        let (role_refs, tag_refs): (Vec<&str>, Vec<&str>) =
            (roles.iter().map(String::as_str).collect(), tags.iter().map(String::as_str).collect());
        let decision = decide(&Request {
            requester: Requester::Peer,
            action: Action::Runbook {
                risk: runbook.risk,
                level: 1,
                needs_account: runbook.steps.iter().any(|s| s.needs_account()),
                assistant_commands: &[],
            },
            target: Target {
                access: if access == "monitor" { Access::Monitor } else { Access::Managed },
                roles: &role_refs,
                tags: &tag_refs,
            },
            peer_auto: policy.as_deref() == Some("auto"),
            auto_rollback: false,
        });
        let params: BTreeMap<String, String> = req.params.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let start = StartJob {
            kind: JobKind::Runbook,
            name: req.runbook.clone(),
            rev: Some(rev),
            machine_id: target.clone(),
            params: params.clone(),
            requested_by: key.clone(),
            incident_id: None,
            approval_id: None,
        };
        match decision {
            Decision::Allow => {
                let actions = self.inner.actions.clone();
                tokio::spawn(async move {
                    if let Err(e) = actions.run(start).await {
                        tracing::warn!(error = %e, "a peer's request didn't start");
                    }
                });
            }
            Decision::NeedsApproval { risk, step_up } => {
                let approval = ApprovalRequest {
                    requester: key.clone(),
                    tool: "run_runbook".into(),
                    target: Some(target),
                    args: serde_json::json!({ "name": req.runbook, "params": params }),
                    runbook_rev: Some(rev),
                    risk,
                    step_up,
                    reason: format!("peer {}: {}", peer.site, req.reason),
                };
                Approvals::new(db.clone())
                    .create(&approval, now_ms(), crate::library::config::hub_or_default(db).approvals.expiry_ms())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Decision::Deny(d) => return Err(format!("{d:?}")),
        }
        let data = serde_json::json!({ "peer": peer.site, "runbook": req.runbook, "requested_by": req.requested_by });
        let _ = self
            .inner
            .audit
            .append(&format!("peer:{}", peer.site), "peer.request", Some(&key), &data.to_string())
            .await;
        Ok(key)
    }

    /// Where a request stands: waiting for an approval, running, or over.
    pub fn request_status(&self, key: &str) -> ActionRequestStatus {
        use action_request_status::Status;
        let job: Option<(String, String)> = self
            .inner
            .db
            .readers()
            .with(|c| {
                use rusqlite::OptionalExtension;
                c.query_row(
                    "SELECT id, state FROM jobs WHERE requested_by = ?1 ORDER BY started_at DESC, id DESC LIMIT 1",
                    [key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
            })
            .ok()
            .flatten();
        if let Some((id, state)) = job {
            return match state.as_str() {
                "succeeded" => status(Status::Done(WireOutcome::Succeeded as i32)),
                "cancelled" => status(Status::Done(WireOutcome::Cancelled as i32)),
                "failed" | "timed_out" | "interrupted" => status(Status::Done(WireOutcome::Failed as i32)),
                _ => {
                    let bytes = ulid::Ulid::from_string(&id).map(|u| u.to_bytes().to_vec()).unwrap_or_default();
                    status(Status::RunningJob(bytes))
                }
            };
        }
        let approval: Option<(String, i64, Option<i64>)> = self
            .inner
            .db
            .readers()
            .with(|c| {
                use rusqlite::OptionalExtension;
                c.query_row(
                    "SELECT state, expires_at, decided_at FROM approvals WHERE requested_by = ?1 ORDER BY rowid DESC LIMIT 1",
                    [key],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()
            })
            .ok()
            .flatten();
        match approval {
            Some((state, expires, _)) if state == "pending" && expires <= now_ms() => rejected("the approval expired"),
            Some((state, _, _)) if state == "pending" => status(Status::NeedsApproval(true)),
            Some((state, _, _)) if state == "rejected" => rejected("the approval was rejected"),
            Some((state, _, _)) if state == "expired" => rejected("the approval expired"),
            Some((_, _, Some(decided))) if now_ms() - decided > START_WAIT_MS => rejected("the job didn't start"),
            Some(_) => status(Status::Queued(true)),
            None => status(Status::Queued(true)),
        }
    }

    pub(super) async fn on_request(&self, peer: &PeerRow, req: ActionRequest, send: &mut SendStream) {
        let key = match self.handle_request(peer, &req).await {
            Ok(key) => key,
            Err(why) => {
                let _ = wire::write(send, &rejected(why)).await;
                return;
            }
        };
        let mut last = None;
        loop {
            let now = self.request_status(&key);
            if last.as_ref() != Some(&now) {
                if !wire::write(send, &now).await {
                    return;
                }
                last = Some(now.clone());
            }
            if is_final(&now) {
                return;
            }
            tokio::time::sleep(STATUS_EVERY).await;
        }
    }

    /// An approval a peer's request waits for was decided: approved, the job starts with it.
    pub async fn approval_decided(&self, approval_id: &str, approved: bool) {
        type A = (String, Option<String>, String, Option<i64>);
        let row: Option<A> = self
            .inner
            .db
            .readers()
            .with(|c| {
                use rusqlite::OptionalExtension;
                c.query_row(
                    "SELECT requested_by, target, args, runbook_rev FROM approvals WHERE id = ?1",
                    [approval_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()
            })
            .ok()
            .flatten();
        let Some((requested_by, Some(machine), args, rev)) = row else { return };
        if !approved || !requested_by.starts_with("peer:") {
            return;
        }
        let args: serde_json::Value = serde_json::from_str(&args).unwrap_or_default();
        let params: BTreeMap<String, String> = args["params"]
            .as_object()
            .map(|m| m.iter().filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string()))).collect())
            .unwrap_or_default();
        let start = StartJob {
            kind: JobKind::Runbook,
            name: args["name"].as_str().unwrap_or_default().to_string(),
            rev,
            machine_id: machine,
            params,
            requested_by,
            incident_id: None,
            approval_id: Some(approval_id.to_string()),
        };
        let actions = self.inner.actions.clone();
        tokio::spawn(async move {
            if let Err(e) = actions.run(start).await {
                tracing::warn!(error = %e, "a peer's approved request didn't start");
            }
        });
    }

    /// Follows the approvals people decide, to start the jobs peers asked for.
    pub fn spawn(self, mut sub: Subscription) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(delivery) = sub.recv().await {
                if let Delivery::Event(BusEvent::ApprovalDecided { id, approved }) = delivery {
                    self.approval_decided(&ulid::Ulid::from_bytes(id).to_string(), approved).await;
                }
            }
        })
    }
}
