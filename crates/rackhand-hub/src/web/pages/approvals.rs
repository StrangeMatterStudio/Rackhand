//! Approvals (7.7.1, FR-14): each waiting approval with exactly what it binds (action, target, arguments, runbook
//! revision, risk, requester, reason and the hash), and Approve and Reject for those whose role allows it. High risk
//! needs a fresh step-up; the first decision wins (E42).

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use rackhand_runbook::runbook::Risk;

use super::{html, redirect, status};
use crate::policy::approvals::{ApprovalError, Approvals, Decider, can_approve};
use crate::web::auth::step_up;
use crate::web::{Ctx, Web};

struct Waiting {
    id: String,
    tool: String,
    target: String,
    args: String,
    rev: Option<i64>,
    hash: String,
    risk: String,
    step_up: bool,
    requested_by: String,
    reason: String,
    can_decide: bool,
}

#[derive(Template)]
#[template(path = "approvals.html")]
struct Page<'a> {
    csrf: &'a str,
    waiting: Vec<Waiting>,
}

fn risk(name: &str) -> Risk {
    match name {
        "high" => Risk::High,
        "normal" => Risk::Normal,
        _ => Risk::Low,
    }
}

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let rows: Result<Vec<Waiting>, _> = web.0.db.readers().with(|c| {
        let mut s = c.prepare(
            "SELECT id, tool, target, args, runbook_rev, args_hash, risk, step_up, requested_by, reason
             FROM approvals WHERE state = 'pending' AND expires_at > ?1 ORDER BY expires_at",
        )?;
        let rows = s.query_map([ctx.now_ms], |r| {
            let args: String = r.get(3)?;
            let pretty = serde_json::from_str::<serde_json::Value>(&args)
                .ok()
                .and_then(|v| serde_json::to_string_pretty(&v).ok())
                .unwrap_or(args);
            let hash: Vec<u8> = r.get(5)?;
            let risk_name: String = r.get(6)?;
            Ok(Waiting {
                id: r.get(0)?,
                tool: r.get(1)?,
                target: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                args: pretty,
                rev: r.get(4)?,
                hash: hash.iter().map(|b| format!("{b:02x}")).collect(),
                can_decide: can_approve(user.role, risk(&risk_name), true).is_ok(),
                risk: risk_name,
                step_up: r.get(7)?,
                requested_by: r.get(8)?,
                reason: r.get(9)?,
            })
        })?;
        rows.collect()
    });
    match rows {
        Ok(waiting) => html(StatusCode::OK, Page { csrf: &ctx.csrf, waiting }.render()),
        Err(e) => {
            tracing::error!(error = %e, "approvals");
            status(StatusCode::INTERNAL_SERVER_ERROR, "Approvals unreadable")
        }
    }
}

/// `/approvals/<id>/<verb>` → the id.
fn approval_id(path: &str) -> Option<&str> {
    let id = path.strip_prefix("/approvals/")?.split('/').next()?;
    (!id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric())).then_some(id)
}

pub(super) async fn decide(web: &Web, ctx: &Ctx, approve: bool) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let Some(id) = approval_id(&ctx.path) else { return status(StatusCode::NOT_FOUND, "No such approval") };
    let by = Decider {
        user: user.name.clone(),
        role: user.role,
        step_up_fresh: step_up::fresh(user.step_up_at, ctx.now_ms),
    };
    match Approvals::new(web.0.db.clone()).decide(id, &by, approve, ctx.now_ms).await {
        Ok(()) => {
            let action = if approve { "approval.approved" } else { "approval.rejected" };
            if let Err(e) = web.0.audit.append(&user.name, action, Some(id), "{}").await {
                tracing::error!(error = %e, "audit");
            }
            // the decision is committed; tell the systems waiting on it (7.3.8)
            if let (Some(bus), Ok(ulid)) = (web.0.bus.as_ref(), ulid::Ulid::from_string(id)) {
                bus.publish(crate::bus::BusEvent::ApprovalDecided { id: ulid.to_bytes(), approved: approve }).await;
            }
            redirect("/approvals")
        }
        Err(ApprovalError::StepUpRequired) => redirect("/step-up"),
        Err(ApprovalError::NotPermitted) => {
            status(StatusCode::FORBIDDEN, "Your role can't decide an approval at this risk")
        }
        Err(ApprovalError::AlreadyDecided) => {
            status(StatusCode::CONFLICT, "This approval was already decided by someone else; nothing changed")
        }
        Err(ApprovalError::Expired) => status(StatusCode::CONFLICT, "This approval has expired"),
        Err(ApprovalError::Unknown) => status(StatusCode::NOT_FOUND, "No such approval"),
        Err(e) => {
            tracing::error!(error = %e, "approval");
            status(StatusCode::INTERNAL_SERVER_ERROR, "The decision couldn't be recorded")
        }
    }
}
