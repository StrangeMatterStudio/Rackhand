//! Approvals (7.7.1, FR-14): each waiting approval with exactly what it binds (action, target, arguments, runbook
//! revision, risk, requester, reason and the hash), and Approve and Reject for those whose role allows it. High risk
//! needs a fresh step-up; the first decision wins (E42).

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use rackhand_runbook::runbook::Risk;

use super::{html, redirect, status};
use crate::policy::approvals::{ApprovalError, Approvals, Decider, can_approve};
use crate::web::auth::flow::to_step_up;
use crate::web::auth::step_up;
use crate::web::ui::{self, Confirm, Shell};
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
    /// For an `exec`, the line that runs on the machine.
    runs: Option<String>,
    expires: String,
}

#[derive(Template)]
#[template(path = "approvals.html")]
struct Page<'a> {
    csrf: &'a str,
    shell: Shell,
    q: String,
    confirm: String,
    waiting: Vec<Waiting>,
    /// Why a decision wasn't taken.
    notice: Option<&'a str>,
}

fn risk(name: &str) -> Risk {
    match name {
        "high" => Risk::High,
        "normal" => Risk::Normal,
        _ => Risk::Low,
    }
}

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    show(web, ctx, StatusCode::OK, None)
}

fn show(web: &Web, ctx: &Ctx, code: StatusCode, notice: Option<&str>) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let rows: Result<Vec<Waiting>, _> = web.0.db.readers().with(|c| {
        let mut s = c.prepare(
            "SELECT id, tool, target, args, runbook_rev, args_hash, risk, step_up, requested_by, reason, expires_at
             FROM approvals WHERE state = 'pending' AND expires_at > ?1 ORDER BY expires_at",
        )?;
        let rows = s.query_map([ctx.now_ms], |r| {
            let args: String = r.get(3)?;
            let tool: String = r.get(1)?;
            let runs = (tool == "exec")
                .then(|| serde_json::from_str::<serde_json::Value>(&args).ok())
                .flatten()
                .and_then(|v| v["command"].as_str().map(|c| crate::executor::exec_line(c, crate::mcp::EXEC_TIMEOUT)));
            let pretty = serde_json::from_str::<serde_json::Value>(&args)
                .ok()
                .and_then(|v| serde_json::to_string_pretty(&v).ok())
                .unwrap_or(args);
            let hash: Vec<u8> = r.get(5)?;
            let risk_name: String = r.get(6)?;
            Ok(Waiting {
                id: r.get(0)?,
                tool,
                runs,
                target: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                args: pretty,
                rev: r.get(4)?,
                hash: hash.iter().map(|b| format!("{b:02x}")).collect(),
                can_decide: can_approve(user.role, risk(&risk_name), true).is_ok(),
                risk: risk_name,
                step_up: r.get(7)?,
                requested_by: r.get(8)?,
                reason: r.get(9)?,
                expires: ui::time(r.get(10)?),
            })
        })?;
        rows.collect()
    });
    match rows {
        Ok(all) => {
            let confirm = ui::asked(ctx, "confirm")
                .and_then(|c| c.strip_prefix("reject:"))
                .and_then(|id| all.iter().find(|a| a.id == id && a.can_decide))
                .map(|a| {
                    let ask = Confirm {
                        title: format!("Reject {} on {}?", a.tool, a.target),
                        body: "It won't run. Whoever asked is told and can ask again.".into(),
                        action: format!("/approvals/{}/reject", a.id),
                        keep: "Keep it waiting",
                        does: "Reject".into(),
                        back: "/approvals",
                    };
                    ask.html(&ctx.csrf)
                })
                .unwrap_or_default();
            let q = ui::query(ctx);
            let fits = |a: &Waiting| ui::found(&q, &[&a.tool, &a.target, &a.requested_by, &a.reason, &a.risk]);
            let waiting = all.into_iter().filter(fits).collect();
            let shell = Shell::at(web, ctx, "Approvals", "/approvals");
            html(code, Page { shell, q: q.clone(), confirm, csrf: &ctx.csrf, waiting, notice }.render())
        }
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
        step_up_fresh: step_up::fresh(&web.0.db, user.step_up_at, ctx.now_ms),
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
        Err(ApprovalError::StepUpRequired) => to_step_up("/approvals"),
        Err(ApprovalError::NotPermitted) => {
            show(web, ctx, StatusCode::FORBIDDEN, Some("Your role can't decide an approval at this risk."))
        }
        Err(ApprovalError::AlreadyDecided) => show(
            web,
            ctx,
            StatusCode::CONFLICT,
            Some("This approval was already decided by someone else; nothing changed."),
        ),
        Err(ApprovalError::Expired) => {
            show(web, ctx, StatusCode::CONFLICT, Some("This approval has expired; nothing changed."))
        }
        Err(ApprovalError::Unknown) => show(web, ctx, StatusCode::NOT_FOUND, Some("No such approval.")),
        Err(e) => {
            tracing::error!(error = %e, "approval");
            let why = "The decision couldn't be recorded; try again.";
            show(web, ctx, StatusCode::INTERNAL_SERVER_ERROR, Some(why))
        }
    }
}
