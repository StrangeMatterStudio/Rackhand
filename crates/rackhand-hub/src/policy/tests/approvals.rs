use std::sync::Arc;

use rackhand_runbook::runbook::Risk;
use rackhand_store::Db;
use serde_json::json;

use crate::policy::approvals::{ApprovalError, ApprovalRequest, Approvals, Decider, Role, approval_hash, can_approve};

const HOUR: i64 = 3_600_000;

fn db(name: &str) -> Arc<Db> {
    let dir = std::env::temp_dir().join(format!("rackhand-approvals-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Arc::new(Db::open(&dir.join("hub.db")).unwrap())
}

fn request() -> ApprovalRequest {
    ApprovalRequest {
        requester: "job:01JOB".into(),
        tool: "run_runbook".into(),
        target: Some("01MACHINE".into()),
        args: json!({"name": "compose-restart", "params": {"project": "web"}}),
        runbook_rev: Some(3),
        risk: Risk::Normal,
        step_up: false,
        reason: "containers restarting".into(),
    }
}

fn admin() -> Decider {
    Decider { user: "admin".into(), role: Role::Admin, step_up_fresh: true }
}

#[test]
fn hash_binds_requester_tool_target_args_revision() {
    let base = approval_hash(&request());
    assert_eq!(base, approval_hash(&request()), "stable");
    let changes: Vec<(&str, ApprovalRequest)> = vec![
        ("requester", ApprovalRequest { requester: "job:02OTHER".into(), ..request() }),
        ("tool", ApprovalRequest { tool: "exec".into(), ..request() }),
        ("target", ApprovalRequest { target: Some("01OTHER".into()), ..request() }),
        ("no target", ApprovalRequest { target: None, ..request() }),
        (
            "args",
            ApprovalRequest { args: json!({"name": "compose-restart", "params": {"project": "db"}}), ..request() },
        ),
        ("revision", ApprovalRequest { runbook_rev: Some(4), ..request() }),
    ];
    for (what, changed) in changes {
        assert_ne!(approval_hash(&changed), base, "{what} isn't bound");
    }
    // Key order in the arguments doesn't matter; their content does.
    let reordered =
        ApprovalRequest { args: json!({"params": {"project": "web"}, "name": "compose-restart"}), ..request() };
    assert_eq!(approval_hash(&reordered), base);
}

#[tokio::test(flavor = "multi_thread")]
async fn used_once_and_expired_refused() {
    let approvals = Approvals::new(db("once"));
    let now = 1_000 * HOUR;
    let id = approvals.create(&request(), now, HOUR).await.unwrap();
    let hash = approval_hash(&request());
    assert_eq!(approvals.use_approval(&id, "job:01JOB", &hash, now).await, Err(ApprovalError::NotApproved), "pending");
    approvals.decide(&id, &admin(), true, now + 1).await.unwrap();
    let other = approval_hash(&ApprovalRequest { args: json!({"name": "compose-restart"}), ..request() });
    assert_eq!(approvals.use_approval(&id, "job:01JOB", &other, now + 2).await, Err(ApprovalError::Mismatch));
    assert_eq!(
        approvals.use_approval(&id, "job:02OTHER", &hash, now + 2).await,
        Err(ApprovalError::Mismatch),
        "another caller"
    );
    approvals.use_approval(&id, "job:01JOB", &hash, now + 2).await.unwrap();
    assert_eq!(approvals.use_approval(&id, "job:01JOB", &hash, now + 3).await, Err(ApprovalError::Used));

    let late = approvals.create(&request(), now, HOUR).await.unwrap();
    approvals.decide(&late, &admin(), true, now + 1).await.unwrap();
    assert_eq!(approvals.use_approval(&late, "job:01JOB", &hash, now + HOUR).await, Err(ApprovalError::Expired));
    let undecided = approvals.create(&request(), now, HOUR).await.unwrap();
    assert_eq!(approvals.decide(&undecided, &admin(), true, now + HOUR).await, Err(ApprovalError::Expired));
    let rejected = approvals.create(&request(), now, HOUR).await.unwrap();
    approvals.decide(&rejected, &admin(), false, now + 1).await.unwrap();
    assert_eq!(approvals.use_approval(&rejected, "job:01JOB", &hash, now + 2).await, Err(ApprovalError::Rejected));
}

#[tokio::test(flavor = "multi_thread")]
async fn first_decision_wins() {
    let approvals = Arc::new(Approvals::new(db("race")));
    let now = 1_000 * HOUR;
    let id = approvals.create(&request(), now, HOUR).await.unwrap();
    let (a, b) = (approvals.clone(), approvals.clone());
    let (ida, idb) = (id.clone(), id.clone());
    let one = tokio::spawn(async move { a.decide(&ida, &admin(), true, now + 1).await });
    let two = tokio::spawn(async move {
        let other = Decider { user: "second".into(), role: Role::Admin, step_up_fresh: true };
        b.decide(&idb, &other, false, now + 1).await
    });
    let mut results = [one.await.unwrap(), two.await.unwrap()];
    results.sort_by_key(|r| r.is_err());
    assert_eq!(results[0], Ok(()));
    assert_eq!(results[1], Err(ApprovalError::AlreadyDecided));
    assert_eq!(approvals.decide(&id, &admin(), true, now + 5).await, Err(ApprovalError::AlreadyDecided));
}

#[test]
fn self_approval_allowed_viewer_cannot_responder_not_high() {
    use Risk::*;
    use Role::*;
    for risk in [Low, Normal, High] {
        assert_eq!(can_approve(Viewer, risk, true), Err(ApprovalError::NotPermitted), "viewer {risk:?}");
    }
    assert_eq!(can_approve(Responder, Low, false), Ok(()));
    assert_eq!(can_approve(Responder, Normal, false), Ok(()));
    assert_eq!(can_approve(Responder, High, true), Err(ApprovalError::NotPermitted));
    assert_eq!(can_approve(Admin, High, true), Ok(()));
    assert_eq!(can_approve(Admin, High, false), Err(ApprovalError::StepUpRequired), "high risk needs step-up");
    // A person approving their own request: the requester isn't an input, so nothing forbids it.
    let mine = ApprovalRequest { requester: "user:admin".into(), ..request() };
    assert_eq!(approval_hash(&mine), approval_hash(&mine));
}
