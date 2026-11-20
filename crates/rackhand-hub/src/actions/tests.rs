use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;
use tokio::sync::Notify;

use super::runner::{BoxFuture, StepCtx, StepOutcome, StepResult, StepRunner};
use super::{Actions, ActionsError, JobKind, StartJob};
use crate::audit::Audit;
use crate::bus::{Bus, BusEvent, Delivery, JobOutcome};
use crate::library::items::{Kind, Library};
use crate::policy::approvals::{ApprovalRequest, Approvals, Decider, Role};
use rackhand_runbook::runbook::{Risk, Step};

const RUNBOOK: &str = r#"name = "restart-web"
description = "Restart the web service"
identity = "automation"
risk = "low"
autonomy = 2
[params.unit]
type = "string"
pattern = "[a-z]+\\.service"
[[step]]
id = "restart"
kind = "ssh"
cmd = ["sudo", "/usr/local/lib/rackhand/run", "/usr/bin/systemctl", "restart", "{{unit}}"]
timeout = "30s"
"#;

/// A step runner the tests control.
#[derive(Default)]
struct Fake {
    calls: AtomicUsize,
    release: Notify,
    block: bool,
    panic: bool,
}

impl StepRunner for Fake {
    fn run<'a>(&'a self, _ctx: &'a StepCtx, _step: &'a Step, argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.panic {
                panic!("injected crash inside the step");
            }
            if self.block {
                self.release.notified().await;
            }
            StepResult {
                outcome: StepOutcome::Succeeded,
                command: argv.map(|a| a.join(" ")),
                exit_code: Some(0),
                stdout: b"ok\n".to_vec(),
                stderr: Vec::new(),
            }
        })
    }
}

async fn setup(name: &str, access: &str, runner: Arc<Fake>) -> (Arc<Db>, Actions, Bus) {
    let dir = std::env::temp_dir().join(format!("rackhand-actions-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    db.writer()
        .send(WriteCmd::Batch(vec![
            RowWrite::insert(
                "sites",
                Row::from([
                    ("id", Value::Text("s".into())),
                    ("name", Value::Text("home".into())),
                    ("timezone", Value::Text("UTC".into())),
                ]),
            ),
            RowWrite::insert(
                "machines",
                Row::from([
                    ("id", Value::Text("m1".into())),
                    ("site_id", Value::Text("s".into())),
                    ("name", Value::Text("web".into())),
                    ("kind", Value::Text("linux".into())),
                    ("access", Value::Text(access.into())),
                    ("address", Value::Text("192.0.2.20".into())),
                    ("state", Value::Text("enrolled".into())),
                ]),
            ),
        ]))
        .await
        .unwrap();
    let audit = Audit::new(db.writer());
    let (lib, _) = Library::new(db.clone(), audit.clone());
    lib.save(Kind::Runbook, "restart-web", RUNBOOK, "admin", 1).await.unwrap();
    let bus = Bus::new();
    let actions = Actions::new(db.clone(), audit, bus.clone(), runner);
    (db, actions, bus)
}

fn job(by: &str) -> StartJob {
    StartJob {
        kind: JobKind::Runbook,
        name: "restart-web".into(),
        rev: None,
        machine_id: "m1".into(),
        params: BTreeMap::from([("unit".to_string(), "nginx.service".to_string())]),
        requested_by: by.into(),
        incident_id: None,
        approval_id: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn second_job_waits_60s_then_machine_busy() {
    let runner = Arc::new(Fake { block: true, ..Fake::default() });
    let (db, actions, bus) = setup("busy", "managed", runner.clone()).await;
    let mut events = bus.subscribe("test");
    let actions = actions.with_lock_wait(Duration::from_millis(600));
    let first = tokio::spawn({
        let a = actions.clone();
        async move { a.run(job("admin")).await }
    });
    while runner.calls.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // A second job waits (queued) for the lock, then fails with machine_busy; its row and JobFinished record it.
    let started = std::time::Instant::now();
    let busy = actions.run(job("alice")).await.unwrap();
    assert_eq!((busy.outcome, busy.reason.as_deref()), (JobOutcome::Failed, Some("machine_busy")));
    assert!(started.elapsed() >= Duration::from_millis(600), "it waited");
    let (state, outcome): (String, String) = db
        .readers()
        .with(|c| {
            c.query_row("SELECT state, outcome FROM jobs WHERE id = ?1", [&busy.job_id], |r| Ok((r.get(0)?, r.get(1)?)))
        })
        .unwrap();
    assert_eq!((state.as_str(), outcome.as_str()), ("failed", "machine_busy"));
    match tokio::time::timeout(Duration::from_secs(1), events.recv()).await.unwrap() {
        Some(Delivery::Event(BusEvent::JobFinished { outcome, .. })) => assert_eq!(outcome, JobOutcome::Failed),
        other => panic!("{other:?}"),
    }
    // One that arrives while the first is finishing gets the machine once it's free.
    let third = tokio::spawn({
        let a = actions.clone();
        async move { a.run(job("bob")).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    runner.release.notify_one();
    assert_eq!(first.await.unwrap().unwrap().outcome, JobOutcome::Succeeded);
    tokio::time::sleep(Duration::from_millis(50)).await;
    runner.release.notify_one();
    assert_eq!(third.await.unwrap().unwrap().outcome, JobOutcome::Succeeded);
    assert_eq!(super::DEFAULT_LOCK_WAIT, Duration::from_secs(60));
}

#[tokio::test(flavor = "multi_thread")]
async fn step_recorded_before_it_runs() {
    let runner = Arc::new(Fake { panic: true, ..Fake::default() });
    let (db, actions, _) = setup("recorded", "managed", runner).await;
    let crashed = tokio::spawn(async move { actions.run(job("admin")).await }).await;
    assert!(crashed.is_err(), "the step crashed");
    let rows: Vec<(String, String, Option<String>)> = db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT step_id, state, command FROM job_steps")?;
            let rows = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect()
        })
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].0.as_str(), rows[0].1.as_str()), ("restart", "running"), "recorded before the crash");
    assert_eq!(rows[0].2.as_deref(), Some("sudo /usr/local/lib/rackhand/run /usr/bin/systemctl restart nginx.service"));
}

#[tokio::test(flavor = "multi_thread")]
async fn monitor_machine_ssh_step_fails_monitor_only_before_sending() {
    let runner = Arc::new(Fake::default());
    let (db, actions, _) = setup("monitor", "monitor", runner.clone()).await;
    let result = actions.run(job("admin")).await.unwrap();
    assert_eq!(result.outcome, JobOutcome::Failed);
    assert_eq!(result.reason.as_deref(), Some("monitor_only"));
    assert_eq!(runner.calls.load(Ordering::SeqCst), 0, "no connection attempted");
    let state: String = db.readers().with(|c| c.query_row("SELECT state FROM jobs", [], |r| r.get(0))).unwrap();
    assert_eq!(state, "failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn jobs_and_approvals_are_audited() {
    let runner = Arc::new(Fake::default());
    let (db, actions, bus) = setup("audited", "managed", runner).await;
    let mut events = bus.subscribe("test");
    // An approval for exactly this call.
    let approvals = Approvals::new(db.clone());
    let mut j = job("job:01JASSIST");
    let request = ApprovalRequest {
        requester: j.requested_by.clone(),
        tool: "run_runbook".into(),
        target: Some("m1".into()),
        args: serde_json::json!({ "name": "restart-web", "params": { "unit": "nginx.service" } }),
        runbook_rev: Some(1),
        risk: Risk::Low,
        step_up: false,
        reason: "nginx down".into(),
    };
    let now = rackhand_store::ids::now_ms();
    let id = approvals.create(&request, now, 3_600_000).await.unwrap();
    approvals
        .decide(&id, &Decider { user: "admin".into(), role: Role::Admin, step_up_fresh: true }, true, now)
        .await
        .unwrap();
    j.approval_id = Some(id.clone());
    j.rev = Some(1);
    let result = actions.run(j.clone()).await.unwrap();
    assert_eq!(result.outcome, JobOutcome::Succeeded);
    // Used once: the same approval doesn't start a second job.
    assert!(matches!(actions.run(j).await, Err(ActionsError::Approval(_))));
    let actions_logged: Vec<String> = db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT action FROM audit_log WHERE action LIKE 'job.%' OR action LIKE 'approval.%' ORDER BY seq",
            )?;
            let rows = s.query_map([], |r| r.get(0))?;
            rows.collect()
        })
        .unwrap();
    assert_eq!(actions_logged, ["approval.used", "job.started", "job.finished"]);
    match tokio::time::timeout(Duration::from_secs(1), events.recv()).await.unwrap() {
        Some(Delivery::Event(BusEvent::JobFinished { outcome, .. })) => assert_eq!(outcome, JobOutcome::Succeeded),
        other => panic!("{other:?}"),
    }
}

/// A step runner whose `exec` echoes the command after a short wait.
struct Echo;

impl StepRunner for Echo {
    fn run<'a>(&'a self, _ctx: &'a StepCtx, _step: &'a Step, _argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async { StepResult::failed("unused") })
    }
    fn exec<'a>(&'a self, _ctx: &'a StepCtx, command: &'a str) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            StepResult {
                outcome: StepOutcome::Succeeded,
                command: Some(command.into()),
                exit_code: Some(0),
                stdout: command.as_bytes().to_vec(),
                stderr: Vec::new(),
            }
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_execs_of_one_job_keep_their_own_rows() {
    let dir = std::env::temp_dir().join(format!("rackhand-actions-execs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let site = |id: &str, name: &str| {
        RowWrite::insert(
            "machines",
            Row::from([
                ("id", Value::Text(id.into())),
                ("site_id", Value::Text("s".into())),
                ("name", Value::Text(name.into())),
                ("kind", Value::Text("linux".into())),
            ]),
        )
    };
    db.writer()
        .send(WriteCmd::Batch(vec![
            RowWrite::insert(
                "sites",
                Row::from([
                    ("id", Value::Text("s".into())),
                    ("name", Value::Text("home".into())),
                    ("timezone", Value::Text("UTC".into())),
                ]),
            ),
            site("m1", "web"),
            site("m2", "db"),
        ]))
        .await
        .unwrap();
    let actions = Actions::new(db.clone(), Audit::new(db.writer()), Bus::new(), Arc::new(Echo));
    let job = actions.open_assistant_job("service-down", "user:admin", None).await.unwrap();
    let (a, b) = tokio::join!(
        actions.exec(&job, "m1", "uptime", Duration::from_secs(5)),
        actions.exec(&job, "m2", "df -h", Duration::from_secs(5)),
    );
    assert!(a.is_ok() && b.is_ok());
    let mut commands: Vec<String> = db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT command FROM job_steps WHERE job_id = ?1")?;
            let rows = s.query_map([&job], |r| r.get(0))?;
            rows.collect()
        })
        .unwrap();
    commands.sort();
    assert_eq!(commands, ["df -h", "uptime"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn busy_machine_doesnt_spend_the_approval() {
    let runner = Arc::new(Fake { block: true, ..Fake::default() });
    let (db, actions, _) = setup("busy-approval", "managed", runner.clone()).await;
    let actions = actions.with_lock_wait(Duration::from_millis(300));
    let holder = tokio::spawn({
        let a = actions.clone();
        async move { a.run(job("admin")).await }
    });
    while runner.calls.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let approvals = Approvals::new(db.clone());
    let mut j = job("key:01JKEY");
    let request = ApprovalRequest {
        requester: j.requested_by.clone(),
        tool: "run_runbook".into(),
        target: Some("m1".into()),
        args: serde_json::json!({ "name": "restart-web", "params": { "unit": "nginx.service" } }),
        runbook_rev: Some(1),
        risk: Risk::Low,
        step_up: false,
        reason: "r".into(),
    };
    let now = rackhand_store::ids::now_ms();
    let id = approvals.create(&request, now, 3_600_000).await.unwrap();
    approvals
        .decide(&id, &Decider { user: "admin".into(), role: Role::Admin, step_up_fresh: true }, true, now)
        .await
        .unwrap();
    j.approval_id = Some(id.clone());
    // Busy: the job fails machine_busy, and the approval is still there for a later try.
    assert_eq!(actions.run(j.clone()).await.unwrap().reason.as_deref(), Some("machine_busy"));
    let state: String =
        db.readers().with(|c| c.query_row("SELECT state FROM approvals WHERE id = ?1", [&id], |r| r.get(0))).unwrap();
    assert_eq!(state, "approved");
    runner.release.notify_one();
    holder.await.unwrap().unwrap();
    runner.release.notify_one();
    assert_eq!(actions.run(j).await.unwrap().outcome, JobOutcome::Succeeded);
}

/// Says whether new jobs may start, as Ingest does from the hub's free disk (E32).
#[derive(Debug)]
struct Gate(std::sync::atomic::AtomicBool);

impl super::JobGate for Gate {
    fn accepting_jobs(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn new_job_refused_while_disk_low() {
    let runner = Arc::new(Fake::default());
    let (db, actions, _bus) = setup("disk-low", "managed", runner.clone()).await;
    let gate = Arc::new(Gate(std::sync::atomic::AtomicBool::new(false)));
    let actions = actions.with_gate(gate.clone());
    let refused = actions.run(job("admin")).await.unwrap();
    assert_eq!((refused.outcome, refused.reason.as_deref()), (JobOutcome::Failed, Some("disk_low")));
    assert_eq!(runner.calls.load(Ordering::SeqCst), 0, "nothing ran");
    let outcome: String = db
        .readers()
        .with(|c| c.query_row("SELECT outcome FROM jobs WHERE id = ?1", [&refused.job_id], |r| r.get(0)))
        .unwrap();
    assert_eq!(outcome, "disk_low", "the job's row says why");
    gate.0.store(true, Ordering::SeqCst);
    let ran = actions.run(job("admin")).await.unwrap();
    assert_eq!(ran.outcome, JobOutcome::Succeeded, "jobs start again once there is space");
}
