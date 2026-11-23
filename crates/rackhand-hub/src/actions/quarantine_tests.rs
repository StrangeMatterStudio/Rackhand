//! What Actions does with a machine's quarantine (7.5.6, D61, E23): the block on runbooks, and the state a quarantine job
//! moves the machine through.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rackhand_runbook::runbook::Step;
use rackhand_store::{Db, Row, RowUpdate, RowWrite, WriteCmd};
use rusqlite::types::Value;
use tokio::sync::Notify;

use super::runner::{BoxFuture, StepCtx, StepOutcome, StepResult, StepRunner};
use super::{Actions, ActionsError, StartJob};
use crate::audit::Audit;
use crate::bus::{Bus, JobOutcome};
use crate::library::items::{Kind, Library};

const WEB: &str = r#"name = "restart-web"
description = "Restart the web service"
identity = "automation"
risk = "low"
autonomy = 2
[[step]]
id = "restart"
kind = "ssh"
cmd = ["sudo", "/usr/local/lib/rackhand/run", "/usr/bin/systemctl", "restart", "nginx.service"]
timeout = "30s"
"#;

/// A runner that fails the steps it is told to, records the steps it ran, and can hold a step.
#[derive(Default)]
struct Steps {
    fail: Mutex<Vec<String>>,
    ran: Mutex<Vec<String>>,
    hold: AtomicBool,
    release: Notify,
}

impl StepRunner for Steps {
    fn run<'a>(&'a self, _ctx: &'a StepCtx, step: &'a Step, _argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            self.ran.lock().unwrap().push(step.id.clone());
            if self.hold.load(Ordering::SeqCst) {
                self.release.notified().await;
            }
            if self.fail.lock().unwrap().contains(&step.id) {
                return StepResult::failed(format!("{}_failed", step.id));
            }
            StepResult {
                outcome: StepOutcome::Succeeded,
                command: None,
                exit_code: Some(0),
                stdout: b"{}\n".to_vec(),
                stderr: Vec::new(),
            }
        })
    }
}

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

async fn setup(name: &str, quarantine: &str) -> (Arc<Db>, Actions, Arc<Steps>) {
    let dir = std::env::temp_dir().join(format!("rackhand-actions-q-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let site = Row::from([("id", t("s")), ("name", t("home")), ("timezone", t("UTC"))]);
    let machine = Row::from([
        ("id", t("m1")),
        ("site_id", t("s")),
        ("name", t("web")),
        ("kind", t("linux")),
        ("access", t("managed")),
        ("address", t("192.0.2.20")),
        ("state", t("enrolled")),
        ("quarantine", t(quarantine)),
    ]);
    db.writer()
        .send(WriteCmd::Batch(vec![RowWrite::insert("sites", site), RowWrite::insert("machines", machine)]))
        .await
        .unwrap();
    let audit = Audit::new(db.writer());
    let (lib, _) = Library::new(db.clone(), audit.clone());
    lib.save(Kind::Runbook, "restart-web", WEB, "admin", 1).await.unwrap();
    for name in ["quarantine", "quarantine-release"] {
        lib.save(Kind::Runbook, name, rackhand_runbook::builtin::runbook(name).unwrap(), "admin", 1).await.unwrap();
    }
    let steps = Arc::new(Steps::default());
    let actions = Actions::new(db.clone(), audit, Bus::new(), steps.clone());
    (db, actions, steps)
}

fn start(name: &str, by: &str) -> StartJob {
    StartJob { requested_by: by.into(), ..StartJob::runbook(name, "m1", by) }
}

fn state(db: &Db) -> String {
    db.readers().with(|c| c.query_row("SELECT quarantine FROM machines WHERE id = 'm1'", [], |r| r.get(0))).unwrap()
}

fn events(db: &Db, kind: &str) -> Vec<String> {
    db.readers()
        .with(|c| {
            let mut s = c.prepare("SELECT severity FROM events WHERE machine_id = 'm1' AND kind = ?1")?;
            s.query_map([kind], |r| r.get(0))?.collect()
        })
        .unwrap()
}

async fn set_state(db: &Arc<Db>, to: &str) {
    let update = RowUpdate { table: "machines", key: ("id", t("m1")), set: Row::from([("quarantine", t(to))]) };
    let change = rackhand_store::RegistryChange { updates: vec![update], ..Default::default() };
    db.writer().send(WriteCmd::RegistryChange(change)).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn quarantined_machine_refuses_runbooks_but_release() {
    let (db, actions, steps) = setup("block", "active").await;
    // whoever asks, a runbook other than the release is refused before anything runs: Incidents, the dashboard, the
    // Scheduler, an assistant's job
    for by in ["user:admin", "incident:01INC", "schedule:window", "job:01JOB", "peer:other"] {
        let refused = actions.run(start("restart-web", by)).await;
        assert_eq!(refused, Err(ActionsError::Quarantined), "{by}");
    }
    assert_eq!(
        actions.run(start("quarantine", "user:admin")).await,
        Err(ActionsError::Quarantined),
        "already quarantined"
    );
    assert!(steps.ran.lock().unwrap().is_empty(), "nothing reached the machine");
    let jobs: i64 = db.readers().with(|c| c.query_row("SELECT count(*) FROM jobs", [], |r| r.get(0))).unwrap();
    assert_eq!(jobs, 0, "no job row either");
    // the release runs, and the machine is a normal one again
    let done = actions.run(start("quarantine-release", "user:admin")).await.unwrap();
    assert_eq!(done.outcome, JobOutcome::Succeeded, "{done:?}");
    assert_eq!(state(&db), "none");
    assert_eq!(actions.run(start("restart-web", "user:admin")).await.unwrap().outcome, JobOutcome::Succeeded);
    // a failed quarantine blocks too, except for a retry of the quarantine itself
    set_state(&db, "failed").await;
    assert_eq!(actions.run(start("restart-web", "user:admin")).await, Err(ActionsError::Quarantined));
    assert_eq!(actions.run(start("quarantine-release", "user:admin")).await, Err(ActionsError::Quarantined));
    assert_eq!(actions.run(start("quarantine", "user:admin")).await.unwrap().outcome, JobOutcome::Succeeded);
    assert_eq!(state(&db), "active");
    // one waiting for approval doesn't block anything
    set_state(&db, "pending").await;
    assert_eq!(actions.run(start("restart-web", "user:admin")).await.unwrap().outcome, JobOutcome::Succeeded);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_quarantine_job_moves_the_machine_through_applying_to_active() {
    let (db, actions, steps) = setup("applying", "none").await;
    steps.hold.store(true, Ordering::SeqCst);
    let running = tokio::spawn({
        let actions = actions.clone();
        async move { actions.run(start("quarantine", "rule:dmz-known-bad")).await }
    });
    while steps.ran.lock().unwrap().is_empty() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(state(&db), "applying", "from the moment the job starts");
    // nothing else gets in while it applies
    assert_eq!(actions.run(start("restart-web", "user:admin")).await, Err(ActionsError::Quarantined));
    steps.release.notify_one();
    steps.hold.store(false, Ordering::SeqCst);
    let done = running.await.unwrap().unwrap();
    assert_eq!(done.outcome, JobOutcome::Succeeded);
    assert_eq!(state(&db), "active");
    assert_eq!(*steps.ran.lock().unwrap(), ["isolate", "snapshot"]);
    assert_eq!(events(&db, "quarantine.active"), ["info"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn isolation_failure_sets_failed_and_critical() {
    let (db, actions, steps) = setup("failed", "none").await;
    steps.fail.lock().unwrap().push("isolate".into());
    let done = actions.run(start("quarantine", "user:admin")).await.unwrap();
    assert_eq!((done.outcome, done.reason.as_deref()), (JobOutcome::Failed, Some("isolate_failed")));
    assert_eq!(state(&db), "failed");
    assert_eq!(events(&db, "quarantine.failed"), ["critical"], "a critical event, which opens a critical incident");
    assert_eq!(*steps.ran.lock().unwrap(), ["isolate"], "the snapshot didn't run after a failed isolation");
    // a retry with an approval goes through applying again
    steps.fail.lock().unwrap().clear();
    let again = actions.run(start("quarantine", "user:admin")).await.unwrap();
    assert_eq!(again.outcome, JobOutcome::Succeeded);
    assert_eq!(state(&db), "active");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_snapshot_after_isolation_is_failed_too() {
    let (db, actions, steps) = setup("snapfail", "none").await;
    steps.fail.lock().unwrap().push("snapshot".into());
    let done = actions.run(start("quarantine", "user:admin")).await.unwrap();
    assert_eq!(done.outcome, JobOutcome::Failed);
    assert_eq!(state(&db), "failed");
    assert_eq!(events(&db, "quarantine.failed"), ["critical"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_release_stays_active_with_a_critical_event() {
    let (db, actions, steps) = setup("relfail", "active").await;
    steps.fail.lock().unwrap().push("release".into());
    let done = actions.run(start("quarantine-release", "user:admin")).await.unwrap();
    assert_eq!((done.outcome, done.reason.as_deref()), (JobOutcome::Failed, Some("release_failed")));
    assert_eq!(state(&db), "active", "removal failed: still quarantined");
    assert_eq!(events(&db, "quarantine.release_failed"), ["critical"]);
    steps.fail.lock().unwrap().clear();
    assert_eq!(actions.run(start("quarantine-release", "user:admin")).await.unwrap().outcome, JobOutcome::Succeeded);
    assert_eq!(state(&db), "none");
    assert_eq!(events(&db, "quarantine.released"), ["info"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_busy_machine_changes_nothing_about_the_state() {
    let (db, actions, steps) = setup("busy", "none").await;
    let actions = actions.with_lock_wait(Duration::from_millis(300));
    steps.hold.store(true, Ordering::SeqCst);
    let first = tokio::spawn({
        let actions = actions.clone();
        async move { actions.run(start("restart-web", "user:admin")).await }
    });
    while steps.ran.lock().unwrap().is_empty() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // the quarantine waits for the machine and gives up: the machine isn't marked as applying, for nothing is
    let busy = actions.run(start("quarantine", "rule:x")).await.unwrap();
    assert_eq!(busy.reason.as_deref(), Some("machine_busy"));
    assert_eq!(state(&db), "none");
    steps.release.notify_one();
    steps.hold.store(false, Ordering::SeqCst);
    first.await.unwrap().unwrap();
}
