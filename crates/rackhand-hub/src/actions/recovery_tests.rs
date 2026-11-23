//! A hub restart and the jobs it leaves (7.5.3 step 8, 7.3.7, E44): a job in a detached step is picked up by polling it,
//! one marked resumable goes on at its step (T60c), and every other running job ends `interrupted` with an incident.

use std::sync::{Arc, Mutex};

use rackhand_runbook::runbook::Step;
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use crate::actions::Actions;
use crate::actions::jobs::{self, NewJob};
use crate::actions::runner::{BoxFuture, StepCtx, StepOutcome, StepResult, StepRunner};
use crate::audit::Audit;
use crate::bus::Bus;
use crate::library::items::{Kind, Library};

const MACHINE: &str = "m1";

const DETACHED: &str = r#"name = "pull-then-verify"
description = "A detached pull, then a check"
identity = "automation"
risk = "normal"
autonomy = 1
[[step]]
id = "pull"
kind = "ssh"
cmd = ["sudo", "/usr/local/lib/rackhand/run", "/usr/bin/docker", "compose", "pull"]
detached = true
timeout = "30s"
[[step]]
id = "after"
kind = "ssh"
cmd = ["/usr/bin/true"]
timeout = "30s"
"#;

const PLAIN: &str = r#"name = "plain"
description = "One plain step"
identity = "automation"
risk = "normal"
autonomy = 1
[[step]]
id = "one"
kind = "ssh"
cmd = ["/usr/bin/true"]
timeout = "30s"
"#;

/// A runner that records what it was asked to start and what it was asked to take up.
#[derive(Default)]
struct Runner {
    run: Mutex<Vec<String>>,
    adopted: Mutex<Vec<String>>,
    /// What an adopted step ends with.
    adopt_fails: bool,
    cannot_adopt: bool,
}

impl StepRunner for Runner {
    fn run<'a>(&'a self, _ctx: &'a StepCtx, step: &'a Step, _argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            self.run.lock().unwrap().push(step.id.clone());
            StepResult { stdout: b"ran\n".to_vec(), ..ok() }
        })
    }

    fn adopt<'a>(
        &'a self,
        _ctx: &'a StepCtx,
        step: &'a Step,
        _argv: Option<&'a [String]>,
    ) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            self.adopted.lock().unwrap().push(step.id.clone());
            if self.cannot_adopt {
                return StepResult::failed("adopt_unavailable");
            }
            if self.adopt_fails {
                return StepResult::failed("exit_code 1");
            }
            StepResult { stdout: b"pulled\n".to_vec(), exit_code: Some(0), ..ok() }
        })
    }
}

fn ok() -> StepResult {
    StepResult { outcome: StepOutcome::Succeeded, command: None, exit_code: Some(0), stdout: vec![], stderr: vec![] }
}

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

async fn setup(name: &str, runner: Arc<Runner>) -> (Arc<Db>, Actions) {
    let dir = std::env::temp_dir().join(format!("rackhand-recovery-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let site = Row::from([("id", t("s")), ("name", t("home")), ("timezone", t("UTC"))]);
    let machine = Row::from([
        ("id", t(MACHINE)),
        ("site_id", t("s")),
        ("name", t("web")),
        ("kind", t("linux")),
        ("address", t("192.0.2.20")),
        ("state", t("enrolled")),
    ]);
    let batch = vec![RowWrite::insert("sites", site), RowWrite::insert("machines", machine)];
    db.writer().send(WriteCmd::Batch(batch)).await.unwrap();
    let audit = Audit::new(db.writer());
    let (library, _) = Library::new(db.clone(), audit.clone());
    library.save(Kind::Runbook, "pull-then-verify", DETACHED, "admin", 1).await.unwrap();
    library.save(Kind::Runbook, "plain", PLAIN, "admin", 1).await.unwrap();
    let actions = Actions::new(db.clone(), audit, Bus::new(), runner);
    (db, actions)
}

/// A job a stopped hub left running, in its step `step`.
async fn left(db: &Db, id: &str, kind: &str, name: &str, state: &str, step: Option<&str>) {
    let new = NewJob {
        id,
        kind,
        name,
        rev: None,
        target: Some(MACHINE),
        params: "{}",
        requested_by: "user:admin",
        incident_id: None,
        approval_id: None,
        state,
        now_ms: 1_000,
    };
    jobs::create(db, &new).await.unwrap();
    if let Some(step) = step {
        jobs::step_started(db, id, step, Some("docker compose pull"), 1_100).await.unwrap();
    }
}

fn job(db: &Db, id: &str) -> (String, Option<String>) {
    db.readers()
        .with(|c| c.query_row("SELECT state, outcome FROM jobs WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?))))
        .unwrap()
}

fn steps(db: &Db, id: &str) -> Vec<(String, String, String)> {
    db.readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT step_id, state, coalesce(CAST(stdout AS TEXT), '') FROM job_steps WHERE job_id = ?1 ORDER BY started_at, step_id",
            )?;
            s.query_map([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
        })
        .unwrap()
}

async fn until(what: &str, f: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !f() {
        assert!(std::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn non_resumable_running_job_interrupted_with_incident() {
    let (db, actions) = setup("interrupted", Arc::new(Runner::default())).await;
    left(&db, "J1", "runbook", "plain", "running", Some("one")).await;
    left(&db, "J2", "assistant", "assist", "running", None).await;
    left(&db, "J3", "runbook", "plain", "queued", None).await;
    left(&db, "J4", "runbook", "plain", "waiting_approval", None).await;
    let ingest = crate::ingest::Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    ingest.start(10_000).await.unwrap();
    let incidents = crate::incidents::Incidents::new(db.clone(), ingest, Bus::new());
    incidents.set_started(i64::MAX / 4);
    assert_eq!(actions.resume().await.unwrap(), 0, "nothing to take up");
    assert_eq!(job(&db, "J1"), ("interrupted".into(), Some("hub_restarted".into())));
    assert_eq!(job(&db, "J2"), ("interrupted".into(), Some("hub_restarted".into())), "an assistant job too");
    assert_eq!(job(&db, "J3").0, "queued", "a job that never started isn't one the restart interrupted");
    assert_eq!(job(&db, "J4").0, "waiting_approval");
    assert_eq!(steps(&db, "J1")[0].1, "interrupted", "the step that was running says so");
    // a warning event for each, which opens an incident on its machine
    let events: Vec<(String, String, Option<String>, Option<String>)> = db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT kind, severity, machine_id, job_id FROM events WHERE kind = 'job.interrupted' ORDER BY job_id",
            )?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect()
        })
        .unwrap();
    assert_eq!(events.len(), 2, "{events:?}");
    assert!(events.iter().all(|e| e.1 == "warning" && e.2.as_deref() == Some(MACHINE)), "{events:?}");
    incidents.evaluate(20_000).await.unwrap();
    let kinds: Vec<(String, String)> = db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT kind, state FROM incidents ORDER BY kind")?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })
        .unwrap();
    assert!(kinds.iter().any(|(k, s)| k == "job.interrupted" && s == "open"), "{kinds:?}");
    // a second start finds nothing more to do
    assert_eq!(actions.resume().await.unwrap(), 0);
    assert_eq!(
        db.readers()
            .with(|c| c
                .query_row("SELECT count(*) FROM events WHERE kind = 'job.interrupted'", [], |r| r.get::<_, i64>(0)))
            .unwrap(),
        2
    );
}

#[derive(Debug)]
struct Roomy;

impl crate::ingest::DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_job_in_a_detached_step_is_picked_up_by_polling_and_goes_on() {
    let runner = Arc::new(Runner::default());
    let (db, actions) = setup("detached", runner.clone()).await;
    left(&db, "J1", "runbook", "pull-then-verify", "running", Some("pull")).await;
    assert_eq!(actions.resume().await.unwrap(), 1);
    until("the job to finish", || job(&db, "J1").0 != "running").await;
    assert_eq!(job(&db, "J1"), ("succeeded".into(), None));
    assert_eq!(*runner.adopted.lock().unwrap(), ["pull"], "the running step was taken up");
    assert_eq!(*runner.run.lock().unwrap(), ["after"], "and not started again: only the step after it ran");
    let rows = steps(&db, "J1");
    assert_eq!(
        rows[0],
        ("pull".into(), "succeeded".into(), "pulled\n".into()),
        "its output and result recorded: {rows:?}"
    );
    assert_eq!(rows[1].0, "after");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_adopted_step_that_fails_fails_the_job_and_one_that_cannot_be_taken_up_is_interrupted() {
    let runner = Arc::new(Runner { adopt_fails: true, ..Runner::default() });
    let (db, actions) = setup("detached-fails", runner.clone()).await;
    left(&db, "J1", "runbook", "pull-then-verify", "running", Some("pull")).await;
    assert_eq!(actions.resume().await.unwrap(), 1);
    until("the job to finish", || job(&db, "J1").0 != "running").await;
    assert_eq!(job(&db, "J1"), ("failed".into(), Some("exit_code 1".into())));
    assert!(runner.run.lock().unwrap().is_empty(), "nothing after a failed step");
    // a runner that has no way to take a step up leaves the job interrupted, not hanging
    let runner = Arc::new(Runner { cannot_adopt: true, ..Runner::default() });
    let (db, actions) = setup("detached-cannot", runner).await;
    left(&db, "J1", "runbook", "pull-then-verify", "running", Some("pull")).await;
    actions.resume().await.unwrap();
    until("the job to finish", || job(&db, "J1").0 != "running").await;
    assert_eq!(job(&db, "J1"), ("interrupted".into(), Some("hub_restarted".into())));
}
