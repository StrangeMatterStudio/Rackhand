use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;
use tokio::sync::oneshot;

use super::*;
use crate::actions::{JobResult, StartJob};
use crate::bus::JobOutcome;
use crate::policy::approvals::{Approvals, Decider, Role};

const MIN: i64 = 60_000;
/// Window times are around the real clock, which approvals and jobs use.
const LEN: i64 = 180 * MIN;

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

#[derive(Default)]
struct FakeWorld {
    offline: Mutex<HashSet<String>>,
    maintenance: Mutex<HashSet<String>>,
    pending: Mutex<HashMap<String, (u32, u32)>>,
}

impl World for FakeWorld {
    fn online(&self, id: &str, _now_ms: i64) -> bool {
        !self.offline.lock().unwrap().contains(id)
    }
    fn pending(&self, id: &str) -> (u32, u32) {
        self.pending.lock().unwrap().get(id).copied().unwrap_or((1, 3))
    }
    fn in_maintenance(&self, id: &str, _tags: &[String], _now_ms: i64) -> bool {
        self.maintenance.lock().unwrap().contains(id)
    }
}

/// Jobs that run until the test ends them.
#[derive(Default)]
struct FakeJobs {
    started: Mutex<Vec<StartJob>>,
    running: Mutex<BTreeMap<String, oneshot::Sender<JobOutcome>>>,
    /// The reason a job that isn't `Succeeded` ends with.
    reason: Mutex<Option<String>>,
}

impl Jobs for FakeJobs {
    fn run(&self, job: StartJob) -> BoxFuture<'static, Result<JobResult, ActionsError>> {
        let (tx, rx) = oneshot::channel();
        self.running.lock().unwrap().insert(job.machine_id.clone(), tx);
        let n = {
            let mut s = self.started.lock().unwrap();
            s.push(job);
            s.len()
        };
        let reason = self.reason.lock().unwrap().clone();
        Box::pin(async move {
            let outcome = rx.await.unwrap_or(JobOutcome::Failed);
            let reason = reason.filter(|_| outcome != JobOutcome::Succeeded);
            Ok(JobResult { job_id: format!("01JJOB{n:020}"), outcome, reason })
        })
    }
}

impl FakeJobs {
    fn started(&self) -> Vec<(String, String)> {
        self.started.lock().unwrap().iter().map(|j| (j.name.clone(), j.machine_id.clone())).collect()
    }
    fn end(&self, machine: &str) {
        self.end_with(machine, JobOutcome::Succeeded);
    }
    fn end_with(&self, machine: &str, outcome: JobOutcome) {
        self.running.lock().unwrap().remove(machine).unwrap().send(outcome).unwrap();
    }
}

struct Env {
    db: Arc<Db>,
    world: Arc<FakeWorld>,
    jobs: Arc<FakeJobs>,
    driver: Arc<Driver>,
    now: i64,
}

async fn env(name: &str) -> Env {
    let dir = std::env::temp_dir().join(format!("rackhand-patchdriver-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let policy = |id: &str, patch: &str| {
        RowWrite::insert("policies", Row::from([("id", t(id)), ("name", t(id)), ("patch", t(patch))]))
    };
    db.writer()
        .send(WriteCmd::Batch(vec![
            RowWrite::insert("sites", Row::from([("id", t("s1")), ("name", t("home")), ("timezone", t("UTC"))])),
            policy("auto", "auto"),
            policy("auto2", "auto"),
            policy("ask", "approve-only"),
            policy("hold", "hold"),
        ]))
        .await
        .unwrap();
    let (library, _) = crate::library::items::Library::new(db.clone(), crate::audit::Audit::new(db.writer()));
    library.seed(rackhand_runbook::builtin::runbooks(), 1).await.unwrap();
    let (world, jobs) = (Arc::new(FakeWorld::default()), Arc::new(FakeJobs::default()));
    let driver = Driver::new(db.clone(), world.clone(), jobs.clone());
    Env { db, world, jobs, driver, now: rackhand_store::ids::now_ms() }
}

impl Env {
    async fn machine(&self, id: &str, kind: &str, policy: &str, roles: &str) {
        let row = Row::from([
            ("id", t(id)),
            ("site_id", t("s1")),
            ("name", t(id)),
            ("kind", t(kind)),
            ("access", t("managed")),
            ("policy_id", t(policy)),
            ("roles", t(roles)),
            ("state", t("enrolled")),
        ]);
        self.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("machines", row)])).await.unwrap();
    }

    fn window(&self, policy: &str, window: Window) -> OpenWindow {
        OpenWindow {
            policy: policy.into(),
            site: "s1".into(),
            window,
            starts_ms: self.now - MIN,
            ends_ms: self.now - MIN + LEN,
            next_ends_ms: self.now - MIN + 24 * 60 * MIN + LEN,
        }
    }

    async fn tick(&self, open: Vec<OpenWindow>, at: i64) {
        self.driver.tick(open, at).await;
    }

    /// Ends the machine's job and waits until the driver has seen it.
    async fn end(&self, machine: &str) {
        self.jobs.end(machine);
        for _ in 0..200 {
            if !self.driver.busy(machine).await {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("{machine}'s job didn't end");
    }

    fn approvals(&self) -> Vec<(String, String, String)> {
        self.db
            .readers()
            .with(|c| {
                let mut s = c.prepare("SELECT id, target, state FROM approvals ORDER BY target, id")?;
                s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
            })
            .unwrap()
    }

    async fn approve(&self, id: &str, at: i64) {
        let by = Decider { user: "admin".into(), role: Role::Admin, step_up_fresh: true };
        Approvals::new(self.db.clone()).decide(id, &by, true, at).await.unwrap();
    }
}

/// FR-13: a window starts the runbook of each machine's kind, and leaves out `hold`, another policy's machines, machines
/// in maintenance, pending or quarantined ones, and kinds and roles whose runbooks don't exist yet (T60, T90).
#[tokio::test(flavor = "multi_thread")]
async fn window_starts_the_runbook_of_each_kind() {
    let e = env("starts").await;
    e.machine("web", "linux", "auto", "[]").await;
    e.machine("alp", "alpine", "auto", "[]").await;
    e.machine("held", "linux", "hold", "[]").await;
    e.machine("other", "linux", "auto2", "[]").await;
    e.machine("maint", "linux", "auto", "[]").await;
    e.machine("win", "windows", "auto", "[]").await;
    e.machine("pve", "linux", "auto", "[\"hypervisor\"]").await;
    e.machine("new", "linux", "auto", "[]").await;
    e.machine("quar", "linux", "auto", "[]").await;
    for (id, col, v) in [("new", "state", "pending"), ("quar", "quarantine", "active")] {
        let set = Row::from([(col, t(v))]);
        let update = rackhand_store::RowUpdate { table: "machines", key: ("id", t(id)), set };
        let change = rackhand_store::RegistryChange { updates: vec![update], ..Default::default() };
        e.db.writer().send(WriteCmd::RegistryChange(change)).await.unwrap();
    }
    e.world.maintenance.lock().unwrap().insert("maint".into());
    e.tick(vec![e.window("auto", Window::Security), e.window("hold", Window::Security)], e.now).await;
    assert_eq!(e.jobs.started(), [("patch-debian".to_string(), "web".to_string())], "Alpine waits for the full window");
    e.end("web").await;
    e.tick(vec![e.window("auto", Window::Full)], e.now + MIN).await;
    let mut started = e.jobs.started();
    started.sort();
    assert!(started.contains(&("patch-alpine".into(), "alp".into())), "{started:?}");
    assert!(started.iter().all(|(_, m)| ["web", "alp"].contains(&m.as_str())), "{started:?}");
    let job = e.jobs.started.lock().unwrap()[0].clone();
    assert_eq!((job.requested_by.as_str(), job.approval_id), (REQUESTER, None));
}

/// 7.5.3: at most 3 at once at a site, across its policies; a finished job frees its place.
#[tokio::test(flavor = "multi_thread")]
async fn site_limit_holds_across_policies() {
    let e = env("limit").await;
    for id in ["a1", "a2"] {
        e.machine(id, "linux", "auto", "[]").await;
    }
    for id in ["b1", "b2"] {
        e.machine(id, "linux", "auto2", "[]").await;
    }
    let open = || vec![e.window("auto", Window::Security), e.window("auto2", Window::Security)];
    e.tick(open(), e.now).await;
    assert_eq!(e.jobs.started().len(), 3, "{:?}", e.jobs.started());
    e.tick(open(), e.now + MIN).await;
    assert_eq!(e.jobs.started().len(), 3, "still full");
    e.end("a1").await;
    e.tick(open(), e.now + 2 * MIN).await;
    assert_eq!(e.jobs.started().len(), 4);
}

/// A machine is tried once per window: not again after its job, nor by a hub that restarted during the window.
#[tokio::test(flavor = "multi_thread")]
async fn once_per_window_also_after_a_restart() {
    let e = env("once").await;
    e.machine("web", "linux", "auto", "[]").await;
    e.machine("db", "linux", "auto", "[]").await;
    let job = Row::from([
        ("id", t("01JDONE")),
        ("kind", t("runbook")),
        ("name", t("patch-debian")),
        ("target", t("web")),
        ("requested_by", t(REQUESTER)),
        ("state", t("failed")),
        ("started_at", Value::Integer(e.now - 1000)),
    ]);
    e.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("jobs", job)])).await.unwrap();
    e.tick(vec![e.window("auto", Window::Security)], e.now).await;
    assert_eq!(e.jobs.started(), [("patch-debian".to_string(), "db".to_string())], "web had its job in this window");
    e.end("db").await;
    e.tick(vec![e.window("auto", Window::Security)], e.now + MIN).await;
    assert_eq!(e.jobs.started().len(), 1, "once per window");
}

/// 7.5.3 step 2: a machine offline at its turn is tried again every 15 minutes.
#[tokio::test(flavor = "multi_thread")]
async fn offline_machine_tried_again() {
    let e = env("offline").await;
    e.machine("web", "linux", "auto", "[]").await;
    e.world.offline.lock().unwrap().insert("web".into());
    let open = || vec![e.window("auto", Window::Security)];
    e.tick(open(), e.now).await;
    e.world.offline.lock().unwrap().clear();
    e.tick(open(), e.now + 14 * MIN).await;
    assert!(e.jobs.started().is_empty(), "not before its next try");
    e.tick(open(), e.now + 15 * MIN).await;
    assert_eq!(e.jobs.started().len(), 1);
}

/// AC20: nothing patches during a maintenance window, also one that starts while the machine waits its turn.
#[tokio::test(flavor = "multi_thread")]
async fn maintenance_after_selection_holds_the_machine_back() {
    let e = env("late-maintenance").await;
    for id in ["a", "b", "c", "d"] {
        e.machine(id, "linux", "auto", "[]").await;
    }
    let open = || vec![e.window("auto", Window::Security)];
    e.tick(open(), e.now).await;
    assert_eq!(e.jobs.started().len(), 3, "3 at a time per site");
    e.world.maintenance.lock().unwrap().insert("d".into());
    e.end("a").await;
    e.tick(open(), e.now + MIN).await;
    assert_eq!(e.jobs.started().len(), 3, "d's maintenance window has started");
    e.world.maintenance.lock().unwrap().clear();
    e.tick(open(), e.now + 16 * MIN).await;
    assert_eq!(e.jobs.started().last().map(|j| j.1.as_str()), Some("d"), "over before the patch window is");
}

/// 7.5.3 step 3 (D89): an approve-only machine's approval is asked for once, bound to the runbook's revision, and its
/// job starts with it; a rejected one starts nothing.
#[tokio::test(flavor = "multi_thread")]
async fn approve_only_asks_once_and_starts_with_the_approval() {
    let e = env("approve").await;
    e.machine("no", "linux", "ask", "[]").await;
    e.machine("yes", "linux", "ask", "[]").await;
    let open = || vec![e.window("ask", Window::Security)];
    e.tick(open(), e.now).await;
    e.tick(open(), e.now + MIN).await;
    let asked = e.approvals();
    assert_eq!(asked.iter().map(|a| a.1.as_str()).collect::<Vec<_>>(), ["no", "yes"], "asked once each");
    assert!(e.jobs.started().is_empty());
    e.approve(&asked[1].0, e.now + MIN).await;
    let by = Decider { user: "admin".into(), role: Role::Admin, step_up_fresh: true };
    Approvals::new(e.db.clone()).decide(&asked[0].0, &by, false, e.now + MIN).await.unwrap();
    e.tick(open(), e.now + 2 * MIN).await;
    assert_eq!(e.jobs.started(), [("patch-debian".to_string(), "yes".to_string())]);
    let job = e.jobs.started.lock().unwrap()[0].clone();
    assert_eq!(job.approval_id.as_deref(), Some(asked[1].0.as_str()));
    // it is an approval Actions takes for exactly this job
    let (rev, _) =
        crate::library::items::Library::current_in(&e.db, crate::library::items::Kind::Runbook, "patch-debian")
            .unwrap()
            .unwrap();
    let hash = crate::policy::approvals::approval_hash(&request(
        "patch-debian",
        "yes",
        rev,
        rackhand_runbook::runbook::Risk::Normal,
    ));
    Approvals::new(e.db.clone()).check(&asked[1].0, REQUESTER, &hash, e.now + MIN).unwrap();
    assert_eq!(e.approvals().len(), 2, "a rejected machine isn't asked again in the window");
}

/// D89: an approval given after its window ended starts nothing then, and the next window runs the machine without
/// asking again.
#[tokio::test(flavor = "multi_thread")]
async fn late_approval_carries_to_the_next_window() {
    let e = env("late").await;
    e.machine("web", "linux", "ask", "[]").await;
    e.tick(vec![e.window("ask", Window::Security)], e.now).await;
    let asked = e.approvals();
    assert_eq!(asked.len(), 1);
    let after = e.now + LEN + MIN;
    e.tick(vec![], after).await;
    e.approve(&asked[0].0, after).await;
    e.tick(vec![], after + MIN).await;
    assert!(e.jobs.started().is_empty(), "the window is over");
    let day = 24 * 60 * MIN;
    let w = e.window("ask", Window::Security);
    let next =
        OpenWindow { starts_ms: w.starts_ms + day, ends_ms: w.ends_ms + day, next_ends_ms: w.next_ends_ms + day, ..w };
    e.tick(vec![next], e.now + day).await;
    assert_eq!(e.jobs.started(), [("patch-debian".to_string(), "web".to_string())]);
    assert_eq!(e.approvals().len(), 1, "not asked again");
}

/// 7.5.3 step 6, D45: a machine that never reported after its patch's reboot is rolled back to the snapshot the job took,
/// once, when its policy has `auto_rollback`; not for another failure, without a snapshot, or without the policy.
#[tokio::test(flavor = "multi_thread")]
async fn rolls_back_only_under_d45() {
    for (name, auto, snapshot, reason, expected) in [
        ("yes", 1, r#"{"snapshot":"rackhand-patch-20261122-0400"}"#, "no_report_after_reboot", true),
        ("off", 0, r#"{"snapshot":"rackhand-patch-20261122-0400"}"#, "no_report_after_reboot", false),
        ("none", 1, r#"{"snapshot":null,"notes":["not a Proxmox guest"]}"#, "no_report_after_reboot", false),
        ("up", 1, r#"{"snapshot":"rackhand-patch-20261122-0400"}"#, "did_not_reboot", false),
        ("verify", 1, r#"{"snapshot":"rackhand-patch-20261122-0400"}"#, "as_recorded", false),
    ] {
        let e = env(&format!("rollback-{name}")).await;
        e.machine("web", "linux", "auto", "[]").await;
        let set = Row::from([("auto_rollback", Value::Integer(auto))]);
        let update = rackhand_store::RowUpdate { table: "policies", key: ("id", t("auto")), set };
        let change = rackhand_store::RegistryChange { updates: vec![update], ..Default::default() };
        e.db.writer().send(WriteCmd::RegistryChange(change)).await.unwrap();
        *e.jobs.reason.lock().unwrap() = Some(reason.to_string());
        e.tick(vec![e.window("auto", Window::Security)], e.now).await;
        let job = format!("01JJOB{:020}", 1);
        let row = Row::from([
            ("id", t(&job)),
            ("kind", t("runbook")),
            ("name", t("patch-debian")),
            ("target", t("web")),
            ("requested_by", t(REQUESTER)),
            ("state", t("failed")),
        ]);
        let step = Row::from([
            ("job_id", t(&job)),
            ("step_id", t("snapshot")),
            ("state", t("succeeded")),
            ("stdout", Value::Blob(snapshot.as_bytes().to_vec())),
        ]);
        e.db.writer()
            .send(WriteCmd::Batch(vec![RowWrite::insert("jobs", row), RowWrite::insert("job_steps", step)]))
            .await
            .unwrap();
        e.jobs.end_with("web", JobOutcome::Failed);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let started = e.jobs.started.lock().unwrap().clone();
        let rollback: Vec<&StartJob> = started.iter().filter(|j| j.name == "rollback").collect();
        assert_eq!(rollback.len(), usize::from(expected), "{name}: {started:?}");
        if expected {
            assert_eq!(rollback[0].params.get("job"), Some(&job));
            assert_eq!((rollback[0].machine_id.as_str(), rollback[0].requested_by.as_str()), ("web", REQUESTER));
            assert!(e.driver.busy("web").await, "the machine stays the window's until the rollback ends");
            e.jobs.end_with("web", JobOutcome::Failed);
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            assert_eq!(e.jobs.started.lock().unwrap().len(), 2, "a failed rollback isn't rolled back");
            assert!(!e.driver.busy("web").await);
        }
    }
}
