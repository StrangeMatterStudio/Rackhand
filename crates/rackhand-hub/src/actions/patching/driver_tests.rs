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

/// Hypervisors as their APIs give them.
#[derive(Default)]
struct FakeHosts(Mutex<HashMap<String, HostView>>);

impl Hosts for FakeHosts {
    fn view<'a>(&'a self, host: &'a str) -> crate::actions::runner::BoxFuture<'a, Result<HostView, String>> {
        let v = self.0.lock().unwrap().get(host).cloned().ok_or_else(|| "no_hypervisor".to_string());
        Box::pin(async move { v })
    }
}

impl FakeHosts {
    fn put(&self, host: &str, node: &str, nodes: &[&str], guests: &[(u64, &str, bool)]) {
        let guests = guests
            .iter()
            .map(|(vmid, name, running)| HostGuest {
                vmid: *vmid,
                kind: "qemu".into(),
                name: (*name).into(),
                running: *running,
            })
            .collect();
        let nodes = nodes.iter().map(|n| n.to_string()).collect();
        self.0.lock().unwrap().insert(host.into(), HostView { node: node.into(), nodes, guests });
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
    hosts: Arc<FakeHosts>,
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
    let hosts = Arc::new(FakeHosts::default());
    let driver = Driver::with_hosts(db.clone(), world.clone(), jobs.clone(), hosts.clone());
    Env { db, world, jobs, hosts, driver, now: rackhand_store::ids::now_ms() }
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

    /// Ends the host's patch, whose reboot step left `reboot` in the job log.
    async fn end_patch(&self, machine: &str, reboot: &str) {
        let n = self.jobs.started.lock().unwrap().iter().position(|j| j.machine_id == machine).unwrap() + 1;
        let job = format!("01JJOB{n:020}");
        let row = Row::from([
            ("id", t(&job)),
            ("kind", t("runbook")),
            ("name", t("patch-proxmox-host")),
            ("target", t(machine)),
            ("requested_by", t("test")),
            ("state", t("succeeded")),
        ]);
        let step = Row::from([
            ("job_id", t(&job)),
            ("step_id", t("reboot")),
            ("state", t("succeeded")),
            ("stdout", Value::Blob(format!("{{\"reboot\":\"{reboot}\"}}\n").into_bytes())),
        ]);
        self.db
            .writer()
            .send(WriteCmd::Batch(vec![RowWrite::insert("jobs", row), RowWrite::insert("job_steps", step)]))
            .await
            .unwrap();
        self.end(machine).await;
    }

    /// The machine's `reboot-host` job in the log and its approval used, as Actions would have it.
    async fn log_reboot(&self, machine: &str, started_ms: i64) {
        for (id, ..) in self.reboots().into_iter().filter(|r| r.1 == machine) {
            let hash: Vec<u8> = self
                .db
                .readers()
                .with(|c| c.query_row("SELECT args_hash FROM approvals WHERE id = ?1", [&id], |r| r.get(0)))
                .unwrap();
            Approvals::new(self.db.clone()).use_approval(&id, REQUESTER, &hash, started_ms).await.unwrap();
        }
        let row = Row::from([
            ("id", t(&ulid::Ulid::new().to_string())),
            ("kind", t("runbook")),
            ("name", t("reboot-host")),
            ("target", t(machine)),
            ("requested_by", t(REQUESTER)),
            ("state", t("succeeded")),
            ("started_at", Value::Integer(started_ms)),
        ]);
        self.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("jobs", row)])).await.unwrap();
    }

    /// The reboot approvals: (id, target, risk, step-up, reason).
    fn reboots(&self) -> Vec<(String, String, String, bool, String)> {
        self.db
            .readers()
            .with(|c| {
                let mut s = c.prepare(
                    "SELECT id, target, risk, step_up != 0, reason FROM approvals
                     WHERE json_extract(args, '$.name') = 'reboot-host' ORDER BY target, id",
                )?;
                s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?.collect()
            })
            .unwrap()
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
/// in maintenance, pending or quarantined ones, and the kind whose runbook doesn't exist yet (T90).
#[tokio::test(flavor = "multi_thread")]
async fn window_starts_the_runbook_of_each_kind() {
    let e = env("starts").await;
    e.machine("web", "linux", "auto", "[]").await;
    e.machine("alp", "alpine", "auto", "[]").await;
    e.machine("held", "linux", "hold", "[]").await;
    e.machine("other", "linux", "auto2", "[]").await;
    e.machine("maint", "linux", "auto", "[]").await;
    e.machine("win", "windows", "auto", "[]").await;
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

/// 7.5.3 steps 2 and 7: hypervisors, by role or by kind, have a runbook of their own and go after every other machine,
/// one at a time.
#[tokio::test(flavor = "multi_thread")]
async fn hypervisors_go_last_with_their_own_runbook() {
    let e = env("hosts").await;
    e.machine("pve1", "linux", "auto", "[\"hypervisor\"]").await;
    e.machine("pve2", "hypervisor", "auto", "[]").await;
    e.machine("web", "linux", "auto", "[]").await;
    let open = || vec![e.window("auto", Window::Security)];
    for (i, (runbook, machine)) in
        [("patch-debian", "web"), ("patch-proxmox-host", "pve1"), ("patch-proxmox-host", "pve2")]
            .into_iter()
            .enumerate()
    {
        e.tick(open(), e.now + i as i64 * MIN).await;
        assert_eq!(e.jobs.started().last(), Some(&(runbook.to_string(), machine.to_string())));
        assert_eq!(e.jobs.started().len(), i + 1, "one at a time");
        e.end(machine).await;
    }
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

/// E13: a patched hypervisor that needs a reboot isn't rebooted; a high-risk approval with step-up lists every guest that
/// goes down with it, and the reboot runs once approved. One that needs none asks nothing.
#[tokio::test(flavor = "multi_thread")]
async fn hypervisor_reboot_needs_high_risk_approval_listing_guests() {
    let e = env("hv-reboot").await;
    e.machine("pve", "hypervisor", "auto", "[]").await;
    e.machine("calm", "hypervisor", "auto", "[]").await;
    e.hosts.put("pve", "pve1", &["pve1"], &[(101, "web", true), (102, "db", true), (103, "spare", false)]);
    e.hosts.put("calm", "pve2", &["pve2"], &[(201, "x", true)]);
    let open = || vec![e.window("auto", Window::Security)];
    e.tick(open(), e.now).await;
    e.end_patch("calm", "not_required").await;
    e.tick(open(), e.now + MIN).await;
    e.end_patch("pve", "required_not_allowed").await;
    let asked = e.reboots();
    assert_eq!(asked.len(), 1, "{asked:?}");
    let (id, target, risk, step_up, reason) = asked[0].clone();
    assert_eq!((target.as_str(), risk.as_str(), step_up), ("pve", "high", true));
    for part in ["web (VM 101)", "db (VM 102)", "spare (VM 103, stopped)"] {
        assert!(reason.contains(part), "{reason}");
    }
    e.tick(open(), e.now + 2 * MIN).await;
    assert!(e.jobs.started().iter().all(|j| j.0 != "reboot-host"), "not before it is approved");
    e.approve(&id, e.now + 2 * MIN).await;
    e.tick(open(), e.now + 3 * MIN).await;
    assert_eq!(e.jobs.started().last(), Some(&("reboot-host".to_string(), "pve".to_string())));
    let job = e.jobs.started.lock().unwrap().last().unwrap().clone();
    assert_eq!(job.approval_id.as_deref(), Some(id.as_str()));
    e.tick(open(), e.now + 4 * MIN).await;
    assert_eq!(e.jobs.started().iter().filter(|j| j.0 == "reboot-host").count(), 1, "once");
    assert_eq!(e.reboots().len(), 1, "asked once");
}

/// A hypervisor whose guests can't be listed isn't asked about: a person couldn't see what goes down.
#[tokio::test(flavor = "multi_thread")]
async fn hypervisor_without_a_guest_list_asks_nothing() {
    let e = env("hv-blind").await;
    e.machine("pve", "hypervisor", "auto", "[]").await;
    e.tick(vec![e.window("auto", Window::Security)], e.now).await;
    e.end_patch("pve", "required_not_allowed").await;
    assert!(e.reboots().is_empty());
}

/// E62: when the hub is one of the guests (its confirmed binding), the approval says so.
#[tokio::test(flavor = "multi_thread")]
async fn hypervisor_approval_names_hub_when_hub_is_a_guest() {
    for (state, named) in [("confirmed", true), ("proposed", false)] {
        let e = env(&format!("hv-hub-{state}")).await;
        e.machine("pve", "hypervisor", "auto", "[]").await;
        let reference = r#"{"cluster":"pve","node":"pve1","vmid":102,"type":"qemu"}"#;
        let hub = Row::from([
            ("id", t("hub")),
            ("site_id", t("s1")),
            ("name", t("rackhand")),
            ("kind", t("linux")),
            ("roles", t("[\"hub\"]")),
            ("state", t("enrolled")),
            ("proxmox_ref", t(reference)),
            ("proxmox_ref_state", t(state)),
        ]);
        e.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("machines", hub)])).await.unwrap();
        e.hosts.put("pve", "pve1", &["pve1"], &[(101, "web", true), (102, "rackhand", true)]);
        e.tick(vec![e.window("auto", Window::Security)], e.now).await;
        e.end_patch("pve", "required_not_allowed").await;
        let (id, _, _, _, reason) = e.reboots()[0].clone();
        assert_eq!(reason.contains("This hub is one of them: rackhand (VM 102)"), named, "{state}: {reason}");
        e.approve(&id, e.now + MIN).await;
        e.tick(vec![e.window("auto", Window::Security)], e.now + MIN).await;
        assert!(e.jobs.started().iter().any(|j| j.0 == "reboot-host"), "{state}: the step schedules it");
    }
}

/// 7.5.3 step 7: two hypervisors of one cluster are never rebooted in the same window, whoever rebooted the first and
/// also after the hub restarted; one that stands alone is.
#[tokio::test(flavor = "multi_thread")]
async fn hypervisor_two_cluster_members_never_rebooted_same_window() {
    let e = env("hv-cluster").await;
    for (id, node, nodes) in [("a", "n1", &["n1", "n2"][..]), ("b", "n2", &["n1", "n2"][..]), ("c", "n1", &["n1"][..])]
    {
        e.machine(id, "hypervisor", "auto", "[]").await;
        e.hosts.put(id, node, nodes, &[(101, "web", true)]);
    }
    let open = || vec![e.window("auto", Window::Security)];
    let mut at = e.now;
    for id in ["a", "b", "c"] {
        e.tick(open(), at).await;
        e.end_patch(id, "required_not_allowed").await;
        at += MIN;
    }
    for (id, ..) in e.reboots() {
        e.approve(&id, at).await;
    }
    e.tick(open(), at).await;
    assert_eq!(e.jobs.started().last().unwrap(), &("reboot-host".to_string(), "a".to_string()), "one at a time");
    e.log_reboot("a", at).await;
    e.end("a").await;
    e.tick(open(), at + MIN).await;
    assert_eq!(e.jobs.started().last().unwrap().1, "c", "b is in a's cluster and waits; c stands alone");
    e.log_reboot("c", at + MIN).await;
    e.end("c").await;
    e.tick(open(), at + 2 * MIN).await;
    assert!(!e.jobs.started().contains(&("reboot-host".into(), "b".into())));
    // a hub that restarted knows it from the job log
    let hosts: Arc<dyn Hosts> = e.hosts.clone();
    let restarted = Driver::with_hosts(e.db.clone(), e.world.clone(), e.jobs.clone(), hosts);
    restarted.tick(open(), at + 3 * MIN).await;
    assert!(!e.jobs.started().contains(&("reboot-host".into(), "b".into())));
    // the next window takes it, without asking again
    let day = 24 * 60 * MIN;
    let w = e.window("auto", Window::Security);
    let next =
        OpenWindow { starts_ms: w.starts_ms + day, ends_ms: w.ends_ms + day, next_ends_ms: w.next_ends_ms + day, ..w };
    e.world.pending.lock().unwrap().extend(["a", "b", "c"].map(|m| (m.to_string(), (0, 0))));
    e.tick(vec![next], e.now + day).await;
    assert!(e.jobs.started().contains(&("reboot-host".into(), "b".into())));
    assert_eq!(e.reboots().len(), 3);
}

/// A reboot job that ended without using its approval (the machine was busy, say) isn't started again in that window.
#[tokio::test(flavor = "multi_thread")]
async fn hypervisor_reboot_is_tried_once_per_window() {
    let e = env("hv-once").await;
    e.machine("pve", "hypervisor", "auto", "[]").await;
    e.hosts.put("pve", "pve1", &["pve1"], &[(101, "web", true)]);
    let open = || vec![e.window("auto", Window::Security)];
    e.tick(open(), e.now).await;
    e.end_patch("pve", "required_not_allowed").await;
    e.approve(&e.reboots()[0].0.clone(), e.now + MIN).await;
    e.tick(open(), e.now + MIN).await;
    let row = Row::from([
        ("id", t("01JBUSY0000000000000000001")),
        ("kind", t("runbook")),
        ("name", t("reboot-host")),
        ("target", t("pve")),
        ("requested_by", t(REQUESTER)),
        ("state", t("failed")),
        ("started_at", Value::Integer(e.now + MIN)),
    ]);
    e.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("jobs", row)])).await.unwrap();
    e.end("pve").await;
    e.tick(open(), e.now + 2 * MIN).await;
    assert_eq!(e.jobs.started().iter().filter(|j| j.0 == "reboot-host").count(), 1);
}

/// 7.5.3 step 8: the hub's host has its own runbook and goes last, after the hypervisors; its reboot needs an approval
/// that says the hub goes away with it. A hub on a hypervisor itself is patched as one.
#[tokio::test(flavor = "multi_thread")]
async fn hub_host_goes_last_and_asks_before_it_reboots() {
    let e = env("hub-host").await;
    e.machine("ahub", "linux", "auto", "[\"hub\"]").await;
    e.machine("pve", "hypervisor", "auto", "[]").await;
    e.machine("web", "linux", "auto", "[]").await;
    let open = || vec![e.window("auto", Window::Security)];
    for (i, (runbook, machine)) in
        [("patch-debian", "web"), ("patch-proxmox-host", "pve"), ("patch-hub-host", "ahub")].into_iter().enumerate()
    {
        e.tick(open(), e.now + i as i64 * MIN).await;
        assert_eq!(e.jobs.started().last(), Some(&(runbook.to_string(), machine.to_string())));
        if machine == "ahub" {
            e.end_patch(machine, "required_not_allowed").await;
        } else {
            e.end(machine).await;
        }
    }
    let asked = e.reboots();
    assert_eq!(asked.len(), 1);
    assert_eq!((asked[0].1.as_str(), asked[0].2.as_str(), asked[0].3), ("ahub", "high", true));
    assert!(asked[0].4.contains("the machine this hub runs on"), "{}", asked[0].4);
    e.approve(&asked[0].0, e.now + 4 * MIN).await;
    e.tick(open(), e.now + 4 * MIN).await;
    assert_eq!(e.jobs.started().last(), Some(&("reboot-host".to_string(), "ahub".to_string())));
    assert_eq!(runbook_for("hypervisor", &["hub".into()]), Some("patch-proxmox-host"));
    assert_eq!(runbook_for("linux", &["hub".into(), "hypervisor".into()]), Some("patch-proxmox-host"));
}
