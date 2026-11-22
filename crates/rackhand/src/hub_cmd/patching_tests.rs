use std::collections::BTreeMap;
use std::time::Duration;

use rackhand_hub::actions::runner::{BoxFuture, StepCtx, StepOutcome, StepResult, StepRunner};
use rackhand_hub::audit::Audit;
use rackhand_hub::bus::Bus;
use rackhand_hub::incidents::machine_silence::Quiet;
use rackhand_hub::ingest::{DiskSpace, Stream};
use rackhand_proto::common::LabelEntry;
use rackhand_proto::probe::{Report, Sample, UpdateSummary};
use rackhand_runbook::runbook::Step;
use rackhand_store::ids::now_ms;
use rackhand_store::{Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use super::*;

const M: &str = "01JD0000000000000000000021";

#[derive(Debug)]
struct Roomy;

impl DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

async fn machines(name: &str) -> Machines {
    let dir = std::env::temp_dir().join(format!("rackhand-hub-patching-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let machine = |id: &str, kind: &str, roles: &str, policy: Option<&str>| {
        let mut row = Row::from([
            ("id", t(id)),
            ("site_id", t("s")),
            ("name", t(id)),
            ("kind", t(kind)),
            ("roles", t(roles)),
            ("state", t("enrolled")),
        ]);
        if let Some(p) = policy {
            row.insert("policy_id", t(p));
        }
        RowWrite::insert("machines", row)
    };
    let policy = |id: &str, auto: i64| {
        RowWrite::insert("policies", Row::from([("id", t(id)), ("name", t(id)), ("auto_reboot", Value::Integer(auto))]))
    };
    let window =
        Row::from([("id", t("w")), ("tag", t("db")), ("rrule", t("daily 00:00 1440m")), ("timezone", t("UTC"))]);
    db.writer()
        .send(WriteCmd::Batch(vec![
            RowWrite::insert("sites", Row::from([("id", t("s")), ("name", t("home")), ("timezone", t("UTC"))])),
            policy("yes", 1),
            policy("no", 0),
            machine(M, "linux", "[]", Some("yes")),
            machine("held", "linux", "[]", Some("no")),
            machine("plain", "linux", "[]", None),
            machine("desk", "linux", "[\"desktop\"]", None),
            machine("pve", "linux", "[\"hypervisor\"]", Some("yes")),
            machine("pve2", "hypervisor", "[]", Some("yes")),
            RowWrite::insert("windows", window),
        ]))
        .await
        .unwrap();
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    ingest.hello(M, 1, &[LabelEntry { id: 1, labels: BTreeMap::new() }]).await.unwrap();
    Machines { db, ingest }
}

/// A report sampled at `at` from a machine up for `uptime_s`.
async fn report(m: &Machines, seq: u64, at: i64, uptime_s: f64, updates: Option<(u32, u32)>) {
    let updates = updates.map(|(security, pending)| UpdateSummary {
        pending,
        security,
        reboot_required: false,
        packages: vec![],
    });
    let vitals = vec![Sample { metric: 30, labels_id: 1, value: uptime_s }];
    let r = Report { epoch: 1, seq, sampled_at_ms: at, vitals, updates, ..Default::default() };
    m.ingest.receive(M, Stream::Live, vec![r], 100, at).await.unwrap();
}

/// What a patch window asks: heard from lately, updates pending from its last summary, in a maintenance window by tag.
#[tokio::test(flavor = "multi_thread")]
async fn window_facts_from_reports_and_maintenance() {
    let m = machines("world").await;
    let now = now_ms();
    assert!(!m.online(M, now), "never heard from");
    assert_eq!(m.pending(M), (0, 0));
    report(&m, 1, now, 1000.0, Some((2, 5))).await;
    assert!(m.online(M, now + 30_000));
    assert!(!m.online(M, now + 5 * 60_000), "silent");
    assert_eq!(m.pending(M), (2, 5));
    assert!(m.in_maintenance(M, &["db".into()], now));
    assert!(!m.in_maintenance(M, &[], now));
}

/// What the reboot step asks: the policy's `auto_reboot`, the 7.5.3 defaults without a policy, and whether a report since
/// came from a machine that started after the reboot was asked for.
#[tokio::test(flavor = "multi_thread")]
async fn reboot_facts_from_the_policy_and_uptime() {
    let m = machines("reboot").await;
    assert!(m.auto_reboot(M) && !m.auto_reboot("held"), "the policy decides");
    assert!(m.auto_reboot("plain") && !m.auto_reboot("desk"), "the defaults without one");
    assert!(!m.auto_reboot("nope"));
    assert!(!m.auto_reboot("pve") && !m.auto_reboot("pve2"), "a hypervisor's reboot is never automatic (E13)");
    let asked = now_ms() - 300_000;
    assert!(!m.reported_since(M, asked));
    report(&m, 1, asked + 10_000, 86_400.0, None).await;
    assert!(m.reported_since(M, asked), "still up as it goes down");
    assert!(!m.back_since(M, asked), "it hasn't started again");
    report(&m, 2, asked + 90_000, 25.0, None).await;
    assert!(m.back_since(M, asked), "up 25 s, 90 s after the reboot was asked for");
    assert!(!m.back_since(M, asked + 120_000), "no report since");
}

/// Every step succeeds.
struct Succeeds;

impl StepRunner for Succeeds {
    fn run<'a>(&'a self, _ctx: &'a StepCtx, _step: &'a Step, _argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async {
            StepResult {
                outcome: StepOutcome::Succeeded,
                command: None,
                exit_code: Some(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        })
    }
}

/// The hub's systems around patching, the machine's patch window open all day; its maintenance window too when
/// `maintained` (by its tag).
async fn patched(name: &str, maintained: bool) -> (Machines, Actions, Arc<Driver>) {
    let m = machines(name).await;
    let update = |table, id: &str, set: Row| rackhand_store::RowUpdate { table, key: ("id", t(id)), set };
    let auto = Row::from([
        ("patch", t("auto")),
        ("security_window", t("daily 00:00")),
        ("full_window", t("daily 00:00")),
        ("window_length_min", Value::Integer(1440)),
    ]);
    let tags = Row::from([("tags", t(if maintained { "[\"db\"]" } else { "[]" }))]);
    let updates = vec![update("policies", "yes", auto), update("machines", M, tags)];
    let change = rackhand_store::RegistryChange { updates, ..Default::default() };
    m.db.writer().send(WriteCmd::RegistryChange(change)).await.unwrap();
    let audit = Audit::new(m.db.writer());
    let (library, _) = rackhand_hub::library::items::Library::new(m.db.clone(), audit.clone());
    library.seed(rackhand_runbook::builtin::runbooks(), 1).await.unwrap();
    let actions = Actions::new(m.db.clone(), audit, Bus::new(), Arc::new(Succeeds));
    let driver = Driver::new(m.db.clone(), Arc::new(m.clone()), Arc::new(actions.clone()));
    (m, actions, driver)
}

fn count(m: &Machines, sql: &str) -> i64 {
    m.db.readers().with(|c| c.query_row(sql, [], |r| r.get(0))).unwrap()
}

const PATCH_JOBS: &str = "SELECT count(*) FROM jobs WHERE name = 'patch-debian' AND requested_by = 'schedule:patch'";

/// AC20, with the same machine outside a maintenance window to show that the window is what holds it.
#[tokio::test(flavor = "multi_thread")]
async fn no_patch_or_silence_alert_during_maintenance_window() {
    for maintained in [true, false] {
        let (m, actions, driver) = patched(&format!("ac20-{maintained}"), maintained).await;
        let now = now_ms();
        report(&m, 1, now, 1000.0, Some((1, 3))).await;
        tick(&m.db, &driver, now).await;
        let started = i64::from(!maintained);
        for _ in 0..200 {
            if !driver.busy(M).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(count(&m, PATCH_JOBS), started, "in maintenance: {maintained}");
        let incidents = rackhand_hub::incidents::Incidents::new(m.db.clone(), m.ingest.clone(), Bus::new());
        incidents.set_quiet(Arc::new(Expected { machines: Arc::new(m.clone()), actions }));
        incidents.set_started(now - 3_600_000);
        incidents.evaluate(now + 600_000).await.unwrap();
        let silent = format!("SELECT count(*) FROM incidents WHERE kind = 'machine.silent' AND machine_id = '{M}'");
        assert_eq!(count(&m, &silent), started, "in maintenance: {maintained}");
    }
}

/// The hub's loop takes up a window that is open and starts its job without anyone asking.
#[tokio::test(flavor = "multi_thread")]
async fn window_loop_starts_the_patch_job() {
    let (m, _actions, driver) = patched("loop", false).await;
    report(&m, 1, now_ms(), 1000.0, Some((1, 3))).await;
    spawn(m.db.clone(), driver, Duration::from_millis(20));
    for _ in 0..500 {
        if count(&m, "SELECT count(*) FROM jobs WHERE state = 'succeeded'") > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(count(&m, PATCH_JOBS), 1, "once in the window, however often the loop runs");
}

/// What Incidents asks, answered from the maintenance windows.
#[tokio::test(flavor = "multi_thread")]
async fn expected_silence_from_the_windows() {
    let (m, actions, _driver) = patched("expected", true).await;
    let e = Expected { machines: Arc::new(m), actions };
    assert!(e.in_maintenance(M, &["db".into()], now_ms()));
    assert!(!e.in_maintenance(M, &["web".into()], now_ms()));
    assert!(!e.awaiting_reboot(M));
}

/// E13: only a job with an approved high-risk approval may reboot a hypervisor, and a hypervisor's kernels are compared
/// as it has no flag of its own.
#[tokio::test(flavor = "multi_thread")]
async fn only_an_approved_high_risk_job_may_reboot_a_hypervisor() {
    let m = machines("approved").await;
    let approval = |id: &str, risk: &str, state: &str| {
        RowWrite::insert(
            "approvals",
            Row::from([
                ("id", t(id)),
                ("tool", t("run_runbook")),
                ("target", t("pve")),
                ("args_hash", Value::Blob(vec![1])),
                ("risk", t(risk)),
                ("requested_by", t("schedule:patch")),
                ("state", t(state)),
                ("expires_at", Value::Integer(1)),
            ]),
        )
    };
    let job = |id: &str, name: &str, approval: Option<&str>| {
        let mut row = Row::from([
            ("id", t(id)),
            ("kind", t("runbook")),
            ("name", t(name)),
            ("target", t("pve")),
            ("requested_by", t("schedule:patch")),
            ("state", t("running")),
        ]);
        if let Some(a) = approval {
            row.insert("approval_id", t(a));
        }
        RowWrite::insert("jobs", row)
    };
    m.db.writer()
        .send(WriteCmd::Batch(vec![
            approval("high", "high", "used"),
            approval("normal", "normal", "used"),
            approval("rejected", "high", "rejected"),
            job("j-high", "reboot-host", Some("high")),
            job("j-normal", "reboot-host", Some("normal")),
            job("j-rejected", "reboot-host", Some("rejected")),
            job("j-patch", "patch-proxmox-host", Some("high")),
            job("j-none", "reboot-host", None),
        ]))
        .await
        .unwrap();
    assert!(m.approved("j-high"));
    for no in ["j-normal", "j-rejected", "j-patch", "j-none", "missing"] {
        assert!(!m.approved(no), "{no}");
    }
    assert!(m.compares_kernels("pve") && m.compares_kernels("pve2") && !m.compares_kernels("plain"));
}
