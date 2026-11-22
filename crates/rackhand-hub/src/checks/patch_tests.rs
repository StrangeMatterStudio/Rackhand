//! The `verify` names the patch runbooks use (7.5.3 steps 4 and 5, plan T59c): `patch_precheck` and `record_state`
//! before the update, `as_recorded`, `required_mounts` and `bound_checks` after it.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rackhand_proto::common::LabelEntry;
use rackhand_proto::probe::{ContainerState, Report, Sample, ServiceState, ServiceStatus};
use rackhand_runbook::runbook::{Identity, Step};
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use crate::actions::runner::{StepCtx, StepOutcome, StepResult, StepRunner};
use crate::bus::Bus;
use crate::checks::steps::Verify;
use crate::ingest::{DiskSpace, Ingest, Stream};

const M: &str = "01JD0000000000000000000009";
const JOB: &str = "01JPATCHJOBAAAAAAAAAAAAAAA";
const GB: f64 = (1u64 << 30) as f64;

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

struct Env {
    db: Arc<Db>,
    ingest: Ingest,
    verify: Verify,
    seq: std::sync::atomic::AtomicU64,
}

async fn env(name: &str, required_mounts: &str) -> Env {
    let dir = std::env::temp_dir().join(format!("rackhand-patchchecks-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let rows = vec![
        RowWrite::insert("sites", Row::from([("id", t("s1")), ("name", t("home")), ("timezone", t("UTC"))])),
        RowWrite::insert(
            "policies",
            Row::from([("id", t("p1")), ("name", t("servers")), ("required_mounts", t(required_mounts))]),
        ),
        RowWrite::insert(
            "machines",
            Row::from([
                ("id", t(M)),
                ("site_id", t("s1")),
                ("name", t("web")),
                ("kind", t("linux")),
                ("policy_id", t("p1")),
                ("state", t("enrolled")),
            ]),
        ),
        RowWrite::insert(
            "jobs",
            Row::from([
                ("id", t(JOB)),
                ("kind", t("runbook")),
                ("name", t("patch-debian")),
                ("target", t(M)),
                ("requested_by", t("scheduler")),
                ("state", t("running")),
            ]),
        ),
    ];
    db.writer().send(WriteCmd::Batch(rows)).await.unwrap();
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    let labels = |id: u32, mount: &str| LabelEntry { id, labels: BTreeMap::from([("mount".into(), mount.into())]) };
    ingest.hello(M, 1, &[labels(1, "/"), labels(2, "/srv")]).await.unwrap();
    let verify = Verify::new(db.clone(), ingest.clone());
    Env { db, ingest, verify, seq: 1.into() }
}

fn service(name: &str, status: ServiceStatus) -> ServiceState {
    ServiceState { name: name.into(), status: status as i32, enabled: true, since_ms: 1 }
}

fn container(name: &str, state: &str) -> ContainerState {
    ContainerState { name: name.into(), state: state.into(), ..Default::default() }
}

/// A report with `/` at `root_free` bytes free (of 20 GB), `/srv` mounted unless `srv` is false.
struct Shape {
    root_free: f64,
    srv: bool,
    services: Vec<ServiceState>,
    containers: Vec<ContainerState>,
}

fn healthy() -> Shape {
    Shape {
        root_free: 10.0 * GB,
        srv: true,
        services: vec![service("nginx.service", ServiceStatus::Active), service("cron.service", ServiceStatus::Failed)],
        containers: vec![container("web", "running"), container("old", "exited")],
    }
}

impl Env {
    async fn report(&self, s: Shape) {
        let disk = |labels_id: u32, total: f64, free: f64| {
            vec![Sample { metric: 17, labels_id, value: total }, Sample { metric: 16, labels_id, value: total - free }]
        };
        let mut vitals = disk(1, 20.0 * GB, s.root_free);
        if s.srv {
            vitals.extend(disk(2, 100.0 * GB, 50.0 * GB));
        }
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let now = rackhand_store::ids::now_ms();
        let r = Report {
            epoch: 1,
            seq,
            sampled_at_ms: now,
            vitals,
            services: s.services,
            containers: s.containers,
            ..Default::default()
        };
        self.ingest.receive(M, Stream::Live, vec![r], 100, now).await.unwrap();
    }

    async fn run(&self, check: &str, timeout: Duration) -> StepResult {
        let step: Step = toml::from_str(&format!("id = \"s\"\nkind = \"verify\"\nchecks = [\"{check}\"]\n")).unwrap();
        let ctx = StepCtx {
            job_id: JOB.into(),
            machine_id: M.into(),
            machine_kind: "linux".into(),
            address: None,
            identity: Identity::Automation,
            timeout,
        };
        self.verify.run(&ctx, &step, None).await
    }

    /// The step's result as the coordinator records it.
    async fn record(&self, step_id: &str, r: &StepResult) {
        let row = Row::from([
            ("job_id", t(JOB)),
            ("step_id", t(step_id)),
            ("state", t(if r.outcome == StepOutcome::Succeeded { "succeeded" } else { "failed" })),
            ("stdout", Value::Blob(r.stdout.clone())),
            ("started_at", Value::Integer(rackhand_store::ids::now_ms())),
        ]);
        self.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("job_steps", row)])).await.unwrap();
    }

    async fn incident(&self, id: &str, kind: &str, severity: &str) {
        let row = Row::from([
            ("id", t(id)),
            ("machine_id", t(M)),
            ("dedupe_key", t(&format!("{M}/{kind}"))),
            ("kind", t(kind)),
            ("severity", t(severity)),
            ("state", t("open")),
            ("title", t(kind)),
            ("opened_at", Value::Integer(1)),
        ]);
        self.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("incidents", row)])).await.unwrap();
    }
}

fn failed(r: &StepResult) -> Option<&str> {
    match &r.outcome {
        StepOutcome::Failed(why) => Some(why.as_str()),
        StepOutcome::Succeeded => None,
    }
}

const SHORT: Duration = Duration::from_secs(1);

/// 7.5.3 step 4: 1 GB free on `/`, a report to judge by, and no open critical incident on the machine. The precheck
/// fails at once with its reason (it is judged once, not retried), and the security-updates incident patching is about
/// to clear doesn't stop it.
#[tokio::test(flavor = "multi_thread")]
async fn patch_precheck_judges_the_latest_report_once() {
    let e = env("precheck", "[]").await;
    let no_report = e.run("patch_precheck", Duration::from_secs(30)).await;
    assert_eq!(failed(&no_report), Some("no_report"), "{no_report:?}");
    e.report(Shape { root_free: 0.5 * GB, ..healthy() }).await;
    let started = std::time::Instant::now();
    assert_eq!(failed(&e.run("patch_precheck", Duration::from_secs(30)).await), Some("root_disk_low"));
    assert!(started.elapsed() < Duration::from_secs(5), "judged once, not retried for the step's time");
    e.report(healthy()).await;
    let passed = e.run("patch_precheck", SHORT).await;
    assert_eq!(passed.outcome, StepOutcome::Succeeded, "{passed:?}");
    e.incident("i1", "updates.security", "critical").await;
    assert_eq!(e.run("patch_precheck", SHORT).await.outcome, StepOutcome::Succeeded, "what patching clears");
    e.incident("i2", "disk.used_pct", "critical").await;
    assert_eq!(failed(&e.run("patch_precheck", SHORT).await), Some("open_critical_incident"));
}

/// 7.5.3 steps 4 and 5: `record_state` keeps the active services and running containers in the job log; after the
/// update `as_recorded` wants each of them active or running again, and names the first that isn't.
#[tokio::test(flavor = "multi_thread")]
async fn record_state_then_as_recorded() {
    let e = env("record", "[]").await;
    e.report(healthy()).await;
    let recorded = e.run("record_state", SHORT).await;
    assert_eq!(recorded.outcome, StepOutcome::Succeeded, "{recorded:?}");
    let shown = String::from_utf8_lossy(&recorded.stdout).to_string();
    assert!(shown.contains("nginx.service") && shown.contains("web"), "{shown}");
    assert!(!shown.contains("cron.service") && !shown.contains("old"), "only what was up: {shown}");
    e.record("record", &recorded).await;

    e.report(healthy()).await;
    assert_eq!(e.run("as_recorded", SHORT).await.outcome, StepOutcome::Succeeded);
    let services = vec![service("nginx.service", ServiceStatus::Failed)];
    e.report(Shape { services, ..healthy() }).await;
    let down = e.run("as_recorded", SHORT).await;
    assert_eq!(failed(&down), Some("as_recorded"));
    assert!(String::from_utf8_lossy(&down.stderr).contains("nginx.service"), "{down:?}");
    let containers = vec![container("web", "exited")];
    e.report(Shape { containers, ..healthy() }).await;
    let stopped = e.run("as_recorded", SHORT).await;
    assert!(String::from_utf8_lossy(&stopped.stderr).contains("web"), "{stopped:?}");
}

/// Without a recorded state there is nothing to compare: `as_recorded` fails rather than passing on nothing.
#[tokio::test(flavor = "multi_thread")]
async fn as_recorded_needs_a_record() {
    let e = env("norecord", "[]").await;
    e.report(healthy()).await;
    let r = e.run("as_recorded", SHORT).await;
    assert_eq!(failed(&r), Some("as_recorded"));
    assert!(String::from_utf8_lossy(&r.stderr).contains("record"), "{r:?}");
}

/// D66: every mount in the policy's `required_mounts` is in the latest report.
#[tokio::test(flavor = "multi_thread")]
async fn required_mounts_from_the_policy() {
    let e = env("mounts", r#"["/srv"]"#).await;
    e.report(healthy()).await;
    assert_eq!(e.run("required_mounts", SHORT).await.outcome, StepOutcome::Succeeded);
    e.report(Shape { srv: false, ..healthy() }).await;
    let missing = e.run("required_mounts", SHORT).await;
    assert_eq!(failed(&missing), Some("required_mounts"));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("/srv"), "{missing:?}");
}

/// 7.5.3 step 5: every check bound to the machine passes, with a result from after the step started.
#[tokio::test(flavor = "multi_thread")]
async fn bound_checks_pass_after_the_step_starts() {
    let e = env("bound", "[]").await;
    let check = Row::from([
        ("id", t("web-http")),
        ("kind", t("http")),
        ("target", t("http://web/")),
        ("interval_s", Value::Integer(30)),
        ("machine_id", t(M)),
    ]);
    let old = Row::from([("check_id", t("web-http")), ("at_ms", Value::Integer(1)), ("ok", Value::Integer(1))]);
    e.db.writer()
        .send(WriteCmd::Batch(vec![RowWrite::insert("checks", check), RowWrite::insert("check_results", old)]))
        .await
        .unwrap();
    let stale = e.run("bound_checks", SHORT).await;
    assert_eq!(failed(&stale), Some("bound_checks"), "a result from before the step doesn't count");
    let db = e.db.clone();
    let fresh = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let now = rackhand_store::ids::now_ms();
        let row = Row::from([("check_id", t("web-http")), ("at_ms", Value::Integer(now)), ("ok", Value::Integer(1))]);
        db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("check_results", row)])).await.unwrap();
    });
    let passed = e.run("bound_checks", Duration::from_secs(10)).await;
    fresh.await.unwrap();
    assert_eq!(passed.outcome, StepOutcome::Succeeded, "{passed:?}");
}
