//! The step kinds the Executor hands to Checks (plan T46, carried in from T55): `verify` and `api`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rackhand_drivers::{Driver, DriverError, DriverKind, DriverOp, DriverOpResult, DriverReading, DriverTarget};
use rackhand_proto::probe::{ContainerState, Report};
use rackhand_runbook::runbook::{Identity, Step};
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use crate::actions::runner::{StepCtx, StepOutcome, StepRunner};
use crate::bus::Bus;
use crate::checks::steps::{Api, Verify};
use crate::ingest::{DiskSpace, Ingest, Stream};

const M1: &str = "01JD0000000000000000000001";

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

async fn db(name: &str) -> Arc<Db> {
    let dir = std::env::temp_dir().join(format!("rackhand-executor-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let rows = vec![
        RowWrite::insert("sites", Row::from([("id", t("s1")), ("name", t("home")), ("timezone", t("UTC"))])),
        RowWrite::insert(
            "machines",
            Row::from([
                ("id", t(M1)),
                ("site_id", t("s1")),
                ("name", t("pve")),
                ("kind", t("hypervisor")),
                ("address", t("192.0.2.51:8006")),
                ("driver", t("proxmox")),
                ("state", t("enrolled")),
            ]),
        ),
    ];
    db.writer().send(WriteCmd::Batch(rows)).await.unwrap();
    db
}

fn ctx(timeout: Duration) -> StepCtx {
    StepCtx {
        job_id: "j1".into(),
        machine_id: M1.into(),
        machine_kind: "hypervisor".into(),
        address: Some("192.0.2.51:8006".into()),
        identity: Identity::Automation,
        timeout,
    }
}

fn step(text: &str) -> Step {
    toml::from_str(&format!("id = \"s\"\n{text}")).unwrap()
}

fn container(name: &str, project: &str, state: &str) -> ContainerState {
    ContainerState { name: name.into(), project: project.into(), state: state.into(), ..Default::default() }
}

async fn report(ingest: &Ingest, seq: u64, containers: Vec<ContainerState>) {
    let now = rackhand_store::ids::now_ms();
    let r = Report { epoch: 1, seq, sampled_at_ms: now, containers, ..Default::default() };
    ingest.receive(M1, Stream::Live, vec![r], 100, now).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_step_runs_named_checks() {
    let db = db("verify").await;
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    ingest.hello(M1, 1, &[rackhand_proto::common::LabelEntry::default()]).await.unwrap();
    let verify = Verify::new(db.clone(), ingest.clone());
    // the coordinator has substituted `containers_running:{{project}}` with the job's project
    let running = step("kind = \"verify\"\nchecks = [\"containers_running:shop\"]\n");
    report(&ingest, 1, vec![container("shop-web-1", "shop", "running"), container("shop-db-1", "shop", "running")])
        .await;
    let ok = verify.run(&ctx(Duration::from_secs(2)), &running, None).await;
    assert_eq!(ok.outcome, StepOutcome::Succeeded, "{:?}", String::from_utf8_lossy(&ok.stderr));
    // one of the project's containers exited: the step fails with the check's name, once its time is up
    report(&ingest, 2, vec![container("shop-web-1", "shop", "running"), container("shop-db-1", "shop", "exited")])
        .await;
    let failed = verify.run(&ctx(Duration::from_millis(600)), &running, None).await;
    assert_eq!(failed.outcome, StepOutcome::Failed("containers_running:shop".into()));
    assert!(String::from_utf8_lossy(&failed.stderr).contains("shop-db-1"), "says which container");
    // a project with no container at all doesn't pass
    let other = step("kind = \"verify\"\nchecks = [\"containers_running:blog\"]\n");
    assert_eq!(
        verify.run(&ctx(Duration::from_millis(300)), &other, None).await.outcome,
        StepOutcome::Failed("containers_running:blog".into())
    );
    // a check bound to the machine: its newest result passes
    let check = Row::from([
        ("id", t("pve-web")),
        ("kind", t("http")),
        ("target", t("https://192.0.2.51:8006/")),
        ("interval_s", Value::Integer(60)),
        ("machine_id", t(M1)),
        ("settings", t("{}")),
    ]);
    db.writer().send(WriteCmd::PutCheck(check)).await.unwrap();
    let result = |ok: bool| {
        Row::from([
            ("check_id", t("pve-web")),
            ("at_ms", Value::Integer(rackhand_store::ids::now_ms())),
            ("ok", Value::Integer(ok as i64)),
        ])
    };
    let bound = step("kind = \"verify\"\nchecks = [\"check:pve-web\"]\n");
    db.writer().send(WriteCmd::PutCheckResults(vec![result(false)])).await.unwrap();
    assert_eq!(
        verify.run(&ctx(Duration::from_millis(300)), &bound, None).await.outcome,
        StepOutcome::Failed("check:pve-web".into())
    );
    tokio::time::sleep(Duration::from_millis(5)).await;
    db.writer().send(WriteCmd::PutCheckResults(vec![result(true)])).await.unwrap();
    assert_eq!(verify.run(&ctx(Duration::from_secs(1)), &bound, None).await.outcome, StepOutcome::Succeeded);
    // a pass from before the step started (before an update, say) isn't one: it waits for a newer run
    let api_check = Row::from([
        ("id", t("pve-api")),
        ("kind", t("tcp")),
        ("target", t("192.0.2.51:8006")),
        ("interval_s", Value::Integer(60)),
        ("machine_id", t(M1)),
        ("settings", t("{}")),
    ]);
    db.writer().send(WriteCmd::PutCheck(api_check)).await.unwrap();
    let earlier = Row::from([
        ("check_id", t("pve-api")),
        ("at_ms", Value::Integer(rackhand_store::ids::now_ms() - 60_000)),
        ("ok", Value::Integer(1)),
    ]);
    db.writer().send(WriteCmd::PutCheckResults(vec![earlier])).await.unwrap();
    let stale = verify
        .run(
            &ctx(Duration::from_millis(300)),
            &step(
                "kind = \"verify\"
checks = [\"check:pve-api\"]
",
            ),
            None,
        )
        .await;
    assert_eq!(stale.outcome, StepOutcome::Failed("check:pve-api".into()));
    assert!(String::from_utf8_lossy(&stale.stderr).contains("since the step started"));
    // a check name it doesn't know fails at once
    let unknown = step("kind = \"verify\"\nchecks = [\"moon_phase:full\"]\n");
    assert_eq!(
        verify.run(&ctx(Duration::from_secs(5)), &unknown, None).await.outcome,
        StepOutcome::Failed("unknown_check:moon_phase:full".into())
    );
}

/// A driver that records its calls.
#[derive(Default)]
struct Recording(Mutex<Vec<(String, String)>>);

#[async_trait::async_trait]
impl Driver for Recording {
    fn kind(&self) -> DriverKind {
        DriverKind::Proxmox
    }

    async fn poll(&self, _target: &DriverTarget) -> Result<DriverReading, DriverError> {
        Ok(DriverReading::up(1.0, "", vec![]))
    }

    async fn call(&self, target: &DriverTarget, op: DriverOp) -> Result<DriverOpResult, DriverError> {
        self.0.lock().unwrap().push((target.target.clone(), op.name.clone()));
        match op.name.as_str() {
            "snapshot" => Ok(DriverOpResult { output: serde_json::json!({ "snapshot": "rackhand-1" }) }),
            _ => Err(DriverError::Failed("no such operation".into())),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn api_step_calls_driver() {
    let db = db("api").await;
    let driver = Arc::new(Recording::default());
    let api = Api::new(db.clone()).with_driver(driver.clone());
    let done = api.run(&ctx(Duration::from_secs(2)), &step("kind = \"api\"\ncall = \"snapshot\"\n"), None).await;
    assert_eq!(done.outcome, StepOutcome::Succeeded);
    assert!(String::from_utf8_lossy(&done.stdout).contains("rackhand-1"), "the result is recorded");
    assert_eq!(done.command.as_deref(), Some("proxmox snapshot"));
    assert_eq!(driver.0.lock().unwrap().clone(), vec![("192.0.2.51:8006".to_string(), "snapshot".to_string())]);
    let refused = api.run(&ctx(Duration::from_secs(2)), &step("kind = \"api\"\ncall = \"explode\"\n"), None).await;
    assert_eq!(refused.outcome, StepOutcome::Failed("no such operation".into()));
    // a machine without a driver that has the call
    let none = Api::new(db.clone());
    let missing = none.run(&ctx(Duration::from_secs(2)), &step("kind = \"api\"\ncall = \"snapshot\"\n"), None).await;
    assert_eq!(missing.outcome, StepOutcome::Failed("no_driver:proxmox".into()));
}
