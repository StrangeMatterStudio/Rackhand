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
    // the check runs while the step waits: a result stamped before it, however late it is written, isn't one
    let wait = ctx(Duration::from_secs(4));
    let (passed, ()) = tokio::join!(verify.run(&wait, &bound, None), async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        db.writer().send(WriteCmd::PutCheckResults(vec![result(true)])).await.unwrap();
    });
    assert_eq!(passed.outcome, StepOutcome::Succeeded);
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

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_and_rollback_steps_use_proxmox_driver() {
    use crate::checks::steps::Hypervisor;
    use crate::vault::master_key::MasterKey;
    use crate::vault::{Secret, Vault};
    use rackhand_drivers::proxmox::sim::Sim;
    let db = db("hypervisor").await;
    let sim = Sim::start("pve8").await;
    const GUEST: &str = "01JD0000000000000000000002";
    let guest = |state: &str| {
        Row::from([
            ("id", t(GUEST)),
            ("site_id", t("s1")),
            ("name", t("ct-test")),
            ("kind", t("linux")),
            ("state", t("enrolled")),
            ("proxmox_ref", t(&format!("{{\"cluster\":\"{M1}\",\"node\":\"pve8\",\"vmid\":100,\"type\":\"lxc\"}}"))),
            ("proxmox_ref_state", t(state)),
        ])
    };
    db.writer()
        .send(WriteCmd::Batch(vec![
            RowWrite::upsert(
                "machines",
                "id",
                Row::from([
                    ("id", t(M1)),
                    ("site_id", t("s1")),
                    ("name", t("pve")),
                    ("kind", t("hypervisor")),
                    ("address", t(&sim.url)),
                    ("driver", t("proxmox")),
                    ("state", t("enrolled")),
                ]),
            ),
            RowWrite::insert("machines", guest("proposed")),
        ]))
        .await
        .unwrap();
    let vault = Arc::new(Vault::new(MasterKey::from_bytes([4u8; 32]), db.clone()));
    let creds = serde_json::json!({ "token": "rackhand@pve!hub=secret", "fingerprint": sim.fingerprint }).to_string();
    vault.put(&format!("driver.{M1}"), &Secret::from(creds.as_str())).await.unwrap();
    let steps = Hypervisor::new(db.clone(), vault.clone()).with_driver(Arc::new(rackhand_drivers::Proxmox::new()));
    let ctx = StepCtx {
        machine_id: GUEST.into(),
        job_id: "01JDJOB0000000000000000001".into(),
        ..ctx(Duration::from_secs(10))
    };
    // a binding only proposed: nothing on the hypervisor (7.3.12)
    let snap = step(
        "kind = \"snapshot\"
",
    );
    assert_eq!(steps.run(&ctx, &snap, None).await.outcome, StepOutcome::Failed("guest_binding_unconfirmed".into()));
    assert!(sim.requests().is_empty());
    db.writer().send(WriteCmd::Batch(vec![RowWrite::upsert("machines", "id", guest("confirmed"))])).await.unwrap();
    let made = steps.run(&ctx, &snap, None).await;
    assert_eq!(made.outcome, StepOutcome::Succeeded, "{}", String::from_utf8_lossy(&made.stderr));
    assert!(String::from_utf8_lossy(&made.stdout).contains("rackhand-01jdjob0000000000000000001"));
    let back = steps
        .run(
            &ctx,
            &step(
                "kind = \"rollback\"
",
            ),
            None,
        )
        .await;
    assert_eq!(back.outcome, StepOutcome::Succeeded);
    let writes: Vec<(String, String)> =
        sim.requests().into_iter().filter(|q| q.method == "POST").map(|q| (q.path, q.body)).collect();
    assert_eq!(
        writes,
        vec![
            (
                "/api2/json/nodes/pve8/lxc/100/snapshot".to_string(),
                "snapname=rackhand-01jdjob0000000000000000001".to_string()
            ),
            (
                "/api2/json/nodes/pve8/lxc/100/snapshot/rackhand-01jdjob0000000000000000001/rollback".to_string(),
                String::new()
            ),
        ],
        "the job's own snapshot, on the guest's node"
    );
    // a machine that isn't a Proxmox guest
    let plain = StepCtx { machine_id: M1.into(), ..ctx.clone() };
    assert_eq!(steps.run(&plain, &snap, None).await.outcome, StepOutcome::Failed("not_a_proxmox_guest".into()));
}

/// A Proxmox host and its guests for the patch snapshot (plan T59c2): the guests' policy and binding, and a patch job.
mod patch_snapshot {
    use super::*;
    use crate::checks::steps::Hypervisor;
    use crate::vault::master_key::MasterKey;
    use crate::vault::{Secret, Vault};
    use rackhand_drivers::proxmox::sim::Sim;

    pub(super) const CT: &str = "01JD0000000000000000000003";
    pub(super) const VM: &str = "01JD0000000000000000000004";
    const JOB: &str = "01JDPATCH00000000000000001";

    pub(super) struct Env {
        pub(super) db: Arc<Db>,
        pub(super) sim: Sim,
        pub(super) steps: Arc<Hypervisor>,
    }

    fn guest(id: &str, kind: &str, vmid: u32, binding: &str) -> Row {
        let reference = format!("{{\"cluster\":\"{M1}\",\"node\":\"pve9\",\"vmid\":{vmid},\"type\":\"{kind}\"}}");
        Row::from([
            ("id", t(id)),
            ("site_id", t("s1")),
            ("name", t(id)),
            ("kind", t("linux")),
            ("state", t("enrolled")),
            ("policy_id", t("p1")),
            ("proxmox_ref", t(&reference)),
            ("proxmox_ref_state", t(binding)),
        ])
    }

    fn target(sim: &Sim) -> DriverTarget {
        DriverTarget {
            target: sim.url.clone(),
            settings: serde_json::json!({ "token": "rackhand@pve!hub=secret", "fingerprint": sim.fingerprint }),
            timeout: Duration::from_secs(5),
        }
    }

    pub(super) async fn env(name: &str) -> Env {
        let db = db(name).await;
        let sim = Sim::start("pve9").await;
        let host = Row::from([
            ("id", t(M1)),
            ("site_id", t("s1")),
            ("name", t("pve")),
            ("kind", t("hypervisor")),
            ("address", t(&sim.url)),
            ("driver", t("proxmox")),
            ("state", t("enrolled")),
        ]);
        let job = Row::from([
            ("id", t(JOB)),
            ("kind", t("runbook")),
            ("name", t("patch-debian")),
            ("requested_by", t("scheduler")),
            ("state", t("running")),
        ]);
        let policy = Row::from([("id", t("p1")), ("name", t("guests")), ("snapshot", t("required"))]);
        db.writer()
            .send(WriteCmd::Batch(vec![
                RowWrite::upsert("machines", "id", host),
                RowWrite::insert("policies", policy),
                RowWrite::insert("machines", guest(CT, "lxc", 100, "confirmed")),
                RowWrite::insert("machines", guest(VM, "qemu", 200, "confirmed")),
                RowWrite::insert("jobs", job),
            ]))
            .await
            .unwrap();
        let vault = Arc::new(Vault::new(MasterKey::from_bytes([4u8; 32]), db.clone()));
        let creds =
            serde_json::json!({ "token": "rackhand@pve!hub=secret", "fingerprint": sim.fingerprint }).to_string();
        vault.put(&format!("driver.{M1}"), &Secret::from(creds.as_str())).await.unwrap();
        let steps = Hypervisor::new(db.clone(), vault).with_driver(Arc::new(rackhand_drivers::Proxmox::new()));
        Env { db, sim, steps: Arc::new(steps) }
    }

    impl Env {
        async fn run(&self, machine: &str, kind: &str) -> crate::actions::runner::StepResult {
            let ctx = StepCtx { machine_id: machine.into(), job_id: JOB.into(), ..ctx(Duration::from_secs(10)) };
            self.steps.run(&ctx, &step(&format!("kind = \"{kind}\"\n")), None).await
        }

        pub(super) async fn set(&self, table: &'static str, id: &str, col: &'static str, value: &str) {
            let set = Row::from([(col, t(value))]);
            let update = rackhand_store::RowUpdate { table, key: ("id", t(id)), set };
            let change = rackhand_store::RegistryChange { updates: vec![update], ..Default::default() };
            self.db.writer().send(WriteCmd::RegistryChange(change)).await.unwrap();
        }

        fn posts(&self) -> Vec<String> {
            self.sim.requests().into_iter().filter(|q| q.method == "POST").map(|q| q.body).collect()
        }

        async fn snapshots(&self, kind: &str, vmid: u32) -> Vec<String> {
            let op = DriverOp { name: "snapshots".into(), args: serde_json::json!({ "kind": kind, "vmid": vmid }) };
            let out = rackhand_drivers::Proxmox::new().call(&target(&self.sim), op).await.unwrap().output;
            out.as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap().to_string()).collect()
        }

        async fn make(&self, kind: &str, vmid: u32, name: &str) {
            let args = serde_json::json!({ "kind": kind, "vmid": vmid, "name": name });
            let op = DriverOp { name: "snapshot".into(), args };
            rackhand_drivers::Proxmox::new().call(&target(&self.sim), op).await.unwrap();
        }
    }

    fn reason(r: &crate::actions::runner::StepResult) -> Option<String> {
        match &r.outcome {
            StepOutcome::Failed(why) => Some(why.clone()),
            StepOutcome::Succeeded => None,
        }
    }

    /// 7.5.3 and E12: a patch job's snapshot judges the guest first. Under `snapshot = "required"` an unconfirmed
    /// binding, storage that can't snapshot, or a datastore under 10% or 5 GB free fails the step before anything
    /// changes; under `optional` the patch goes on without a snapshot and the job log says why. A machine that isn't a
    /// Proxmox guest has nothing to snapshot.
    #[tokio::test(flavor = "multi_thread")]
    async fn patch_snapshot_judges_the_guest_first() {
        let e = env("patchsnap-judge").await;
        let plain = e.run(M1, "snapshot").await;
        assert_eq!(plain.outcome, StepOutcome::Succeeded, "{plain:?}");
        assert!(String::from_utf8_lossy(&plain.stdout).contains("not a Proxmox guest"), "{plain:?}");
        e.set("machines", CT, "proxmox_ref_state", "proposed").await;
        assert_eq!(reason(&e.run(CT, "snapshot").await).as_deref(), Some("guest_binding_unconfirmed"));
        e.set("policies", "p1", "snapshot", "optional").await;
        let skipped = e.run(CT, "snapshot").await;
        assert_eq!(skipped.outcome, StepOutcome::Succeeded, "{skipped:?}");
        assert!(String::from_utf8_lossy(&skipped.stdout).contains("without a snapshot"), "{skipped:?}");
        e.set("machines", CT, "proxmox_ref_state", "confirmed").await;
        e.set("policies", "p1", "snapshot", "required").await;
        e.sim.set_storage("tank", "dir", 10 << 30, 16 << 30);
        assert_eq!(reason(&e.run(CT, "snapshot").await).as_deref(), Some("snapshot_unsupported"));
        e.sim.set_storage("tank", "zfspool", 4 << 30, 16 << 30);
        assert_eq!(reason(&e.run(CT, "snapshot").await).as_deref(), Some("datastore_low"), "under 5 GB free");
        e.set("policies", "p1", "snapshot", "optional").await;
        assert_eq!(e.run(CT, "snapshot").await.outcome, StepOutcome::Succeeded);
        assert!(e.posts().is_empty(), "nothing was snapshotted: {:?}", e.posts());
    }

    /// 7.5.3: the snapshot is `rackhand-patch-<YYYYMMDD-HHMM>`, the last 3 `rackhand-patch-*` are kept (others aren't
    /// touched), and a rollback in the same job goes back to the snapshot the job took.
    #[tokio::test(flavor = "multi_thread")]
    async fn patch_snapshot_named_keeps_3_and_rollback_uses_it() {
        let e = env("patchsnap-keep").await;
        for old in ["rackhand-patch-20200101-0000", "rackhand-patch-20200102-0000", "rackhand-patch-20200103-0000"] {
            e.make("qemu", 200, old).await;
        }
        e.make("qemu", 200, "before-upgrade").await;
        let made = e.run(VM, "snapshot").await;
        assert_eq!(made.outcome, StepOutcome::Succeeded, "{made:?}");
        let out: serde_json::Value = serde_json::from_slice(&made.stdout).unwrap();
        let name = out["snapshot"].as_str().unwrap().to_string();
        let stamp = name.strip_prefix("rackhand-patch-").unwrap();
        assert!(stamp.len() == 13 && stamp.as_bytes()[8] == b'-', "{name}");
        let kept = e.snapshots("qemu", 200).await;
        assert_eq!(
            kept,
            ["rackhand-patch-20200102-0000", "rackhand-patch-20200103-0000", "before-upgrade", name.as_str()],
            "the oldest patch snapshot pruned, the admin's own kept"
        );
        // the coordinator records the step; a rollback reads the name back from it
        let row = Row::from([
            ("job_id", t(JOB)),
            ("step_id", t("snapshot")),
            ("state", t("succeeded")),
            ("stdout", Value::Blob(made.stdout.clone())),
            ("started_at", Value::Integer(1)),
        ]);
        e.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("job_steps", row)])).await.unwrap();
        let back = e.run(VM, "rollback").await;
        assert_eq!(back.outcome, StepOutcome::Succeeded, "{back:?}");
        let rolled: Vec<String> =
            e.sim.requests().into_iter().filter(|q| q.path.ends_with("/rollback")).map(|q| q.path).collect();
        assert_eq!(rolled, [format!("/api2/json/nodes/pve9/qemu/200/snapshot/{name}/rollback")]);
    }

    /// The `rollback` runbook goes back to the snapshot a named patch job took of the same machine, and fails rather
    /// than guess when that job took none or was another machine's.
    #[tokio::test(flavor = "multi_thread")]
    async fn rollback_job_uses_the_named_jobs_snapshot() {
        let e = env("patchsnap-other").await;
        e.make("qemu", 200, "rackhand-patch-20261122-0400").await;
        let job = |id: &str, name: &str, target: &str, params: &str| {
            RowWrite::insert(
                "jobs",
                Row::from([
                    ("id", t(id)),
                    ("kind", t("runbook")),
                    ("name", t(name)),
                    ("target", t(target)),
                    ("params", t(params)),
                    ("requested_by", t("schedule:patch")),
                    ("state", t("running")),
                ]),
            )
        };
        let step = Row::from([
            ("job_id", t("01JDPATCHED000000000000001")),
            ("step_id", t("snapshot")),
            ("state", t("succeeded")),
            ("stdout", Value::Blob(br#"{"snapshot":"rackhand-patch-20261122-0400"}"#.to_vec())),
        ]);
        e.db.writer()
            .send(WriteCmd::Batch(vec![
                job("01JDPATCHED000000000000001", "patch-debian", VM, "{}"),
                job("01JDPATCHED000000000000002", "patch-debian", VM, "{}"),
                RowWrite::insert("job_steps", step),
                job("01JDROLLBACK00000000000001", "rollback", VM, r#"{"job":"01JDPATCHED000000000000001"}"#),
                job("01JDROLLBACK00000000000002", "rollback", VM, r#"{"job":"01JDPATCHED000000000000002"}"#),
                job("01JDROLLBACK00000000000003", "rollback", CT, r#"{"job":"01JDPATCHED000000000000001"}"#),
            ]))
            .await
            .unwrap();
        let run = |id: &'static str, machine: &'static str| {
            let ctx = StepCtx { machine_id: machine.into(), job_id: id.into(), ..ctx(Duration::from_secs(10)) };
            let e = &e;
            async move { e.steps.run(&ctx, &step_of("rollback"), None).await }
        };
        let none = run("01JDROLLBACK00000000000002", VM).await;
        assert_eq!(reason(&none).as_deref(), Some("no_snapshot"), "{none:?}");
        let other = run("01JDROLLBACK00000000000003", CT).await;
        assert_eq!(reason(&other).as_deref(), Some("no_snapshot"), "another machine's job: {other:?}");
        let back = run("01JDROLLBACK00000000000001", VM).await;
        assert_eq!(back.outcome, StepOutcome::Succeeded, "{back:?}");
        let rolled: Vec<String> =
            e.sim.requests().into_iter().filter(|q| q.path.ends_with("/rollback")).map(|q| q.path).collect();
        assert_eq!(rolled, ["/api2/json/nodes/pve9/qemu/200/snapshot/rackhand-patch-20261122-0400/rollback"]);
    }

    fn step_of(kind: &str) -> Step {
        step(&format!("kind = \"{kind}\"\n"))
    }
}

/// E13: the hypervisor's guests as the reboot approval lists them, from its API with the Vault's credentials.
#[tokio::test(flavor = "multi_thread")]
async fn hypervisor_view_from_its_api() {
    use crate::actions::patching::hypervisor::Hosts;
    use crate::checks::steps::Hypervisor;
    use crate::vault::master_key::MasterKey;
    use crate::vault::{Secret, Vault};
    use rackhand_drivers::proxmox::sim::Sim;
    let db = db("hostview").await;
    let sim = Sim::start("pve9").await;
    let vault = Arc::new(Vault::new(MasterKey::from_bytes([4u8; 32]), db.clone()));
    let steps = Hypervisor::new(db.clone(), vault.clone()).with_driver(Arc::new(rackhand_drivers::Proxmox::new()));
    assert!(steps.view(M1).await.is_err(), "no API attached");
    let row = Row::from([
        ("id", t(M1)),
        ("site_id", t("s1")),
        ("name", t("pve")),
        ("kind", t("hypervisor")),
        ("address", t(&sim.url)),
        ("driver", t("proxmox")),
        ("state", t("enrolled")),
    ]);
    db.writer().send(WriteCmd::Batch(vec![RowWrite::upsert("machines", "id", row)])).await.unwrap();
    assert!(steps.view(M1).await.is_err(), "no credentials");
    let creds = serde_json::json!({ "token": "rackhand@pve!hub=secret", "fingerprint": sim.fingerprint }).to_string();
    vault.put(&format!("driver.{M1}"), &Secret::from(creds.as_str())).await.unwrap();
    let v = steps.view(M1).await.unwrap();
    assert_eq!((v.node.as_str(), v.nodes.as_slice()), ("pve9", &["pve9".to_string()][..]));
    let ct = v.guests.iter().find(|g| g.vmid == 100).unwrap();
    assert_eq!((ct.kind.as_str(), ct.name.as_str(), ct.running), ("lxc", "ct-test", true));
}

/// A `hub` step is the hub's own: without the part of the hub that does it, it fails like any unwired kind.
#[tokio::test(flavor = "multi_thread")]
async fn hub_step_unavailable_until_wired() {
    use crate::executor::Executor;
    use crate::ssh::hostkeys::HostKeys;
    use crate::vault::Vault;
    use crate::vault::master_key::MasterKey;
    let db = db("hubstep").await;
    let vault = Arc::new(Vault::new(MasterKey::from_bytes([4u8; 32]), db.clone()));
    let (host_keys, _) = HostKeys::new(db.clone());
    let executor = Executor::new(vault, host_keys);
    let result =
        executor.run(&ctx(Duration::from_secs(2)), &step("kind = \"hub\"\ncall = \"send_commands\"\n"), None).await;
    assert_eq!(result.outcome, StepOutcome::Failed("hub_unavailable".into()));
}

/// 7.3.12, D93, E50, AC60: what a hypervisor-side action does to a guest whose binding isn't confirmed.
mod guard {
    use super::patch_snapshot::{CT, VM, env};
    use super::*;
    use crate::actions::hypervisor_guard::GuestAction;

    const ACTIONS: [GuestAction; 4] =
        [GuestAction::Snapshot, GuestAction::Rollback, GuestAction::Firewall, GuestAction::Power];

    fn args(action: GuestAction) -> serde_json::Value {
        match action {
            GuestAction::Snapshot | GuestAction::Rollback => serde_json::json!({ "name": "before" }),
            GuestAction::Firewall => serde_json::json!({}),
            GuestAction::Power => serde_json::json!({ "action": "reboot" }),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mismatched_binding_refuses_snapshot_rollback_firewall_power() {
        let e = env("guard-mismatch").await;
        e.set("machines", CT, "proxmox_ref_state", "mismatch").await;
        for action in ACTIONS {
            let refused = e.steps.guest_call(CT, action, args(action), Duration::from_secs(5)).await;
            assert_eq!(refused.unwrap_err(), "guest_binding_mismatch", "{action:?}");
        }
        assert!(e.sim.requests().is_empty(), "refused before any API call: {:?}", e.sim.requests());
        // a binding that is only proposed, or none, is refused too, and says so
        e.set("machines", CT, "proxmox_ref_state", "proposed").await;
        let proposed =
            e.steps.guest_call(CT, GuestAction::Power, args(GuestAction::Power), Duration::from_secs(5)).await;
        assert_eq!(proposed.unwrap_err(), "guest_binding_unconfirmed");
        assert!(e.sim.requests().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn other_guest_never_touched() {
        let e = env("guard-other").await;
        e.set("machines", CT, "proxmox_ref_state", "mismatch").await;
        for action in ACTIONS {
            let _ = e.steps.guest_call(CT, action, args(action), Duration::from_secs(5)).await;
        }
        // the confirmed guest next to it still works, and only it is addressed
        let ok =
            e.steps.guest_call(VM, GuestAction::Snapshot, args(GuestAction::Snapshot), Duration::from_secs(5)).await;
        assert!(ok.is_ok(), "{ok:?}");
        let paths: Vec<String> = e.sim.requests().into_iter().map(|q| q.path).collect();
        assert!(!paths.is_empty());
        assert!(paths.iter().all(|p| !p.contains("/100/")), "the other guest (vmid 100) was addressed: {paths:?}");
        assert!(paths.iter().any(|p| p.contains("/qemu/200/")), "{paths:?}");
        // an admin confirming the binding again lets the actions through
        e.set("machines", CT, "proxmox_ref_state", "confirmed").await;
        let after =
            e.steps.guest_call(CT, GuestAction::Firewall, args(GuestAction::Firewall), Duration::from_secs(5)).await;
        assert!(after.is_ok(), "{after:?}");
    }
}

/// `quarantine` and `quarantine-release` on a Proxmox guest (7.5.6, D104, E24, E66, AC72): the hub's three calls against the
/// simulated API, through a hub that keeps the isolate step's record as the store does.
mod quarantine {
    use serde_json::{Value, json};

    use super::patch_snapshot::{CT, Env, env};
    use super::*;
    use crate::actions::hypervisor_guard::GuestAction;
    use crate::actions::runner::BoxFuture;
    use crate::checks::steps::Hypervisor;
    use crate::executor::{Executor, HubSide};
    use crate::ssh::hostkeys::HostKeys;
    use crate::vault::Vault;
    use crate::vault::master_key::MasterKey;

    const HUB: &str = "192.0.2.10:4433";

    struct Hub {
        steps: Arc<Hypervisor>,
        record: Mutex<Option<Value>>,
        addrs: Vec<String>,
        managed: bool,
        host: Mutex<Option<crate::executor::GuestHost>>,
    }

    impl HubSide for Hub {
        fn signed_commands(&self, _now_ms: i64) -> Vec<u8> {
            Vec::new()
        }
        fn signed_keys(&self, _now_ms: i64, _body: &[u8]) -> Vec<u8> {
            Vec::new()
        }
        fn ssh_from(&self, _machine: &str) -> Vec<String> {
            Vec::new()
        }
        fn managed(&self, _machine: &str) -> bool {
            self.managed
        }
        fn revoke<'a>(&'a self, _machine: &'a str) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async { Ok(()) })
        }
        fn quarantine_addrs(&self) -> Vec<String> {
            self.addrs.clone()
        }
        fn guest_firewall<'a>(
            &'a self,
            machine: &'a str,
            op: &'a str,
            args: Value,
            timeout: Duration,
        ) -> BoxFuture<'a, Result<Value, String>> {
            Box::pin(async move { self.steps.guest_firewall(machine, op, args, timeout).await })
        }
        fn guest_snapshot<'a>(
            &'a self,
            machine: &'a str,
            name: &'a str,
            timeout: Duration,
        ) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                self.steps
                    .guest_call(machine, GuestAction::Snapshot, json!({ "name": name }), timeout)
                    .await
                    .map(|_| ())
            })
        }
        fn quarantine_record(&self, _machine: &str) -> Option<Value> {
            self.record.lock().unwrap().clone()
        }
        fn guest_host(&self, _machine: &str) -> Option<crate::executor::GuestHost> {
            self.host.lock().unwrap().clone()
        }
    }

    struct Q {
        e: Env,
        hub: Arc<Hub>,
        executor: Executor,
    }

    async fn q(name: &str, addrs: &[&str], managed: bool) -> Q {
        let e = env(name).await;
        e.sim.set_datacenter_firewall(true);
        let hub = Arc::new(Hub {
            steps: e.steps.clone(),
            record: Mutex::new(None),
            addrs: addrs.iter().map(|a| a.to_string()).collect(),
            managed,
            host: Mutex::new(None),
        });
        let vault = Arc::new(Vault::new(MasterKey::from_bytes([4u8; 32]), e.db.clone()));
        let (host_keys, _) = HostKeys::new(e.db.clone());
        let executor = Executor::new(vault, host_keys).with_hub(hub.clone());
        Q { e, hub, executor }
    }

    impl Q {
        async fn call(&self, call: &str, kind: &str) -> crate::actions::runner::StepResult {
            let ctx = StepCtx {
                machine_id: CT.into(),
                machine_kind: kind.into(),
                address: None,
                ..ctx(Duration::from_secs(10))
            };
            self.executor.run(&ctx, &step(&format!("kind = \"hub\"\ncall = \"{call}\"\n")), None).await
        }

        /// The isolate step's output, kept as the record the store would give back.
        fn keep(&self, r: &crate::actions::runner::StepResult) {
            let line = String::from_utf8_lossy(&r.stdout);
            *self.hub.record.lock().unwrap() = serde_json::from_str(line.lines().next().unwrap()).ok();
        }

        async fn firewall(&self) -> Value {
            self.e.steps.guest_firewall(CT, "firewall_read", json!({}), Duration::from_secs(5)).await.unwrap()
        }

        fn writes(&self) -> usize {
            self.e.sim.requests().iter().filter(|q| q.method != "GET").count()
        }

        /// The machine isn't a guest on any hypervisor.
        async fn unbind(&self) {
            let update = rackhand_store::RowUpdate {
                table: "machines",
                key: ("id", t(CT)),
                set: Row::from([("proxmox_ref", rusqlite::types::Value::Null)]),
            };
            let change = rackhand_store::RegistryChange { updates: vec![update], ..Default::default() };
            self.e.db.writer().send(WriteCmd::RegistryChange(change)).await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pve_firewall_off_fails_with_instructions_never_enables() {
        let q = q("q-off", &[HUB], true).await;
        q.e.sim.set_datacenter_firewall(false);
        let r = q.call("quarantine_isolate", "linux").await;
        assert_eq!(r.outcome, StepOutcome::Failed("pve_firewall_off".into()), "{r:?}");
        assert!(String::from_utf8_lossy(&r.stderr).contains("Datacenter"), "the admin is told what to do");
        assert_eq!(q.writes(), 0, "the simulated API saw no write at all: the datacenter firewall is never turned on");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn proxmox_guest_is_isolated_snapshotted_and_released_identically() {
        let q = q("q-flow", &[HUB, "[2001:db8::10]:4433"], true).await;
        let before = q.firewall().await;
        let isolated = q.call("quarantine_isolate", "linux").await;
        assert_eq!(isolated.outcome, StepOutcome::Succeeded, "{isolated:?}");
        q.keep(&isolated);
        let record = q.hub.record.lock().unwrap().clone().unwrap();
        assert_eq!((record["method"].as_str(), record["enforced"].as_bool()), (Some("proxmox"), Some(true)));
        assert_eq!(record["saved"], before, "the whole prior configuration is in the record");
        assert_eq!(q.firewall().await["options"]["policy_in"], "DROP");
        // the forensic snapshot, named by the time
        let snap = q.call("quarantine_snapshot", "linux").await;
        assert_eq!(snap.outcome, StepOutcome::Succeeded, "{snap:?}");
        let posts: Vec<String> =
            q.e.sim.requests().into_iter().filter(|r| r.method == "POST").map(|r| r.body).collect();
        assert!(posts.iter().any(|b| b.starts_with("snapname=rackhand-quarantine-")), "{posts:?}");
        // the release puts back exactly what was there
        let released = q.call("quarantine_release", "linux").await;
        assert_eq!(released.outcome, StepOutcome::Succeeded, "{released:?}");
        assert_eq!(q.firewall().await, before);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn changed_config_stops_release() {
        let q = q("q-changed", &[HUB], true).await;
        let isolated = q.call("quarantine_isolate", "linux").await;
        q.keep(&isolated);
        q.e.sim.set_guest_option(100, "policy_out", json!("ACCEPT"));
        let r = q.call("quarantine_release", "linux").await;
        assert_eq!(r.outcome, StepOutcome::Failed("quarantine_config_changed".into()), "{r:?}");
        assert_eq!(q.firewall().await["options"]["policy_out"], "ACCEPT", "the admin's version is left alone");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_retry_takes_up_the_earlier_record() {
        let q = q("q-retry", &[HUB], true).await;
        let first = q.call("quarantine_isolate", "linux").await;
        q.keep(&first);
        let writes = q.writes();
        let again = q.call("quarantine_isolate", "linux").await;
        assert_eq!(again.outcome, StepOutcome::Succeeded, "{again:?}");
        let text = String::from_utf8_lossy(&again.stdout).to_string();
        let v: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(v["reused"], true);
        let original = q.hub.record.lock().unwrap().clone().unwrap()["saved"].clone();
        assert_eq!(v["saved"], original, "still the original, not the isolated one");
        assert_eq!(q.writes(), writes, "nothing was written again");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unconfirmed_binding_is_refused_before_any_call() {
        let q = q("q-binding", &[HUB], true).await;
        q.e.set("machines", CT, "proxmox_ref_state", "mismatch").await;
        let r = q.call("quarantine_isolate", "linux").await;
        assert_eq!(r.outcome, StepOutcome::Failed("guest_binding_mismatch".into()), "{r:?}");
        assert!(q.e.sim.requests().is_empty(), "{:?}", q.e.sim.requests());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn in_guest_needs_an_account_a_supported_system_and_the_hubs_addresses() {
        // a monitor machine that isn't a guest has no account, so only a hypervisor could cut it off
        let monitor = q("q-monitor", &[HUB], false).await;
        monitor.unbind().await;
        let r = monitor.call("quarantine_isolate", "linux").await;
        assert_eq!(r.outcome, StepOutcome::Failed("monitor_machine_needs_hypervisor".into()), "{r:?}");
        // an operating system with no in-guest quarantine yet
        assert_eq!(
            monitor.call("quarantine_isolate", "windows").await.outcome,
            StepOutcome::Failed("in_guest_quarantine_unsupported".into())
        );
        // with an account it goes over SSH (and this machine has no address to reach)
        let managed = q("q-managed", &[HUB], true).await;
        managed.unbind().await;
        let ssh = managed.call("quarantine_isolate", "linux").await;
        assert_eq!(ssh.outcome, StepOutcome::Failed("machine_unreachable".into()), "{ssh:?}");
        // no addresses of the hub's: nothing can be allowed, so nothing is done
        let none = q("q-noaddr", &[], true).await;
        let r = none.call("quarantine_isolate", "linux").await;
        assert_eq!(r.outcome, StepOutcome::Failed("hub_addresses_unknown".into()));
        assert_eq!(none.writes(), 0);
    }

    fn host(managed: bool, address: Option<&str>, guest: &[&str]) -> crate::executor::GuestHost {
        crate::executor::GuestHost {
            host_id: M1.into(),
            host_address: address.map(str::to_string),
            managed,
            addresses: guest.iter().map(|a| a.to_string()).collect(),
        }
    }

    #[test]
    fn the_flush_runs_the_listed_commands_for_each_address_and_nothing_else() {
        use crate::executor::quarantine::conntrack_lines;
        let ips = ["192.0.2.151", "2001:db8::10", "not an address", "192.0.2.9 -F"];
        assert_eq!(
            conntrack_lines(&ips.map(str::to_string)),
            [
                "sudo /usr/local/lib/rackhand/run /usr/sbin/conntrack -D -s 192.0.2.151",
                "sudo /usr/local/lib/rackhand/run /usr/sbin/conntrack -D -d 192.0.2.151",
                "sudo /usr/local/lib/rackhand/run /usr/sbin/conntrack -D -s 2001:db8::10",
                "sudo /usr/local/lib/rackhand/run /usr/sbin/conntrack -D -d 2001:db8::10",
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn established_sessions_are_flushed_through_the_hypervisor_or_the_record_says_why_not() {
        let cases = [
            (None, "hypervisor_unknown"),
            (Some(host(false, Some("192.0.2.51"), &["192.0.2.151"])), "hypervisor_not_managed"),
            (Some(host(true, Some("192.0.2.51"), &[])), "no_guest_address"),
            // managed, but not reachable from here: no address to log in to
            (Some(host(true, None, &["192.0.2.151"])), "machine_unreachable"),
        ];
        for (n, (found, why)) in cases.into_iter().enumerate() {
            let q = q(&format!("q-flush{n}"), &[HUB], true).await;
            *q.hub.host.lock().unwrap() = found;
            let r = q.call("quarantine_isolate", "linux").await;
            assert_eq!(r.outcome, StepOutcome::Succeeded, "the quarantine applies anyway: {r:?}");
            let text = String::from_utf8_lossy(&r.stdout).to_string();
            let v: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
            assert_eq!(v["conntrack"], "conntrack_not_flushed", "{why}: {v}");
            assert_eq!(v["conntrack_why"], why);
            assert_eq!(q.firewall().await["options"]["policy_in"], "DROP", "isolated all the same");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_and_release_need_the_record() {
        let q = q("q-norecord", &[HUB], true).await;
        for call in ["quarantine_snapshot", "quarantine_release"] {
            let r = q.call(call, "linux").await;
            assert_eq!(r.outcome, StepOutcome::Failed("no_quarantine_record".into()), "{call}");
        }
    }
}
