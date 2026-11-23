//! Provisioning (plan T64, FR-23, 7.3.12): what the two runbooks ask of the Proxmox API, the machine and token they
//! make, and the binding they record.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rackhand_drivers::proxmox::sim::Sim;
use rackhand_runbook::runbook::{Runbook, Step, StepKind};
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use super::*;
use crate::actions::coordinator::with_params;
use crate::actions::runner::{StepCtx, StepOutcome, StepRunner};
use crate::checks::steps::Api;
use crate::registry::Registry;
use crate::vault::master_key::MasterKey;
use crate::vault::{Secret, Vault};

const HOST: &str = "01JD0000000000000000000001";
const NOBODY: &str = "01JDNOSUCH0000000000000000";

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn now() -> i64 {
    rackhand_store::ids::now_ms()
}

struct Env {
    db: Arc<Db>,
    registry: Arc<Registry>,
    sim: Sim,
    api: Api,
}

async fn env(name: &str) -> Env {
    let dir = std::env::temp_dir().join(format!("rackhand-provision-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let sim = Sim::start("pve9").await;
    let host = Row::from([
        ("id", t(HOST)),
        ("site_id", t("s1")),
        ("name", t("pve")),
        ("kind", t("hypervisor")),
        ("address", t(&sim.url)),
        ("driver", t("proxmox")),
        ("state", t("enrolled")),
    ]);
    let site =
        Row::from([("id", t("s1")), ("name", t("home")), ("timezone", t("UTC")), ("is_local", Value::Integer(1))]);
    db.writer()
        .send(WriteCmd::Batch(vec![RowWrite::insert("sites", site), RowWrite::insert("machines", host)]))
        .await
        .unwrap();
    let vault = Arc::new(Vault::new(MasterKey::from_bytes([5u8; 32]), db.clone()));
    let creds = serde_json::json!({ "token": "rackhand@pve!hub=secret", "fingerprint": sim.fingerprint }).to_string();
    vault.put(&format!("driver.{HOST}"), &Secret::from(creds.as_str())).await.unwrap();
    let api = Api::new(db.clone()).with_driver(Arc::new(rackhand_drivers::Proxmox::new())).with_vault(vault);
    let registry = Registry::load(db.clone()).unwrap();
    Env { db, registry, sim, api }
}

fn runbook(name: &str) -> Runbook {
    Runbook::parse(rackhand_runbook::builtin::runbook(name).unwrap()).unwrap()
}

fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

impl Env {
    /// Runs the runbook's API steps, parameters in, one after another against the simulator.
    async fn api_steps(&self, name: &str, params: &BTreeMap<String, String>) {
        let ctx = StepCtx {
            job_id: "j1".into(),
            machine_id: HOST.into(),
            machine_kind: "hypervisor".into(),
            address: None,
            identity: rackhand_runbook::runbook::Identity::Automation,
            timeout: Duration::from_secs(10),
        };
        for step in runbook(name).steps.iter().filter(|s| s.kind == StepKind::Api) {
            let step: Step = with_params(step, params);
            let done = self.api.run(&ctx, &step, None).await;
            assert_eq!(done.outcome, StepOutcome::Succeeded, "{}: {done:?}", step.id);
        }
    }

    fn writes(&self) -> Vec<(String, String)> {
        let writes = self.sim.requests().into_iter().filter(|q| q.method != "GET");
        writes.map(|q| (format!("{} {}", q.method, q.path.trim_start_matches("/api2/json")), q.body)).collect()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn vm_clone_cloudinit_start_calls_match_recorded_api() {
    let e = env("vm").await;
    let p = params(&[("template", "200"), ("newid", "300"), ("name", "web-new"), ("storage", "tank")]);
    e.api_steps("provision-vm", &p).await;
    let writes = e.writes();
    assert_eq!(
        writes.iter().map(|(call, _)| call.as_str()).collect::<Vec<_>>(),
        [
            "POST /nodes/pve9/qemu/200/clone",
            "PUT /nodes/pve9/qemu/300/config",
            "POST /nodes/pve9/qemu/300/status/start"
        ],
        "clone, cloud-init settings, start, in that order and nothing else"
    );
    for part in ["newid=300", "name=web-new", "storage=tank", "full=1"] {
        assert!(writes[0].1.contains(part), "{part} in {}", writes[0].1);
    }
    // the user data is the snippet the hypervisor's wrapper wrote for this guest (`send_guest`), named by its id
    assert!(writes[1].1.contains("cicustom=user%3Dlocal%3Asnippets%2Frackhand-300.yml"), "{}", writes[1].1);
    assert!(writes[1].1.contains("agent=1"), "{}", writes[1].1);
    // the credentials were the hypervisor's own, from the Vault
    assert!(e.sim.requests().iter().all(|q| q.authorization == "PVEAPIToken=rackhand@pve!hub=secret"));
}

#[tokio::test(flavor = "multi_thread")]
async fn lxc_variant() {
    let e = env("lxc").await;
    let template = "local:vztmpl/alpine-3.20-default_20240908_amd64.tar.xz";
    let p = params(&[("template", template), ("newid", "400"), ("name", "ct-new"), ("storage", "tank")]);
    e.api_steps("provision-lxc", &p).await;
    let writes = e.writes();
    assert_eq!(
        writes.iter().map(|(call, _)| call.as_str()).collect::<Vec<_>>(),
        ["POST /nodes/pve9/lxc", "POST /nodes/pve9/lxc/400/status/start"]
    );
    for part in ["vmid=400", "hostname=ct-new", "rootfs=tank%3A8", "unprivileged=1", "ostemplate=local%3Avztmpl"] {
        assert!(writes[0].1.contains(part), "{part} in {}", writes[0].1);
    }
}

type MachineRow = (String, String, String, Option<String>, String, Option<String>);

fn row(db: &Db, name: &str) -> MachineRow {
    db.readers()
        .with(|c| {
            c.query_row(
                "SELECT id, state, access, proxmox_ref, proxmox_ref_state, proxmox_ref_confirmed_by
                 FROM machines WHERE name = ?1",
                [name],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
        })
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn binding_confirmed_by_runbook() {
    let e = env("bind").await;
    let (id, _) = pending_guest(&e.registry, HOST, "web-new", "job:j1", now()).await.unwrap();
    let id = id.to_string();
    assert_eq!(row(&e.db, "web-new").4, "none", "made, not bound");
    bind_guest(&e.db, HOST, "pve9", &id, "qemu", 300, "job:j1").await.unwrap();
    let (_, _, _, reference, state, by) = row(&e.db, "web-new");
    assert_eq!(state, "confirmed", "the runbook that made the guest confirms its binding, with no admin");
    assert_eq!(by.as_deref(), Some("job:j1"));
    let reference: serde_json::Value = serde_json::from_str(&reference.unwrap()).unwrap();
    assert_eq!(reference, serde_json::json!({ "cluster": HOST, "node": "pve9", "vmid": 300, "type": "qemu" }));
    // fixed from then on: nothing binds it again, and nothing binds a machine this runbook didn't make
    assert!(bind_guest(&e.db, HOST, "pve9", &id, "qemu", 301, "job:j1").await.is_err());
    assert!(row(&e.db, "web-new").3.unwrap().contains("300"));
    assert!(bind_guest(&e.db, HOST, "pve9", HOST, "qemu", 302, "job:j1").await.is_err(), "the host isn't a guest");
    assert!(bind_guest(&e.db, HOST, "pve9", NOBODY, "qemu", 303, "job:j1").await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn token_single_use_and_expires_60_min() {
    let e = env("token").await;
    let before = now();
    let (id, token) = pending_guest(&e.registry, HOST, "web-new", "job:j1", before).await.unwrap();
    let (state, access, site): (String, String, String) =
        e.db.readers()
            .with(|c| {
                c.query_row("SELECT state, access, site_id FROM machines WHERE id = ?1", [id.to_string()], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
            })
            .unwrap();
    assert_eq!((state.as_str(), access.as_str(), site.as_str()), ("pending", "managed", "s1"), "the host's site");
    let (kind, bound, expires, used): (String, String, i64, Option<i64>) =
        e.db.readers()
            .with(|c| {
                c.query_row(
                    "SELECT kind, bound, expires_at, used_at FROM join_tokens ORDER BY rowid DESC LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
            })
            .unwrap();
    assert_eq!((kind.as_str(), used), ("machine", None));
    assert_eq!(expires - before, 3_600_000, "60 minutes");
    let bound: serde_json::Value = serde_json::from_str(&bound).unwrap();
    assert_eq!(bound["machine_id"].as_str(), Some(id.to_string().as_str()));
    assert_eq!(bound["access"].as_str(), Some("managed"));
    assert_eq!(token.as_str().len(), 26);
    // a name that is taken makes nothing, and neither does a host that isn't one
    assert!(pending_guest(&e.registry, HOST, "web-new", "job:j1", before).await.is_err());
    assert!(pending_guest(&e.registry, NOBODY, "other", "job:j1", before).await.is_err());
    let count: i64 =
        e.db.readers().with(|c| c.query_row("SELECT count(*) FROM join_tokens", [], |r| r.get(0))).unwrap();
    assert_eq!(count, 1, "one token for the one machine made");
}

#[tokio::test(flavor = "multi_thread")]
async fn await_machine_sees_enrolled_by_name_on_the_hosts_site() {
    let e = env("await").await;
    assert!(!is_enrolled(&e.db, HOST, "web-new"), "no such machine");
    let (id, _) = pending_guest(&e.registry, HOST, "web-new", "job:j1", now()).await.unwrap();
    assert!(!is_enrolled(&e.db, HOST, "web-new"), "pending");
    let set = Row::from([("state", t("enrolled"))]);
    let update = rackhand_store::RowUpdate { table: "machines", key: ("id", t(&id.to_string())), set };
    let change = rackhand_store::RegistryChange { updates: vec![update], ..Default::default() };
    e.db.writer().send(WriteCmd::RegistryChange(change)).await.unwrap();
    assert!(is_enrolled(&e.db, HOST, "web-new"));
}
