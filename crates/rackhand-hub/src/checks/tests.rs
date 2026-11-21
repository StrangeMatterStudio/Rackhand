use std::sync::Arc;

use rackhand_store::Db;

use super::*;
use crate::bus::Bus;
use crate::incidents::Incidents;
use crate::ingest::{DiskSpace, Ingest};
use crate::library::items::{Kind, validate};

const T0: i64 = 1_795_068_000_000;

#[derive(Debug)]
struct Roomy;

impl DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

fn db(name: &str) -> Arc<Db> {
    let dir = std::env::temp_dir().join(format!("rackhand-checks-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Arc::new(Db::open(&dir.join("hub.db")).unwrap())
}

fn one(interval: &str, kind: &str, extra: &str) -> String {
    format!("[[check]]\nname = \"web\"\nkind = \"{kind}\"\ntarget = \"192.0.2.80:80\"\n{interval}{extra}")
}

#[test]
fn interval_bounds_15s_to_1h() {
    let at = |s: i64| config::parse(&one(&format!("interval_s = {s}\n"), "tcp", ""));
    assert!(at(14).is_err(), "under 15 s");
    assert!(at(3601).is_err(), "over 1 h");
    assert_eq!(at(15).unwrap().check[0].interval_s, 15);
    assert_eq!(at(3600).unwrap().check[0].interval_s, 3600);
    assert_eq!(config::parse(&one("", "tcp", "")).unwrap().check[0].interval_s, 60, "60 s by default");
    for bad in [
        one("", "smtp", ""),
        one("", "proxmox", ""),
        one("", "http", "[check.settings]\nverify = false\n"),
        one("", "tcp", "").replace("\"web\"", "\"Web!\""),
        format!("{}\n{}", one("", "tcp", ""), one("", "icmp", "")),
    ] {
        assert!(config::parse(&bad).is_err(), "refused: {bad}");
    }
    assert!(config::parse(&one("", "http", "[check.settings]\nstatus = 204\n")).is_ok());
    // saving config/checks through the Library checks the same
    assert!(validate(Kind::Config, "checks", &one("interval_s = 10\n", "tcp", "")).is_err());
    assert!(validate(Kind::Config, "checks", &one("interval_s = 30\n", "tcp", "")).is_ok());
}

struct Env {
    db: Arc<Db>,
    ingest: Ingest,
    incidents: Incidents,
    checks: Checks,
}

impl Env {
    fn start(db: Arc<Db>, ingest: Ingest) -> Env {
        let incidents = Incidents::new(db.clone(), ingest.clone(), Bus::new());
        let checks = Checks::new(db.clone(), ingest.clone());
        Env { db, ingest, incidents, checks }
    }

    async fn run(&self, at: i64) {
        self.checks.run_due(at).await.unwrap();
        self.incidents.evaluate(at).await.unwrap();
    }

    fn incident(&self) -> Option<(String, String)> {
        self.db
            .readers()
            .with(|c| {
                use rusqlite::OptionalExtension;
                c.query_row(
                    "SELECT state, severity FROM incidents WHERE kind = 'check.failing' AND machine_id IS NULL",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
            })
            .unwrap()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_failures_warn_four_critical() {
    let db = db("failing");
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    let env = Env::start(db.clone(), ingest.clone());
    // a TCP check of a port nothing listens on, from the hub (bound to no machine)
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let text = format!("[[check]]\nname = \"svc\"\nkind = \"tcp\"\ntarget = \"127.0.0.1:{port}\"\ninterval_s = 15\n");
    assert_eq!(env.checks.sync(&text).await.unwrap(), 1);
    env.run(T0).await;
    assert_eq!(env.incident(), None, "one failure");
    env.run(T0 + 5_000).await;
    assert_eq!(env.incident(), None, "not due yet: still one result");
    env.run(T0 + 15_000).await;
    assert_eq!(env.incident(), Some(("open".into(), "warning".into())), "2 in a row");
    env.run(T0 + 30_000).await;
    env.run(T0 + 45_000).await;
    assert_eq!(env.incident(), Some(("open".into(), "critical".into())), "4 in a row");
    // the hub restarts: the count comes from the stored results, so the next failure keeps it critical
    drop(env);
    let env = Env::start(db.clone(), ingest);
    env.checks.sync(&text).await.unwrap();
    env.run(T0 + 60_000).await;
    assert_eq!(env.incident(), Some(("open".into(), "critical".into())), "after the restart");
    // the service is back: one good run isn't enough, two resolve it
    let _listening = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    env.run(T0 + 75_000).await;
    assert_eq!(env.incident().map(|i| i.0), Some("open".into()));
    env.run(T0 + 90_000).await;
    assert_eq!(env.incident().map(|i| i.0), Some("resolved".into()));
    let results: i64 =
        db.readers().with(|c| c.query_row("SELECT count(*) FROM check_results", [], |r| r.get(0))).unwrap();
    assert_eq!(results, 7, "one result per run");
    // the readings are series too, under the hub for an unbound check
    let up = env.ingest.tier_series(
        "hub",
        "check.up",
        "{\"check\":\"svc\"}",
        rackhand_store::series::chunk::Tier::Raw,
        T0,
        T0 + MIN_MS * 2,
    );
    assert_eq!(up.unwrap().iter().map(|p| p.1[0]).collect::<Vec<_>>(), vec![0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0]);
    // a check taken out of config/checks stops, and its incidents resolve
    env.checks.sync("").await.unwrap();
    assert_eq!(env.checks.run_due(T0 + 120_000).await.unwrap(), 0);
}

const MIN_MS: i64 = 60_000;

mod agentless {
    use super::*;
    use rackhand_drivers::TrueNas;
    use rackhand_drivers::truenas::sim::{Api, Sim};
    use rackhand_store::{RegistryChange, RowUpdate, RowWrite};

    use crate::vault::master_key::MasterKey;
    use crate::vault::{Secret, Vault};

    const KEY: &str = "1-invented-api-key";
    const NAS: &str = "01JD00000000000000000000NS";

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    async fn appliance(db: &Arc<Db>, address: &str) {
        let rows = vec![
            RowWrite::insert("sites", Row::from([("id", t("s1")), ("name", t("home")), ("timezone", t("UTC"))])),
            RowWrite::insert(
                "machines",
                Row::from([
                    ("id", t(NAS)),
                    ("site_id", t("s1")),
                    ("name", t("nas1")),
                    ("kind", t("appliance")),
                    ("state", t("enrolled")),
                    ("driver", t("truenas")),
                    ("address", t(address)),
                    ("driver_settings", t(&format!("{{\"api_key\":\"secret:driver.{NAS}\"}}"))),
                ]),
            ),
        ];
        db.writer().send(WriteCmd::Batch(rows)).await.unwrap();
    }

    async fn credentials(vault: &Vault, key: &str, fingerprint: &str) {
        let v = serde_json::json!({ "api_key": key, "fingerprint": fingerprint });
        vault.put(&format!("driver.{NAS}"), &Secret::new(v.to_string().into_bytes())).await.unwrap();
    }

    fn setup(db: &Arc<Db>) -> (Env, Arc<Vault>) {
        let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
        let vault = Arc::new(Vault::new(MasterKey::from_bytes([5u8; 32]), db.clone()));
        let mut env = Env::start(db.clone(), ingest);
        env.checks =
            Checks::new(db.clone(), env.ingest.clone()).with_agentless(vault.clone(), vec![Arc::new(TrueNas::new())]);
        (env, vault)
    }

    fn results(db: &Db) -> Vec<bool> {
        db.readers()
            .with(|c| {
                let mut s = c.prepare("SELECT ok FROM check_results WHERE check_id = ?1 ORDER BY at_ms")?;
                s.query_map([format!("driver:{NAS}")], |r| r.get::<_, i64>(0).map(|v| v != 0))?.collect()
            })
            .unwrap()
    }

    fn incident(db: &Db, kind: &str) -> Option<(String, String)> {
        db.readers()
            .with(|c| {
                use rusqlite::OptionalExtension;
                c.query_row(
                    "SELECT state, severity FROM incidents WHERE kind = ?1 AND machine_id = ?2",
                    [kind, NAS],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
            })
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn polled_every_60s_with_its_vault_settings_and_kept_across_config_syncs() {
        let db = db("agentless-poll");
        let sim = Sim::start(Api::WebSocket).await;
        appliance(&db, &sim.url).await;
        let (env, vault) = setup(&db);
        credentials(&vault, KEY, &sim.fingerprint).await;
        env.checks.refresh().await.unwrap();
        assert_eq!(env.checks.run_due(T0).await.unwrap(), 1);
        assert_eq!(env.checks.run_due(T0 + 30_000).await.unwrap(), 0, "not due for 60 s");
        assert_eq!(results(&db), vec![true]);
        assert!(sim.authorized(), "with the key from the Vault");
        // its 7.4.2 readings are series of the machine
        let pool = env.ingest.tier_series(
            NAS,
            "truenas.pool.used_pct",
            "{\"pool\":\"tank1\"}",
            rackhand_store::series::chunk::Tier::Raw,
            T0 - 1,
            T0 + 1,
        );
        assert_eq!(pool.unwrap().len(), 1, "the pool's use as a series of nas1");
        // config/checks changes don't touch it, run or row
        env.checks.sync("").await.unwrap();
        assert_eq!(env.checks.run_due(T0 + 60_000).await.unwrap(), 1);
        let interval = |db: &Db| -> i64 {
            db.readers()
                .with(|c| {
                    c.query_row("SELECT interval_s FROM checks WHERE id = ?1", [format!("driver:{NAS}")], |r| r.get(0))
                })
                .unwrap()
        };
        assert_eq!(interval(&db), 60, "not retired by a config/checks sync");
        // revoked, it stops
        let revoke = RowUpdate { table: "machines", key: ("id", t(NAS)), set: Row::from([("state", t("revoked"))]) };
        let change = RegistryChange { consume: None, writes: vec![], updates: vec![revoke] };
        db.writer().send(WriteCmd::RegistryChange(change)).await.unwrap();
        env.checks.refresh().await.unwrap();
        assert_eq!(env.checks.run_due(T0 + 120_000).await.unwrap(), 0);
        assert_eq!(interval(&db), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn silent_after_2_failed_polls_critical_after_5() {
        let db = db("agentless-silent");
        let sim = Sim::start(Api::WebSocket).await;
        appliance(&db, &sim.url).await;
        let (env, vault) = setup(&db);
        credentials(&vault, "1-revoked-key", &sim.fingerprint).await;
        env.incidents.set_started(T0 - 10 * MIN_MS);
        env.checks.refresh().await.unwrap();
        env.run(T0).await;
        assert_eq!(incident(&db, "machine.silent"), None, "one failed poll");
        env.run(T0 + MIN_MS).await;
        assert_eq!(incident(&db, "machine.silent"), Some(("open".into(), "warning".into())), "2 in a row");
        for i in 2..5 {
            env.run(T0 + i * MIN_MS).await;
        }
        assert_eq!(incident(&db, "machine.silent"), Some(("open".into(), "critical".into())), "5 in a row");
        assert_eq!(incident(&db, "check.failing"), None, "one incident for it, not a check's too");
        // the hub restarts: in its first 3 minutes the open incident stays
        let (env, vault) = setup(&db);
        env.incidents.set_started(T0 + 5 * MIN_MS);
        env.checks.refresh().await.unwrap();
        env.incidents.evaluate(T0 + 5 * MIN_MS + 1_000).await.unwrap();
        assert_eq!(incident(&db, "machine.silent").map(|i| i.0), Some("open".into()));
        // the key is put right: the next poll answers and resolves it
        credentials(&vault, KEY, &sim.fingerprint).await;
        env.run(T0 + 9 * MIN_MS).await;
        assert_eq!(results(&db).last(), Some(&true));
        assert_eq!(incident(&db, "machine.silent").map(|i| i.0), Some("resolved".into()));
    }
}
