use super::*;

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rackhand-hub-cmd-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[tokio::test(flavor = "multi_thread")]
async fn init_creates_keys_and_config_with_modes() {
    let dir = temp("init");
    let (etc, data) = (dir.join("etc"), dir.join("lib"));
    let made = init(&etc, &data).await.unwrap();
    assert!(made.setup_code.starts_with("SETUP-") && made.setup_code.len() == 20, "{}", made.setup_code);
    assert!(!made.recovery_code.is_empty());
    let config = HubConfig::load(&made.config).unwrap();
    assert_eq!(config, HubConfig::defaults(&etc, &data), "hub.toml holds the defaults");
    assert_eq!(std::fs::read(&config.master_key).unwrap().len(), 32);
    #[cfg(unix)]
    {
        assert_eq!(mode(&config.master_key), 0o600, "the master key is the owner's only");
        assert_eq!(mode(&config.node_key), 0o600);
        assert_eq!(mode(&made.config), 0o640);
    }
    let db = Db::open(&config.db_path()).unwrap();
    let names: Vec<String> = db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT name FROM secrets ORDER BY name")?;
            s.query_map([], |r| r.get(0))?.collect()
        })
        .unwrap();
    for name in ["csrf_key", "metrics_token", "setup_code_hash"] {
        assert!(names.iter().any(|n| n == name), "{name} in {names:?}");
    }
    assert!(names.iter().filter(|n| n.contains("ssh")).count() >= 2, "the automation and assistant keys: {names:?}");
    let again = init(&etc, &data).await.unwrap_err();
    assert!(again.contains("already"), "{again}");
}

#[tokio::test(flavor = "multi_thread")]
async fn run_refuses_missing_master_key_with_clear_message() {
    let dir = temp("no-key");
    let config = HubConfig::defaults(&dir.join("etc"), &dir.join("lib"));
    // SAFETY of the test: no credentials directory, so the configured path is the one read
    assert!(std::env::var_os("CREDENTIALS_DIRECTORY").is_none());
    let err = run(&config).await.unwrap_err();
    assert!(err.contains(&config.master_key.display().to_string()), "{err}");
    assert!(err.contains("master key"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn detect_replay_prints_what_would_have_fired() {
    let dir = temp("replay");
    let path = dir.join("hub.db");
    let machine = "01JD0000000000000000000001";
    let t0 = 1_795_068_000_000i64;
    {
        let db = Db::open(&path).unwrap();
        // 20 minutes of normal CPU, 20 over 90%, then normal again, in tier 0
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("INSERT INTO metric_keys (id, name, unit, label_set) VALUES (1, 'cpu.busy_pct', '%', '{}')", [])
            .unwrap();
        let ts: Vec<i64> = (0..240).map(|i| t0 + i * 15_000).collect();
        let values: Vec<f64> = (0..240).map(|i| if (80..160).contains(&i) { 95.0 } else { 40.0 }).collect();
        let key = rackhand_store::series::chunk::SeriesKey { machine_id: machine.into(), metric_key_id: 1 };
        rackhand_store::series::chunk::append(
            &conn,
            &key,
            rackhand_store::series::chunk::Tier::Raw,
            None,
            &ts,
            &[values],
        )
        .unwrap();
        drop(db);
    }
    let lines = detect_replay(&path, machine, t0, t0 + 3_600_000).unwrap();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].contains("cpu.busy {} would open warning"), "{lines:?}");
    // the 15-minute window excludes its start, so it is full of breaching samples at the 60th: 06:34:45
    assert!(lines[0].starts_with("2026-11-19T06:34:45Z"), "15 minutes after the rise: {lines:?}");
    assert!(lines[1].contains("would resolve"), "{lines:?}");
    let db = Db::open(&path).unwrap();
    let written: i64 = db.readers().with(|c| c.query_row("SELECT count(*) FROM incidents", [], |r| r.get(0))).unwrap();
    assert_eq!(written, 0, "nothing written");
}

async fn machine_row(db: &Db, id: &str) {
    use rackhand_store::{Row, RowWrite, WriteCmd};
    use rusqlite::types::Value;
    let site = Row::from([
        ("id", Value::Text("s".into())),
        ("name", Value::Text("home".into())),
        ("timezone", Value::Text("UTC".into())),
    ]);
    let machine = Row::from([
        ("id", Value::Text(id.into())),
        ("site_id", Value::Text("s".into())),
        ("name", Value::Text("web".into())),
        ("kind", Value::Text("linux".into())),
    ]);
    db.writer()
        .send(WriteCmd::Batch(vec![RowWrite::insert("sites", site), RowWrite::insert("machines", machine)]))
        .await
        .unwrap();
}

fn events(db: &Db) -> Vec<(String, String, String)> {
    db.readers()
        .with(|c| {
            let mut s = c.prepare("SELECT kind, severity, coalesce(machine_id, '') FROM events ORDER BY kind")?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
        })
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn join_and_host_key_events_wired() {
    use rackhand_hub::library::mirror::MirrorAlert;
    use rackhand_hub::registry::join_server::Joined;
    use rackhand_hub::registry::tokens::TokenKind;
    use rackhand_hub::ssh::hostkeys::{HostKeyAlert, HostKeys};
    const M: &str = "01JD0000000000000000000001";
    let dir = temp("joins");
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    machine_row(&db, M).await;
    let ingest = Ingest::new(db.clone(), rackhand_hub::bus::Bus::new(), Arc::new(Statvfs(dir.clone())));
    let (host_keys, _) = HostKeys::new(db.clone());
    let (joined, joined_rx) = tokio::sync::mpsc::unbounded_channel();
    let (host_alerts, host_alerts_rx) = tokio::sync::mpsc::unbounded_channel();
    let (mirror_alerts, mirror_alerts_rx) = tokio::sync::mpsc::unbounded_channel();
    let login = rackhand_hub::ssh::enroll_test::Pinned {
        vault: Arc::new(Vault::new(MasterKey::from_bytes([3; 32]), db.clone())),
        host_keys: host_keys.clone(),
    };
    let test = Arc::new(rackhand_hub::ssh::enroll_test::EnrollTest::new(db.clone(), Arc::new(login)));
    joins::spawn_events(ingest, host_keys.clone(), joined_rx, host_alerts_rx, mirror_alerts_rx, test);

    let (_, key) = rackhand_hub::ssh::keys::generate_ed25519("host").unwrap();
    let openssh = key.to_openssh().unwrap();
    let mut parts = openssh.split(' ');
    let (algorithm, public_key) = (parts.next().unwrap().to_string(), parts.next().unwrap().to_string());
    let endpoint_id = iroh::SecretKey::from_bytes(&[7; 32]).public();
    let keys = vec![rackhand_proto::common::SshHostKey { algorithm, public_key }];
    joined.send(Joined { kind: TokenKind::Machine, id: M.into(), endpoint_id, ssh_host_keys: keys }).unwrap();
    host_alerts
        .send(HostKeyAlert::Changed {
            machine_id: M.into(),
            key_type: "ssh-ed25519".into(),
            offered: "SHA256:x".into(),
        })
        .unwrap();
    mirror_alerts.send(MirrorAlert::Failed { error: "unreachable".into(), retry_at_ms: 1 }).unwrap();
    mirror_alerts.send(MirrorAlert::Pushed { commit: "abc".into() }).unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while (host_keys.check(M, &key).is_err() || events(&db).len() < 2) && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(host_keys.check(M, &key), Ok(()), "the joined machine's host key is pinned in SSH");
    assert_eq!(
        events(&db),
        vec![
            ("git_mirror_failed".to_string(), "warning".to_string(), String::new()),
            ("ssh.host_key_changed".to_string(), "critical".to_string(), M.to_string()),
        ],
        "host key and mirror alerts become events; a push that went through raises none"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_setup_has_keys_sudoers_and_signed_commands() {
    use rackhand_hub::registry::join_server::ManagedSetupSource;
    let dir = temp("setup");
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let signing = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let setup = joins::HubSetup {
        db,
        automation: "ssh-ed25519 AAAA automation".into(),
        assistant: "ssh-ed25519 BBBB assistant".into(),
        signing: signing.clone(),
    };
    let managed = setup.managed_setup(ulid::Ulid::new(), true);
    assert_eq!(managed.automation_pubkey, "ssh-ed25519 AAAA automation");
    assert_eq!(managed.assistant_pubkey.as_deref(), Some("ssh-ed25519 BBBB assistant"));
    assert_eq!(
        managed.sudoers,
        "rackhand ALL=(root) NOPASSWD: /usr/local/lib/rackhand/run\n\
         Defaults:rackhand-ai log_output, iolog_dir=/var/log/rackhand/sudo-io\nrackhand-ai ALL=(ALL) NOPASSWD: ALL\n",
        "the wrapper's entry, and the assistant's with its sessions logged"
    );
    let commands = managed.commands.expect("the first command list comes with the join");
    let env = rackhand_proto::signed::verify(&commands, &signing.verifying_key(), "commands", 0, now_ms())
        .expect("signed with the hub's node key");
    let body: serde_json::Value = serde_json::from_slice(&env.body).unwrap();
    let listed = body["commands"].as_array().cloned().unwrap_or_default();
    let diagnostics = serde_json::to_value(rackhand_runbook::diagnostics::templates()).unwrap();
    let diagnostics = diagnostics.as_array().unwrap();
    assert!(
        !diagnostics.is_empty() && diagnostics.iter().all(|t| listed.contains(t)),
        "the diagnostics' root commands"
    );
    let hub_role = setup.managed_setup(ulid::Ulid::new(), false);
    assert_eq!(hub_role.assistant_pubkey, None, "no assistant account on a machine with role hub");
    assert_eq!(hub_role.sudoers, "rackhand ALL=(root) NOPASSWD: /usr/local/lib/rackhand/run\n", "nor its sudo");
}

#[tokio::test(flavor = "multi_thread")]
async fn join_server_waits_for_first_run_site() {
    let dir = temp("lazyjoin");
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let registry = rackhand_hub::registry::Registry::load(db.clone()).unwrap();
    let setup = Arc::new(joins::HubSetup {
        db: db.clone(),
        automation: String::new(),
        assistant: String::new(),
        signing: ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
    });
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = reads.clone();
    let addrs: joins::HubAddrs = Arc::new(move || {
        counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        vec!["192.0.2.10:7443".into()]
    });
    let join = joins::LazyJoin::new(db.clone(), registry, setup, addrs, tx);
    assert!(join.server().is_none(), "no join server before first run names the site");
    let site = rackhand_hub::registry::peers::local_site_row("home", "UTC");
    db.writer().send(rackhand_store::WriteCmd::Batch(vec![site])).await.unwrap();
    let server = join.server().expect("built once the site exists");
    assert!(Arc::ptr_eq(&server, &join.server().unwrap()), "built once");
    assert!(format!("{server:?}").contains("home"), "{server:?}");
    assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 1, "the addresses are read when the server is built");
}

#[test]
fn hub_addrs_from_endpoint_and_names() {
    let dir = temp("addrs");
    let mut config = HubConfig::defaults(&dir.join("etc"), &dir.join("lib"));
    let sock = |s: &str| s.parse::<SocketAddr>().unwrap();
    let endpoint =
        [sock("127.0.0.1:7443"), sock("192.168.1.5:7443"), sock("[fe80::1]:7443"), sock("[2001:db8::5]:7443")];
    assert_eq!(
        hub_addrs(&config, &endpoint),
        vec!["192.168.1.5:7443".to_string(), "[2001:db8::5]:7443".to_string()],
        "a default hub (0.0.0.0) advertises its endpoint's direct addresses, without loopback or link-local"
    );
    config.names = vec!["10.0.0.2".into(), "hub.example.net".into(), "192.168.1.5".into()];
    assert_eq!(
        hub_addrs(&config, &endpoint),
        vec!["192.168.1.5:7443".to_string(), "[2001:db8::5]:7443".to_string(), "10.0.0.2:7443".to_string()],
        "IP names on the QUIC port, each address once"
    );
    config.quic = sock("192.0.2.10:7443");
    config.names.clear();
    assert_eq!(
        hub_addrs(&config, &[sock("192.0.2.10:7443")]),
        vec!["192.0.2.10:7443".to_string()],
        "a specific bind once"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_welcome_from_settings() {
    use rackhand_hub::library::config::{HUB, parse_hub, put};
    use rackhand_hub::library::items::{Kind, validate};
    let dir = temp("probe-settings");
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let config = probe_server_settings(&db).config;
    assert_eq!((config.interval_s, config.max_connection_tuples, config.buffer_max_mb), (15, 500, 64), "defaults");
    put(&db, HUB, "[probe]\ninterval_s = 5\nbuffer_max_mb = 1\n", "admin", now_ms()).await.unwrap();
    let config = probe_server_settings(&db).config;
    let got = (config.interval_s, config.max_connection_tuples, config.buffer_max_mb);
    assert_eq!(got, (5, 500, 1), "from config/hub.toml");
    for bad in ["[probe]\ninterval_s = 2\n", "[probe]\nconnection_tuples = 99\n", "[probe]\nbuffer_max_mb = 65\n"] {
        assert!(parse_hub(bad).is_err(), "{bad} is out of range");
        assert!(validate(Kind::Config, "hub", bad).is_err(), "{bad} is refused on save");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn step_kinds_reach_their_systems() {
    use rackhand_hub::actions::runner::{StepCtx, StepOutcome, StepRunner};
    let dir = temp("steps");
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let ingest = Ingest::new(db.clone(), rackhand_hub::bus::Bus::new(), Arc::new(Statvfs(dir.clone())));
    let notify = rackhand_hub::notify::Notify::new(db.clone(), ingest.clone(), Vec::new());
    let server = ProbeServer::new(ingest.clone(), Arc::new(MachinesDirectory(db.clone())), ServerSettings::default());
    let vault = Arc::new(Vault::new(MasterKey::from_bytes([6u8; 32]), db.clone()));
    let steps = steps(&db, &vault, &notify, &ingest, &server);
    let ctx = StepCtx {
        job_id: "j1".into(),
        machine_id: "m1".into(),
        machine_kind: "linux".into(),
        address: None,
        identity: rackhand_runbook::runbook::Identity::Automation,
        timeout: Duration::from_millis(300),
    };
    let step = |kind: &str| -> rackhand_runbook::runbook::Step {
        toml::from_str(&format!("id = \"s\"\nkind = \"{kind}\"\nmessage = \"hi\"\n")).unwrap()
    };
    let outcome = |o: rackhand_hub::actions::runner::StepResult| o.outcome;
    assert_eq!(
        outcome(steps.run(&ctx, &step("wait_report"), None).await),
        StepOutcome::Failed("timeout".into()),
        "Ingest waits for a report"
    );
    assert_ne!(
        outcome(steps.run(&ctx, &step("notify"), None).await),
        StepOutcome::Failed("notify_unavailable".into()),
        "Notify sends it"
    );
    assert_eq!(
        outcome(steps.run(&ctx, &step("probe_check"), None).await),
        StepOutcome::Succeeded,
        "the probe server runs it (no checks: nothing to ask the probe)"
    );
    let one: rackhand_runbook::runbook::Step = toml::from_str(
        "id = \"s\"
kind = \"probe_check\"
checks = [\"tcp:127.0.0.1:5432\"]
",
    )
    .unwrap();
    assert_eq!(outcome(steps.run(&ctx, &one, None).await), StepOutcome::Failed("probe_not_connected".into()));
    // verify and api go to Checks: a verify with nothing to check passes, an api step without a call says so
    assert_eq!(outcome(steps.run(&ctx, &step("verify"), None).await), StepOutcome::Succeeded, "Checks verifies");
    assert_eq!(
        outcome(steps.run(&ctx, &step("api"), None).await),
        StepOutcome::Failed("no_call".into()),
        "Checks calls"
    );
    // snapshot and rollback go to the hypervisor's driver, for a Proxmox guest
    for kind in ["snapshot", "rollback"] {
        assert_eq!(
            outcome(steps.run(&ctx, &step(kind), None).await),
            StepOutcome::Failed("not_a_proxmox_guest".into())
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn backup_and_restore_commands() {
    let dir = temp("backup-cmd");
    let made = init(&dir.join("etc"), &dir.join("lib")).await.unwrap();
    let config = HubConfig::load(&made.config).unwrap();
    let file = backups::backup_now(&config, 1_000).unwrap();
    assert!(file.starts_with(dir.join("lib/backups")), "{}", file.display());
    // a new machine, with the old hub's master key
    let (etc, data) = (dir.join("new-etc"), dir.join("new-lib"));
    let toml = backups::restore(&file, &config.master_key, &etc, &data).unwrap();
    let restored = HubConfig::load(&toml).unwrap();
    assert_eq!(
        std::fs::read(&restored.node_key).unwrap(),
        std::fs::read(&config.node_key).unwrap(),
        "the same node key"
    );
    assert_eq!(std::fs::read(&restored.master_key).unwrap(), std::fs::read(&config.master_key).unwrap());
    let db = Db::open(&restored.db_path()).unwrap();
    let secrets: i64 = db.readers().with(|c| c.query_row("SELECT count(*) FROM secrets", [], |r| r.get(0))).unwrap();
    assert!(secrets >= 3, "the Vault came along");
    assert!(
        backups::restore(&file, &config.master_key, &etc, &data).unwrap_err().contains("already exists"),
        "never over a hub"
    );
}

#[test]
fn nightly_at_two_site_time() {
    assert_eq!(backups::nightly(120), (true, false), "02:00: the backup");
    assert_eq!(backups::nightly(150), (false, true), "02:30: the self-watch");
    assert_eq!(backups::nightly(121), (false, false));
}

#[tokio::test(flavor = "multi_thread")]
async fn site_minute_in_the_sites_time_zone() {
    use rackhand_store::{Row, RowWrite, WriteCmd};
    use rusqlite::types::Value;
    let dir = temp("site-minute");
    let db = Db::open(&dir.join("hub.db")).unwrap();
    assert_eq!(backups::site_minute(&db, 0), None, "no site before first run");
    let site = Row::from([
        ("id", Value::Text("s".into())),
        ("name", Value::Text("home".into())),
        ("timezone", Value::Text("Europe/Berlin".into())),
        ("is_local", Value::Integer(1)),
    ]);
    db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("sites", site)])).await.unwrap();
    // 2026-01-15 01:00 UTC is 02:00 in Berlin (winter)
    assert_eq!(backups::site_minute(&db, 1_768_438_800_000), Some(120));
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_token_read_with_the_master_key() {
    let dir = temp("metrics-token");
    let made = init(&dir.join("etc"), &dir.join("lib")).await.unwrap();
    let config = HubConfig::load(&made.config).unwrap();
    let stored = {
        let db = Arc::new(Db::open(&config.db_path()).unwrap());
        let vault = Vault::new(MasterKey::load(Some(&config.master_key)).unwrap(), db);
        String::from_utf8(vault.get("metrics_token").unwrap().expose().to_vec()).unwrap()
    };
    assert_eq!(metrics_token(&config).unwrap(), stored, "the token /metrics checks");
    assert_eq!(stored.len(), 48);
    // another master key opens nothing
    let other = dir.join("other.key");
    MasterKey::generate().save(&other).unwrap();
    let wrong = HubConfig { master_key: other, ..config.clone() };
    assert!(metrics_token(&wrong).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn ticket_names_the_node_key_and_addresses() {
    let dir = temp("ticket");
    let made = init(&dir.join("etc"), &dir.join("lib")).await.unwrap();
    let config = HubConfig::load(&made.config).unwrap();
    let key: [u8; 32] = std::fs::read(&config.node_key).unwrap().try_into().unwrap();
    let id: String = iroh::SecretKey::from_bytes(&key).public().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let addrs = ["192.0.2.10".parse().unwrap(), "2001:db8::10".parse().unwrap()];
    assert_eq!(
        ticket(&config, &addrs).unwrap(),
        format!("rackhand1:{id}@192.0.2.10:7443,[2001:db8::10]:7443"),
        "the endpoint id and the QUIC port, as the probe's installer reads them"
    );
    assert!(ticket(&config, &[]).is_err(), "a ticket needs an address");
}

/// The hub's SSH test after a managed machine's first report (7.3.12): its outcome becomes an event on the machine,
/// a failure naming the account; a failed machine is tested again at its next report, a passed one isn't.
#[tokio::test(flavor = "multi_thread")]
async fn ssh_test_after_first_report_wired() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use rackhand_hub::registry::join_server::Joined;
    use rackhand_hub::registry::tokens::TokenKind;
    use rackhand_hub::ssh::client::{Output, SshError};
    use rackhand_hub::ssh::enroll_test::{BoxFuture, EnrollTest, Login};
    use rackhand_hub::ssh::hostkeys::HostKeys;
    use rackhand_hub::ssh::keys::Identity;
    use rackhand_store::{Row, RowUpdate, WriteCmd};
    use rusqlite::types::Value;

    #[derive(Default)]
    struct Sudo {
        works: AtomicBool,
        logins: AtomicUsize,
    }
    impl Login for Sudo {
        fn run<'a>(
            &'a self,
            _: std::net::SocketAddr,
            _: &'a str,
            id: Identity,
            _: &'a str,
        ) -> BoxFuture<'a, Result<Output, SshError>> {
            self.logins.fetch_add(1, Ordering::SeqCst);
            let code = u32::from(id == Identity::Assistant && !self.works.load(Ordering::SeqCst));
            Box::pin(async move { Ok(Output { exit_code: Some(code), stdout: Vec::new(), stderr: Vec::new() }) })
        }
    }

    const M: &str = "01JD0000000000000000000002";
    let dir = temp("ssh-test");
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    machine_row(&db, M).await;
    let enrolled = RowUpdate {
        table: "machines",
        key: ("id", Value::Text(M.into())),
        set: Row::from([("state", Value::Text("enrolled".into())), ("address", Value::Text("192.0.2.5".into()))]),
    };
    db.writer()
        .send(WriteCmd::RegistryChange(rackhand_store::RegistryChange {
            updates: vec![enrolled],
            ..Default::default()
        }))
        .await
        .unwrap();
    let ingest = Ingest::new(db.clone(), rackhand_hub::bus::Bus::new(), Arc::new(Statvfs(dir.clone())));
    let (host_keys, _) = HostKeys::new(db.clone());
    let login = Arc::new(Sudo::default());
    let test = Arc::new(EnrollTest::new(db.clone(), login.clone()));
    let (joined, joined_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_host_alerts, host_alerts_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_mirror_alerts, mirror_alerts_rx) = tokio::sync::mpsc::unbounded_channel();
    let (greeted, greeted_rx) = tokio::sync::mpsc::unbounded_channel();
    joins::spawn_events(ingest.clone(), host_keys, joined_rx, host_alerts_rx, mirror_alerts_rx, test.clone());
    joins::spawn_enroll_tests(ingest, test, greeted_rx);

    let (_, key) = rackhand_hub::ssh::keys::generate_ed25519("host").unwrap();
    let openssh = key.to_openssh().unwrap();
    let mut parts = openssh.split(' ');
    let (algorithm, public_key) = (parts.next().unwrap().to_string(), parts.next().unwrap().to_string());
    let endpoint_id = iroh::SecretKey::from_bytes(&[8; 32]).public();
    let keys = vec![rackhand_proto::common::SshHostKey { algorithm, public_key }];
    joined.send(Joined { kind: TokenKind::Machine, id: M.into(), endpoint_id, ssh_host_keys: keys }).unwrap();

    let ssh_events = |db: &Db| -> Vec<(String, String, String)> {
        db.readers()
            .with(|c| {
                let mut s = c.prepare(
                    "SELECT kind, severity, coalesce(json_extract(data, '$.account'), '') FROM events
                     WHERE machine_id = ?1 AND kind LIKE 'machine.ssh_test_%' ORDER BY at_ms, kind",
                )?;
                s.query_map([M], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
            })
            .unwrap()
    };
    let wait = |n: usize| {
        let db = db.clone();
        async move {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while ssh_events(&db).len() < n && std::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            ssh_events(&db)
        }
    };
    greeted.send(M.to_string()).unwrap();
    let failed = ("machine.ssh_test_failed".to_string(), "warning".to_string(), "rackhand-ai".to_string());
    assert_eq!(
        wait(1).await,
        std::slice::from_ref(&failed),
        "the first report is followed by the test; the failure names the account"
    );

    login.works.store(true, Ordering::SeqCst);
    greeted.send(M.to_string()).unwrap();
    let passed = ("machine.ssh_test_passed".to_string(), "info".to_string(), String::new());
    assert_eq!(wait(2).await, [failed.clone(), passed.clone()], "tested again at the next report until it passes");

    let before = login.logins.load(Ordering::SeqCst);
    greeted.send(M.to_string()).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(login.logins.load(Ordering::SeqCst), before, "a passed machine isn't tested at every report");
    assert_eq!(ssh_events(&db), [failed, passed]);
}
