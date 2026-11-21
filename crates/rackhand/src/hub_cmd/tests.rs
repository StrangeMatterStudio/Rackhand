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
    joins::spawn_events(ingest, host_keys.clone(), joined_rx, host_alerts_rx, mirror_alerts_rx);

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
    assert_eq!(managed.sudoers, "rackhand ALL=(root) NOPASSWD: /usr/local/lib/rackhand/run\n");
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

#[test]
fn probe_welcome_has_design_defaults() {
    let config = probe_server_settings().config;
    assert_eq!((config.interval_s, config.max_connection_tuples, config.buffer_max_mb), (15, 500, 64));
}
