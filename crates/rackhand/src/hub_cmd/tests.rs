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
