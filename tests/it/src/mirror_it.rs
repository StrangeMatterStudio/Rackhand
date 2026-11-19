//! The library's git mirror against a real git server over SSH (7.3.13, AC38).

mod mirror {
    use std::sync::Arc;
    use std::time::Duration;

    use rackhand_hub::audit::Audit;
    use rackhand_hub::library::items::{Kind, Library};
    use rackhand_hub::library::mirror::{DEPLOY_KEY, Mirror, MirrorAlert, RETRY_MS, Target};
    use rackhand_hub::ssh::keys::generate_ed25519;
    use rackhand_hub::vault::master_key::MasterKey;
    use rackhand_hub::vault::{Secret, Vault};
    use rackhand_store::Db;
    use rackhand_store::ids::now_ms;

    use crate::support::Container;

    const RUNBOOK: &str = r#"name = "compose-restart"
description = "Restart one Docker Compose project"
identity = "automation"
risk = "low"
autonomy = 1
[[step]]
id = "restart"
kind = "ssh"
cmd = ["/usr/bin/true"]
"#;

    fn store(name: &str) -> (Arc<Db>, Arc<Vault>) {
        let dir = std::env::temp_dir().join(format!("rackhand-it-mirror-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
        let vault = Arc::new(Vault::new(MasterKey::from_bytes([8u8; 32]), db.clone()));
        (db, vault)
    }

    fn mirror(db: &Arc<Db>, vault: &Arc<Vault>, url: String, name: &str) -> Mirror {
        Mirror {
            db: db.clone(),
            vault: vault.clone(),
            audit: Audit::new(db.writer()),
            workdir: std::env::temp_dir().join(format!("rackhand-it-mirror-work-{name}-{}", std::process::id())),
            target: Arc::new(move || Some(Target { url: url.clone(), branch: "main".into(), host_fingerprint: None })),
            debounce_ms: 30_000,
            clock: Arc::new(now_ms),
        }
    }

    fn git(c: &Container, args: &str) -> String {
        let out = c.root(&format!("git --git-dir=/srv/git/rackhand.git {args}"));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn change_pushed_within_60s_and_planted_secret_blocks() {
        let (db, vault) = store("push");
        let server = Container::start("gitd");
        let (ip, _) = server.ip_and_gateway();
        let (private, public) = generate_ed25519("rackhand-mirror").unwrap();
        let pem = private.to_openssh(russh::keys::ssh_key::LineEnding::LF).unwrap();
        vault.put(DEPLOY_KEY, &Secret::from(pem.as_str())).await.unwrap();
        let line = public.to_openssh().unwrap();
        let w = server.exec(
            None,
            &["sh", "-c", "cat > /home/git/.ssh/authorized_keys && chown git:git /home/git/.ssh/authorized_keys"],
            Some(line.as_bytes()),
        );
        assert!(w.status.success());
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (lib, changes) = Library::new(db.clone(), Audit::new(db.writer()));
        let mut alerts = mirror(&db, &vault, format!("ssh://git@{ip}/srv/git/rackhand.git"), "push").spawn(changes);

        let saved_at = std::time::Instant::now();
        lib.save(Kind::Runbook, "compose-restart", RUNBOOK, "admin", now_ms()).await.unwrap();
        let alert = tokio::time::timeout(Duration::from_secs(60), alerts.recv()).await.expect("within 60 s").unwrap();
        assert!(matches!(alert, MirrorAlert::Pushed { .. }), "{alert:?}");
        assert!(saved_at.elapsed() < Duration::from_secs(60));
        assert_eq!(git(&server, "show main:runbooks/compose-restart.toml"), RUNBOOK.trim());
        assert_eq!(git(&server, "log -1 --format=%s main"), "admin: add runbook/compose-restart");
        assert!(git(&server, "show main:README.md").contains("compose-restart"));

        // A planted secret: the scan blocks the whole push.
        let planted = RUNBOOK.replace("Restart one Docker Compose project", "uses AKIAABCDEFGHIJKLMNOP");
        lib.save(Kind::Runbook, "compose-restart", &planted, "alice", now_ms()).await.unwrap();
        let alert = tokio::time::timeout(Duration::from_secs(60), alerts.recv()).await.expect("within 60 s").unwrap();
        assert!(
            matches!(&alert, MirrorAlert::SecretBlocked { findings } if findings.iter().any(|(p, _)| p == "runbooks/compose-restart.toml")),
            "{alert:?}"
        );
        assert_eq!(alert.severity(), "critical");
        assert_eq!(git(&server, "rev-list --count main"), "1", "nothing pushed");
        let audited: String = db
            .readers()
            .with(|c| {
                c.query_row("SELECT data FROM audit_log WHERE action = 'git_mirror.secret_blocked'", [], |r| r.get(0))
            })
            .unwrap();
        assert!(audited.contains("critical") && audited.contains("runbooks/compose-restart.toml"), "{audited}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_push_raises_warning_and_retries_hourly() {
        let (db, vault) = store("fail");
        let (private, _) = generate_ed25519("rackhand-mirror").unwrap();
        let pem = private.to_openssh(russh::keys::ssh_key::LineEnding::LF).unwrap();
        vault.put(DEPLOY_KEY, &Secret::from(pem.as_str())).await.unwrap();
        let (lib, _changes) = Library::new(db.clone(), Audit::new(db.writer()));
        lib.save(Kind::Runbook, "compose-restart", RUNBOOK, "admin", now_ms()).await.unwrap();
        // Nothing listens on port 1.
        let m = mirror(&db, &vault, "ssh://git@127.0.0.1:1/srv/git/rackhand.git".into(), "fail");
        let before = now_ms();
        let alert = m.sync("admin: add runbook/compose-restart").await;
        assert_eq!((alert.kind(), alert.severity()), ("git_mirror_failed", "warning"));
        let MirrorAlert::Failed { retry_at_ms, .. } = alert else { panic!() };
        assert!((before + RETRY_MS..=now_ms() + RETRY_MS).contains(&retry_at_ms), "retried an hour later");
    }
}
