//! The hub's SSH system against a real OpenSSH server (7.3.7, E8, FR-12).

mod ssh {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use rackhand_hub::audit::Audit;
    use rackhand_hub::policy::approvals::Role;
    use rackhand_hub::ssh::client::{OUTPUT_CAP, SshError, TRUNCATED, run};
    use rackhand_hub::ssh::hostkeys::HostKeys;
    use rackhand_hub::ssh::keys::{Identity, authorized_keys_line, load_or_create};
    use rackhand_hub::vault::Vault;
    use rackhand_hub::vault::master_key::MasterKey;
    use rackhand_hub::web::auth::users::create_local;
    use rackhand_hub::web::{Web, WebConfig, session};
    use rackhand_store::{Db, Row, RowWrite, WriteCmd};
    use rusqlite::types::Value;
    use russh::keys::PublicKey;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    use crate::support::Container;

    fn form_urlencoded_byte(s: &str) -> String {
        s.bytes()
            .map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("%{b:02X}") })
            .collect()
    }

    struct Hub {
        db: Arc<Db>,
        vault: Arc<Vault>,
        keys: Arc<HostKeys>,
        sshd: Container,
        addr: SocketAddr,
    }

    async fn hub(name: &str, from: Option<&str>) -> Hub {
        let dir = std::env::temp_dir().join(format!("rackhand-it-ssh-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
        let vault = Arc::new(Vault::new(MasterKey::from_bytes([4u8; 32]), db.clone()));
        db.writer()
            .send(WriteCmd::Batch(vec![
                RowWrite::insert(
                    "sites",
                    Row::from([
                        ("id", Value::Text("s".into())),
                        ("name", Value::Text("home".into())),
                        ("timezone", Value::Text("UTC".into())),
                    ]),
                ),
                RowWrite::insert(
                    "machines",
                    Row::from([
                        ("id", Value::Text("m1".into())),
                        ("site_id", Value::Text("s".into())),
                        ("name", Value::Text("target".into())),
                        ("kind", Value::Text("linux".into())),
                    ]),
                ),
            ]))
            .await
            .unwrap();
        let sshd = Container::start("sshd");
        let (ip, gateway) = sshd.ip_and_gateway();
        // The hub's keys, installed as the installer would (T44), limited to the address the hub connects from.
        let from = from.map_or_else(|| gateway.clone(), str::to_string);
        for id in [Identity::Automation, Identity::Assistant] {
            let key = load_or_create(&vault, id).await.unwrap();
            let line = authorized_keys_line(key.public_key(), std::slice::from_ref(&from)).unwrap();
            let user = id.user();
            let path = format!("/home/{user}/.ssh/authorized_keys");
            assert!(
                sshd.exec(
                    None,
                    &["sh", "-c", &format!("cat > {path} && chown {user}:{user} {path} && chmod 600 {path}")],
                    Some(line.as_bytes())
                )
                .status
                .success()
            );
        }
        let (keys, _alerts) = HostKeys::new(db.clone());
        let host = PublicKey::from_openssh(&host_key(&sshd)).unwrap();
        keys.pin_from_join("m1", &[host], 1).await.unwrap();
        let addr: SocketAddr = format!("{ip}:22").parse().unwrap();
        wait_listening(addr).await;
        Hub { db, vault, keys, sshd, addr }
    }

    fn host_key(c: &Container) -> String {
        String::from_utf8_lossy(&c.root("cat /etc/ssh/ssh_host_ed25519_key.pub").stdout).trim().to_string()
    }

    async fn wait_listening(addr: SocketAddr) {
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("sshd never listened on {addr}");
    }

    impl Hub {
        async fn run(&self, id: Identity, command: &str) -> Result<rackhand_hub::ssh::client::Output, SshError> {
            let key = load_or_create(&self.vault, id).await.unwrap();
            run(self.addr, "m1", self.keys.clone(), id, &key, command, Duration::from_secs(60)).await
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runs_as_automation_and_assistant_identities() {
        let hub = hub("identities", None).await;
        let a = hub.run(Identity::Automation, "id -un").await.unwrap();
        assert_eq!((String::from_utf8_lossy(&a.stdout).trim(), a.exit_code), ("rackhand", Some(0)));
        let b = hub.run(Identity::Assistant, "id -un; echo oops >&2; exit 3").await.unwrap();
        assert_eq!(String::from_utf8_lossy(&b.stdout).trim(), "rackhand-ai");
        assert_eq!((String::from_utf8_lossy(&b.stderr).trim(), b.exit_code), ("oops", Some(3)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn output_capped_at_1mb_with_marker() {
        let hub = hub("cap", None).await;
        let out = hub.run(Identity::Automation, "head -c 2000000 /dev/zero | tr '\\000' a").await.unwrap();
        assert_eq!(out.stdout.len(), OUTPUT_CAP + TRUNCATED.len());
        assert!(out.stdout[..OUTPUT_CAP].iter().all(|b| *b == b'a'));
        assert!(out.stdout.ends_with(TRUNCATED.as_bytes()));
        assert_eq!(out.exit_code, Some(0), "the command still runs to its end");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn from_restriction_refuses_other_source() {
        // The key is limited to an address the hub doesn't connect from.
        let hub = hub("from", Some("192.0.2.99")).await;
        assert_eq!(hub.run(Identity::Automation, "true").await, Err(SshError::AuthRefused("rackhand")));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn accepting_new_key_needs_admin_step_up() {
        let hub = hub("accept", None).await;
        assert!(hub.run(Identity::Automation, "true").await.is_ok());
        // The machine gets new host keys (reinstalled, or someone in the middle).
        assert!(hub.sshd.root("rm -f /etc/ssh/ssh_host_* && ssh-keygen -A >/dev/null").status.success());
        assert_eq!(hub.run(Identity::Automation, "true").await, Err(SshError::HostKeyChanged));
        assert!(hub.keys.offered("m1").is_some());
        // The dashboard: an admin without a fresh step-up is sent to step up, and nothing changes.
        let web = Web::new(
            hub.db.clone(),
            hub.vault.clone(),
            Audit::new(hub.db.writer()),
            "RECOVERY".into(),
            WebConfig { setup_code_hash: Sha256::digest(b"x").into(), csrf_key: [6u8; 32], trusted_proxies: vec![] },
        )
        .with_host_keys(hub.keys.clone());
        let router = web.router();
        let admin = create_local(
            &hub.db,
            &hub.vault,
            "admin",
            Role::Admin,
            "correct horse battery staple",
            Some(&[1u8; 20]),
            1,
        )
        .await
        .unwrap();
        let now = rackhand_store::ids::now_ms();
        let token = session::create(&hub.db, &admin, now).await.unwrap();
        let cookie = format!("{}={token}", session::COOKIE);
        let page = router
            .clone()
            .oneshot(Request::get("/").header(header::COOKIE, &cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let html =
            String::from_utf8_lossy(&axum::body::to_bytes(page.into_body(), 1 << 20).await.unwrap()).into_owned();
        let marker = "name=\"csrf\" value=\"";
        let start = html.find(marker).unwrap() + marker.len();
        let csrf = html[start..start + 64].to_string();
        let offered = hub.keys.offered("m1").unwrap().1;
        let accept_with = |fingerprint: &str| {
            Request::post("/machines/m1/host-key/accept")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("csrf={csrf}&fingerprint={}", form_urlencoded_byte(fingerprint))))
                .unwrap()
        };
        let accept = || accept_with(&offered);
        let resp = router.clone().oneshot(accept()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/step-up");
        assert_eq!(hub.run(Identity::Automation, "true").await, Err(SshError::HostKeyChanged), "still blocked");
        // After a step-up the admin accepts it, and actions run again.
        let id_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        session::set_step_up(&hub.db, &id_hash, rackhand_store::ids::now_ms()).await.unwrap();
        let wrong = router.clone().oneshot(accept_with("SHA256:something-else")).await.unwrap();
        assert_eq!(wrong.status(), StatusCode::CONFLICT, "only the key the admin was shown");
        let resp = router.clone().oneshot(accept()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        // back to the machine's page, where the admin was (the dashboard's pages return to where they came from)
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/machines/m1");
        assert!(hub.run(Identity::Automation, "true").await.is_ok());
        let audited: i64 = hub
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT count(*) FROM audit_log WHERE action = 'ssh.host_key_accepted'", [], |r| r.get(0))
            })
            .unwrap();
        assert_eq!(audited, 1);
    }
}
