use std::sync::Arc;

use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use super::hostkeys::{HostKeyAlert, HostKeyError, HostKeys};
use super::keys::generate_ed25519;
use super::quote::{join, quote};

/// A small deterministic generator, so a failure can be replayed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

const HOSTILE: &[&str] = &[
    "'",
    "\"",
    "$(id)",
    "`id`",
    "$HOME",
    "\n",
    "*",
    "?",
    " ",
    "\t",
    ";",
    "|",
    "&",
    "\\",
    "!",
    "#",
    "~",
    "{a,b}",
    "-",
    "--",
    "é",
    "\u{1f511}",
    "%s",
    "a",
];

mod quote {
    use super::*;

    #[test]
    fn posix_quoting_round_trips_hostile_strings() {
        let mut rng = Rng(0x5eed_1234_abcd_ef01);
        for case in 0..300 {
            let n = 1 + (rng.next() % 5) as usize;
            let args: Vec<String> = (0..n)
                .map(|_| (0..(rng.next() % 6)).map(|_| HOSTILE[(rng.next() % HOSTILE.len() as u64) as usize]).collect())
                .collect();
            let command = format!("printf '%s\\0' {}", join(&args));
            let out = std::process::Command::new("sh").args(["-c", &command]).output().unwrap();
            assert!(out.status.success(), "case {case}: {command:?}");
            let got: Vec<String> = String::from_utf8(out.stdout).unwrap().split('\0').map(str::to_string).collect();
            assert_eq!(&got[..got.len() - 1], args.as_slice(), "case {case}: {command:?}");
        }
        assert_eq!(quote("it's"), "'it'\\''s'");
        assert_eq!(quote(""), "''");
    }
}

mod hostkeys {
    use super::*;

    fn db(name: &str) -> Arc<Db> {
        let dir = std::env::temp_dir().join(format!("rackhand-hostkeys-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(Db::open(&dir.join("hub.db")).unwrap())
    }

    async fn machine(db: &Db) {
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
                        ("name", Value::Text("web".into())),
                        ("kind", Value::Text("linux".into())),
                    ]),
                ),
            ]))
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn changed_key_blocks_and_raises_critical() {
        let db = db("changed");
        machine(&db).await;
        let (keys, mut alerts) = HostKeys::new(db.clone());
        let (_, pinned) = generate_ed25519("host").unwrap();
        let (_, other) = generate_ed25519("host").unwrap();
        assert_eq!(keys.check("m1", &pinned), Err(HostKeyError::NotPinned), "only keys from the join are trusted");
        keys.pin_from_join("m1", std::slice::from_ref(&pinned), 1_000).await.unwrap();
        assert_eq!(keys.check("m1", &pinned), Ok(()));
        assert_eq!(keys.check("m1", &other), Err(HostKeyError::Changed), "a different key is refused");
        let alert = alerts.try_recv().unwrap();
        assert_eq!(alert.kind(), "ssh.host_key_changed");
        assert_eq!(alert.severity(), "critical");
        let HostKeyAlert::Changed { machine_id, offered, .. } = &alert;
        assert_eq!(machine_id, "m1");
        assert_eq!(offered, &super::super::hostkeys::fingerprint(&other).unwrap());
        // Still refused until an admin accepts the offered key; then the old one is the stranger.
        assert_eq!(keys.check("m1", &other), Err(HostKeyError::Changed));
        // Accepting names the fingerprint the admin was shown; any other is refused.
        assert!(!keys.accept_offered("m1", "SHA256:not-the-offered-one", "admin", 2_000).await.unwrap());
        assert_eq!(keys.check("m1", &other), Err(HostKeyError::Changed));
        let offered = super::super::hostkeys::fingerprint(&other).unwrap();
        assert!(keys.accept_offered("m1", &offered, "admin", 2_000).await.unwrap());
        assert_eq!(keys.check("m1", &other), Ok(()));
        assert_eq!(keys.check("m1", &pinned), Err(HostKeyError::Changed));
        let (reloaded, _) = HostKeys::new(db.clone());
        assert_eq!(reloaded.check("m1", &other), Ok(()), "pins are stored");
    }
}

/// The hub's SSH test after a managed machine's first report (7.3.12, AC35).
mod enroll_test {
    use std::net::SocketAddr;
    use std::sync::Mutex;

    use super::super::client::{Output, SshError};
    use super::super::enroll_test::{BoxFuture, EnrollTest, Login, Outcome};
    use super::super::keys::Identity;
    use super::*;

    /// Answers each login from a script: per account, the result its command gets.
    #[derive(Default)]
    struct Scripted {
        calls: Mutex<Vec<(SocketAddr, String, &'static str, String)>>,
        refuse: Option<Identity>,
        exit: Option<(Identity, u32)>,
    }

    impl Login for Scripted {
        fn run<'a>(
            &'a self,
            addr: SocketAddr,
            machine_id: &'a str,
            id: Identity,
            command: &'a str,
        ) -> BoxFuture<'a, Result<Output, SshError>> {
            self.calls.lock().unwrap().push((addr, machine_id.into(), id.user(), command.into()));
            let result = if self.refuse == Some(id) {
                Err(SshError::AuthRefused(id.user()))
            } else {
                let code = self.exit.filter(|(i, _)| *i == id).map_or(0, |(_, c)| c);
                Ok(Output {
                    exit_code: Some(code),
                    stdout: Vec::new(),
                    stderr: b"sudo: a password is required\n".to_vec(),
                })
            };
            Box::pin(async move { result })
        }
    }

    impl Scripted {
        fn calls(&self) -> Vec<(String, &'static str, String)> {
            self.calls.lock().unwrap().iter().map(|(a, _, u, c)| (a.to_string(), *u, c.clone())).collect()
        }
    }

    fn db(name: &str) -> Arc<Db> {
        let dir = std::env::temp_dir().join(format!("rackhand-enrolltest-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(Db::open(&dir.join("hub.db")).unwrap())
    }

    async fn machine(db: &Db, id: &str, access: &str, roles: &str, address: Option<&str>) {
        machine_in(db, id, access, roles, address, "enrolled").await;
    }

    async fn machine_in(db: &Db, id: &str, access: &str, roles: &str, address: Option<&str>, state: &str) {
        let mut row = Row::from([
            ("id", Value::Text(id.into())),
            ("site_id", Value::Text("s".into())),
            ("name", Value::Text(id.into())),
            ("kind", Value::Text("linux".into())),
            ("access", Value::Text(access.into())),
            ("roles", Value::Text(roles.into())),
            ("state", Value::Text(state.into())),
        ]);
        if let Some(a) = address {
            row.insert("address", Value::Text(a.into()));
        }
        let site = Row::from([
            ("id", Value::Text("s".into())),
            ("name", Value::Text("home".into())),
            ("timezone", Value::Text("UTC".into())),
        ]);
        let mut writes = vec![RowWrite::insert("machines", row)];
        let has_site = db.readers().with(|c| c.query_row("SELECT count(*) FROM sites", [], |r| r.get::<_, i64>(0)));
        if has_site.unwrap() == 0 {
            writes.insert(0, RowWrite::insert("sites", site));
        }
        db.writer().send(WriteCmd::Batch(writes)).await.unwrap();
    }

    async fn event(db: &Db, machine: &str, kind: &str, at_ms: i64) {
        let row = Row::from([
            ("id", Value::Text(format!("{machine}-{kind}-{at_ms}"))),
            ("machine_id", Value::Text(machine.into())),
            ("at_ms", Value::Integer(at_ms)),
            ("kind", Value::Text(kind.into())),
            ("severity", Value::Text("info".into())),
        ]);
        db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("events", row)])).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn logs_in_as_both_accounts_unless_role_hub() {
        let db = db("both");
        machine(&db, "web1", "managed", "[]", Some("192.0.2.5")).await;
        machine(&db, "hub1", "managed", "[\"hub\"]", Some("192.0.2.6")).await;
        let login = Arc::new(Scripted::default());
        let test = EnrollTest::new(db.clone(), login.clone());
        assert_eq!(test.run("web1").await, Some(Outcome::Passed));
        assert_eq!(
            login.calls(),
            [
                ("192.0.2.5:22".to_string(), "rackhand", "true".to_string()),
                ("192.0.2.5:22".to_string(), "rackhand-ai", "sudo -n true".to_string()),
            ]
        );
        login.calls.lock().unwrap().clear();
        assert_eq!(test.run("hub1").await, Some(Outcome::Passed));
        assert_eq!(
            login.calls(),
            [("192.0.2.6:22".to_string(), "rackhand", "true".to_string())],
            "no assistant on hub"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failure_names_the_account() {
        let db = db("fail");
        machine(&db, "web1", "managed", "[]", Some("192.0.2.5")).await;
        machine(&db, "web2", "managed", "[]", None).await;
        machine(&db, "mon1", "monitor", "[]", Some("192.0.2.7")).await;

        let sudo = Arc::new(Scripted { exit: Some((Identity::Assistant, 1)), ..Scripted::default() });
        let got = EnrollTest::new(db.clone(), sudo).run("web1").await;
        let Some(Outcome::Failed { account, reason }) = got else { panic!("{got:?}") };
        assert_eq!(account, "rackhand-ai");
        assert!(reason.contains("sudo -n true") && reason.contains("exit 1"), "{reason}");
        assert!(reason.contains("a password is required"), "the command's error is kept: {reason}");

        let refused = Arc::new(Scripted { refuse: Some(Identity::Automation), ..Scripted::default() });
        let got = EnrollTest::new(db.clone(), refused.clone()).run("web1").await;
        let Some(Outcome::Failed { account, reason }) = got else { panic!("{got:?}") };
        assert_eq!(account, "rackhand");
        assert!(reason.contains("refused"), "{reason}");
        assert_eq!(refused.calls().len(), 1, "the assistant isn't tried after the automation account failed");

        let login = Arc::new(Scripted::default());
        let test = EnrollTest::new(db.clone(), login.clone());
        let got = test.run("web2").await;
        let Some(Outcome::Failed { account, reason }) = got else { panic!("{got:?}") };
        assert_eq!((account, reason.contains("no address")), ("rackhand", true), "{reason}");
        assert_eq!(test.run("mon1").await, None, "no SSH test for a monitor machine");
        assert!(login.calls().is_empty());
    }

    /// D84: a managed machine that joined is `pending` until the hub's SSH test passes; the pass enrolls it, a failure
    /// leaves it pending, and nothing else is moved.
    #[tokio::test(flavor = "multi_thread")]
    async fn pending_machine_is_tested_and_enrolled_by_a_pass() {
        let db = db("pending");
        machine_in(&db, "web1", "managed", "[]", Some("192.0.2.5"), "pending").await;
        machine_in(&db, "web2", "managed", "[]", Some("192.0.2.6"), "revoked").await;
        let state = |id: &str| -> String {
            db.readers().with(|c| c.query_row("SELECT state FROM machines WHERE id = ?1", [id], |r| r.get(0))).unwrap()
        };
        let refused = Arc::new(Scripted { refuse: Some(Identity::Automation), ..Scripted::default() });
        let failing = EnrollTest::new(db.clone(), refused);
        assert!(failing.due("web1"), "a joined pending machine is tested");
        assert!(matches!(failing.run("web1").await, Some(Outcome::Failed { .. })));
        assert_eq!(state("web1"), "pending", "a failed test leaves it pending");

        let test = EnrollTest::new(db.clone(), Arc::new(Scripted::default()));
        assert_eq!(test.run("web1").await, Some(Outcome::Passed));
        test.passed("web1").await.unwrap();
        assert_eq!(state("web1"), "enrolled", "the pass enrolls it");
        test.passed("web1").await.unwrap();
        assert_eq!(state("web1"), "enrolled", "again changes nothing");
        assert!(!test.due("web2") && test.run("web2").await.is_none(), "a revoked machine isn't tested");
        test.passed("web2").await.unwrap();
        assert_eq!(state("web2"), "revoked", "a revoked machine stays revoked");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn due_until_it_passes_and_again_after_a_join() {
        let db = db("due");
        machine(&db, "web1", "managed", "[]", Some("192.0.2.5")).await;
        machine(&db, "mon1", "monitor", "[]", Some("192.0.2.7")).await;
        let test = EnrollTest::new(db.clone(), Arc::new(Scripted::default()));
        assert!(test.due("web1"), "never tested");
        assert!(!test.due("mon1"), "monitor machines aren't tested");
        assert!(!test.due("nope"), "unknown machine");
        event(&db, "web1", "machine.ssh_test_failed", 10).await;
        assert!(test.due("web1"), "the last test failed, so the next report tries again");
        event(&db, "web1", "machine.ssh_test_passed", 20).await;
        assert!(!test.due("web1"), "passed");
        test.joined("web1");
        assert!(test.due("web1"), "a new join (a reinstall or a level change) tests again");
        assert!(!test.due("web1"), "once per join");
    }
}
