//! Actions and the Executor against a managed machine (7.3.7, FR-12, AC12, AC50, E54, E55): runbooks become a signed
//! command list, the wrapper installs it, and jobs run over SSH, plain and detached.

mod executor {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ed25519_dalek::SigningKey;
    use rackhand_hub::actions::{Actions, ActionsError, JobKind, StartJob};
    use rackhand_hub::audit::Audit;
    use rackhand_hub::bus::{Bus, BusEvent, Delivery, JobOutcome, Subscription};
    use rackhand_hub::executor::Executor;
    use rackhand_hub::executor::commands::signed_command_list;
    use rackhand_hub::library::items::{Kind, Library};
    use rackhand_hub::ssh::client::TRUNCATED;
    use rackhand_hub::ssh::hostkeys::HostKeys;
    use rackhand_hub::ssh::keys::{Identity, authorized_keys_line, load_or_create};
    use rackhand_hub::vault::Vault;
    use rackhand_hub::vault::master_key::MasterKey;
    use rackhand_runbook::runbook::Runbook;
    use rackhand_store::{Db, Row, RowWrite, WriteCmd};
    use rusqlite::types::Value;
    use russh::keys::PublicKey;

    use crate::support::{Container, binary};

    const WRAPPER: &str = "/usr/local/lib/rackhand/run";

    const PLAIN: &str = r#"name = "plain"
description = "Plain steps"
identity = "automation"
risk = "low"
autonomy = 1
[params.mode]
type = "string"
pattern = "sleep|flood"
[[step]]
id = "work"
kind = "ssh"
cmd = ["sh", "-c", "if [ \"$0\" = sleep ]; then sleep 600; else head -c 2000000 /dev/zero | tr '\\000' a; echo end >&2; exit 3; fi", "{{mode}}"]
timeout = "5s"
"#;

    fn slow(timeout: &str) -> String {
        format!(
            r#"name = "slow"
description = "A long command, detached"
identity = "automation"
risk = "low"
autonomy = 1
[params.n]
type = "int"
pattern = "[0-9]{{1,2}}"
[[step]]
id = "echo"
kind = "ssh"
cmd = ["sudo", "{WRAPPER}", "/usr/local/bin/slow-echo", "{{{{n}}}}"]
detached = true
timeout = "{timeout}"
"#
        )
    }

    struct Lab {
        db: Arc<Db>,
        machine: Container,
        actions: Actions,
        events: Subscription,
    }

    fn sh(c: &Container, script: &str) {
        let out = c.root(script);
        assert!(out.status.success(), "{script}: {}", String::from_utf8_lossy(&out.stderr));
    }

    async fn lab(name: &str, slow_timeout: &str, lock_wait: Duration) -> Lab {
        let dir = std::env::temp_dir().join(format!("rackhand-it-exec-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
        let vault = Arc::new(Vault::new(MasterKey::from_bytes([5u8; 32]), db.clone()));
        let machine = Container::start_systemd("executor");
        let (ip, gateway) = machine.ip_and_gateway();
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
                        ("address", Value::Text(ip.clone())),
                        ("state", Value::Text("enrolled".into())),
                    ]),
                ),
            ]))
            .await
            .unwrap();
        // The hub's keys, as the installer puts them (T44).
        for id in [Identity::Automation, Identity::Assistant] {
            let key = load_or_create(&vault, id).await.unwrap();
            let line = authorized_keys_line(key.public_key(), std::slice::from_ref(&gateway)).unwrap();
            let (user, path) = (id.user(), format!("/home/{}/.ssh/authorized_keys", id.user()));
            let w = machine.exec(
                None,
                &["sh", "-c", &format!("cat > {path} && chown {user}:{user} {path} && chmod 600 {path}")],
                Some(line.as_bytes()),
            );
            assert!(w.status.success());
        }
        // The wrapper, the pinned hub key, and the command list from the runbooks, signed and installed by the wrapper.
        machine.copy_in(&binary("rackhand-probe", "rackhand-probe"), WRAPPER);
        sh(&machine, &format!("chown root:root {WRAPPER} && chmod 0755 {WRAPPER}"));
        let node = SigningKey::from_bytes(&[7u8; 32]);
        let hex: String = node.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        sh(&machine, &format!("printf '[hub]\\nid = \"{hex}\"\\n' > /etc/rackhand-probe/probe.toml"));
        let audit = Audit::new(db.writer());
        let (library, _) = Library::new(db.clone(), audit.clone());
        let slow = slow(slow_timeout);
        library.save(Kind::Runbook, "plain", PLAIN, "admin", 1).await.unwrap();
        library.save(Kind::Runbook, "slow", &slow, "admin", 1).await.unwrap();
        let runbooks = [Runbook::parse(PLAIN).unwrap(), Runbook::parse(&slow).unwrap()];
        let now = rackhand_store::ids::now_ms();
        let payload = signed_command_list(&node, &runbooks, 1, now, 3_600_000);
        let install = machine.exec(Some("rackhand"), &["sudo", "-n", WRAPPER, "install-commands"], Some(&payload));
        assert!(install.status.success(), "install-commands: {}", String::from_utf8_lossy(&install.stderr));
        // The host key from the join (T35), pinned.
        let (host_keys, _alerts) = HostKeys::new(db.clone());
        let host =
            String::from_utf8_lossy(&machine.root("cat /etc/ssh/ssh_host_ed25519_key.pub").stdout).trim().to_string();
        host_keys.pin_from_join("m1", &[PublicKey::from_openssh(&host).unwrap()], 1).await.unwrap();
        wait_listening(&format!("{ip}:22")).await;
        let bus = Bus::new();
        let events = bus.subscribe("test");
        let executor = Executor::new(vault, host_keys).with_poll(Duration::from_millis(500));
        let actions = Actions::new(db.clone(), audit, bus, Arc::new(executor)).with_lock_wait(lock_wait);
        Lab { db, machine, actions, events }
    }

    async fn wait_listening(addr: &str) {
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("sshd never listened on {addr}");
    }

    fn start(name: &str, param: (&str, &str)) -> StartJob {
        StartJob {
            kind: JobKind::Runbook,
            name: name.into(),
            rev: None,
            machine_id: "m1".into(),
            params: BTreeMap::from([(param.0.to_string(), param.1.to_string())]),
            requested_by: "user:admin".into(),
            incident_id: None,
            approval_id: None,
        }
    }

    struct StepRow {
        state: String,
        command: Option<String>,
        exit_code: Option<i64>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

    fn step(db: &Db, job: &str) -> StepRow {
        db.readers()
            .with(|c| {
                c.query_row(
                    "SELECT state, command, exit_code, stdout, stderr FROM job_steps WHERE job_id = ?1",
                    [job],
                    |r| {
                        Ok(StepRow {
                            state: r.get(0)?,
                            command: r.get(1)?,
                            exit_code: r.get(2)?,
                            stdout: r.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
                            stderr: r.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default(),
                        })
                    },
                )
            })
            .unwrap()
    }

    fn job_state(db: &Db, job: &str) -> String {
        db.readers().with(|c| c.query_row("SELECT state FROM jobs WHERE id = ?1", [job], |r| r.get(0))).unwrap()
    }

    async fn finished(events: &mut Subscription) -> JobOutcome {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), events.recv()).await.expect("JobFinished") {
                Some(Delivery::Event(BusEvent::JobFinished { outcome, .. })) => return outcome,
                Some(_) => {}
                None => panic!("bus closed"),
            }
        }
    }

    /// Waits until the step row reaches a final state.
    async fn step_done(db: &Db, job: &str, limit: Duration) -> StepRow {
        let start = Instant::now();
        loop {
            let s = step(db, job);
            if s.state != "running" || start.elapsed() > limit {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn step_timeout_fails_with_timeout() {
        let mut lab = lab("timeout", "60s", Duration::from_secs(5)).await;
        let started = Instant::now();
        let result = lab.actions.run(start("plain", ("mode", "sleep"))).await.unwrap();
        assert_eq!((result.outcome, result.reason.as_deref()), (JobOutcome::TimedOut, Some("timeout")));
        assert!(started.elapsed() < Duration::from_secs(30), "{:?}", started.elapsed());
        assert_eq!(step(&lab.db, &result.job_id).state, "timed_out");
        assert_eq!(job_state(&lab.db, &result.job_id), "timed_out");
        assert_eq!(finished(&mut lab.events).await, JobOutcome::TimedOut);
        // A plain step is stopped on the machine too, not left running after the machine is free.
        let start = Instant::now();
        while lab.machine.root("pgrep -f '[s]leep 600'").status.success() {
            assert!(start.elapsed() < Duration::from_secs(15), "the command still runs on the machine");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn output_over_1mb_cut_with_marker_in_job_log() {
        let lab = lab("cap", "60s", Duration::from_secs(5)).await;
        let result = lab.actions.run(start("plain", ("mode", "flood"))).await.unwrap();
        assert_eq!((result.outcome, result.reason.as_deref()), (JobOutcome::Failed, Some("exit_code 3")));
        let s = step(&lab.db, &result.job_id);
        assert_eq!((s.state.as_str(), s.exit_code), ("failed", Some(3)));
        assert!(s.command.as_deref().unwrap().starts_with("sh -c "), "{:?}", s.command);
        assert!(s.command.as_deref().unwrap().ends_with(" flood"), "{:?}", s.command);
        assert_eq!(s.stdout.len(), 1 << 20, "cut to the row limit");
        assert!(s.stdout.ends_with(TRUNCATED.as_bytes()));
        assert!(s.stdout[..1000].iter().all(|b| *b == b'a'));
        assert_eq!(String::from_utf8_lossy(&s.stderr).trim(), "end");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn detached_step_timeout_not_killed_machine_locked() {
        let mut lab = lab("detached-timeout", "3s", Duration::from_secs(1)).await;
        let result = lab.actions.run(start("slow", ("n", "8"))).await.unwrap();
        assert_eq!((result.outcome, result.reason.as_deref()), (JobOutcome::TimedOut, Some("timeout")));
        // JobFinished(TimedOut) is what Incidents opens its incident from (T32, T57).
        assert_eq!(finished(&mut lab.events).await, JobOutcome::TimedOut);
        assert_eq!(job_state(&lab.db, &result.job_id), "timed_out");
        // Not killed: the machine stays locked while the unit runs.
        let busy = lab.actions.run(start("plain", ("mode", "flood"))).await.unwrap();
        assert_eq!((busy.outcome, busy.reason.as_deref()), (JobOutcome::Failed, Some("machine_busy")));
        let s = step_done(&lab.db, &result.job_id, Duration::from_secs(30)).await;
        assert_eq!((s.state.as_str(), s.exit_code), ("succeeded", Some(0)));
        let out = String::from_utf8_lossy(&s.stdout);
        assert!(out.contains("line 8\n") && out.ends_with("done\n"), "{out}");
        // Recorded: the machine is free again, and the job files are cleaned up.
        let next = lab.actions.run(start("plain", ("mode", "flood"))).await.unwrap();
        assert_eq!(next.outcome, JobOutcome::Failed, "ran (and failed with its exit code)");
        let left = lab.machine.root("ls /var/lib/rackhand-run/jobs/ 2>/dev/null | wc -l");
        assert_eq!(String::from_utf8_lossy(&left.stdout).trim(), "0");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ssh_cut_during_detached_step_recovers() {
        let lab = lab("cut", "60s", Duration::from_secs(5)).await;
        let job = tokio::spawn({
            let a = lab.actions.clone();
            async move { a.run(start("slow", ("n", "8"))).await }
        });
        // Once the step runs, take SSH away (sessions too) for a few seconds. `[r]` keeps pkill off its own shell.
        tokio::time::sleep(Duration::from_secs(2)).await;
        sh(&lab.machine, "systemctl stop ssh && (pkill -9 -f 'sshd: [r]ackhand' || true)");
        tokio::time::sleep(Duration::from_secs(4)).await;
        sh(&lab.machine, "systemctl start ssh");
        let result = job.await.unwrap().unwrap();
        assert_eq!(result.outcome, JobOutcome::Succeeded, "{:?}", result.reason);
        let s = step(&lab.db, &result.job_id);
        assert_eq!((s.state.as_str(), s.exit_code), ("succeeded", Some(0)));
        let out = String::from_utf8_lossy(&s.stdout);
        for i in 1..=8 {
            assert!(out.contains(&format!("line {i}\n")), "{out}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn second_job_of_any_kind_waits_then_machine_busy() {
        let lab = lab("busy", "60s", Duration::from_secs(3)).await;
        let runbook = tokio::spawn({
            let a = lab.actions.clone();
            async move { a.run(start("slow", ("n", "8"))).await }
        });
        tokio::time::sleep(Duration::from_secs(1)).await;
        // An assistant exec on the same machine waits for the lock, then fails machine_busy.
        let assistant = lab.actions.open_assistant_job("service-down", "user:admin", None).await.unwrap();
        let waited = Instant::now();
        let busy = lab.actions.exec(&assistant, "m1", "id -un", Duration::from_secs(30)).await;
        assert_eq!(busy, Err(ActionsError::MachineBusy));
        assert!(waited.elapsed() >= Duration::from_secs(3), "{:?}", waited.elapsed());
        assert_eq!(runbook.await.unwrap().unwrap().outcome, JobOutcome::Succeeded);
        // Free again: the exec runs as the assistant identity.
        let ran = lab.actions.exec(&assistant, "m1", "id -un", Duration::from_secs(30)).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&ran.stdout).trim(), "rackhand-ai");
    }
}
