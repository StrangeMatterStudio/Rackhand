//! Actions and the Executor against a managed machine (7.3.7, FR-12, AC12, AC50, E54, E55): runbooks become a signed
//! command list, the wrapper installs it, and jobs run over SSH, plain and detached.

mod executor {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ed25519_dalek::SigningKey;
    use rackhand_hub::actions::runner::StepOutcome;
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

    use crate::support::{Container, container_binary};

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

    /// A root command through the wrapper that outlives its timeout, as real runbooks send it.
    const WRAPPED: &str = r#"name = "wrapped"
description = "A long root command"
identity = "automation"
risk = "low"
autonomy = 1
[[step]]
id = "hang"
kind = "ssh"
cmd = ["sudo", "/usr/local/lib/rackhand/run", "/bin/sleep", "601"]
timeout = "5s"
"#;

    /// A reboot if the machine asks for one; `wait` is how long it may take to come back.
    const REBOOT: &str = r#"name = "reboot-now"
description = "Reboot if required"
identity = "automation"
risk = "normal"
autonomy = 2
[[step]]
id = "reboot"
kind = "reboot_if_required"
timeout = "60s"
"#;

    /// The machine's policy and whether it is back, as a test sets them.
    #[derive(Debug, Default)]
    pub(super) struct Facts {
        auto: std::sync::atomic::AtomicBool,
        back: std::sync::atomic::AtomicBool,
        reporting: std::sync::atomic::AtomicBool,
        hypervisor: std::sync::atomic::AtomicBool,
        approved: std::sync::atomic::AtomicBool,
    }

    impl rackhand_hub::executor::RebootFacts for Facts {
        fn auto_reboot(&self, _machine: &str) -> bool {
            self.auto.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn approved(&self, _job: &str) -> bool {
            self.approved.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn compares_kernels(&self, _machine: &str) -> bool {
            self.hypervisor.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn back_since(&self, _machine: &str, _since_ms: i64) -> bool {
            self.back.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn reported_since(&self, _machine: &str, _since_ms: i64) -> bool {
            self.reporting.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

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

    pub(super) struct Lab {
        pub(super) db: Arc<Db>,
        pub(super) machine: Container,
        pub(super) actions: Actions,
        pub(super) events: Subscription,
        facts: Arc<Facts>,
    }

    pub(super) fn sh(c: &Container, script: &str) {
        let out = c.root(script);
        assert!(out.status.success(), "{script}: {}", String::from_utf8_lossy(&out.stderr));
    }

    pub(super) async fn lab(name: &str, slow_timeout: &str, lock_wait: Duration) -> Lab {
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
        machine.copy_in(&container_binary("rackhand-probe", "rackhand-probe"), WRAPPER);
        sh(&machine, &format!("chown root:root {WRAPPER} && chmod 0755 {WRAPPER}"));
        let node = SigningKey::from_bytes(&[7u8; 32]);
        let hex: String = node.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        sh(&machine, &format!("printf '[hub]\\nid = \"{hex}\"\\n' > /etc/rackhand-probe/probe.toml"));
        let audit = Audit::new(db.writer());
        let (library, _) = Library::new(db.clone(), audit.clone());
        let slow = slow(slow_timeout);
        library.save(Kind::Runbook, "plain", PLAIN, "admin", 1).await.unwrap();
        library.save(Kind::Runbook, "slow", &slow, "admin", 1).await.unwrap();
        library.save(Kind::Runbook, "wrapped", WRAPPED, "admin", 1).await.unwrap();
        library.save(Kind::Runbook, "reboot-now", REBOOT, "admin", 1).await.unwrap();
        let runbooks = [PLAIN, slow.as_str(), WRAPPED, REBOOT].map(|r| Runbook::parse(r).unwrap());
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
        let facts = Arc::new(Facts::default());
        let executor = Executor::new(vault, host_keys)
            .with_poll(Duration::from_millis(500))
            .with_reboot(facts.clone(), Duration::from_secs(6));
        let actions = Actions::new(db.clone(), audit, bus, Arc::new(executor)).with_lock_wait(lock_wait);
        Lab { db, machine, actions, events, facts }
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
    async fn wrapped_step_timeout_stops_root_command() {
        let lab = lab("wrapped-timeout", "60s", Duration::from_secs(5)).await;
        let job = StartJob { params: BTreeMap::new(), ..start("wrapped", ("unused", "")) };
        let result = lab.actions.run(job).await.unwrap();
        assert_eq!((result.outcome, result.reason.as_deref()), (JobOutcome::TimedOut, Some("timeout")));
        // The root command (sudo, the wrapper, then sleep) is stopped too (D33).
        let start = Instant::now();
        while lab.machine.root("pgrep -f '[s]leep 601'").status.success() {
            assert!(start.elapsed() < Duration::from_secs(15), "the root command still runs on the machine");
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
        assert_eq!((s.state.as_str(), s.exit_code), ("succeeded", Some(0)), "{}", post_mortem(&lab.machine));
        let out = String::from_utf8_lossy(&s.stdout);
        assert!(out.contains("line 8\n") && out.ends_with("done\n"), "{out}");
        // Recorded: the machine is free again, and the job files are cleaned up.
        let next = lab.actions.run(start("plain", ("mode", "flood"))).await.unwrap();
        assert_eq!(next.outcome, JobOutcome::Failed, "ran (and failed with its exit code)");
        let left = lab.machine.root("ls /var/lib/rackhand-run/jobs/ 2>/dev/null | wc -l");
        assert_eq!(String::from_utf8_lossy(&left.stdout).trim(), "0");
    }

    /// What the machine says about its detached jobs, for a failure's message: the job files (the start path returns
    /// before they are cleaned up), each `exit`, whether the command still runs, and the journal's end.
    fn post_mortem(machine: &Container) -> String {
        let out = machine.root(
            "ls -la /var/lib/rackhand-run/jobs/*/* 2>&1 | head -30;              for f in /var/lib/rackhand-run/jobs/*/*/exit; do [ -e \"$f\" ] && echo \"$f: $(cat $f)\"; done;              pgrep -af '[s]low-echo' || echo 'slow-echo not running'; journalctl --no-pager -n 40 2>&1 | tail -40",
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ssh_cut_during_detached_step_recovers() {
        let lab = lab("cut", "60s", Duration::from_secs(5)).await;
        let job = tokio::spawn({
            let a = lab.actions.clone();
            async move { a.run(start("slow", ("n", "8"))).await }
        });
        // Once the step runs on the machine (not after a guess: starting it over SSH takes longer on a loaded host),
        // take SSH away (sessions too) for a few seconds. `[r]`/`[s]` keep pkill and pgrep off their own shell.
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while !lab.machine.root("pgrep -f '[s]low-echo 8'").status.success() {
            assert!(std::time::Instant::now() < deadline, "the detached step never started");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        sh(&lab.machine, "systemctl stop ssh && (pkill -9 -f 'sshd: [r]ackhand' || true)");
        tokio::time::sleep(Duration::from_secs(4)).await;
        sh(&lab.machine, "systemctl start ssh");
        let result = job.await.unwrap().unwrap();
        if result.outcome != JobOutcome::Succeeded {
            panic!(
                "{:?} {:?}
{}",
                result.outcome,
                result.reason,
                post_mortem(&lab.machine)
            );
        }
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

    /// Owner review (B4): an assistant `exec` that passes its timeout is stopped on the machine, as a runbook step is
    /// (D33), rather than left running after the hub gave up on it; its step records the line that ran.
    #[tokio::test(flavor = "multi_thread")]
    async fn exec_timeout_stops_command_on_machine() {
        let lab = lab("exec-timeout", "60s", Duration::from_secs(3)).await;
        let assistant = lab.actions.open_assistant_job("service-down", "user:admin", None).await.unwrap();
        let ran = lab.actions.exec(&assistant, "m1", "sleep 602; echo late", Duration::from_secs(3)).await.unwrap();
        assert_eq!(ran.outcome, StepOutcome::Failed("timeout".into()), "{ran:?}");
        let start = Instant::now();
        while lab.machine.root("pgrep -f '[s]leep 602'").status.success() {
            assert!(start.elapsed() < Duration::from_secs(15), "the exec still runs on the machine");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        // An exec that finishes in time is unchanged: its output and exit code.
        let ok =
            lab.actions.exec(&assistant, "m1", "echo \"$(id -un)\"; exit 4", Duration::from_secs(30)).await.unwrap();
        assert_eq!((String::from_utf8_lossy(&ok.stdout).trim(), ok.exit_code), ("rackhand-ai", Some(4)));
        assert!(ok.command.as_deref().is_some_and(|c| c.starts_with("timeout -k 5 30 sh -c ")), "{:?}", ok.command);
    }

    /// 7.8.7 and 7.5.3: the step reboots only when the machine asks for it (`/run/reboot-required`) and its policy has
    /// `auto_reboot`, through the wrapper, and waits until the machine reports again; a machine that doesn't come back
    /// fails `no_report_after_reboot` (E11, D45). `/sbin/reboot` is a stand-in: a container can't reboot.
    #[tokio::test(flavor = "multi_thread")]
    async fn reboot_if_required_reboots_only_when_flagged() {
        use std::sync::atomic::Ordering::SeqCst;
        let lab = lab("reboot", "60s", Duration::from_secs(5)).await;
        sh(
            &lab.machine,
            "rm -f /sbin/reboot; printf '#!/bin/sh\\nid -un >> /root/rebooted\\n' > /sbin/reboot; chmod 755 /sbin/reboot",
        );
        let reboots = |lab: &Lab| {
            let out = lab.machine.root("cat /root/rebooted 2>/dev/null | wc -l; head -1 /root/rebooted 2>/dev/null");
            String::from_utf8_lossy(&out.stdout).split_whitespace().map(str::to_string).collect::<Vec<_>>()
        };
        let run = |lab: &Lab| {
            let a = lab.actions.clone();
            async move { a.run(StartJob { params: BTreeMap::new(), ..start("reboot-now", ("unused", "")) }).await.unwrap() }
        };
        let said = |lab: &Lab, job: &str| -> serde_json::Value {
            serde_json::from_slice(&step(&lab.db, job).stdout).unwrap_or_default()
        };
        lab.facts.auto.store(true, SeqCst);
        lab.facts.back.store(true, SeqCst);
        let none = run(&lab).await;
        assert_eq!(none.outcome, JobOutcome::Succeeded, "{none:?}");
        assert_eq!(said(&lab, &none.job_id)["reboot"], "not_required");
        assert_eq!(reboots(&lab), ["0"]);

        sh(&lab.machine, "touch /run/reboot-required");
        lab.facts.auto.store(false, SeqCst);
        let held = run(&lab).await;
        assert_eq!(held.outcome, JobOutcome::Succeeded, "{held:?}");
        assert_eq!(said(&lab, &held.job_id)["reboot"], "required_not_allowed");
        assert_eq!(reboots(&lab), ["0"], "the policy doesn't reboot");

        lab.facts.auto.store(true, SeqCst);
        let done = run(&lab).await;
        assert_eq!(done.outcome, JobOutcome::Succeeded, "{done:?}");
        assert_eq!(said(&lab, &done.job_id)["reboot"], "done");
        assert_eq!(reboots(&lab), ["1", "root"], "once, as root through the wrapper");

        lab.facts.back.store(false, SeqCst);
        let lost = run(&lab).await;
        assert_eq!((lost.outcome, lost.reason.as_deref()), (JobOutcome::Failed, Some("no_report_after_reboot")));
        assert_eq!(said(&lab, &lost.job_id)["reboot"], "done", "the job log says it rebooted");

        // a machine that goes on reporting hasn't rebooted: not the silence that rolls a guest back
        lab.facts.reporting.store(true, SeqCst);
        let up = run(&lab).await;
        assert_eq!((up.outcome, up.reason.as_deref()), (JobOutcome::Failed, Some("did_not_reboot")));
    }

    /// 7.5.3 step 7: a hypervisor sets no flag, so it wants a reboot when its newest installed kernel isn't the one it
    /// runs and none is pinned; only an approved job reboots it (E13). Asked in a real shell on the machine.
    #[tokio::test(flavor = "multi_thread")]
    async fn hypervisor_rebooted_for_a_newer_kernel_only_when_approved() {
        use std::sync::atomic::Ordering::SeqCst;
        let lab = lab("hvreboot", "60s", Duration::from_secs(5)).await;
        sh(
            &lab.machine,
            "rm -f /sbin/reboot; printf '#!/bin/sh\\nid -un >> /root/rebooted\\n' > /sbin/reboot; chmod 755 /sbin/reboot; \
             mkdir -p /boot /etc/kernel; rm -f /boot/vmlinuz-*",
        );
        let said = |how: &'static str| {
            let (a, db) = (lab.actions.clone(), lab.db.clone());
            async move {
                let job =
                    a.run(StartJob { params: BTreeMap::new(), ..start("reboot-now", ("unused", "")) }).await.unwrap();
                assert_eq!(job.outcome, JobOutcome::Succeeded, "{how}: {job:?}");
                let out: serde_json::Value = serde_json::from_slice(&step(&db, &job.job_id).stdout).unwrap_or_default();
                out["reboot"].as_str().unwrap_or_default().to_string()
            }
        };
        lab.facts.back.store(true, SeqCst);
        lab.facts.hypervisor.store(true, SeqCst);
        assert_eq!(said("no kernels").await, "not_required");
        sh(&lab.machine, "touch /boot/vmlinuz-$(uname -r) /boot/vmlinuz-0.0.1-1-pve");
        assert_eq!(said("the newest is running").await, "not_required");
        sh(&lab.machine, "touch /boot/vmlinuz-999.0.0-10-pve /boot/vmlinuz-999.0.0-9-pve");
        assert_eq!(said("a newer one").await, "required_not_allowed");
        sh(&lab.machine, "touch /etc/kernel/proxmox-boot-pin");
        assert_eq!(said("pinned").await, "not_required");
        sh(&lab.machine, "touch /run/reboot-required");
        assert_eq!(said("pinned and flagged").await, "required_not_allowed");
        assert!(!lab.machine.root("test -e /root/rebooted").status.success());
        lab.facts.approved.store(true, SeqCst);
        assert_eq!(said("approved").await, "done");
        assert!(lab.machine.root("test -e /root/rebooted").status.success());
        // a machine that isn't a hypervisor isn't asked about its kernels
        sh(&lab.machine, "rm -f /run/reboot-required /etc/kernel/proxmox-boot-pin");
        lab.facts.hypervisor.store(false, SeqCst);
        assert_eq!(said("an ordinary machine").await, "not_required");
    }

    /// A notifier that records messages, or fails every send.
    #[derive(Debug, Default)]
    struct Recorder {
        sent: std::sync::Mutex<Vec<String>>,
        fail: bool,
    }

    impl rackhand_hub::notify::Transport for Recorder {
        fn name(&self) -> &str {
            "recorder"
        }
        fn send<'a>(
            &'a self,
            msg: &'a rackhand_hub::notify::Message,
        ) -> rackhand_hub::notify::BoxFuture<'a, Result<(), rackhand_hub::notify::SendError>> {
            Box::pin(async move {
                if self.fail {
                    return Err(rackhand_hub::notify::SendError::Failed("refused".into()));
                }
                self.sent.lock().unwrap().push(msg.incidents[0].title.clone());
                Ok(())
            })
        }
    }

    #[derive(Debug)]
    struct Roomy;

    impl rackhand_hub::ingest::DiskSpace for Roomy {
        fn free_fraction(&self) -> f64 {
            0.5
        }
    }

    const NOTIFY: &str = r#"name = "tell"
description = "Say something"
identity = "automation"
risk = "low"
autonomy = 1
[[step]]
id = "say"
kind = "notify"
message = "Backup of web finished"
"#;

    #[tokio::test(flavor = "multi_thread")]
    async fn notify_step_sends_message() {
        use rackhand_hub::actions::runner::{StepCtx, StepOutcome, StepRunner};
        let dir = std::env::temp_dir().join(format!("rackhand-it-exec-notify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
        let vault = Arc::new(Vault::new(MasterKey::from_bytes([5u8; 32]), db.clone()));
        let (host_keys, _alerts) = HostKeys::new(db.clone());
        let runbook = Runbook::parse(NOTIFY).unwrap();
        let step = runbook.steps[0].clone();
        let ctx = StepCtx {
            job_id: "j".into(),
            machine_id: "m1".into(),
            machine_kind: "linux".into(),
            address: None,
            identity: rackhand_runbook::runbook::Identity::Automation,
            timeout: Duration::from_secs(30),
        };
        for fail in [false, true] {
            let recorder = Arc::new(Recorder { fail, ..Recorder::default() });
            let ingest = rackhand_hub::ingest::Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
            let notify = rackhand_hub::notify::Notify::new(db.clone(), ingest, vec![recorder.clone()]);
            let executor = Executor::new(vault.clone(), host_keys.clone()).with_other(Arc::new(notify));
            let result = executor.run(&ctx, &step, None).await;
            if fail {
                assert!(matches!(result.outcome, StepOutcome::Failed(_)), "a failed send fails the step");
            } else {
                assert_eq!(result.outcome, StepOutcome::Succeeded);
                assert_eq!(*recorder.sent.lock().unwrap(), ["Backup of web finished"]);
            }
        }
    }
}

mod diagnostics {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use rackhand_hub::actions::diagnostics::OUTPUT_LIMIT;
    use rackhand_store::{Row, RowWrite, WriteCmd};
    use rusqlite::types::Value;

    use super::executor::{lab, sh};

    #[tokio::test(flavor = "multi_thread")]
    async fn each_linux_diagnostic_runs_read_only() {
        let lab = lab("diagnostics", "60s", Duration::from_secs(5)).await;
        let (ip, gateway) = lab.machine.ip_and_gateway();
        // An HTTP endpoint the machine's check watches, on the host side of the container network.
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let app = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));
            axum::serve(listener, app).await.unwrap();
        });
        let url = format!("http://{gateway}:{port}/healthz");
        lab.db
            .writer()
            .send(WriteCmd::Batch(vec![RowWrite::insert(
                "checks",
                Row::from([
                    ("id", Value::Text("c1".into())),
                    ("kind", Value::Text("http".into())),
                    ("target", Value::Text(url.clone())),
                    ("interval_s", Value::Integer(60)),
                    ("machine_id", Value::Text("m1".into())),
                ]),
            )]))
            .await
            .unwrap();
        sh(&lab.machine, "touch /tmp/before-diagnostics && sleep 1");
        let calls: Vec<(&str, Vec<(&str, String)>)> = vec![
            ("journal", vec![("unit", "ssh.service".into()), ("since", "today".into()), ("lines", "50".into())]),
            ("failed_units", vec![]),
            ("service_status", vec![("name", "ssh".into())]),
            ("docker_ps", vec![]),
            ("compose_ps", vec![]),
            ("docker_logs", vec![("container", "web".into()), ("lines", "100".into())]),
            ("df", vec![]),
            ("mounts", vec![]),
            ("du_top", vec![("path", "/var/lib".into()), ("depth", "1".into())]),
            ("free", vec![]),
            ("uptime", vec![]),
            ("top_processes", vec![]),
            ("ss_listen", vec![]),
            ("ss_established", vec![]),
            ("dmesg_tail", vec![]),
            ("updates_pending", vec![]),
            ("last_logins", vec![]),
            ("ping", vec![("target", ip.clone())]),
            ("http_head", vec![("url", url.clone())]),
        ];
        let names: Vec<&str> = calls.iter().map(|(n, _)| *n).collect();
        let all: Vec<&str> = rackhand_runbook::diagnostics::builtin().iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, all, "every diagnostic is run");
        for (name, args) in &calls {
            let args: BTreeMap<String, String> = args.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
            let out = lab.actions.run_diagnostic(None, "user:admin", "m1", name, &args).await.unwrap();
            let text = String::from_utf8_lossy(&out.output);
            assert_eq!(out.exit_code, Some(0), "{name}: {text}");
            assert!(!out.output.is_empty() && out.output.len() <= OUTPUT_LIMIT, "{name}: {} bytes", out.output.len());
            match *name {
                "ss_listen" => assert!(text.contains(":22"), "{text}"),
                "http_head" => assert!(text.starts_with("HTTP/1.1 200"), "{text}"),
                "top_processes" => assert!(text.lines().count() <= 21, "{text}"),
                "docker_logs" => assert!(text.contains("a log line"), "{text}"),
                _ => {}
            }
        }
        // Read-only: nothing under /etc, /usr, /opt or the home directories changed.
        let changed = lab.machine.root("find /etc /usr /opt /home -newer /tmp/before-diagnostics -print");
        assert_eq!(String::from_utf8_lossy(&changed.stdout).trim(), "", "files changed");
    }
}
