//! Patching a machine end to end (plan T59): the built-in `patch-debian` over SSH through the wrapper, with the real apt
//! against a repository on the machine's own disk. The reports are the test's, since a container runs no probe here.
#![allow(clippy::unwrap_used)]

#[cfg(test)]
mod patch {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
    use std::time::{Duration, Instant};

    use ed25519_dalek::SigningKey;
    use rackhand_hub::actions::{Actions, JobResult, StartJob};
    use rackhand_hub::audit::Audit;
    use rackhand_hub::bus::{Bus, JobOutcome};
    use rackhand_hub::checks::steps::{Hypervisor, Verify};
    use rackhand_hub::executor::commands::signed_command_list;
    use rackhand_hub::executor::{ByKind, Executor, RebootFacts};
    use rackhand_hub::incidents::Incidents;
    use rackhand_hub::incidents::routing::{BoxFuture, JobStarter, Routing};
    use rackhand_hub::ingest::{DiskSpace, Ingest, Stream};
    use rackhand_hub::library::items::{Kind, Library};
    use rackhand_hub::ssh::hostkeys::HostKeys;
    use rackhand_hub::ssh::keys::{Identity, authorized_keys_line, load_or_create};
    use rackhand_hub::vault::Vault;
    use rackhand_hub::vault::master_key::MasterKey;
    use rackhand_proto::common::LabelEntry;
    use rackhand_proto::probe::{ContainerState, Report, Sample, ServiceState, ServiceStatus};
    use rackhand_runbook::runbook::{Runbook, StepKind};
    use rackhand_store::ids::now_ms;
    use rackhand_store::{Db, Row, RowWrite, WriteCmd};
    use rusqlite::types::Value;
    use russh::keys::PublicKey;

    use crate::support::{Container, container_binary};

    const WRAPPER: &str = "/usr/local/lib/rackhand/run";
    const M: &str = "01JD0000000000000000000031";
    const GB: f64 = (1u64 << 30) as f64;

    #[derive(Debug)]
    struct Roomy;

    impl DiskSpace for Roomy {
        fn free_fraction(&self) -> f64 {
            0.5
        }
    }

    /// The machine may be rebooted, and is back at once.
    struct Reboots;

    impl RebootFacts for Reboots {
        fn auto_reboot(&self, _machine: &str) -> bool {
            true
        }
        fn back_since(&self, _machine: &str, _since_ms: i64) -> bool {
            true
        }
        fn reported_since(&self, _machine: &str, _since_ms: i64) -> bool {
            true
        }
    }

    /// No runbook is started by an incident here.
    #[derive(Debug)]
    struct NoJobs;

    impl JobStarter for NoJobs {
        fn start(&self, job: StartJob) -> BoxFuture<Result<(), String>> {
            Box::pin(async move { Err(format!("{} isn't started in this test", job.name)) })
        }
    }

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn sh(c: &Container, script: &str) -> String {
        let out = c.root(script);
        assert!(out.status.success(), "{script}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// What a restarted hub is made from again.
    struct Parts {
        vault: Arc<Vault>,
        host_keys: Arc<HostKeys>,
        ingest: Ingest,
        audit: Audit,
        bus: Bus,
    }

    struct Lab {
        db: Arc<Db>,
        machine: Container,
        actions: Actions,
        parts: Parts,
        /// Whether the machine's reports have `/srv/data`.
        data_mounted: Arc<AtomicBool>,
    }

    /// The machine, the hub's systems around a patch job, and reports every half second. `lock_s` replaces the 10 minutes
    /// the runbook waits for a package lock.
    async fn lab(name: &str, lock_s: u32) -> Lab {
        let dir = std::env::temp_dir().join(format!("rackhand-it-patch-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
        let vault = Arc::new(Vault::new(MasterKey::from_bytes([6u8; 32]), db.clone()));
        let machine = Container::start_systemd("fakepkg");
        let (ip, gateway) = machine.ip_and_gateway();
        let policy = Row::from([
            ("id", t("p")),
            ("name", t("servers")),
            ("patch", t("auto")),
            ("required_mounts", t(r#"["/srv/data"]"#)),
        ]);
        let row = Row::from([
            ("id", t(M)),
            ("site_id", t("s")),
            ("name", t("web")),
            ("kind", t("linux")),
            ("address", t(&ip)),
            ("policy_id", t("p")),
            ("state", t("enrolled")),
        ]);
        let site = Row::from([("id", t("s")), ("name", t("home")), ("timezone", t("UTC"))]);
        db.writer()
            .send(WriteCmd::Batch(vec![
                RowWrite::insert("sites", site),
                RowWrite::insert("policies", policy),
                RowWrite::insert("machines", row),
            ]))
            .await
            .unwrap();
        let key = load_or_create(&vault, Identity::Automation).await.unwrap();
        let line = authorized_keys_line(key.public_key(), std::slice::from_ref(&gateway)).unwrap();
        let path = "/home/rackhand/.ssh/authorized_keys";
        let put = machine.exec(
            None,
            &["sh", "-c", &format!("cat > {path} && chown rackhand:rackhand {path} && chmod 600 {path}")],
            Some(line.as_bytes()),
        );
        assert!(put.status.success());
        machine.copy_in(&container_binary("rackhand-probe", "rackhand-probe"), WRAPPER);
        sh(&machine, &format!("chown root:root {WRAPPER} && chmod 0755 {WRAPPER}"));
        let node = SigningKey::from_bytes(&[8u8; 32]);
        let hex: String = node.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        sh(&machine, &format!("printf '[hub]\\nid = \"{hex}\"\\n' > /etc/rackhand-probe/probe.toml"));

        // the shipped runbook, with a shorter lock wait
        let source = rackhand_runbook::builtin::runbook("patch-debian").unwrap();
        let source = source.replace("=600", &format!("={lock_s}")).replace("WAIT_S=600", &format!("WAIT_S={lock_s}"));
        let audit = Audit::new(db.writer());
        let (library, _) = Library::new(db.clone(), audit.clone());
        library.save(Kind::Runbook, "patch-debian", &source, "admin", 1).await.unwrap();
        let list = signed_command_list(&node, &[Runbook::parse(&source).unwrap()], 1, now_ms(), 3_600_000);
        let install = machine.exec(Some("rackhand"), &["sudo", "-n", WRAPPER, "install-commands"], Some(&list));
        assert!(install.status.success(), "install-commands: {}", String::from_utf8_lossy(&install.stderr));
        let (host_keys, _alerts) = HostKeys::new(db.clone());
        let host = sh(&machine, "cat /etc/ssh/ssh_host_ed25519_key.pub");
        host_keys.pin_from_join(M, &[PublicKey::from_openssh(&host).unwrap()], 1).await.unwrap();
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(format!("{ip}:22")).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let bus = Bus::new();
        let ingest = Ingest::new(db.clone(), bus.clone(), Arc::new(Roomy));
        let data_mounted = Arc::new(AtomicBool::new(true));
        reports(ingest.clone(), data_mounted.clone()).await;
        let incidents = Incidents::new(db.clone(), ingest.clone(), bus.clone());
        Routing::new(incidents, Arc::new(NoJobs)).spawn(bus.subscribe("routing"));
        let other = ByKind::default()
            .with(StepKind::WaitReport, Arc::new(ingest.clone()))
            .with(StepKind::Verify, Arc::new(Verify::new(db.clone(), ingest.clone())))
            .with(StepKind::Snapshot, Arc::new(Hypervisor::new(db.clone(), vault.clone())));
        let executor = Executor::new(vault.clone(), host_keys.clone())
            .with_poll(Duration::from_millis(500))
            .with_other(Arc::new(other))
            .with_reboot(Arc::new(Reboots), Duration::from_secs(10));
        let actions = Actions::new(db.clone(), audit.clone(), bus.clone(), Arc::new(executor));
        let parts = Parts { vault, host_keys, ingest, audit, bus };
        Lab { db, machine, actions, parts, data_mounted }
    }

    /// A report every half second: 10 GB free on `/`, a service, a container, and `/srv/data` while it is mounted.
    async fn reports(ingest: Ingest, data_mounted: Arc<AtomicBool>) {
        let mount = |id: u32, m: &str| LabelEntry { id, labels: BTreeMap::from([("mount".into(), m.into())]) };
        ingest.hello(M, 1, &[mount(1, "/"), mount(2, "/srv/data")]).await.unwrap();
        let seq = AtomicU64::new(1);
        tokio::spawn(async move {
            loop {
                let mut vitals = Vec::new();
                for labels_id in if data_mounted.load(SeqCst) { vec![1, 2] } else { vec![1] } {
                    vitals.push(Sample { metric: 17, labels_id, value: 20.0 * GB });
                    vitals.push(Sample { metric: 16, labels_id, value: 10.0 * GB });
                }
                let now = now_ms();
                let r = Report {
                    epoch: 1,
                    seq: seq.fetch_add(1, SeqCst),
                    sampled_at_ms: now,
                    vitals,
                    services: vec![ServiceState {
                        name: "nginx.service".into(),
                        status: ServiceStatus::Active as i32,
                        enabled: true,
                        since_ms: 1,
                    }],
                    containers: vec![ContainerState {
                        name: "db".into(),
                        state: "running".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                };
                let _ = ingest.receive(M, Stream::Live, vec![r], 100, now).await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });
        tokio::time::sleep(Duration::from_millis(600)).await;
    }

    impl Lab {
        /// The hub as a restart makes it: new Actions and Executor over the same database and machine.
        fn restarted(&self) -> Actions {
            let p = &self.parts;
            let other = ByKind::default()
                .with(StepKind::WaitReport, Arc::new(p.ingest.clone()))
                .with(StepKind::Verify, Arc::new(Verify::new(self.db.clone(), p.ingest.clone())))
                .with(StepKind::Snapshot, Arc::new(Hypervisor::new(self.db.clone(), p.vault.clone())));
            let executor = Executor::new(p.vault.clone(), p.host_keys.clone())
                .with_poll(Duration::from_millis(500))
                .with_other(Arc::new(other))
                .with_reboot(Arc::new(Reboots), Duration::from_secs(10));
            Actions::new(self.db.clone(), p.audit.clone(), p.bus.clone(), Arc::new(executor))
        }

        async fn patch(&self) -> JobResult {
            self.actions.run(StartJob::runbook("patch-debian", M, "schedule:patch")).await.unwrap()
        }

        fn version(&self) -> String {
            sh(&self.machine, "dpkg-query -W -f '${Version}' rackhand-demo")
        }

        fn steps(&self, job: &str) -> Vec<(String, String)> {
            self.db
                .readers()
                .with(|c| {
                    let mut s =
                        c.prepare("SELECT step_id, state FROM job_steps WHERE job_id = ?1 ORDER BY started_at")?;
                    s.query_map([job], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
                })
                .unwrap()
        }

        fn output(&self, job: &str, step: &str) -> String {
            let out: Option<Vec<u8>> = self
                .db
                .readers()
                .with(|c| {
                    c.query_row("SELECT stdout FROM job_steps WHERE job_id = ?1 AND step_id = ?2", [job, step], |r| {
                        r.get(0)
                    })
                })
                .unwrap();
            String::from_utf8_lossy(&out.unwrap_or_default()).to_string()
        }

        fn all_output(&self, job: &str) -> String {
            self.steps(job).iter().map(|(s, st)| format!("{s} {st}: {}\n", self.output(job, s))).collect()
        }

        /// Holds a lock file as another package manager would, for `seconds`.
        fn hold(&self, file: &str, seconds: u32) {
            let script = format!(
                "use Fcntl; open F, q(>>), q({file}) or die; my $l = pack(q(s s x4 q q l), F_WRLCK, 0, 0, 0, 0); \
                 fcntl(F, F_SETLK, $l) or die; open O, q(>), q(/tmp/held); close O; sleep {seconds}"
            );
            sh(&self.machine, &format!("rm -f /tmp/held; setsid perl -e '{script}' >/dev/null 2>&1 </dev/null &"));
            let deadline = Instant::now() + Duration::from_secs(10);
            while !self.machine.root("test -e /tmp/held").status.success() {
                assert!(Instant::now() < deadline, "the lock wasn't taken");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    /// AC19 on a machine that isn't a Proxmox guest: every step in order and in the job log, the update installed, the
    /// reboot it asked for made once, and the verify passed.
    #[tokio::test(flavor = "multi_thread")]
    async fn debian_full_flow_with_fake_package_manager() {
        let lab = lab("flow", 20).await;
        sh(&lab.machine, "touch /srv/ctl/reboot");
        assert_eq!(lab.version(), "1.0");
        let r = lab.patch().await;
        assert_eq!(r.outcome, JobOutcome::Succeeded, "{r:?}\n{}", lab.all_output(&r.job_id));
        assert_eq!(lab.version(), "2.0");
        let mut steps = lab.steps(&r.job_id);
        assert!(steps.iter().all(|(_, s)| s == "succeeded"), "{steps:?}");
        steps.sort();
        let names: Vec<&str> = steps.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["install", "precheck", "reboot", "record", "report", "snapshot", "update", "verify"]);
        assert!(lab.output(&r.job_id, "snapshot").contains("not a Proxmox guest"), "the log says why there is none");
        assert!(lab.output(&r.job_id, "record").contains("nginx.service"));
        assert!(lab.output(&r.job_id, "install").contains("rackhand-demo"), "{}", lab.output(&r.job_id, "install"));
        assert!(lab.output(&r.job_id, "reboot").contains("done"));
        assert_eq!(sh(&lab.machine, "cat /root/rebooted"), "root", "once, through the wrapper");
    }

    /// E9: a package manager busy for the whole wait fails the job before anything changed, whichever of apt's locks it
    /// holds; busy for less, the job waits and goes on.
    #[tokio::test(flavor = "multi_thread")]
    async fn apt_lock_waits_10_min_then_fails_without_changes() {
        let lab = lab("lock", 12).await;
        for (file, step) in [("/var/lib/apt/lists/lock", "update"), ("/var/lib/dpkg/lock-frontend", "install")] {
            lab.hold(file, 120);
            let started = Instant::now();
            let r = lab.patch().await;
            assert_eq!(r.outcome, JobOutcome::Failed, "{file}: {r:?}");
            let steps = lab.steps(&r.job_id);
            assert!(steps.contains(&(step.to_string(), "failed".to_string())), "{file}: {steps:?}");
            assert!(started.elapsed() >= Duration::from_secs(12), "{file}: waited {:?}", started.elapsed());
            assert_eq!(lab.version(), "1.0", "{file}: nothing changed");
            assert!(!lab.machine.root("test -e /root/rebooted").status.success());
            sh(&lab.machine, "pkill -f '[F]_WRLCK' || true");
        }
        lab.hold("/var/lib/apt/lists/lock", 5);
        let r = lab.patch().await;
        assert_eq!(r.outcome, JobOutcome::Succeeded, "{r:?}\n{}", lab.all_output(&r.job_id));
        assert_eq!(lab.version(), "2.0");
    }

    /// AC21, D66: a required mount missing after the update fails the verify, and `patch_failed` opens on the machine.
    #[tokio::test(flavor = "multi_thread")]
    async fn verify_fails_on_missing_required_mount() {
        let lab = lab("mount", 20).await;
        let source: String = lab
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT content FROM library_revisions WHERE name = 'patch-debian'", [], |r| r.get(0))
            })
            .unwrap();
        let (library, _) = Library::new(lab.db.clone(), Audit::new(lab.db.writer()));
        let quick = source.replace("timeout = \"5m\"", "timeout = \"6s\"");
        library.save(Kind::Runbook, "patch-debian", &quick, "admin", 2).await.unwrap();
        lab.data_mounted.store(false, SeqCst);
        let r = lab.patch().await;
        assert_eq!(
            (r.outcome, r.reason.as_deref()),
            (JobOutcome::Failed, Some("required_mounts")),
            "{}",
            lab.all_output(&r.job_id)
        );
        assert_eq!(lab.version(), "2.0", "the update itself went through");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let open: Option<String> = lab
                .db
                .readers()
                .with(|c| {
                    let mut s = c.prepare(
                        "SELECT machine_id FROM incidents WHERE kind = 'patch_failed' AND state != 'resolved'",
                    )?;
                    let mut rows = s.query_map([], |r| r.get(0))?;
                    rows.next().transpose()
                })
                .unwrap();
            if open.as_deref() == Some(M) {
                break;
            }
            assert!(Instant::now() < deadline, "patch_failed opens: {open:?}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// AC63: SSH cut while the package manager runs. It finishes on the machine, the hub records its output and exit
    /// code, and the job goes on to verify.
    #[tokio::test(flavor = "multi_thread")]
    async fn ssh_cut_during_install_finishes_and_verifies() {
        let lab = lab("cut", 20).await;
        sh(&lab.machine, "echo 12 > /srv/ctl/seconds");
        let job = tokio::spawn({
            let actions = lab.actions.clone();
            async move { actions.run(StartJob::runbook("patch-debian", M, "schedule:patch")).await.unwrap() }
        });
        let deadline = Instant::now() + Duration::from_secs(90);
        while !lab.machine.root("pgrep -f '[r]ackhand-demo.postinst'").status.success() {
            assert!(Instant::now() < deadline, "the install never started");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        sh(&lab.machine, "systemctl stop ssh && (pkill -9 -f 'sshd: [r]ackhand' || true)");
        tokio::time::sleep(Duration::from_secs(4)).await;
        sh(&lab.machine, "systemctl start ssh");
        let r = job.await.unwrap();
        assert_eq!(r.outcome, JobOutcome::Succeeded, "{r:?}\n{}", lab.all_output(&r.job_id));
        assert_eq!(lab.version(), "2.0");
        let install = lab.output(&r.job_id, "install");
        for left in [12, 1] {
            assert!(install.contains(&format!("installing, {left} s left")), "{install}");
        }
        let exit: Option<i64> = lab
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT exit_code FROM job_steps WHERE job_id = ?1 AND step_id = 'install'",
                    [&r.job_id],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert_eq!(exit, Some(0));
    }

    /// AC63, E44, E54: the hub itself dies while the package manager runs. The update finishes on the machine; a hub
    /// started afterwards takes the install step up where it is, records its output and exit code, and the job goes on
    /// to verify.
    #[tokio::test(flavor = "multi_thread")]
    async fn hub_restart_during_patch_install_finishes_and_verifies() {
        let lab = lab("restart", 20).await;
        sh(&lab.machine, "echo 12 > /srv/ctl/seconds");
        let dying = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let actions = lab.actions.clone();
        dying.spawn(async move {
            let _ = actions.run(StartJob::runbook("patch-debian", M, "schedule:patch")).await;
        });
        let deadline = Instant::now() + Duration::from_secs(90);
        while !lab.machine.root("pgrep -f '[r]ackhand-demo.postinst'").status.success() {
            assert!(Instant::now() < deadline, "the install never started");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        // the hub is gone; the package manager is not
        dying.shutdown_background();
        let job: String = lab
            .db
            .readers()
            .with(|c| c.query_row("SELECT id FROM jobs WHERE name = 'patch-debian'", [], |r| r.get(0)))
            .unwrap();
        let hub = lab.restarted();
        assert_eq!(hub.resume().await.unwrap(), 1, "the job is taken up");
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let state: String = lab
                .db
                .readers()
                .with(|c| c.query_row("SELECT state FROM jobs WHERE id = ?1", [&job], |r| r.get(0)))
                .unwrap();
            if state != "running" {
                assert_eq!(state, "succeeded", "{}", lab.all_output(&job));
                break;
            }
            assert!(Instant::now() < deadline, "the job never ended: {}", lab.all_output(&job));
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert_eq!(lab.version(), "2.0", "the package manager finished");
        let install = lab.output(&job, "install");
        assert!(install.contains("installing, 12 s left") && install.contains("installing, 1 s left"), "{install}");
        let exit: Option<i64> = lab
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT exit_code FROM job_steps WHERE job_id = ?1 AND step_id = 'install'",
                    [&job],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert_eq!(exit, Some(0));
        let steps = lab.steps(&job);
        assert_eq!(
            steps.last().map(|(id, state)| (id.as_str(), state.as_str())),
            Some(("verify", "succeeded")),
            "{steps:?}"
        );
    }
}
