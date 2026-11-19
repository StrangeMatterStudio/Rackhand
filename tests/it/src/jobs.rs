//! Detached steps and file receive through the command wrapper (7.3.7, 7.3.11), in containers.

use std::time::{Duration, Instant};

use crate::support::{Container, binary, musl_binary};

const JOB: &str = "01JH9X4M7Z8KQ2V3W5Y6T1R0PA";

/// A container with the wrapper installed and a command list allowing `slow-echo <n>`.
fn with_wrapper(c: Container, musl: bool) -> Container {
    let probe =
        if musl { musl_binary("rackhand-probe", "rackhand-probe") } else { binary("rackhand-probe", "rackhand-probe") };
    c.copy_in(&probe, "/usr/local/lib/rackhand/run");
    assert!(
        c.root("chown root:root /usr/local/lib/rackhand/run && chmod 0755 /usr/local/lib/rackhand/run")
            .status
            .success()
    );
    let list = serde_json::json!({
        "version": 1,
        "transfer_roots": ["/var/lib/rackhand-run/incoming"],
        "commands": [{"runbook": "t", "step": "slow", "args": [{"literal": "/usr/local/bin/slow-echo"},
            {"param": "n", "regex": "^(?:[0-9]+)$", "allow_leading_dash": false}]}]
    });
    let w = c.exec(None, &["sh", "-c", "cat > /etc/rackhand/commands.json"], Some(list.to_string().as_bytes()));
    assert!(w.status.success());
    c
}

fn run(c: &Container, args: &[&str]) -> std::process::Output {
    let mut all = vec!["sudo", "-n", "/usr/local/lib/rackhand/run"];
    all.extend_from_slice(args);
    c.exec(Some("rackhand"), &all, None)
}

fn status(c: &Container, step: &str, offset: u64) -> serde_json::Value {
    let out = run(c, &["job-status", &format!("{JOB}/{step}"), &offset.to_string()]);
    assert!(out.status.success(), "job-status: {}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)))
}

fn wait_for(c: &Container, step: &str, state: &str, limit: Duration) -> serde_json::Value {
    let start = Instant::now();
    loop {
        let s = status(c, step, 0);
        if s["state"] == state || start.elapsed() > limit {
            return s;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Starts a 10-second job from a session, kills the whole session, and checks the job finished anyway.
fn survives_session_kill(c: &Container) {
    // The session leads its own process group, as an SSH session does; killing the group is dropping the session.
    let session = format!(
        "exec setsid sh -c 'sudo -n /usr/local/lib/rackhand/run job-start {JOB}/survive -- /usr/local/bin/slow-echo 10; echo $$ > /tmp/session; sleep 300'"
    );
    c.spawn_detached("rackhand", &session);
    let start = Instant::now();
    while !c.root("test -s /tmp/session").status.success() {
        assert!(start.elapsed() < Duration::from_secs(20), "the session never started the job");
        std::thread::sleep(Duration::from_millis(200));
    }
    // `kill -9 -<pgid>`: dash and busybox both take a negative pid this way (dash refuses `--` before it).
    assert!(c.root("kill -9 -$(cat /tmp/session)").status.success(), "killing the session");
    std::thread::sleep(Duration::from_millis(300));
    assert!(!c.root("kill -0 -$(cat /tmp/session)").status.success(), "the session is gone");
    assert_eq!(status(c, "survive", 0)["state"], "running", "still running after the session died");
    let done = wait_for(c, "survive", "exited", Duration::from_secs(40));
    assert_eq!(done["state"], "exited", "{done}");
    assert_eq!(done["exit_code"], 0);
    let output = done["output"].as_str().unwrap();
    for i in 1..=10 {
        assert!(output.contains(&format!("line {i}\n")), "{output}");
    }
    assert!(output.ends_with("done\n"), "{output}");
}

mod detached {
    use super::*;

    #[test]
    fn job_survives_ssh_disconnect() {
        let c = with_wrapper(Container::start_systemd("systemd"), false);
        survives_session_kill(&c);
    }

    #[test]
    fn status_offsets_return_only_new_output() {
        let c = with_wrapper(Container::start_systemd("systemd"), false);
        assert!(
            run(&c, &["job-start", &format!("{JOB}/offsets"), "--", "/usr/local/bin/slow-echo", "3"]).status.success()
        );
        let all = wait_for(&c, "offsets", "exited", Duration::from_secs(20));
        assert_eq!(all["output"], "line 1\nline 2\nline 3\ndone\n");
        let end = all["next_offset"].as_u64().unwrap();
        assert_eq!(end, 26);
        assert_eq!(status(&c, "offsets", 7)["output"], "line 2\nline 3\ndone\n", "from the second line");
        let rest = status(&c, "offsets", end);
        assert_eq!((rest["output"].as_str(), rest["next_offset"].as_u64()), (Some(""), Some(end)));
        // The internal supervisor can't be replayed through sudo to run the step again.
        let replay = run(&c, &["job-supervise", &format!("{JOB}/offsets")]);
        assert!(!replay.status.success(), "replayed");
        std::thread::sleep(Duration::from_secs(4));
        assert_eq!(status(&c, "offsets", 0)["next_offset"], 26, "nothing ran again");
        // Clean removes the files once the result is recorded.
        assert!(run(&c, &["job-clean", &format!("{JOB}/offsets")]).status.success());
        assert!(!c.root(&format!("test -e /var/lib/rackhand-run/jobs/{JOB}/offsets")).status.success());
    }

    #[test]
    fn job_stop_ends_unit() {
        let c = with_wrapper(Container::start_systemd("systemd"), false);
        assert!(
            run(&c, &["job-start", &format!("{JOB}/stop"), "--", "/usr/local/bin/slow-echo", "60"]).status.success()
        );
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(status(&c, "stop", 0)["state"], "running");
        assert!(run(&c, &["job-stop", &format!("{JOB}/stop")]).status.success());
        let s = wait_for(&c, "stop", "stopped", Duration::from_secs(15));
        assert_eq!(s["state"], "stopped", "{s}");
        // The bracket keeps pgrep from matching the shell that runs it.
        assert!(!c.root("pgrep -f 'slow-ech[o] 60'").status.success(), "the command is gone");
        let units = c.root("systemctl list-units --all --plain --no-legend 'rackhand-job-*'");
        assert!(
            String::from_utf8_lossy(&units.stdout).trim().is_empty(),
            "the unit is gone: {}",
            String::from_utf8_lossy(&units.stdout)
        );
        // A request outside the list is refused before anything starts.
        let refused = run(&c, &["job-start", &format!("{JOB}/bad"), "--", "/usr/bin/id"]);
        assert_eq!(refused.status.code(), Some(126));
        assert!(!c.root(&format!("test -e /var/lib/rackhand-run/jobs/{JOB}/bad")).status.success());
    }

    #[test]
    fn openrc_variant_same_behaviour() {
        // An init that reaps orphans, as on a real machine (`sleep` as PID 1 would leave the killed session as zombies).
        let c = with_wrapper(Container::start_with("openrc", &["--init"]), true);
        survives_session_kill(&c);
    }
}

mod receive {
    use super::*;

    fn blake3_hex(data: &[u8]) -> String {
        blake3::hash(data).to_hex().to_string()
    }

    #[test]
    fn outside_transfer_roots_refused() {
        let c = with_wrapper(Container::start("runcmd"), false);
        let before = c.root("sha256sum /etc/passwd");
        let data = b"root::0:0::/root:/bin/sh\n";
        let out = c.exec(
            Some("rackhand"),
            &["sudo", "-n", "/usr/local/lib/rackhand/run", "receive", "/etc/passwd", &blake3_hex(data), "0"],
            Some(data),
        );
        assert_eq!(out.status.code(), Some(126), "{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(c.root("sha256sum /etc/passwd").stdout, before.stdout);
        assert!(!c.root("ls /etc/passwd.rackhand-partial").status.success());
    }

    #[test]
    fn hash_mismatch_keeps_temp_and_no_rename() {
        let c = with_wrapper(Container::start("runcmd"), false);
        let dest = "/var/lib/rackhand-run/incoming/backup.bin";
        let whole: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let hash = blake3_hex(&whole);
        let send = |chunk: &[u8], offset: usize| {
            c.exec(
                Some("rackhand"),
                &["sudo", "-n", "/usr/local/lib/rackhand/run", "receive", dest, &hash, &offset.to_string()],
                Some(chunk),
            )
        };
        // The first part: the hash doesn't match yet, so nothing is renamed and the part is kept.
        let first = send(&whole[..100_000], 0);
        assert_eq!(first.status.code(), Some(3), "{}", String::from_utf8_lossy(&first.stderr));
        assert!(!c.root(&format!("test -e {dest}")).status.success(), "destination untouched");
        let size = c.root(&format!("stat -c %s {dest}.rackhand-partial"));
        assert_eq!(String::from_utf8_lossy(&size.stdout).trim(), "100000", "partial kept for resume");
        // Resuming at the wrong offset is refused; at the right one it completes.
        assert!(!send(&whole[100_000..], 50_000).status.success());
        let done = send(&whole[100_000..], 100_000);
        assert!(done.status.success(), "{}", String::from_utf8_lossy(&done.stderr));
        let stat = c.root(&format!("stat -c '%U %a %s' {dest}"));
        assert_eq!(String::from_utf8_lossy(&stat.stdout).trim(), "root 640 300000");
        assert!(!c.root(&format!("test -e {dest}.rackhand-partial")).status.success());
    }
}
