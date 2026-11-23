//! The root helper under its systemd unit in a Debian container (plan T43, 7.3.3).

use std::path::Path;
use std::time::{Duration, Instant};

use crate::support::{Container, musl_binary};

/// A container with the probe binary, both units, the probe user, and `other`, a user in the probe's group.
pub(crate) fn machine() -> Container {
    let c = Container::start_systemd("systemd");
    c.copy_in(&musl_binary("rackhand-probe", "rackhand-probe"), "/usr/local/lib/rackhand/rackhand-probe");
    let units = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/systemd");
    c.copy_in(&units.join("rackhand-probe-helper.service"), "/etc/systemd/system/rackhand-probe-helper.service");
    c.copy_in(&units.join("rackhand-probe.service"), "/etc/systemd/system/rackhand-probe.service");
    let setup = "useradd -r -s /usr/sbin/nologin rackhand-probe && useradd -m -G rackhand-probe other \
        && chmod 0755 /usr/local/lib/rackhand/rackhand-probe && systemctl daemon-reload";
    assert!(c.root(setup).status.success());
    c
}

pub(crate) fn start_helper(c: &Container) {
    let out = c.root("systemctl start rackhand-probe-helper");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let deadline = Instant::now() + Duration::from_secs(20);
    while !c.root("test -S /run/rackhand-helper/helper.sock").status.success() {
        assert!(Instant::now() < deadline, "no socket: {}", journal(c));
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn journal(c: &Container) -> String {
    String::from_utf8_lossy(&c.root("journalctl -u rackhand-probe-helper --no-pager | tail -20").stdout).into_owned()
}

/// One request line to the helper as `user`; the answer line (empty when there is none).
pub(crate) fn ask(c: &Container, user: &str, request: &str) -> String {
    let script = format!("echo '{request}' | socat -t 3 - UNIX-CONNECT:/run/rackhand-helper/helper.sock");
    let out = c.exec(Some(user), &["sh", "-c", &script], None);
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

mod helper {
    use super::*;

    #[test]
    fn socket_refuses_other_users() {
        let c = machine();
        start_helper(&c);
        assert!(
            ask(&c, "rackhand-probe", r#"{"op":"ping"}"#).contains(r#""kind":"pong""#),
            "the probe user is answered"
        );
        assert_eq!(ask(&c, "other", r#"{"op":"ping"}"#), "", "another user in the probe's group gets no answer");
        let stat = c.root("stat -c '%a %U %G' /run/rackhand-helper/helper.sock");
        assert_eq!(String::from_utf8_lossy(&stat.stdout).trim(), "660 root rackhand-probe");
        assert_eq!(ask(&c, "nobody", r#"{"op":"ping"}"#), "", "and a user outside it can't connect");
    }

    #[test]
    fn layout_matches_ownership_table() {
        let c = machine();
        // a probe.toml the probe user could change, as a careless install would leave it
        c.root(
            "mkdir -p /etc/rackhand-probe && echo '[hub]' > /etc/rackhand-probe/probe.toml \
            && chown rackhand-probe /etc/rackhand-probe/probe.toml && chmod 0666 /etc/rackhand-probe/probe.toml",
        );
        start_helper(&c);
        c.root("systemctl start rackhand-probe; sleep 1");
        let expected = [
            ("/run/rackhand-helper", "755 root"),
            ("/usr/local/lib/rackhand", "755 root"),
            ("/etc/rackhand-probe/probe.toml", "644 root"),
            ("/etc/rackhand", "755 root"),
            ("/var/lib/rackhand-helper", "700 root"),
            ("/var/lib/rackhand-run", "700 root"),
            ("/run/rackhand-probe", "755 rackhand-probe"),
            ("/var/lib/rackhand-probe", "700 rackhand-probe"),
        ];
        for (path, want) in expected {
            let out = c.root(&format!("stat -c '%a %U' {path}"));
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), want, "{path}");
        }
    }

    #[test]
    fn refresh_runs_fixed_commands_at_low_priority() {
        let c = machine();
        // a fake apt-get that records its priority and arguments, and has one security update
        let fake = "#!/bin/sh\necho \"$(ps -o ni= -p $$ | tr -d ' ') $(ionice -p $$) $*\" >> /var/log/fake-apt.log\n\
            case \"$*\" in *-s*) echo 'Inst openssl [1] (2 Debian-Security:12/stable-security [amd64])';; esac\n";
        let script = std::env::temp_dir().join(format!("rackhand-fake-apt-get-{}", std::process::id()));
        std::fs::write(&script, fake).unwrap();
        c.copy_in(&script, "/usr/bin/apt-get");
        let _ = std::fs::remove_file(&script);
        c.root("chmod 0755 /usr/bin/apt-get");
        start_helper(&c);
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut answer = String::new();
        while !answer.contains(r#""kind":"updates""#) {
            assert!(Instant::now() < deadline, "no updates: {answer} {}", journal(&c));
            std::thread::sleep(Duration::from_millis(500));
            answer = ask(&c, "rackhand-probe", r#"{"op":"updates_status"}"#);
        }
        assert!(answer.contains(r#""pending":1"#) && answer.contains(r#""security":1"#), "{answer}");
        let log = String::from_utf8_lossy(&c.root("cat /var/log/fake-apt.log").stdout).into_owned();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(
            lines,
            ["19 idle update -q", "19 idle -s -q upgrade"],
            "only the fixed commands, at nice 19 and idle I/O"
        );
    }
}
