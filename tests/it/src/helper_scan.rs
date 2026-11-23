//! The helper's scans (plan T66, 7.3.3): what it reads as root and answers the probe with, in a Debian container under
//! systemd with the helper's own unit.

use std::time::{Duration, Instant};

use crate::helper_it::{ask, machine, start_helper};
use crate::support::Container;

const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A Docker engine as far as the helper asks: a socket that answers the two read calls it makes and records every request
/// line.
fn fake_engine(c: &Container) {
    let list = format!(r#"[{{"Id":"{ID}","Names":["/web"],"Image":"nginx","State":"running","Labels":{{}}}}]"#);
    let detail = r#"{"State":{"StartedAt":"2026-01-01T00:00:00Z"},"RestartCount":0}"#;
    let script = format!(
        "#!/bin/sh\nread -r req\necho \"$req\" >> /var/log/fake-docker.log\ncase \"$req\" in\n\
         \"GET /containers/json?all=1 \"*) body='{list}';;\n\
         \"GET /containers/{ID}/json \"*) body='{detail}';;\n\
         *) body='{{}}';;\nesac\n\
         printf 'HTTP/1.0 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n%s' \"$body\"\n"
    );
    let file = std::env::temp_dir().join(format!("rackhand-fake-docker-{}", std::process::id()));
    std::fs::write(&file, script).unwrap();
    c.copy_in(&file, "/usr/local/bin/fake-docker.sh");
    let _ = std::fs::remove_file(&file);
    c.root("chmod 0755 /usr/local/bin/fake-docker.sh; rm -f /var/log/fake-docker.log");
    c.root("systemd-run --unit=fake-docker socat UNIX-LISTEN:/var/run/docker.sock,fork,mode=0666 EXEC:/usr/local/bin/fake-docker.sh");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !c.root("test -S /var/run/docker.sock").status.success() {
        assert!(Instant::now() < deadline, "the fake engine never listened");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn ask_json(c: &Container, request: &str) -> serde_json::Value {
    serde_json::from_str(&ask(c, "rackhand-probe", request)).unwrap_or_else(|e| panic!("{request}: {e}"))
}

/// The hash of `/etc/sudoers.d/x` in the helper's answer, if the file is in it.
fn sudoers_x(c: &Container) -> Option<String> {
    let answer = ask_json(c, r#"{"op":"hash_files"}"#);
    let files = answer["files"].as_array().expect("files").clone();
    files.iter().find(|f| f["path"] == "/etc/sudoers.d/x").and_then(|f| f["sha256"].as_str().map(str::to_string))
}

/// Waits until `/etc/sudoers.d/x` has a hash other than `not`.
fn changes_from(c: &Container, not: Option<&str>) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(sha) = sudoers_x(c).filter(|s| Some(s.as_str()) != not) {
            return sha;
        }
        assert!(Instant::now() < deadline, "no change seen in 10 s");
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// FR-6: a change to a critical file is seen within seconds, not at the next 5 minutes.
#[test]
fn inotify_change_reported_within_seconds() {
    let c = machine();
    start_helper(&c);
    let answer = ask_json(&c, r#"{"op":"hash_files"}"#);
    let passwd = answer["files"].as_array().unwrap().iter().find(|f| f["path"] == "/etc/passwd").cloned().unwrap();
    assert_eq!(passwd["exists"], true, "a file that is there is hashed");
    assert_eq!(sudoers_x(&c), None, "not there yet");
    let started = Instant::now();
    c.root("echo 'other ALL=(ALL) ALL' > /etc/sudoers.d/x");
    let first = changes_from(&c, None);
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    c.root("echo 'other ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/x");
    let second = changes_from(&c, Some(&first));
    assert_ne!(first, second);
    // not a byte of the file in the answer, and nobody but the probe user can ask
    assert!(!ask(&c, "rackhand-probe", r#"{"op":"hash_files"}"#).contains("NOPASSWD"));
    assert_eq!(ask(&c, "other", r#"{"op":"hash_files"}"#), "");
}

/// D64: the helper reads the engine's socket with GET and nothing else.
#[test]
fn containers_read_only_calls() {
    let c = machine();
    fake_engine(&c);
    start_helper(&c);
    let answer = ask_json(&c, r#"{"op":"containers"}"#);
    assert_eq!(answer["items"][0]["name"], "web", "{answer}");
    let log = String::from_utf8_lossy(&c.root("cat /var/log/fake-docker.log").stdout).into_owned();
    assert!(!log.is_empty(), "the engine was asked");
    assert!(log.lines().all(|l| l.starts_with("GET ")), "only GETs: {log}");
}

/// D103: a socket's owner is found by its inode, and its container by its cgroup, named as the engine names it; a cgroup's
/// id is the id of its directory.
#[test]
fn socket_owner_and_cgroup_to_container_name() {
    let c = machine();
    fake_engine(&c);
    start_helper(&c);
    c.root(&format!("systemd-run --unit=docker-{ID} socat TCP-LISTEN:9999,reuseaddr,fork /dev/null"));
    let deadline = Instant::now() + Duration::from_secs(20);
    let inode = loop {
        let out = c.root("awk 'NR>1 && $2 ~ /:270F$/ {print $10}' /proc/net/tcp");
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if let Ok(n) = text.lines().next().unwrap_or("").parse::<u64>() {
            break n;
        }
        assert!(Instant::now() < deadline, "the listener never came up");
        std::thread::sleep(Duration::from_millis(300));
    };
    let owners = ask_json(&c, &format!(r#"{{"op":"socket_owners","inodes":[{inode},1]}}"#));
    let o = &owners["owners"][0];
    assert_eq!(o["inode"], inode);
    assert!(o["exe"].as_str().unwrap().ends_with("socat"), "{owners}");
    assert_eq!(o["container"], "web", "named by the engine: {owners}");
    assert_eq!(owners["owners"].as_array().unwrap().len(), 1, "an inode nobody holds is left out");
    let find = format!("stat -c %i $(find /sys/fs/cgroup -type d -name 'docker-{ID}*' | head -1)");
    let cg = String::from_utf8_lossy(&c.root(&find).stdout).trim().to_string();
    let names = ask_json(&c, &format!(r#"{{"op":"container_of","cgroup_ids":[{cg},1]}}"#));
    assert_eq!(names["names"][0][1], "web", "{names}");
    assert_eq!(names["names"].as_array().unwrap().len(), 1);
}

/// S11: a machine with no `auth.log` reports its logins from the journal, each once.
#[test]
fn journal_only_system_auth_events() {
    let c = machine();
    assert!(!c.root("test -e /var/log/auth.log").status.success(), "no auth.log here");
    start_helper(&c);
    let first = ask_json(&c, r#"{"op":"auth_events_since","cursor":null}"#);
    assert_eq!(first["events"].as_array().unwrap().len(), 0, "history isn't replayed: {first}");
    let cursor = first["cursor"].as_str().unwrap_or_else(|| panic!("{first}")).to_string();
    assert!(cursor.starts_with("s="), "{cursor}");
    c.root("logger -t sshd 'Accepted publickey for alice from 192.0.2.10 port 40222 ssh2: ED25519 SHA256:abc'");
    c.root("logger -t sshd 'Failed password for invalid user mallory from 198.51.100.9 port 5555 ssh2'");
    c.root("logger -t sudo '   alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/cat /etc/shadow'");
    let deadline = Instant::now() + Duration::from_secs(20);
    let events = loop {
        let answer = ask_json(&c, &format!(r#"{{"op":"auth_events_since","cursor":"{cursor}"}}"#));
        let events = answer["events"].as_array().unwrap_or_else(|| panic!("{answer}")).clone();
        if events.len() >= 3 {
            break events;
        }
        let raw =
            String::from_utf8_lossy(&c.root("journalctl -o json --no-pager -t sshd -t sudo | cut -c1-1500").stdout)
                .into_owned();
        assert!(
            Instant::now() < deadline,
            "the journal's events never came after {cursor}: {answer}
{raw}"
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    let kinds: Vec<&str> = events.iter().map(|e| e["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["ssh_login", "ssh_failed", "sudo"]);
    assert_eq!(events[0]["user"], "alice");
    assert_eq!(events[0]["source_ip"], "192.0.2.10");
    assert!(!events.iter().any(|e| e.to_string().contains("shadow")), "no command line is carried");
    // asked again from where the last answer ended, nothing comes twice
    let answer = ask_json(&c, &format!(r#"{{"op":"auth_events_since","cursor":"{cursor}"}}"#));
    let next = answer["cursor"].as_str().unwrap().to_string();
    let again = ask_json(&c, &format!(r#"{{"op":"auth_events_since","cursor":"{next}"}}"#));
    assert_eq!(again["events"].as_array().unwrap().len(), 0, "{again}");
}
