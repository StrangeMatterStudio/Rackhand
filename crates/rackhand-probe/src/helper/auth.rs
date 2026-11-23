//! `AuthEventsSince` (7.3.3, FR-6, S11): SSH logins and failures, `sudo` and `su` uses, new users and group changes, read
//! from the journal with `journalctl -o json` and a cursor where a machine has no `auth.log`, and from `auth.log` or
//! `secure` where it has one. Only the time, the kind, the user, the source address and the method of a login are returned:
//! never a command line, a password or a key.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use rackhand_proto::helper::{AuthEvent, AuthKind};

/// The most events one answer carries; the cursor says where the next one starts.
pub const MAX_EVENTS: usize = 2000;
/// The most journal entries read in one go.
const MAX_ENTRIES: usize = 20_000;
/// A cursor longer than this, or with another character than these, is refused before it reaches `journalctl`.
const MAX_CURSOR: usize = 256;
const LOG_FILES: &[&str] = &["var/log/auth.log", "var/log/secure"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Journal,
    File(PathBuf),
}

/// `auth.log` (Debian with rsyslog) or `secure` (Red Hat) when there is one, the journal otherwise.
pub fn detect(root: &Path) -> Source {
    LOG_FILES.iter().map(|f| root.join(f)).find(|p| p.is_file()).map_or(Source::Journal, Source::File)
}

/// Runs `journalctl` as the helper does: the fixed program with a clean environment.
pub fn run_journalctl(argv: &[String]) -> Result<String, String> {
    let (program, args) = argv.split_first().ok_or("empty command")?;
    if program != "journalctl" {
        return Err("only journalctl".into());
    }
    let out = std::process::Command::new("journalctl")
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output()
        .map_err(|e| format!("journalctl: {e}"))?;
    if !out.status.success() {
        return Err(format!("journalctl: exit {:?}", out.status.code()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A cursor that is safe to hand to `journalctl --after-cursor=`.
pub fn cursor_ok(cursor: &str) -> bool {
    // journald's own form: `s=<hex>;i=<hex>;b=<hex>;m=<hex>;t=<hex>;x=<hex>`
    cursor.starts_with("s=")
        && cursor.len() <= MAX_CURSOR
        && cursor.bytes().all(|b| b.is_ascii_hexdigit() || b"=;simbtx".contains(&b))
}

fn event(at_ms: i64, kind: AuthKind, user: &str, ip: Option<&str>, method: Option<&str>) -> AuthEvent {
    AuthEvent { at_ms, kind, user: user.into(), source_ip: ip.map(str::to_string), method: method.map(str::to_string) }
}

/// The word after `marker` in `text`.
fn after<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    text.split_once(marker)?.1.split_whitespace().next()
}

/// One log message (without the time, host and program) as an event, or nothing.
pub fn parse_message(program: &str, message: &str, at_ms: i64) -> Option<AuthEvent> {
    let m = message.trim();
    match program {
        "sshd" | "sshd-session" => {
            if let Some(rest) = m.strip_prefix("Accepted ") {
                let method = rest.split_whitespace().next()?;
                let user = after(rest, " for ")?;
                return Some(event(at_ms, AuthKind::SshLogin, user, after(rest, " from "), Some(method)));
            }
            if let Some(rest) = m.strip_prefix("Failed ") {
                let method = rest.split_whitespace().next()?;
                let tail = rest.split_once(" for ")?.1;
                let tail = tail.strip_prefix("invalid user ").unwrap_or(tail);
                let user = tail.split_whitespace().next()?;
                return Some(event(at_ms, AuthKind::SshFailed, user, after(rest, " from "), Some(method)));
            }
            if let Some(rest) = m.strip_prefix("Invalid user ") {
                let user = rest.split_whitespace().next().unwrap_or("");
                return Some(event(at_ms, AuthKind::SshFailed, user, after(rest, " from "), None));
            }
            None
        }
        "sudo" => {
            // `alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/true`
            let (who, rest) = m.split_once(" : ")?;
            if !rest.contains("COMMAND=") || who.contains(' ') {
                return None;
            }
            Some(event(at_ms, AuthKind::Sudo, who, None, None))
        }
        "su" => {
            // `(to root) alice on pts/0`, or from PAM: `pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)`
            if let Some(rest) = m.strip_prefix("(to ") {
                let user = rest.split_once(") ")?.1.split_whitespace().next()?;
                return Some(event(at_ms, AuthKind::Su, user, None, None));
            }
            if m.contains("session opened for user") {
                let by = after(m, " by ")?;
                let user = by.split('(').next()?;
                return Some(event(at_ms, AuthKind::Su, user, None, None));
            }
            None
        }
        "useradd" | "adduser" => {
            // `new user: name=eve, UID=1001, GID=1001, home=/home/eve, shell=/bin/bash`
            let name = m.strip_prefix("new user: name=")?.split(',').next()?;
            Some(event(at_ms, AuthKind::UserAdded, name, None, None))
        }
        "usermod" | "gpasswd" | "groupmod" | "groupadd" => {
            // `add 'eve' to group 'sudo'`, `user eve added by root to group sudo`
            if let Some(rest) = m.strip_prefix("add '") {
                return Some(event(at_ms, AuthKind::GroupChanged, rest.split('\'').next()?, None, None));
            }
            if let Some(rest) = m.strip_prefix("user ") {
                return Some(event(at_ms, AuthKind::GroupChanged, rest.split_whitespace().next()?, None, None));
            }
            if let Some(rest) = m.strip_prefix("new group: name=") {
                return Some(event(at_ms, AuthKind::GroupChanged, rest.split(',').next()?, None, None));
            }
            None
        }
        _ => None,
    }
}

/// `journalctl -o json` lines: the events and the cursor of the last entry read.
pub fn parse_journal(output: &str) -> (Vec<AuthEvent>, Option<String>) {
    let mut events = Vec::new();
    let mut cursor = None;
    for line in output.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        if let Some(c) = v["__CURSOR"].as_str() {
            cursor = Some(c.to_string());
        }
        let program = v["SYSLOG_IDENTIFIER"].as_str().or_else(|| v["_COMM"].as_str()).unwrap_or_default();
        let message = match &v["MESSAGE"] {
            serde_json::Value::String(s) => s.clone(),
            _ => continue,
        };
        let at_ms = v["__REALTIME_TIMESTAMP"].as_str().and_then(|t| t.parse::<i64>().ok()).map_or(0, |us| us / 1000);
        if let Some(e) = parse_message(program, &message, at_ms) {
            events.push(e);
        }
    }
    (events, cursor)
}

/// `Nov 23 09:00:01 host sshd[123]: message` as the program and the message.
fn syslog_line(line: &str) -> Option<(&str, &str)> {
    let mut rest = line;
    // the time (three words), then the host
    for _ in 0..4 {
        rest = rest.split_once(' ')?.1.trim_start();
    }
    let (tag, message) = rest.split_once(": ")?;
    let program = tag.split('[').next()?;
    Some((program, message))
}

/// The month and day at the start of an `auth.log` line, as milliseconds in `year` (UTC: the line has no zone).
fn syslog_time(line: &str, year: i64) -> Option<i64> {
    let mut w = line.split_whitespace();
    let name = w.next()?;
    let month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        .iter()
        .position(|m| *m == name)? as i64
        + 1;
    let day: i64 = w.next()?.parse().ok()?;
    let mut hms = w.next()?.split(':').map(|p| p.parse::<i64>().ok());
    let (h, mi, s) = (hms.next()??, hms.next()??, hms.next()??);
    let y2 = if month <= 2 { year - 1 } else { year };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    Some(((days * 24 + h) * 60 + mi) * 60_000 + s * 1000)
}

/// Lines of an `auth.log` as events.
pub fn parse_syslog(text: &str, year: i64) -> Vec<AuthEvent> {
    text.lines()
        .filter_map(|line| {
            let (program, message) = syslog_line(line)?;
            parse_message(program, message, syslog_time(line, year).unwrap_or(0))
        })
        .collect()
}

/// What `AuthEventsSince` answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub events: Vec<AuthEvent>,
    pub cursor: String,
}

/// Runs `journalctl` with these arguments and gives its output.
pub type Run<'a> = &'a dyn Fn(&[String]) -> Result<String, String>;

fn journalctl(args: &[&str]) -> Vec<String> {
    let mut v = vec!["journalctl".to_string(), "--no-pager".into(), "-o".into(), "json".into()];
    v.extend(args.iter().map(|a| a.to_string()));
    v
}

/// The events after `cursor` in the journal; with no cursor, none, and a cursor at the end so that history isn't
/// replayed.
pub fn since_journal(cursor: Option<&str>, run: Run<'_>) -> Result<Batch, String> {
    let Some(cursor) = cursor else {
        let out = run(&journalctl(&["-n", "1"]))?;
        let (_, c) = parse_journal(&out);
        return Ok(Batch { events: Vec::new(), cursor: c.unwrap_or_default() });
    };
    if !cursor_ok(cursor) {
        return Err("the cursor isn't one this helper made".into());
    }
    // No match on the program here: `journalctl` takes the first entry after the cursor that matches for the cursor's own
    // entry and skips it, which would lose a login. The programs are picked out below.
    let after = format!("--after-cursor={cursor}");
    let lines = MAX_ENTRIES.to_string();
    let args = [after.as_str(), "--lines", &lines, "--output-fields=MESSAGE,SYSLOG_IDENTIFIER,_COMM"];
    let out = run(&journalctl(&args))?;
    let (events, last) = parse_journal(&out);
    Ok(Batch { events, cursor: last.unwrap_or_else(|| cursor.to_string()) })
}

/// A file cursor: the file's inode and the offset read so far.
fn file_cursor(ino: u64, offset: u64) -> String {
    format!("f:{ino}:{offset}")
}

fn parse_file_cursor(c: &str) -> Option<(u64, u64)> {
    let rest = c.strip_prefix("f:")?;
    let (ino, offset) = rest.split_once(':')?;
    Some((ino.parse().ok()?, offset.parse().ok()?))
}

/// The events appended to `path` since `cursor`; a rotated file (another inode) is read from its start.
pub fn since_file(path: &Path, cursor: Option<&str>, year: i64) -> Result<Batch, String> {
    use std::os::unix::fs::MetadataExt;
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let meta = f.metadata().map_err(|e| e.to_string())?;
    let end = meta.len();
    let Some(cursor) = cursor else {
        return Ok(Batch { events: Vec::new(), cursor: file_cursor(meta.ino(), end) });
    };
    let (ino, offset) = parse_file_cursor(cursor).ok_or("the cursor isn't one this helper made")?;
    let from = if ino == meta.ino() && offset <= end { offset } else { 0 };
    f.seek(SeekFrom::Start(from)).map_err(|e| e.to_string())?;
    let mut text = String::new();
    f.take(8 << 20).read_to_string(&mut text).map_err(|e| e.to_string())?;
    // only whole lines: a line still being written is read next time
    let whole = text.rfind('\n').map_or(0, |i| i + 1);
    let events: Vec<AuthEvent> = parse_syslog(&text[..whole], year).into_iter().take(MAX_EVENTS).collect();
    Ok(Batch { events, cursor: file_cursor(meta.ino(), from + whole as u64) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `sshd`, `sudo`, `su` and the account tools log on Debian 12 and Ubuntu 24.04, as `journalctl -o json` prints
    /// it (the formats S11 recorded): the fields the helper reads, and a line of another program it must ignore.
    const JOURNAL: &str = r#"{"__CURSOR":"s=a;i=1","__REALTIME_TIMESTAMP":"1795068000000000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted publickey for alice from 192.0.2.10 port 40222 ssh2: ED25519 SHA256:abc"}
{"__CURSOR":"s=a;i=2","__REALTIME_TIMESTAMP":"1795068001000000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for invalid user mallory from 198.51.100.9 port 5555 ssh2"}
{"__CURSOR":"s=a;i=3","__REALTIME_TIMESTAMP":"1795068002000000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Invalid user guest from 198.51.100.9 port 5556"}
{"__CURSOR":"s=a;i=4","__REALTIME_TIMESTAMP":"1795068003000000","SYSLOG_IDENTIFIER":"sudo","MESSAGE":"   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"}
{"__CURSOR":"s=a;i=5","__REALTIME_TIMESTAMP":"1795068004000000","SYSLOG_IDENTIFIER":"su","MESSAGE":"(to root) alice on pts/0"}
{"__CURSOR":"s=a;i=6","__REALTIME_TIMESTAMP":"1795068005000000","SYSLOG_IDENTIFIER":"useradd","MESSAGE":"new user: name=eve, UID=1001, GID=1001, home=/home/eve, shell=/bin/bash, from=/dev/pts/0"}
{"__CURSOR":"s=a;i=7","__REALTIME_TIMESTAMP":"1795068006000000","SYSLOG_IDENTIFIER":"usermod","MESSAGE":"add 'eve' to group 'sudo'"}
{"__CURSOR":"s=a;i=8","__REALTIME_TIMESTAMP":"1795068007000000","SYSLOG_IDENTIFIER":"systemd","MESSAGE":"Started Session 4 of User alice."}
not json at all
"#;

    #[test]
    fn parses_ssh_sudo_su_user_and_group_events() {
        let (events, cursor) = parse_journal(JOURNAL);
        let at = 1_795_068_000_000i64;
        assert_eq!(
            events,
            vec![
                event(at, AuthKind::SshLogin, "alice", Some("192.0.2.10"), Some("publickey")),
                event(at + 1000, AuthKind::SshFailed, "mallory", Some("198.51.100.9"), Some("password")),
                event(at + 2000, AuthKind::SshFailed, "guest", Some("198.51.100.9"), None),
                event(at + 3000, AuthKind::Sudo, "alice", None, None),
                event(at + 4000, AuthKind::Su, "alice", None, None),
                event(at + 5000, AuthKind::UserAdded, "eve", None, None),
                event(at + 6000, AuthKind::GroupChanged, "eve", None, None),
            ]
        );
        assert_eq!(cursor.as_deref(), Some("s=a;i=8"), "the last entry read, matched or not");
        // a command line is never carried: nothing of the sudo line but who ran it
        assert!(!format!("{events:?}").contains("shadow"));
        // PAM's own line for su, and a failed key
        let su = parse_message("su", "pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)", 5);
        assert_eq!(su, Some(event(5, AuthKind::Su, "alice", None, None)));
        assert_eq!(
            parse_message("sshd", "Accepted password for bob from 2001:db8::1 port 22 ssh2", 1)
                .unwrap()
                .source_ip
                .as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(parse_message("sshd", "Connection closed by 192.0.2.1 port 22", 1), None);
        assert_eq!(
            parse_message("sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)", 1),
            None
        );
    }

    #[test]
    fn auth_log_lines_parse_too() {
        let text = "Nov 23 09:00:01 web sshd[123]: Accepted publickey for alice from 192.0.2.10 port 4 ssh2: ED25519 SHA256:x\n\
                    Nov 23 09:00:02 web sudo:    alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls\n\
                    Nov 23 09:00:03 web CRON[9]: pam_unix(cron:session): session opened for user root\n";
        let events = parse_syslog(text, 2026);
        assert_eq!(events.len(), 2, "{events:?}");
        assert_eq!(events[0].kind, AuthKind::SshLogin);
        assert_eq!(events[1], event(events[1].at_ms, AuthKind::Sudo, "alice", None, None));
        // 2026-11-23 09:00:01 UTC
        assert_eq!(events[0].at_ms, 1_795_424_401_000);
    }

    #[test]
    fn journal_only_system_auth_events() {
        // a Debian machine without `auth.log`: the journal is the source, read with a fixed command line
        let root = std::env::temp_dir().join(format!("rackhand-auth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("var/log")).unwrap();
        assert_eq!(detect(&root), Source::Journal);
        std::fs::write(root.join("var/log/auth.log"), "").unwrap();
        assert_eq!(detect(&root), Source::File(root.join("var/log/auth.log")));
        let seen = std::sync::Mutex::new(Vec::<Vec<String>>::new());
        let run = |argv: &[String]| {
            seen.lock().unwrap().push(argv.to_vec());
            Ok(JOURNAL.to_string())
        };
        // no cursor: nothing is replayed, and the cursor is the newest entry's
        let first = since_journal(None, &run).unwrap();
        assert_eq!((first.events.len(), first.cursor.as_str()), (0, "s=a;i=8"));
        let next = since_journal(Some("s=a;i=8"), &run).unwrap();
        assert_eq!(next.events.len(), 7);
        let calls = seen.lock().unwrap();
        assert!(calls[1].contains(&"--after-cursor=s=a;i=8".to_string()), "{:?}", calls[1]);
        assert!(calls[1].iter().any(|a| a.starts_with("--output-fields=")), "{:?}", calls[1]);
        assert!(
            !calls[1].iter().any(|a| a.starts_with("SYSLOG_IDENTIFIER")),
            "no match that skips the cursor's neighbour"
        );
        assert!(calls.iter().all(|c| c[0] == "journalctl"), "only journalctl");
        drop(calls);
        // a cursor that could be taken for an option, or isn't ours, never reaches it
        for bad in ["--output=export", "a b", "s=a;i=1\n--x", "", &"x".repeat(300)] {
            assert!(since_journal(Some(bad), &run).is_err(), "{bad:?}");
        }
        assert_eq!(seen.lock().unwrap().len(), 2, "nothing was run for them");
    }

    #[test]
    fn a_log_file_is_read_from_the_cursor_and_survives_rotation() {
        let dir = std::env::temp_dir().join(format!("rackhand-authfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("auth.log");
        let line =
            |n: u32| format!("Nov 23 09:00:0{n} web sshd[1]: Accepted publickey for u{n} from 192.0.2.1 port 1 ssh2\n");
        std::fs::write(&log, line(1)).unwrap();
        let start = since_file(&log, None, 2026).unwrap();
        assert!(start.events.is_empty(), "history isn't replayed");
        let mut text = std::fs::read_to_string(&log).unwrap();
        text.push_str(&line(2));
        text.push_str("Nov 23 09:00:03 web sshd[1]: Accepted pub"); // a line still being written
        std::fs::write(&log, &text).unwrap();
        let second = since_file(&log, Some(&start.cursor), 2026).unwrap();
        assert_eq!(second.events.iter().map(|e| e.user.as_str()).collect::<Vec<_>>(), ["u2"]);
        let again = since_file(&log, Some(&second.cursor), 2026).unwrap();
        assert!(again.events.is_empty(), "nothing twice");
        // rotated: a new file with a new inode is read from its start
        std::fs::rename(&log, dir.join("auth.log.1")).unwrap();
        std::fs::write(&log, line(4)).unwrap();
        let rotated = since_file(&log, Some(&second.cursor), 2026).unwrap();
        assert_eq!(rotated.events.iter().map(|e| e.user.as_str()).collect::<Vec<_>>(), ["u4"]);
        assert!(since_file(&log, Some("not-a-cursor"), 2026).is_err());
    }
}
