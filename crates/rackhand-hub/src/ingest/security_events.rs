//! Security events (7.6.6, FR-5, FR-6, G3, AC15, AC16): what a probe reports about a machine, each with the severity the
//! design gives it, and the three that need a history: a login from a new source, a burst of failed logins, a root login.

use std::collections::{BTreeMap, HashSet, VecDeque};

use super::events::Severity;

/// Files whose change is critical (7.6.6); any other listed file's is a warning.
pub fn critical_file(path: &str) -> bool {
    const EXACT: [&str; 7] = [
        "/etc/sudoers",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/rackhand/commands.json",
        "/etc/rackhand-probe/probe.toml",
    ];
    EXACT.contains(&path)
        || path.starts_with("/etc/sudoers.d/")
        || path == "/etc/ssh/sshd_config"
        || path.starts_with("/etc/ssh/sshd_config.d/")
        || path.starts_with("/etc/pam.d/")
        || (path.starts_with("/etc/security/") && path.ends_with(".conf"))
}

/// The groups a user can be added to that give administrative rights.
fn admin_group(group: &str) -> bool {
    matches!(group, "sudo" | "wheel" | "admin" | "root" | "Administrators")
}

/// A probe event's severity by its kind and fields, or `None` for a kind the hub doesn't know (7.6.6). `auth.login` and
/// `auth.failed` are facts the derived events below are made from: info.
pub fn severity(kind: &str, fields: &BTreeMap<String, String>) -> Option<Severity> {
    let field = |k: &str| fields.get(k).map(String::as_str).unwrap_or("");
    Some(match kind {
        // Linux: under /tmp, /var/tmp or /dev/shm, or deleted. Windows (a path with a drive letter): under %TEMP% or Downloads.
        "proc.exec_from_tmp" => {
            let exe = field("exe").as_bytes();
            if exe.get(1) == Some(&b':') && exe.first().is_some_and(u8::is_ascii_alphabetic) {
                Severity::Warning
            } else {
                Severity::Critical
            }
        }
        "port.new_listener" => Severity::Warning,
        "conn.overflow" | "series_cap_reached" | "auth.login" | "auth.failed" => Severity::Info,
        "helper_version_mismatch" => Severity::Warning,
        "auth.keys_changed" => Severity::Critical,
        "file.changed" => {
            if critical_file(field("path")) {
                Severity::Critical
            } else {
                Severity::Warning
            }
        }
        // UID 0, or already in an administrative group when it is made
        "user.added" => {
            if field("detail") == "uid=0" || admin_group(field("group")) {
                Severity::Critical
            } else {
                Severity::Warning
            }
        }
        "group.changed" => {
            if admin_group(field("detail")) {
                Severity::Critical
            } else {
                Severity::Info
            }
        }
        _ => return None,
    })
}

/// More than this many failed logins in [`BURST_WINDOW_MS`] is `auth.failed_burst`.
pub const BURST_FAILURES: usize = 20;
pub const BURST_WINDOW_MS: i64 = 5 * 60_000;

/// What the hub remembers of a machine's logins.
#[derive(Debug, Default)]
pub struct Logins {
    /// `(user, source address)` pairs a login has come from.
    seen: HashSet<(String, String)>,
    failures: VecDeque<i64>,
    /// Whether the burst has been told of; reset when the failures fall back under the limit.
    told: bool,
    /// Whether `seen` has been filled from what was stored.
    pub loaded: bool,
}

/// An event made from a login or a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derived {
    pub kind: &'static str,
    pub severity: Severity,
}

impl Logins {
    /// Sources already known, from the logins stored before.
    pub fn learn(&mut self, user: &str, source: &str) {
        self.seen.insert((user.to_string(), source.to_string()));
        self.loaded = true;
    }

    /// A login: from a source this user has not come from before is a warning, and a login as root is one too.
    pub fn login(&mut self, fields: &BTreeMap<String, String>) -> Vec<Derived> {
        let user = fields.get("user").cloned().unwrap_or_default();
        let source = fields.get("source_ip").cloned().unwrap_or_default();
        let mut out = Vec::new();
        // a machine's first logins are how its sources are learned, not news
        let learning = self.seen.is_empty();
        if user == "root" {
            out.push(Derived { kind: "auth.root_login", severity: Severity::Warning });
        }
        if !source.is_empty() && self.seen.insert((user, source)) && !learning {
            out.push(Derived { kind: "auth.login_new_source", severity: Severity::Warning });
        }
        out
    }

    /// A failed login at `at_ms`; the burst is told of once, when the 21st failure within 5 minutes arrives.
    pub fn failure(&mut self, at_ms: i64) -> Option<Derived> {
        self.failures.push_back(at_ms);
        while self.failures.front().is_some_and(|t| at_ms - t > BURST_WINDOW_MS) {
            self.failures.pop_front();
        }
        if self.failures.len() <= BURST_FAILURES {
            self.told = false;
            return None;
        }
        if self.told {
            return None;
        }
        self.told = true;
        Some(Derived { kind: "auth.failed_burst", severity: Severity::Warning })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// Each row of the design's table (7.6.6).
    #[test]
    fn severity_table_matches_design() {
        use Severity::{Critical, Info, Warning};
        let cases: Vec<(&str, BTreeMap<String, String>, Option<Severity>)> = vec![
            ("conn.known_bad", f(&[]), None), // the hub's own scoring raises it, not a probe
            ("proc.exec_from_tmp", f(&[("exe", "/tmp/x")]), Some(Critical)),
            // Windows: an executable under %TEMP% or Downloads is a warning, as a path with a drive letter says
            ("proc.exec_from_tmp", f(&[("exe", r"C:\Users\alice\AppData\Local\Temp\setup.exe")]), Some(Warning)),
            ("proc.exec_from_tmp", f(&[("exe", r"D:\Users\bob\Downloads\tool.exe")]), Some(Warning)),
            ("proc.exec_from_tmp", f(&[("exe", "/home/u/c:/odd")]), Some(Critical)),
            ("user.added", f(&[("detail", "uid=0")]), Some(Critical)),
            ("user.added", f(&[("detail", "uid=1001")]), Some(Warning)),
            ("group.changed", f(&[("detail", "sudo")]), Some(Critical)),
            ("group.changed", f(&[("detail", "wheel")]), Some(Critical)),
            ("group.changed", f(&[("detail", "docker")]), Some(Info)),
            ("auth.keys_changed", f(&[("path", "/home/u/.ssh/authorized_keys")]), Some(Critical)),
            ("file.changed", f(&[("path", "/etc/sudoers.d/x")]), Some(Critical)),
            ("file.changed", f(&[("path", "/etc/sudoers")]), Some(Critical)),
            ("file.changed", f(&[("path", "/etc/ssh/sshd_config")]), Some(Critical)),
            ("file.changed", f(&[("path", "/etc/pam.d/sshd")]), Some(Critical)),
            ("file.changed", f(&[("path", "/etc/passwd")]), Some(Critical)),
            ("file.changed", f(&[("path", "/etc/shadow")]), Some(Critical)),
            ("file.changed", f(&[("path", "/etc/group")]), Some(Critical)),
            ("file.changed", f(&[("path", "/etc/rackhand/commands.json")]), Some(Critical)),
            ("file.changed", f(&[("path", "/etc/rackhand-probe/probe.toml")]), Some(Critical)),
            ("file.changed", f(&[("path", "/etc/hosts")]), Some(Warning)),
            ("file.changed", f(&[("path", "/etc/crontab")]), Some(Warning)),
            ("file.changed", f(&[("path", "/usr/bin/sudo")]), Some(Warning)),
            ("port.new_listener", f(&[("port", "4444")]), Some(Warning)),
            ("kernel.panic", f(&[]), None),
        ];
        for (kind, fields, want) in cases {
            assert_eq!(severity(kind, &fields), want, "{kind} {fields:?}");
        }
    }

    #[test]
    fn a_login_from_a_new_source_or_as_root_is_a_warning() {
        let mut l = Logins::default();
        l.learn("alice", "192.0.2.1");
        assert!(l.login(&f(&[("user", "alice"), ("source_ip", "192.0.2.1")])).is_empty(), "a source it has seen");
        let new = l.login(&f(&[("user", "alice"), ("source_ip", "198.51.100.7")]));
        assert_eq!(new, [Derived { kind: "auth.login_new_source", severity: Severity::Warning }]);
        assert!(l.login(&f(&[("user", "alice"), ("source_ip", "198.51.100.7")])).is_empty(), "known from then on");
        // the same address for another user is new for that user
        assert_eq!(l.login(&f(&[("user", "bob"), ("source_ip", "192.0.2.1")])).len(), 1);
        let root = l.login(&f(&[("user", "root"), ("source_ip", "192.0.2.1")]));
        assert!(root.iter().any(|d| d.kind == "auth.root_login" && d.severity == Severity::Warning), "{root:?}");
    }

    #[test]
    fn failed_burst_over_20_in_5_min() {
        let mut l = Logins::default();
        let mut told = Vec::new();
        for i in 0..20 {
            told.extend(l.failure(i * 1000));
        }
        assert!(told.is_empty(), "20 failures are not over 20");
        assert_eq!(
            l.failure(20_000),
            Some(Derived { kind: "auth.failed_burst", severity: Severity::Warning }),
            "the 21st"
        );
        assert_eq!(l.failure(21_000), None, "told once");
        // spread over more than 5 minutes it never reaches the limit
        let mut slow = Logins::default();
        for i in 0..100 {
            assert_eq!(slow.failure(i * 20_000), None, "one in 20 s is 15 in 5 minutes");
        }
        // after the burst has passed, a new one is told again
        assert_eq!(l.failure(20_000 + BURST_WINDOW_MS + 1), None);
        let mut again = None;
        for i in 0..25 {
            again = again.or(l.failure(1_000_000 + i * 100));
        }
        assert!(again.is_some());
    }
}
