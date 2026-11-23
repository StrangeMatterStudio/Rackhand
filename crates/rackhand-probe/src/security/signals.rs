//! What the root helper's scans become in reports (FR-5, FR-6, 7.6.6): a change to a critical file (`file.changed`, and
//! `auth.keys_changed` for an `authorized_keys`), and the authentication events (`auth.login`, `auth.failed`, `user.added`,
//! `group.changed`). The probe sends the facts; the hub gives each its severity and decides what is new (7.6.6).

use std::collections::BTreeMap;

use rackhand_proto::helper::{AuthEvent, AuthKind, FileHash};
use rackhand_proto::probe::ProbeEvent;

use crate::helper::client::HelperClient;

pub const FILE_CHANGED: &str = "file.changed";
pub const KEYS_CHANGED: &str = "auth.keys_changed";

fn event(kind: &str, at_ms: i64, fields: &[(&str, String)]) -> ProbeEvent {
    ProbeEvent { kind: kind.into(), at_ms, fields: fields.iter().map(|(k, v)| (k.to_string(), v.clone())).collect() }
}

fn is_keys_file(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.starts_with("authorized_keys") || name == "administrators_authorized_keys"
}

/// The critical files as last seen. The first look only learns them.
#[derive(Debug, Default)]
pub struct FileWatch {
    last: Option<BTreeMap<String, FileHash>>,
}

impl FileWatch {
    pub fn observe(&mut self, now: Vec<FileHash>, at_ms: i64) -> Vec<ProbeEvent> {
        let now: BTreeMap<String, FileHash> = now.into_iter().map(|h| (h.path.clone(), h)).collect();
        let Some(last) = self.last.replace(now.clone()) else { return Vec::new() };
        let mut events = Vec::new();
        let mut paths: Vec<&String> = last.keys().chain(now.keys()).collect();
        paths.sort();
        paths.dedup();
        for path in paths {
            let (old, new) = (last.get(path), now.get(path));
            let had = old.is_some_and(|h| h.exists);
            let has = new.is_some_and(|h| h.exists);
            let change = match (had, has) {
                (false, false) => continue,
                (false, true) => "created",
                (true, false) => "removed",
                (true, true) => {
                    let missing = FileHash::default_missing();
                    let (o, n) = (old.unwrap_or(&missing), new.unwrap_or(&missing));
                    if o.sha256 != n.sha256 {
                        "modified"
                    } else if (o.mode, o.uid, o.gid) != (n.mode, n.uid, n.gid) {
                        "attributes"
                    } else {
                        continue;
                    }
                }
            };
            let sha = |h: Option<&FileHash>| h.and_then(|h| h.sha256.clone()).unwrap_or_default();
            let fields = [
                ("path", path.clone()),
                ("change", change.to_string()),
                ("old_sha256", sha(old)),
                ("new_sha256", sha(new)),
            ];
            events.push(event(FILE_CHANGED, at_ms, &fields));
            if is_keys_file(path) && change != "attributes" {
                events.push(event(KEYS_CHANGED, at_ms, &[("path", path.clone()), ("change", change.to_string())]));
            }
        }
        events
    }
}

trait Missing {
    fn default_missing() -> FileHash;
}

impl Missing for FileHash {
    fn default_missing() -> FileHash {
        FileHash { path: String::new(), exists: false, sha256: None, mode: 0, uid: 0, gid: 0, mtime_ms: 0 }
    }
}

/// An authentication event as a probe event.
pub fn auth_event(e: &AuthEvent) -> Option<ProbeEvent> {
    let mut fields = vec![("user", e.user.clone())];
    if let Some(ip) = &e.source_ip {
        fields.push(("source_ip", ip.clone()));
    }
    if let Some(m) = &e.method {
        fields.push(("method", m.clone()));
    }
    if let Some(d) = &e.detail {
        fields.push(("detail", d.clone()));
    }
    let kind = match e.kind {
        AuthKind::SshLogin | AuthKind::Logon => "auth.login",
        AuthKind::SshFailed => "auth.failed",
        AuthKind::UserAdded => "user.added",
        AuthKind::GroupChanged => "group.changed",
        // a person using sudo or su is not itself an event; the hub counts logins and changes
        AuthKind::Sudo | AuthKind::Su => return None,
    };
    Some(event(kind, e.at_ms, &fields))
}

/// The helper's file hashes and authentication events, asked for on a schedule.
#[derive(Debug, Default)]
pub struct Signals {
    files: FileWatch,
    cursor: Option<String>,
}

impl Signals {
    /// One round: what changed since the last.
    pub async fn poll(&mut self, helper: &HelperClient, now_ms: i64) -> Vec<ProbeEvent> {
        let mut out = Vec::new();
        if let Ok(hashes) = helper.hash_files().await {
            out.extend(self.files.observe(hashes, now_ms));
        }
        if let Ok((events, cursor)) = helper.auth_events_since(self.cursor.as_deref()).await {
            self.cursor = Some(cursor).filter(|c| !c.is_empty()).or(self.cursor.take());
            out.extend(events.iter().filter_map(auth_event));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, sha: &str, mode: u32) -> FileHash {
        FileHash { path: path.into(), exists: true, sha256: Some(sha.into()), mode, uid: 0, gid: 0, mtime_ms: 0 }
    }

    fn gone(path: &str) -> FileHash {
        FileHash { path: path.into(), exists: false, sha256: None, mode: 0, uid: 0, gid: 0, mtime_ms: 0 }
    }

    #[test]
    fn a_changed_critical_file_is_one_event_and_a_changed_keys_file_two() {
        let mut w = FileWatch::default();
        let base = vec![
            file("/etc/passwd", "a", 0o644),
            file("/home/u/.ssh/authorized_keys", "k1", 0o600),
            gone("/etc/sudoers.d/x"),
        ];
        assert!(w.observe(base.clone(), 1).is_empty(), "the first look learns");
        assert!(w.observe(base, 2).is_empty(), "nothing changed");
        let now = vec![
            file("/etc/passwd", "b", 0o644),
            file("/home/u/.ssh/authorized_keys", "k2", 0o600),
            file("/etc/sudoers.d/x", "s", 0o440),
        ];
        let events = w.observe(now, 3);
        let kinds: Vec<(&str, &str)> = events.iter().map(|e| (e.kind.as_str(), e.fields["path"].as_str())).collect();
        assert_eq!(
            kinds,
            [
                (FILE_CHANGED, "/etc/passwd"),
                (FILE_CHANGED, "/etc/sudoers.d/x"),
                (FILE_CHANGED, "/home/u/.ssh/authorized_keys"),
                (KEYS_CHANGED, "/home/u/.ssh/authorized_keys"),
            ]
        );
        assert_eq!(events[0].fields["change"], "modified");
        assert_eq!((events[0].fields["old_sha256"].as_str(), events[0].fields["new_sha256"].as_str()), ("a", "b"));
        assert_eq!(events[1].fields["change"], "created");
        // the file's own bytes are never in an event; only its hashes
        assert!(
            events
                .iter()
                .all(|e| e.fields.keys().all(|k| ["path", "change", "old_sha256", "new_sha256"].contains(&k.as_str())))
        );
        let removed = w.observe(vec![file("/etc/passwd", "b", 0o600)], 4);
        let by: Vec<(&str, &str)> =
            removed.iter().map(|e| (e.fields["path"].as_str(), e.fields["change"].as_str())).collect();
        assert!(by.contains(&("/etc/passwd", "attributes")) && by.contains(&("/etc/sudoers.d/x", "removed")), "{by:?}");
        assert!(removed.iter().any(|e| e.kind == KEYS_CHANGED && e.fields["change"] == "removed"));
    }

    #[test]
    fn authentication_events_become_probe_events() {
        let e = |kind, user: &str, ip: Option<&str>, detail: Option<&str>| AuthEvent {
            at_ms: 9,
            kind,
            user: user.into(),
            source_ip: ip.map(Into::into),
            method: Some("publickey".into()),
            detail: detail.map(Into::into),
        };
        let login = auth_event(&e(AuthKind::SshLogin, "alice", Some("192.0.2.1"), None)).unwrap();
        assert_eq!(
            (login.kind.as_str(), login.at_ms, login.fields["source_ip"].as_str()),
            ("auth.login", 9, "192.0.2.1")
        );
        assert_eq!(auth_event(&e(AuthKind::SshFailed, "x", None, None)).unwrap().kind, "auth.failed");
        let added = auth_event(&e(AuthKind::UserAdded, "eve", None, Some("uid=0"))).unwrap();
        assert_eq!((added.kind.as_str(), added.fields["detail"].as_str()), ("user.added", "uid=0"));
        assert_eq!(auth_event(&e(AuthKind::GroupChanged, "eve", None, Some("sudo"))).unwrap().kind, "group.changed");
        assert!(auth_event(&e(AuthKind::Sudo, "alice", None, None)).is_none());
    }
}
