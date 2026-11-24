//! What is not an event (7.6.6, E48): the exemptions, each as narrow as the design writes it. A container runtime's own
//! `memfd:` executables, a package the running patch job upgraded, the hub's own keys and lists while the jobs that write
//! them run, and `probe.toml` while a machine enrolls or changes level. Nothing is exempt for another user's keys or accounts.

use std::collections::BTreeMap;

/// The jobs that write the hub's keys, sudoers file and command list on a machine.
const KEY_JOBS: [&str; 3] = ["sudoers-refresh", "keys-rotate", "unenroll"];
/// Parents that are container runtime internals.
const RUNTIME_PARENTS: [&str; 4] = ["runc", "crun", "containerd-shim", "conmon"];
/// The hub's own users, whose keys it writes.
const HUB_HOMES: [&str; 2] = ["/home/rackhand/", "/home/rackhand-ai/"];
const COMMANDS: &str = "/etc/rackhand/commands.json";
const PROBE_TOML: &str = "/etc/rackhand-probe/probe.toml";
const HUB_SUDOERS: &str = "/etc/sudoers.d/rackhand";

/// What the hub knows that the exemptions turn on.
pub trait Facts {
    /// The id of a job running on the machine whose name is one of `names` (a name ending in `*` matches a prefix).
    fn running_job(&self, machine: &str, names: &[&str]) -> Option<String>;
    /// The machine is enrolling or changing its access level (its join token is in use).
    fn enrolling(&self, machine: &str) -> bool;
    /// `sha256` is the hash of a command list the hub sent the machine.
    fn sent_commands(&self, machine: &str, sha256: &str) -> bool;
    /// The file belongs to a package the job upgraded (`dpkg -S`, `apk info -W`).
    fn upgraded_by(&self, machine: &str, job: &str, path: &str) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// An event, with the severity it has.
    Raise,
    /// Nothing: not an event.
    Exempt,
    /// An event at info, naming the job that explains it.
    Info { job: String },
}

fn runtime_internal(fields: &BTreeMap<String, String>) -> bool {
    let exe = fields.get("exe").map(String::as_str).unwrap_or("");
    let parent = fields.get("parent").map(String::as_str).unwrap_or("");
    let parent = parent.rsplit('/').next().unwrap_or(parent);
    exe.trim_start_matches('/').starts_with("memfd:") && RUNTIME_PARENTS.iter().any(|p| parent.starts_with(p))
}

fn hub_user_file(path: &str) -> bool {
    HUB_HOMES.iter().any(|h| path.starts_with(h))
}

/// Whether a probe's event is exempt, and how.
pub fn judge(machine: &str, kind: &str, fields: &BTreeMap<String, String>, facts: &dyn Facts) -> Verdict {
    let path = fields.get("path").map(String::as_str).unwrap_or("");
    match kind {
        "proc.exec_from_tmp" if runtime_internal(fields) => Verdict::Exempt,
        "auth.keys_changed" | "file.changed" if hub_user_file(path) => {
            if facts.running_job(machine, &KEY_JOBS).is_some() || facts.enrolling(machine) {
                Verdict::Exempt
            } else {
                Verdict::Raise
            }
        }
        "file.changed" if path == HUB_SUDOERS => {
            if facts.running_job(machine, &KEY_JOBS).is_some() || facts.enrolling(machine) {
                Verdict::Exempt
            } else {
                Verdict::Raise
            }
        }
        "file.changed" if path == COMMANDS => {
            let sha = fields.get("new_sha256").map(String::as_str).unwrap_or("");
            if !sha.is_empty() && facts.sent_commands(machine, sha) { Verdict::Exempt } else { Verdict::Raise }
        }
        "file.changed" if path == PROBE_TOML => {
            if facts.enrolling(machine) {
                Verdict::Exempt
            } else {
                Verdict::Raise
            }
        }
        "file.changed" => match facts.running_job(machine, &["patch-*"]) {
            Some(job) if facts.upgraded_by(machine, &job, path) => Verdict::Info { job },
            _ => Verdict::Raise,
        },
        _ => Verdict::Raise,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        job: Option<(String, String)>,
        enrolling: bool,
        sent: Vec<String>,
        owned: Vec<String>,
    }

    impl Facts for Fake {
        fn running_job(&self, _m: &str, names: &[&str]) -> Option<String> {
            let (name, id) = self.job.clone()?;
            names.iter().any(|n| n.strip_suffix('*').map_or(*n == name, |p| name.starts_with(p))).then_some(id)
        }
        fn enrolling(&self, _m: &str) -> bool {
            self.enrolling
        }
        fn sent_commands(&self, _m: &str, sha: &str) -> bool {
            self.sent.iter().any(|s| s == sha)
        }
        fn upgraded_by(&self, _m: &str, _job: &str, path: &str) -> bool {
            self.owned.iter().any(|p| p == path)
        }
    }

    fn f(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn job(name: &str) -> Fake {
        Fake { job: Some((name.into(), "J1".into())), ..Fake::default() }
    }

    #[test]
    fn memfd_runc_child_exempt() {
        let none = Fake::default();
        for parent in
            ["/usr/bin/runc", "/usr/sbin/runc", "/usr/bin/crun", "/usr/bin/containerd-shim-runc-v2", "/usr/bin/conmon"]
        {
            let fields = f(&[("exe", "/memfd:runc_cloned:/proc/self/exe (deleted)"), ("parent", parent)]);
            assert_eq!(judge("m", "proc.exec_from_tmp", &fields, &none), Verdict::Exempt, "{parent}");
        }
        // a memfd program whose parent is something else, or any other program from /tmp under runc, is an event
        let other = f(&[("exe", "/memfd:x (deleted)"), ("parent", "/usr/bin/bash")]);
        assert_eq!(judge("m", "proc.exec_from_tmp", &other, &none), Verdict::Raise);
        let tmp = f(&[("exe", "/tmp/evil"), ("parent", "/usr/bin/runc")]);
        assert_eq!(judge("m", "proc.exec_from_tmp", &tmp, &none), Verdict::Raise);
    }

    #[test]
    fn patch_job_package_owned_file_change_is_info_with_job_id() {
        let mut facts = job("patch-debian");
        facts.owned = vec!["/usr/bin/sudo".into()];
        let owned = f(&[("path", "/usr/bin/sudo"), ("new_sha256", "x")]);
        assert_eq!(judge("m", "file.changed", &owned, &facts), Verdict::Info { job: "J1".into() });
        // a file the job's packages don't own is an event, and so is the same file when no patch job runs
        let other = f(&[("path", "/etc/hosts")]);
        assert_eq!(judge("m", "file.changed", &other, &facts), Verdict::Raise);
        let idle = Fake { owned: vec!["/usr/bin/sudo".into()], ..Fake::default() };
        assert_eq!(judge("m", "file.changed", &owned, &idle), Verdict::Raise);
        // another kind of job explains nothing
        let mut restart = job("service-restart");
        restart.owned = vec!["/usr/bin/sudo".into()];
        assert_eq!(judge("m", "file.changed", &owned, &restart), Verdict::Raise);
    }

    #[test]
    fn key_change_exempt_only_for_hub_users_in_named_jobs() {
        let hub_keys = f(&[("path", "/home/rackhand/.ssh/authorized_keys")]);
        let ai_keys = f(&[("path", "/home/rackhand-ai/.ssh/authorized_keys")]);
        let other = f(&[("path", "/home/alice/.ssh/authorized_keys")]);
        for name in ["keys-rotate", "sudoers-refresh", "unenroll"] {
            let facts = job(name);
            for kind in ["auth.keys_changed", "file.changed"] {
                assert_eq!(judge("m", kind, &hub_keys, &facts), Verdict::Exempt, "{name} {kind}");
                assert_eq!(judge("m", kind, &ai_keys, &facts), Verdict::Exempt);
                assert_eq!(
                    judge("m", kind, &other, &facts),
                    Verdict::Raise,
                    "another user's keys during {name} are still an event"
                );
            }
        }
        assert_eq!(
            judge("m", "auth.keys_changed", &hub_keys, &job("patch-debian")),
            Verdict::Raise,
            "not during another job"
        );
        assert_eq!(judge("m", "auth.keys_changed", &hub_keys, &Fake::default()), Verdict::Raise, "not outside a job");
        let enrolling = Fake { enrolling: true, ..Fake::default() };
        assert_eq!(judge("m", "auth.keys_changed", &hub_keys, &enrolling), Verdict::Exempt, "enrollment writes them");
        assert_eq!(judge("m", "auth.keys_changed", &other, &enrolling), Verdict::Raise);
    }

    #[test]
    fn commands_json_exempt_only_when_hash_matches_sent_list() {
        let facts = Fake { sent: vec!["good".into()], ..Fake::default() };
        let sent = f(&[("path", "/etc/rackhand/commands.json"), ("new_sha256", "good")]);
        let other = f(&[("path", "/etc/rackhand/commands.json"), ("new_sha256", "bad")]);
        assert_eq!(judge("m", "file.changed", &sent, &facts), Verdict::Exempt);
        assert_eq!(judge("m", "file.changed", &other, &facts), Verdict::Raise, "a different hash is an event");
        assert_eq!(
            judge("m", "file.changed", &f(&[("path", "/etc/rackhand/commands.json")]), &facts),
            Verdict::Raise,
            "no hash"
        );
        // a running job doesn't excuse it
        let during = Fake { sent: vec![], ..job("sudoers-refresh") };
        assert_eq!(judge("m", "file.changed", &sent, &during), Verdict::Raise);
    }

    #[test]
    fn probe_toml_exempt_only_during_enrollment_and_level_change() {
        let change = f(&[("path", "/etc/rackhand-probe/probe.toml")]);
        assert_eq!(judge("m", "file.changed", &change, &Fake::default()), Verdict::Raise);
        assert_eq!(judge("m", "file.changed", &change, &job("keys-rotate")), Verdict::Raise);
        let enrolling = Fake { enrolling: true, ..Fake::default() };
        assert_eq!(judge("m", "file.changed", &change, &enrolling), Verdict::Exempt);
    }
}
