//! `ProcessScan` (7.3.3, FR-5): the processes whose executable runs from `/tmp`, `/var/tmp` or `/dev/shm`, or has been
//! deleted since it started. Read from `/proc` by root, since another user's `exe` link is not readable by the probe; no
//! command line, environment or memory is read.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rackhand_proto::helper::ProcInfo;

/// Where an executable has no business running from.
const TEMP_DIRS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];
const DELETED: &str = " (deleted)";
/// The most processes one answer lists.
pub const MAX_PROCESSES: usize = 500;

/// Whether an `exe` link points somewhere a process shouldn't run from.
pub fn suspicious(exe: &str) -> bool {
    exe.ends_with(DELETED) || TEMP_DIRS.iter().any(|d| exe.starts_with(d))
}

/// The user name of a uid from `passwd`; the number when it has none.
pub fn user_name(passwd: &str, uid: u32) -> String {
    passwd
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.get(2).and_then(|u| u.parse::<u32>().ok()) == Some(uid)).then(|| f[0].to_string())
        })
        .unwrap_or_else(|| uid.to_string())
}

/// The parent pid and start time (in clock ticks since boot) from `/proc/<pid>/stat`: the fields after the command's
/// closing parenthesis, which the command itself may contain.
pub fn stat_fields(stat: &str) -> Option<(u32, u64)> {
    let after = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after.split_whitespace().collect();
    // state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime priority nice
    // threads itrealvalue starttime
    Some((fields.get(1)?.parse().ok()?, fields.get(19)?.parse().ok()?))
}

/// The processes of `proc` (a `/proc`) that run from a temporary directory or a deleted file.
pub fn scan(proc: &Path, passwd: &str, boot_ms: i64, ticks_per_second: i64) -> Vec<ProcInfo> {
    let Ok(entries) = std::fs::read_dir(proc) else { return Vec::new() };
    let mut out = Vec::new();
    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
        let dir = e.path();
        let Ok(exe) = std::fs::read_link(dir.join("exe")) else { continue };
        let exe = exe.to_string_lossy().into_owned();
        if !suspicious(&exe) {
            continue;
        }
        let uid = std::fs::metadata(&dir).map_or(0, |m| m.uid());
        let (ppid, ticks) =
            std::fs::read_to_string(dir.join("stat")).ok().and_then(|s| stat_fields(&s)).unwrap_or((0, 0));
        let started = boot_ms + (ticks as i64) * 1000 / ticks_per_second.max(1);
        out.push(ProcInfo { pid, ppid, exe, user: user_name(passwd, uid), started_at_ms: started });
    }
    out.sort_by_key(|p| p.pid);
    out.truncate(MAX_PROCESSES);
    out
}

/// The machine's boot time in milliseconds, from `btime` in `/proc/stat`.
pub fn boot_ms(proc_stat: &str) -> i64 {
    proc_stat.lines().find_map(|l| l.strip_prefix("btime ")?.trim().parse::<i64>().ok()).unwrap_or(0) * 1000
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    /// A fake `/proc` with these processes: `(pid, exe)`.
    fn proc(name: &str, procs: &[(u32, &str)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rackhand-proc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (pid, exe) in procs {
            let p = dir.join(pid.to_string());
            std::fs::create_dir_all(&p).unwrap();
            symlink(exe, p.join("exe")).unwrap();
            // `(cmd with ) parens)` and a start time of 500 ticks
            let stat = format!(
                "{pid} (my (odd) cmd) S 1 {pid} {pid} 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 500 1000 100 18446744073709551615"
            );
            std::fs::write(p.join("stat"), stat).unwrap();
        }
        std::fs::create_dir_all(dir.join("self")).unwrap();
        std::fs::create_dir_all(dir.join("net")).unwrap();
        dir
    }

    #[test]
    fn finds_exe_in_tmp_vartmp_devshm_and_deleted() {
        let dir = proc(
            "scan",
            &[
                (100, "/tmp/evil"),
                (101, "/usr/bin/curl"),
                (102, "/usr/bin/old-version (deleted)"),
                (103, "/dev/shm/payload"),
                (104, "/var/tmp/x/y"),
                (105, "/opt/tmpfs/not-a-temp-dir"),
                (106, "/tmpfile"),
            ],
        );
        let me = std::fs::metadata(&dir).unwrap().uid();
        let passwd = format!("root:x:0:0::/root:/bin/sh\nalice:x:{me}:{me}::/home/alice:/bin/sh\n");
        let found = scan(&dir, &passwd, 1_000_000, 100);
        assert_eq!(
            found.iter().map(|p| (p.pid, p.exe.as_str())).collect::<Vec<_>>(),
            [
                (100, "/tmp/evil"),
                (102, "/usr/bin/old-version (deleted)"),
                (103, "/dev/shm/payload"),
                (104, "/var/tmp/x/y"),
            ]
        );
        assert!(found.iter().all(|p| p.ppid == 1 && p.user == "alice"), "{found:?}");
        assert_eq!(found[0].started_at_ms, 1_000_000 + 5_000, "500 ticks at 100 Hz after boot");
        assert_eq!(boot_ms("cpu 1 2 3\nbtime 1795000000\n"), 1_795_000_000_000);
        assert_eq!(user_name("root:x:0:0\n", 77), "77", "a uid with no name is the number");
        assert_eq!(stat_fields("1 (a b) S 2 3"), None, "too short");
    }
}
