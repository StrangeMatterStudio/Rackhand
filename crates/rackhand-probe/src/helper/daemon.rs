//! `rackhand-probe helper`: the root helper's process (7.3.3). It serves the socket to the `rackhand-probe` user and
//! refreshes the package lists at start and every 6 hours with the fixed command set at the lowest priority.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::packages::{Manager, REFRESH_MS, low_priority};
use super::server::{Helper, bind, serve};

/// The probe user's uid and gid, from `/etc/passwd`.
pub fn probe_user(passwd: &str, name: &str) -> Option<(u32, u32)> {
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.first() == Some(&name)).then(|| Some((f.get(2)?.parse().ok()?, f.get(3)?.parse().ok()?)))?
    })
}

/// How often the critical files are hashed whether or not anything told the helper they changed.
const HASH_EVERY: Duration = Duration::from_secs(300);
/// A change is acted on this long after the last event of a burst, so an editor's several writes are one hashing.
const SETTLE: Duration = Duration::from_millis(400);

/// Watches the directories of the critical files with inotify and hashes them again when anything in them changes
/// (FR-6). Runs on its own thread until the process ends.
#[cfg(target_os = "linux")]
fn watch_for_changes(helper: &super::server::Helper) {
    use rustix::fs::inotify::{CreateFlags, WatchFlags, add_watch, init};
    let flags = WatchFlags::CREATE
        | WatchFlags::MODIFY
        | WatchFlags::DELETE
        | WatchFlags::MOVED_FROM
        | WatchFlags::MOVED_TO
        | WatchFlags::ATTRIB
        | WatchFlags::CLOSE_WRITE;
    let Ok(fd) = init(CreateFlags::CLOEXEC) else {
        tracing::warn!("inotify isn't available: the critical files are hashed every 5 minutes only");
        return;
    };
    let mut watched: std::collections::HashSet<std::path::PathBuf> = std::collections::HashSet::new();
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 4096];
    let mut reader = rustix::fs::inotify::Reader::new(&fd, &mut buf);
    loop {
        for dir in helper.watch_dirs() {
            if watched.insert(dir.clone()) {
                if let Err(e) = add_watch(&fd, &dir, flags) {
                    tracing::debug!(dir = %dir.display(), error = %e, "not watched");
                }
            }
        }
        // wait for an event (the 5-minute hashing covers a watch that was missed), let the burst settle, take what is
        // queued, and hash once
        if let Err(e) = reader.next() {
            tracing::warn!(error = %e, "inotify stopped");
            return;
        }
        std::thread::sleep(SETTLE);
        while rustix::event::poll(
            &mut [rustix::event::PollFd::new(&fd, rustix::event::PollFlags::IN)],
            Some(&rustix::event::Timespec { tv_sec: 0, tv_nsec: 0 }),
        )
        .is_ok_and(|n| n > 0)
        {
            if reader.next().is_err() {
                break;
            }
        }
        helper.refresh_hashes();
    }
}

/// One refresh: the two fixed commands; the second one's output is the pending list.
pub fn refresh(
    root: &Path,
    run: &dyn Fn(&[String]) -> Result<String, String>,
) -> Result<rackhand_proto::helper::UpdateSummary, String> {
    let manager = Manager::detect(root).ok_or("no apt-get or apk on this machine")?;
    let [update, pending] = manager.commands();
    run(&low_priority(update))?;
    let output = run(&low_priority(pending))?;
    Ok(manager.parse(&output, root.join("var/run/reboot-required").exists()))
}

/// Runs a fixed command with a clean environment (the package managers need only `PATH`).
pub fn run_command(argv: &[String]) -> Result<String, String> {
    let (program, args) = argv.split_first().ok_or("empty command")?;
    let out = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{}: exit {:?}", argv.join(" "), out.status.code()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub socket: PathBuf,
    pub passwd: PathBuf,
    pub root: PathBuf,
    pub probe_user: String,
}

impl Default for Paths {
    fn default() -> Paths {
        Paths {
            socket: super::SOCKET.into(),
            passwd: "/etc/passwd".into(),
            root: "/".into(),
            probe_user: "rackhand-probe".into(),
        }
    }
}

/// Serves until the process is stopped.
pub async fn main(paths: Paths, version: &str) -> Result<(), String> {
    let passwd = std::fs::read_to_string(&paths.passwd).map_err(|e| format!("{}: {e}", paths.passwd.display()))?;
    let (uid, gid) = probe_user(&passwd, &paths.probe_user).ok_or(format!("no user {}", paths.probe_user))?;
    for problem in super::layout::enforce(&paths.root, (uid, gid)) {
        tracing::error!(%problem, "layout (7.3.3)");
    }
    let listener = bind(&paths.socket, Some(gid)).map_err(|e| format!("{}: {e}", paths.socket.display()))?;
    let helper = Helper::new(version);
    let h = helper.clone();
    let root = paths.root.clone();
    tokio::spawn(async move {
        loop {
            let r = root.clone();
            match tokio::task::spawn_blocking(move || refresh(&r, &run_command)).await {
                Ok(Ok(summary)) => h.set_updates(summary, now_ms()),
                Ok(Err(e)) => tracing::warn!(error = %e, "package lists"),
                Err(e) => tracing::warn!(error = %e, "package lists"),
            }
            tokio::time::sleep(Duration::from_millis(REFRESH_MS as u64)).await;
        }
    });
    // the critical files: hashed at start and every 5 minutes, and again when something in their directories changes
    let (h, root) = (helper.clone(), paths.root.clone());
    tokio::spawn(async move {
        loop {
            let hh = h.clone();
            match tokio::task::spawn_blocking(move || hh.refresh_hashes()).await {
                Ok(warnings) => {
                    warnings.iter().for_each(|w| tracing::warn!(warning = %w, "critical file list (7.8.4)"))
                }
                Err(e) => tracing::warn!(error = %e, "hashing the critical files"),
            }
            tokio::time::sleep(HASH_EVERY).await;
        }
    });
    #[cfg(target_os = "linux")]
    {
        let h = helper.clone();
        std::thread::spawn(move || watch_for_changes(&h));
    }
    let _ = root;
    serve(listener, uid, Arc::clone(&helper)).await;
    Ok(())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_user_from_passwd() {
        let passwd = "root:x:0:0::/root:/bin/sh\nrackhand-probe:x:998:997::/nonexistent:/usr/sbin/nologin\n";
        assert_eq!(probe_user(passwd, "rackhand-probe"), Some((998, 997)));
        assert_eq!(probe_user(passwd, "nobody"), None);
    }

    #[test]
    fn refresh_runs_only_the_fixed_commands() {
        let root = std::env::temp_dir().join(format!("rackhand-refresh-{}", std::process::id()));
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::write(root.join("usr/bin/apt-get"), "").unwrap();
        let ran = std::sync::Mutex::new(Vec::new());
        let run = |argv: &[String]| {
            ran.lock().unwrap().push(argv.join(" "));
            Ok("Inst openssl [1] (2 Debian-Security:12/stable-security [amd64])\n".to_string())
        };
        let s = refresh(&root, &run).unwrap();
        assert_eq!((s.pending, s.security), (1, 1));
        assert_eq!(
            *ran.lock().unwrap(),
            ["nice -n 19 ionice -c3 apt-get update -q", "nice -n 19 ionice -c3 apt-get -s -q upgrade"]
        );
    }
}
