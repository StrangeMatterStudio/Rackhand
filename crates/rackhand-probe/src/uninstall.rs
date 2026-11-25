//! `rackhand-probe uninstall` (7.3.12): removes what Rackhand put on a machine: its services, the hub's users with
//! their keys, the sudoers file, the command list, the probe's state and its own files. Only root may run it; it takes
//! nothing from outside but `--after`, and touches only the paths in [`PATHS`].
//!
//! `--after N` is how the hub's `unenroll` runbook runs it: the command answers at once and starts a copy of itself that
//! waits N seconds, so the answer reaches the hub before the account it came through is gone.

use std::path::{Path, PathBuf};

/// Under the machine's root; the directory with the binary and the wrapper comes last. In `/etc/rackhand` only the
/// probe's own files: on the hub's own host the directory also holds the hub's master key, node key and settings.
pub const PATHS: &[&str] = &[
    "etc/sudoers.d/rackhand",
    "etc/rackhand/commands.json",
    "etc/rackhand/helper-extra-paths",
    "etc/rackhand-probe",
    "var/lib/rackhand-probe",
    "var/lib/rackhand-helper",
    "var/lib/rackhand-run",
    "run/rackhand-helper",
    "run/rackhand-probe",
    "etc/systemd/system/rackhand-probe.service",
    "etc/systemd/system/rackhand-probe-helper.service",
    "etc/init.d/rackhand-probe",
    "etc/init.d/rackhand-probe-helper",
    "usr/local/lib/rackhand",
];

/// Removed after the probe's files in it, when nothing else is left in it.
const SHARED_DIR: &str = "etc/rackhand";

/// The users the installer made.
pub const USERS: [&str; 3] = ["rackhand", "rackhand-ai", "rackhand-probe"];
const UNITS: [&str; 2] = ["rackhand-probe.service", "rackhand-probe-helper.service"];
const SERVICES: [&str; 2] = ["rackhand-probe", "rackhand-probe-helper"];
/// Where the copy that waits is started from.
const BIN: &str = "/usr/local/lib/rackhand/rackhand-probe";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UninstallError {
    #[error("uninstall needs root")]
    NotRoot,
    #[error("couldn't start the delayed uninstall: {0}")]
    Spawn(String),
}

#[derive(Debug, Clone)]
pub struct Options {
    /// `/` on a machine.
    pub root: PathBuf,
    pub after: Option<u64>,
    /// This is the copy that waits and then removes.
    pub delayed: bool,
}

/// What it does to the machine.
pub trait Host {
    fn euid(&self) -> u32;
    fn exists(&self, path: &Path) -> bool;
    /// A fixed command, no shell; whether it succeeded.
    fn run(&self, argv: &[&str]) -> bool;
    fn remove(&self, path: &Path);
    /// Removes a directory only when it is empty.
    fn remove_if_empty(&self, path: &Path);
    fn spawn_detached(&self, argv: &[String]) -> std::io::Result<()>;
    fn sleep(&self, seconds: u64);
}

pub fn uninstall(options: &Options, host: &dyn Host) -> Result<(), UninstallError> {
    if host.euid() != 0 {
        return Err(UninstallError::NotRoot);
    }
    if let (Some(seconds), false) = (options.after, options.delayed) {
        let argv = [BIN.to_string(), "uninstall".into(), "--delay".into(), seconds.to_string()];
        return host.spawn_detached(&argv).map_err(|e| UninstallError::Spawn(e.to_string()));
    }
    if let Some(seconds) = options.after {
        host.sleep(seconds);
    }
    let systemd = host.exists(&options.root.join("run/systemd/system"));
    // the services first: the probe stops reporting and the helper stops answering
    if systemd {
        host.run(&["systemctl", "disable", "--now", UNITS[0], UNITS[1]]);
    } else {
        for s in SERVICES {
            host.run(&["rc-service", s, "stop"]);
            host.run(&["rc-update", "del", s, "default"]);
        }
    }
    // then the way in: sudoers and the command list go before the users
    let (last, rest) = PATHS.split_last().map(|(l, r)| (*l, r)).unwrap_or(("", &[]));
    for rel in rest {
        let path = options.root.join(rel);
        if host.exists(&path) {
            host.remove(&path);
        }
    }
    let shared = options.root.join(SHARED_DIR);
    if host.exists(&shared) {
        host.remove_if_empty(&shared);
    }
    for user in USERS {
        if systemd {
            host.run(&["userdel", "--force", "--remove", user]);
        } else {
            host.run(&["deluser", "--remove-home", user]);
        }
    }
    if systemd {
        host.run(&["systemctl", "daemon-reload"]);
    }
    // the binary and the wrapper last, this one with them
    let path = options.root.join(last);
    if host.exists(&path) {
        host.remove(&path);
    }
    Ok(())
}

/// The machine itself.
#[cfg(unix)]
#[derive(Debug)]
pub struct System;

#[cfg(unix)]
impl Host for System {
    #[cfg(target_os = "linux")]
    fn euid(&self) -> u32 {
        rustix::process::geteuid().as_raw()
    }

    #[cfg(not(target_os = "linux"))]
    fn euid(&self) -> u32 {
        1
    }

    fn exists(&self, path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }

    fn run(&self, argv: &[&str]) -> bool {
        let Some((program, args)) = argv.split_first() else { return false };
        std::process::Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// A directory is emptied and removed, a link or file is removed itself: no link is followed.
    fn remove(&self, path: &Path) {
        let is_dir = std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir());
        let _ = if is_dir { std::fs::remove_dir_all(path) } else { std::fs::remove_file(path) };
    }

    fn remove_if_empty(&self, path: &Path) {
        // remove_dir refuses a directory that isn't empty
        let _ = std::fs::remove_dir(path);
    }

    fn spawn_detached(&self, argv: &[String]) -> std::io::Result<()> {
        use std::os::unix::process::CommandExt;
        let Some((program, args)) = argv.split_first() else { return Ok(()) };
        std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .process_group(0)
            .spawn()
            .map(|_| ())
    }

    fn sleep(&self, seconds: u64) {
        std::thread::sleep(std::time::Duration::from_secs(seconds));
    }
}

#[cfg(test)]
#[path = "uninstall_tests.rs"]
mod tests;
