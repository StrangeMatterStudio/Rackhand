//! `ApplyUpdate` in the helper (7.3.3): the copy and its checks are `crate::update::apply`; this starts the guard. The guard is
//! a copy of the running, known-good binary in root's `/run/rackhand-helper`, started as a unit of its own, so a new helper that
//! doesn't work can't stop the way back.

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rackhand_proto::helper::HelperResponse;
use rackhand_release::binary::Version;
use rackhand_release::{Pinned, PublicKey};

use crate::update::apply::{Paths, Request, apply};

/// Another update isn't started while a guard that was started less than this long ago may still be working: it waits 2
/// minutes for the probe and restarts the helper either way.
const GUARD_BUSY: Duration = Duration::from_secs(5 * 60);

/// Starts the guard as a process of its own, outside the helper's service.
pub trait Launcher: Send + Sync + std::fmt::Debug {
    fn start(&self, guard: &Path, args: &[String]) -> Result<(), String>;
}

/// A transient systemd unit, or an OpenRC one-shot on a machine without systemd.
#[derive(Debug)]
pub struct Units;

impl Launcher for Units {
    fn start(&self, guard: &Path, args: &[String]) -> Result<(), String> {
        let mut command = if Path::new("/run/systemd/system").exists() {
            let mut c = std::process::Command::new("systemd-run");
            c.args(["--unit=rackhand-update-guard", "--collect"]).arg(guard);
            c
        } else {
            let mut c = std::process::Command::new("start-stop-daemon");
            c.args(["--start", "--background", "--exec"]).arg(guard).arg("--");
            c
        };
        let status = command.arg("update-guard").args(args).status().map_err(|e| e.to_string())?;
        if status.success() { Ok(()) } else { Err(format!("the guard's unit didn't start ({status})")) }
    }
}

/// The keys an update is checked against and how its guard is started.
#[derive(Debug)]
pub struct Setup {
    keys: Vec<(Pinned, PublicKey)>,
    launcher: Box<dyn Launcher>,
    started: Mutex<Option<Instant>>,
}

impl Setup {
    pub fn new(keys: Vec<(Pinned, PublicKey)>, launcher: impl Launcher + 'static) -> Setup {
        Setup { keys, launcher: Box::new(launcher), started: Mutex::new(None) }
    }

    /// The keys this build pins, and systemd or OpenRC.
    pub fn system() -> Setup {
        Setup::new(rackhand_release::pinned(), Units)
    }
}

fn error(code: &str, message: impl Into<String>) -> HelperResponse {
    HelperResponse::Error { code: code.into(), message: message.into() }
}

/// The answer to `ApplyUpdate`: `UpdateStarted` once the copy is checked and the guard is running, else why not.
pub fn apply_update(
    installed: &str,
    root: &Path,
    setup: &Setup,
    version: &str,
    sha256: &str,
    signature: &str,
) -> HelperResponse {
    if setup.keys.is_empty() {
        return error("no_keys", "this build pins no release keys, so nothing can be installed");
    }
    let Some(installed) = Version::parse(installed) else {
        return error("bad_version", "the helper's own version isn't x.y.z");
    };
    // one at a time, and the slot a guard is switching to isn't touched
    let mut started = setup.started.lock().unwrap_or_else(|e| e.into_inner());
    if started.is_some_and(|at| at.elapsed() < GUARD_BUSY) {
        return error("update_in_progress", "an update is being switched in");
    }
    let paths = Paths::new(root);
    let request = Request { version: version.into(), sha256: sha256.into(), signature: signature.into() };
    let applied = match apply(&paths, installed, &request, &setup.keys) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(code = e.code, error = %e, "an update was refused");
            return error(e.code, e.message);
        }
    };
    let guard = root.join("run/rackhand-helper/update-guard");
    let copied = std::fs::read(paths.slot(applied.old)).and_then(|bytes| Paths::replace(&guard, &bytes, 0o700));
    if let Err(e) = copied {
        return error("guard_failed", format!("the guard's copy of the running binary: {e}"));
    }
    let args = [applied.old.name().to_string(), applied.new.name().to_string(), applied.version.to_string()];
    if let Err(e) = setup.launcher.start(&guard, &args) {
        tracing::warn!(error = %e, "the update guard didn't start");
        return error("guard_failed", e);
    }
    *started = Some(Instant::now());
    tracing::info!(version = %applied.version, "an update was copied into its slot and its guard started");
    HelperResponse::UpdateStarted
}

#[cfg(test)]
mod tests;
