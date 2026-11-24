//! The update guard (7.3.3): the old, known-good binary, run as its own transient unit, switches the slot, restarts the helper
//! and the probe, and waits for the new probe to say `connected` with the new version. If it doesn't in time, the guard points
//! back at the old slot and restarts both. The state file is written by the probe user, so it is only a signal: a probe that
//! lies in it can keep or lose a version that was signed, and nothing else, because the guard never runs or writes anything
//! the helper hadn't already verified.

use std::time::Duration;

use rackhand_release::binary::Version;

use super::apply::{Paths, Slot};

/// How long the new probe has to connect.
pub const TIMEOUT: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct Plan {
    pub paths: Paths,
    pub old: Slot,
    pub new: Slot,
    /// The version the new probe must report.
    pub version: Version,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The new probe connected; it stays.
    Kept,
    /// It didn't; the old slot runs again.
    RolledBack,
    /// The switch itself failed, before anything was restarted.
    NotSwitched,
}

/// What the guard touches outside the slots, so tests can stand in for the services and the clock.
pub trait Env {
    /// Restarts the helper and the probe.
    fn restart(&self) -> Result<(), String>;
    /// The text of `probe.state`, if it can be read.
    fn state(&self) -> Option<String>;
    fn sleep(&self, d: Duration);
    /// Since the guard started.
    fn elapsed(&self) -> Duration;
}

/// Makes `slot` the one the services run: the command wrapper is its copy and the link points at it.
fn switch(paths: &Paths, slot: Slot) -> std::io::Result<()> {
    let file = paths.slot(slot);
    if !std::fs::symlink_metadata(&file)?.is_file() {
        return Err(std::io::Error::other(format!("{} isn't a file", file.display())));
    }
    Paths::replace(&paths.wrapper(), &std::fs::read(&file)?, 0o755)?;
    paths.point_at(slot)
}

/// Whether `probe.state` says the probe is connected and running `version`.
fn connected_with(state: &str, version: Version) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(state) else { return false };
    value["state"] == "connected" && value["version"].as_str().and_then(Version::parse) == Some(version)
}

pub fn run(plan: &Plan, env: &dyn Env) -> Outcome {
    if let Err(e) = switch(&plan.paths, plan.new) {
        tracing::error!(error = %e, "the update guard couldn't switch to the new slot");
        return Outcome::NotSwitched;
    }
    if let Err(e) = env.restart() {
        tracing::warn!(error = %e, "restarting the helper and the probe");
    }
    while env.elapsed() < TIMEOUT {
        if env.state().is_some_and(|s| connected_with(&s, plan.version)) {
            tracing::info!(version = %plan.version, "the new probe is connected; the update stays");
            return Outcome::Kept;
        }
        env.sleep(POLL);
    }
    tracing::warn!(version = %plan.version, "the new probe didn't connect in time; going back");
    if let Err(e) = switch(&plan.paths, plan.old) {
        tracing::error!(error = %e, "the update guard couldn't switch back");
    }
    if let Err(e) = env.restart() {
        tracing::warn!(error = %e, "restarting the helper and the probe");
    }
    Outcome::RolledBack
}

/// `<old-slot> <new-slot> <version>`: the slots by their names, the version the new probe must report.
pub fn parse_args(args: &[String]) -> Result<Plan, String> {
    let [old, new, version] = args else { return Err("update-guard <old-slot> <new-slot> <version>".into()) };
    let slot = |name: &str| match name {
        "probe-a" => Ok(Slot::A),
        "probe-b" => Ok(Slot::B),
        _ => Err(format!("`{name}` isn't a slot")),
    };
    let (old, new) = (slot(old)?, slot(new)?);
    if old == new {
        return Err("the old and the new slot are the same".into());
    }
    let version = Version::parse(version).ok_or("the version isn't x.y.z")?;
    Ok(Plan { paths: Paths::new(std::path::Path::new("/")), old, new, version })
}

/// The machine's services and clock.
#[derive(Debug)]
pub struct System {
    started: std::time::Instant,
    state_file: std::path::PathBuf,
}

impl Env for System {
    fn restart(&self) -> Result<(), String> {
        let systemd = std::path::Path::new("/run/systemd/system").exists();
        let mut failed = Vec::new();
        for service in ["rackhand-probe-helper", "rackhand-probe"] {
            let status = if systemd {
                std::process::Command::new("systemctl").args(["restart", &format!("{service}.service")]).status()
            } else {
                std::process::Command::new("rc-service").args([service, "restart"]).status()
            };
            if !status.is_ok_and(|s| s.success()) {
                failed.push(service);
            }
        }
        if failed.is_empty() { Ok(()) } else { Err(format!("couldn't restart {}", failed.join(" and "))) }
    }

    fn state(&self) -> Option<String> {
        std::fs::read_to_string(&self.state_file).ok()
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }

    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

/// `rackhand-probe update-guard <old-slot> <new-slot> <version>`: run by the helper, as root, from a copy of the old binary.
pub fn main(args: &[String]) -> std::process::ExitCode {
    let plan = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("rackhand-probe update-guard: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    let system = System { started: std::time::Instant::now(), state_file: "/run/rackhand-probe/probe.state".into() };
    match run(&plan, &system) {
        Outcome::Kept => std::process::ExitCode::SUCCESS,
        Outcome::RolledBack | Outcome::NotSwitched => std::process::ExitCode::from(1),
    }
}

#[cfg(test)]
mod tests;
