//! The probe's update guard (7.3.3): the old, known-good binary, run as its own transient unit, switches the slot, restarts the
//! helper and the probe, and waits for the new probe to say `connected` with the new version; if it doesn't in time, the guard
//! points back at the old slot and restarts both (`rackhand_release::slots::guard`). The state file is written by the probe
//! user, so it is only a signal: a probe that lies in it can keep or lose a version that was signed, and nothing else, because
//! the guard never runs or writes anything the helper hadn't already verified.

use std::time::Duration;

use rackhand_release::binary::Version;
use rackhand_release::slots::{Env, Outcome, Plan, guard};

use super::apply::paths;

/// Whether `probe.state` says the probe is connected and running `version`.
pub fn connected_with(state: &str, version: Version) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(state) else { return false };
    value["state"] == "connected" && value["version"].as_str().and_then(Version::parse) == Some(version)
}

/// `<old-slot> <new-slot> <version>`: the slots by their names, the version the new probe must report.
pub fn parse_args(args: &[String]) -> Result<(Plan, Version), String> {
    let [old, new, version] = args else { return Err("update-guard <old-slot> <new-slot> <version>".into()) };
    let layout = paths(std::path::Path::new("/"));
    let slot = |name: &str| layout.slot_named(name).ok_or_else(|| format!("`{name}` isn't a slot"));
    let (old, new) = (slot(old)?, slot(new)?);
    if old == new {
        return Err("the old and the new slot are the same".into());
    }
    let version = Version::parse(version).ok_or("the version isn't x.y.z")?;
    Ok((Plan { layout, old, new }, version))
}

/// The machine's services and clock, and the probe's state file.
#[derive(Debug)]
pub struct System {
    started: std::time::Instant,
    state_file: std::path::PathBuf,
    version: Version,
}

impl Env for System {
    #[cfg(windows)]
    fn restart(&self) -> Result<(), String> {
        crate::windows::update::restart_services()
    }

    #[cfg(unix)]
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

    fn up(&self) -> bool {
        std::fs::read_to_string(&self.state_file).is_ok_and(|s| connected_with(&s, self.version))
    }

    fn rolling_back(&self) {}

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }

    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

/// `rackhand-probe update-guard <old-slot> <new-slot> <version>`: run by the helper, as root, from a copy of the old binary.
pub fn main(args: &[String]) -> std::process::ExitCode {
    let (plan, version) = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("rackhand-probe update-guard: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    #[cfg(unix)]
    let (state_file, activation) = ("/run/rackhand-probe/probe.state", crate::update::apply::Link);
    #[cfg(windows)]
    let (state_file, activation) = (r"C:ProgramDataRackhandprobeprobe.state", crate::windows::update::Services);
    let system = System { started: std::time::Instant::now(), state_file: state_file.into(), version };
    match guard(&plan, &activation, &system) {
        Outcome::Kept => std::process::ExitCode::SUCCESS,
        Outcome::RolledBack | Outcome::NotSwitched => std::process::ExitCode::from(1),
    }
}

#[cfg(test)]
mod tests;
