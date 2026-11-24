//! Probe self-update on Windows (7.3.3): the same A/B slots as on Linux (`rackhand_release::slots`), in the program
//! directory beside the installer's `rackhand-probe.exe`. Windows has no link the services run, so the switch is the services'
//! configured binary path: `RackhandHelper` and `RackhandProbe` are both this binary, with `service helper` and
//! `service probe`. The guard is a copy of the running binary in the helper's own data directory, run once as SYSTEM by a
//! scheduled task, so it outlives the helper service it restarts.
//!
//! The parsing of what `sc.exe qc` prints is here and builds on every platform; the calls run only on Windows and are on the
//! manual checklist (MV16).

use std::path::{Path, PathBuf};

/// The services the probe's binary runs as, and the arguments each starts with.
pub const SERVICES: [(&str, &str); 2] = [("RackhandHelper", "service helper"), ("RackhandProbe", "service probe")];

/// The scheduled task the guard runs as.
pub const TASK: &str = "RackhandUpdateGuard";

/// The program and data directories: `C:\Program Files\Rackhand` and `C:\ProgramData\Rackhand` on a machine, or under `root`
/// when it isn't empty (tests).
pub fn dirs(root: &Path) -> (PathBuf, PathBuf) {
    if !root.as_os_str().is_empty() {
        return (root.join("Program Files").join("Rackhand"), root.join("ProgramData").join("Rackhand"));
    }
    let program = std::env::var_os("ProgramFiles").map_or_else(|| PathBuf::from(r"C:\Program Files"), PathBuf::from);
    let data = std::env::var_os("ProgramData").map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    (program.join("Rackhand"), data.join("Rackhand"))
}

/// The executable a service runs, from `sc.exe qc <service>`: the `BINARY_PATH_NAME` line, quoted or not.
pub fn binary_path(qc: &str) -> Option<PathBuf> {
    let line = qc.lines().find_map(|l| {
        let (key, value) = l.split_once(':')?;
        (key.trim() == "BINARY_PATH_NAME").then(|| value.trim())
    })?;
    let exe = match line.strip_prefix('"') {
        Some(rest) => rest.split('"').next()?,
        None => line.split(' ').next()?,
    };
    (!exe.is_empty()).then(|| PathBuf::from(exe))
}

/// The command line a service of the probe is configured with, for the slot at `exe`.
pub fn command_line(exe: &Path, args: &str) -> String {
    format!("\"{}\" {args}", exe.display())
}

/// Which slot both services run, from their binary paths: `Ok(None)` when they run the installer's file, an error when they
/// don't agree or run something else.
pub fn active_from(
    layout: &rackhand_release::slots::Layout,
    paths: &[PathBuf],
) -> Result<Option<rackhand_release::slots::Slot>, String> {
    let mut found = None;
    for path in paths {
        // split as Windows does, whatever platform this runs on
        let text = path.to_string_lossy();
        let (dir, name) = text.rsplit_once(['\\', '/']).unwrap_or(("", &text));
        let in_dir = same_path(Path::new(dir), &layout.lib());
        let this = if in_dir && name.eq_ignore_ascii_case(layout.link) {
            None
        } else if in_dir {
            let slot = layout
                .slots
                .iter()
                .position(|s| s.eq_ignore_ascii_case(name))
                .map(|i| if i == 0 { rackhand_release::slots::Slot::A } else { rackhand_release::slots::Slot::B });
            Some(slot.ok_or_else(|| format!("{} isn't the probe's", path.display()))?)
        } else {
            return Err(format!("{} isn't in the program directory", path.display()));
        };
        match &found {
            None => found = Some(this),
            Some(f) if *f == this => {}
            Some(_) => return Err("the helper and the probe services run different slots".into()),
        }
    }
    found.ok_or_else(|| "no service of the probe".to_string())
}

/// Windows paths compare without regard to case.
fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().trim_end_matches('\\').eq_ignore_ascii_case(b.to_string_lossy().trim_end_matches('\\'))
}

/// The services' binary path as the switch.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Services;

#[cfg(windows)]
impl rackhand_release::slots::Activation for Services {
    fn active(
        &self,
        layout: &rackhand_release::slots::Layout,
    ) -> Result<Option<rackhand_release::slots::Slot>, rackhand_release::slots::ApplyError> {
        let refuse = |m: String| rackhand_release::slots::refuse("layout", m);
        let mut paths = Vec::new();
        for (service, _) in SERVICES {
            let out = std::process::Command::new("sc.exe")
                .args(["qc", service])
                .output()
                .map_err(|e| refuse(format!("sc.exe qc {service}: {e}")))?;
            let text = String::from_utf8_lossy(&out.stdout);
            paths.push(binary_path(&text).ok_or_else(|| refuse(format!("{service} has no binary path")))?);
        }
        active_from(layout, &paths).map_err(refuse)
    }

    fn point_at(
        &self,
        layout: &rackhand_release::slots::Layout,
        slot: rackhand_release::slots::Slot,
    ) -> std::io::Result<()> {
        let exe = layout.slot(slot);
        for (service, args) in SERVICES {
            let status = std::process::Command::new("sc.exe")
                .args(["config", service, "binPath=", &command_line(&exe, args)])
                .status()?;
            if !status.success() {
                return Err(std::io::Error::other(format!("sc.exe config {service} failed ({status})")));
            }
        }
        Ok(())
    }
}

/// Restarts the helper and the probe services.
#[cfg(windows)]
pub fn restart_services() -> Result<(), String> {
    let status = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Restart-Service -Name RackhandHelper,RackhandProbe -Force",
        ])
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() { Ok(()) } else { Err(format!("Restart-Service failed ({status})")) }
}

/// The guard as a scheduled task that runs once, now, as SYSTEM.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Task;

#[cfg(windows)]
impl crate::helper::update::Launcher for Task {
    fn start(&self, guard: &Path, args: &[String]) -> Result<(), String> {
        let command = format!("\"{}\" update-guard {}", guard.display(), args.join(" "));
        let create = std::process::Command::new("schtasks.exe")
            .args(["/Create", "/F", "/TN", TASK, "/RU", "SYSTEM", "/SC", "ONCE", "/ST", "00:00", "/TR", &command])
            .output()
            .map_err(|e| e.to_string())?;
        if !create.status.success() {
            return Err(format!("schtasks /Create: {}", String::from_utf8_lossy(&create.stderr).trim()));
        }
        let run = std::process::Command::new("schtasks.exe")
            .args(["/Run", "/TN", TASK])
            .output()
            .map_err(|e| e.to_string())?;
        if run.status.success() {
            Ok(())
        } else {
            Err(format!("schtasks /Run: {}", String::from_utf8_lossy(&run.stderr).trim()))
        }
    }
}

#[cfg(test)]
mod tests {
    use rackhand_release::slots::{Layout, Slot};

    use super::*;

    fn layout() -> Layout {
        Layout {
            root: PathBuf::new(),
            lib: PathBuf::from(r"C:\Program Files\Rackhand"),
            slots: ["probe-a.exe", "probe-b.exe"],
            link: "rackhand-probe.exe",
            wrapper: None,
            spool_dir: PathBuf::from(r"C:\ProgramData\Rackhand\probe\update"),
            spool_file: "probe",
            artifact: "rackhand-probe-x86_64-pc-windows-gnu.exe".into(),
        }
    }

    /// What `sc.exe qc` prints, as recorded on a machine with the installer's services.
    const QC: &str = "[SC] QueryServiceConfig SUCCESS\r\n\r\nSERVICE_NAME: RackhandProbe\r\n        TYPE               : 10  WIN32_OWN_PROCESS\r\n        START_TYPE         : 2   AUTO_START\r\n        ERROR_CONTROL      : 1   NORMAL\r\n        BINARY_PATH_NAME   : \"C:\\Program Files\\Rackhand\\rackhand-probe.exe\" service probe\r\n        LOAD_ORDER_GROUP   :\r\n        TAG                : 0\r\n        DISPLAY_NAME       : Rackhand probe\r\n        DEPENDENCIES       :\r\n        SERVICE_START_NAME : NT SERVICE\\RackhandProbe\r\n";

    #[test]
    fn the_binary_path_is_read_from_sc_qc() {
        assert_eq!(binary_path(QC), Some(PathBuf::from(r"C:\Program Files\Rackhand\rackhand-probe.exe")));
        let unquoted = QC.replace("\"C:\\Program Files\\Rackhand\\rackhand-probe.exe\"", "C:\\Rackhand\\probe-b.exe");
        assert_eq!(binary_path(&unquoted), Some(PathBuf::from(r"C:\Rackhand\probe-b.exe")));
        assert_eq!(binary_path("[SC] OpenService FAILED 1060:\r\n"), None);
    }

    #[test]
    fn the_active_slot_is_the_one_both_services_run() {
        let l = layout();
        let p = |s: &str| PathBuf::from(format!(r"C:\Program Files\Rackhand\{s}"));
        assert_eq!(active_from(&l, &[p("rackhand-probe.exe"), p("rackhand-probe.exe")]), Ok(None), "the installer's");
        assert_eq!(active_from(&l, &[p("probe-b.exe"), p("PROBE-B.EXE")]), Ok(Some(Slot::B)), "without regard to case");
        assert_eq!(active_from(&l, &[p("probe-a.exe"), p("probe-a.exe")]), Ok(Some(Slot::A)));
        assert!(active_from(&l, &[p("probe-a.exe"), p("probe-b.exe")]).is_err(), "the two disagree");
        assert!(active_from(&l, &[p("evil.exe"), p("evil.exe")]).is_err(), "not the probe's");
        let elsewhere = PathBuf::from(r"C:\Temp\probe-a.exe");
        assert!(active_from(&l, &[elsewhere.clone(), elsewhere]).is_err(), "not in the program directory");
        assert!(active_from(&l, &[]).is_err());
    }

    #[test]
    fn a_service_is_pointed_at_a_slot_with_its_own_arguments() {
        assert_eq!(
            command_line(Path::new(r"C:\Program Files\Rackhand\probe-b.exe"), "service probe"),
            r#""C:\Program Files\Rackhand\probe-b.exe" service probe"#
        );
        assert_eq!(SERVICES.map(|(s, _)| s), ["RackhandHelper", "RackhandProbe"]);
    }

    #[test]
    fn the_directories_are_under_a_test_root_or_the_machines() {
        let (program, data) = dirs(Path::new("/tmp/x"));
        assert!(program.ends_with("Program Files/Rackhand") || program.ends_with(r"Program Files\Rackhand"));
        assert!(data.ends_with("ProgramData/Rackhand") || data.ends_with(r"ProgramData\Rackhand"));
    }
}
