//! `ApplyUpdate` (7.3.3): the helper's side of an update is the shared A/B slots of `rackhand_release::slots`, with the
//! probe's layout. On Linux: slots `probe-a` and `probe-b`, the link `rackhand-probe` the units run, the command wrapper `run`
//! kept in step with the active slot, and the probe's spool. On Windows: `probe-a.exe` and `probe-b.exe` beside the installer's
//! `rackhand-probe.exe` in `C:\Program Files\Rackhand`, the services' binary path as the switch, and the spool under
//! `C:\ProgramData\Rackhand\probe`.

use std::path::Path;

#[cfg(unix)]
pub use rackhand_release::slots::Link;
pub use rackhand_release::slots::{Activation, Applied, ApplyError, Layout, Request, Slot, apply};

/// The probe's layout under `root` (`/` on a Linux machine; on Windows the paths are absolute and `root` is ignored).
#[cfg(unix)]
pub fn paths(root: &Path) -> Layout {
    Layout {
        root: root.to_path_buf(),
        lib: "usr/local/lib/rackhand".into(),
        slots: ["probe-a", "probe-b"],
        link: "rackhand-probe",
        wrapper: Some("run"),
        spool_dir: "var/lib/rackhand-probe/update".into(),
        spool_file: "probe",
        artifact: super::artifact_name(),
        max_bytes: rackhand_release::slots::MAX_RELEASE_BYTES,
    }
}

/// The probe's layout on Windows: the program directory and the data directory the installer made (`root` is where they are,
/// for tests; `None` is the machine's own).
#[cfg(windows)]
pub fn paths(root: &Path) -> Layout {
    let (program, data) = crate::windows::update::dirs(root);
    Layout {
        root: Default::default(),
        lib: program,
        slots: ["probe-a.exe", "probe-b.exe"],
        link: "rackhand-probe.exe",
        wrapper: None,
        spool_dir: data.join("probe").join("update"),
        spool_file: "probe",
        artifact: super::artifact_name(),
        max_bytes: rackhand_release::slots::MAX_RELEASE_BYTES,
    }
}
