//! `ApplyUpdate` (7.3.3): the helper's side of an update is the shared A/B slots of `rackhand_release::slots`, with the
//! probe's layout: slots `probe-a` and `probe-b`, the link `rackhand-probe` the services run, the command wrapper `run` kept in
//! step with the active slot, and the probe's spool.

use std::path::Path;

pub use rackhand_release::slots::{Applied, ApplyError, Layout, Request, Slot, apply};

/// The probe's layout under `root` (`/` on a machine).
pub fn paths(root: &Path) -> Layout {
    Layout {
        root: root.to_path_buf(),
        lib: "usr/local/lib/rackhand",
        slots: ["probe-a", "probe-b"],
        link: "rackhand-probe",
        wrapper: Some("run"),
        spool_dir: "var/lib/rackhand-probe/update",
        spool_file: "probe",
        artifact: super::artifact_name(),
    }
}
