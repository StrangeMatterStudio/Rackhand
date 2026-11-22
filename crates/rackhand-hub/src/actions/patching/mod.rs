//! Patching (7.5.3, FR-13): which machines a window patches and in what order (`select`), what must hold before a
//! machine is patched (`precheck`), and when a failed patch is rolled back (`rollback`). `driver` runs the windows.

/// The reason a patch job ends with when its machine went silent after its reboot (E11).
pub const NO_REPORT_AFTER_REBOOT: &str = "no_report_after_reboot";

pub mod driver;
pub mod precheck;
pub mod rollback;
pub mod select;
