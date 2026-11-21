//! Patching (7.5.3, FR-13): which machines a window patches and in what order (`select`), what must hold before a
//! machine is patched (`precheck`), and when a failed patch is rolled back (`rollback`).

pub mod precheck;
pub mod rollback;
pub mod select;
