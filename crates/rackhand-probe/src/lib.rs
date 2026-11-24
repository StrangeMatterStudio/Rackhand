//! The probe and its root helper (design 7.2, Probe and Helper).

pub mod buffer;
pub mod collect;
pub mod config;
pub mod enroll;
pub mod helper;
pub mod link;
pub mod logging;
pub mod probe_check;
pub mod remote;
pub mod run;
#[cfg(unix)]
pub mod runcmd;
pub mod security;
pub mod set_hub;
#[cfg(unix)]
pub mod uninstall;
pub mod update;
pub mod windows;

/// This build's version: the workspace's. A lab build can be given another with `RACKHAND_PROBE_VERSION` at build time, to
/// play a newer release in the update tests; a release build can't (`lab-build` is refused in one).
#[cfg(not(feature = "lab-build"))]
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(feature = "lab-build")]
pub const VERSION: &str = match option_env!("RACKHAND_PROBE_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};
