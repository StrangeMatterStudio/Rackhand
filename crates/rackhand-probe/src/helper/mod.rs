//! The root-only helper (design 7.2, Helper; 7.3.3): the only root process on a probe machine. It answers the probe
//! user on a local socket with what needs root (container states, package lists, and in later steps file hashes, auth
//! events and socket owners), never file contents, and takes no paths or URLs.

pub mod client;
#[cfg(unix)]
pub mod containers;
#[cfg(target_os = "linux")]
pub mod daemon;
pub mod keys;
#[cfg(unix)]
pub mod layout;
pub mod packages;
pub mod server;

pub const SOCKET: &str = "/run/rackhand-helper/helper.sock";
