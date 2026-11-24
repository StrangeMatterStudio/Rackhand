//! The root-only helper (design 7.2, Helper; 7.3.3): the only root process on a probe machine. It answers the probe
//! user on a local socket with what needs root (container states, package lists, and in later steps file hashes, auth
//! events and socket owners), never file contents, and takes no paths or URLs.

#[cfg(unix)]
pub mod auth;
pub mod client;
#[cfg(unix)]
pub mod containers;
#[cfg(target_os = "linux")]
pub mod daemon;
#[cfg(unix)]
pub mod hash;
#[cfg(unix)]
pub mod keys;
#[cfg(unix)]
pub mod layout;
pub mod packages;
#[cfg(unix)]
pub mod procscan;
pub mod server;
#[cfg(unix)]
pub mod sockets;
#[cfg(unix)]
pub mod update;

#[cfg(unix)]
pub const SOCKET: &str = "/run/rackhand-helper/helper.sock";
/// The helper's named pipe on Windows (7.3.3).
#[cfg(windows)]
pub const SOCKET: &str = r"\\.\pipe\rackhand-helper";
