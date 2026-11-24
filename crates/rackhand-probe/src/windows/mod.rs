//! The Windows probe (7.3.3, FR-2, FR-4, FR-5, D81): what it collects and how it talks to its helper. The parsing of what
//! Windows gives back (connection tables, process lists, logon events, CIM output, the pipe's ACL) is in [`parse`], which
//! builds on every platform and is tested on recorded outputs. The calls that produce those outputs run only on Windows,
//! and are checked by the manual checklist (MV16).

#[cfg(windows)]
pub mod collect;
#[cfg(windows)]
pub mod conntable;
#[cfg(windows)]
pub mod helper_ops;
pub mod parse;
#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
pub mod ps;
#[cfg(windows)]
pub mod service;
/// Probe self-update on Windows (7.3.3): the services' binary path as the switch, a scheduled task as SYSTEM for the guard.
pub mod update;
