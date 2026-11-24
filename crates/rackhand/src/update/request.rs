//! The request and the answer (7.5.7). The unprivileged side writes `request.json` in its spool; the updater reads only the
//! version from it, whatever else it says, and never a path. The updater's answer and the guard's rollback record are written
//! back in the spool for the unprivileged side to read, audit and show.

use rackhand_release::binary::Version;
use rackhand_release::slots::{ApplyError, refuse};
use serde::{Deserialize, Serialize};

/// The request is a few bytes.
pub const MAX_REQUEST: u64 = 4096;

/// The version asked for, and nothing else from the request.
pub fn version_of(bytes: &[u8]) -> Result<Version, ApplyError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| refuse("bad_request", "the request isn't JSON"))?;
    value
        .get("version")
        .and_then(serde_json::Value::as_str)
        .and_then(Version::parse)
        .ok_or_else(|| refuse("bad_request", "the request names no version of the form x.y.z"))
}

/// What the updater says about a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    pub ok: bool,
    /// The version that was asked for, when the request named one.
    pub version: Option<String>,
    /// `started`, or why it was refused (`bad_signature`, `downgrade`, ...).
    pub code: String,
    pub message: String,
    pub at_ms: i64,
}

/// What the guard says when it went back: the version that didn't come up, and whether it put the database from before the
/// update back (what was written in between is gone).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolledBack {
    pub from: String,
    pub to: String,
    pub restored_database: bool,
    pub window_from_ms: i64,
    pub window_to_ms: i64,
}
