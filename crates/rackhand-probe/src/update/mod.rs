//! Probe self-update (FR-22, 7.3.3, D73, D91): the probe downloads the release into its spool, the root helper copies it into
//! the inactive slot and checks the copy, and a guard running the old binary switches the slot and switches back when the new
//! probe doesn't report `connected` in time. The probe never writes its own binary.

#[cfg(unix)]
pub mod apply;
pub mod download;
#[cfg(unix)]
pub mod guard;
pub mod offers;

/// The release file of this machine's probe, as the release names it and the signature's trusted comment signs it.
pub fn artifact_name() -> String {
    format!("rackhand-probe-{}-unknown-linux-musl", std::env::consts::ARCH)
}

/// At most this much is downloaded into the spool and copied into a slot.
pub const MAX_RELEASE_BYTES: u64 = 64 << 20;
