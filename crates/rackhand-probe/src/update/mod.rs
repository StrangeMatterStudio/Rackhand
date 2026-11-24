//! Probe self-update (FR-22, 7.3.3, D73, D91): the probe downloads the release into its spool, the root helper copies it into
//! the inactive slot and checks the copy, and a guard running the old binary switches the slot and switches back when the new
//! probe doesn't report `connected` in time. The probe never writes its own binary.

pub mod apply;
pub mod download;
pub mod guard;
pub mod offers;

/// The release file of this machine's probe, as the release names it and the signature's trusted comment signs it.
pub fn artifact_name() -> String {
    if cfg!(windows) {
        format!("rackhand-probe-{}-pc-windows-gnu.exe", std::env::consts::ARCH)
    } else {
        format!("rackhand-probe-{}-unknown-linux-musl", std::env::consts::ARCH)
    }
}

/// At most this much is downloaded into the spool and copied into a slot.
pub const MAX_RELEASE_BYTES: u64 = 64 << 20;

/// The spool, from the probe's data directory (the `buffer` directory inside its state directory): the one place the probe
/// puts a download and the helper reads it from.
pub fn spool_dir(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.parent().unwrap_or(data_dir).join("update")
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use std::path::Path;

    /// The probe writes where the helper reads: a download that lands elsewhere is never applied.
    #[test]
    fn probe_and_helper_agree_on_the_spool() {
        let helper = super::apply::paths(Path::new("/")).spool_dir();
        assert_eq!(super::spool_dir(Path::new("/var/lib/rackhand-probe/buffer")), helper);
        assert_eq!(helper, Path::new("/var/lib/rackhand-probe/update"));
    }
}
