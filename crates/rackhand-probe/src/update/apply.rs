//! `ApplyUpdate` (7.3.3): the helper's side of an update. It copies the release in the probe's spool into the inactive slot,
//! checks the copy, and leaves the switch to the guard.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use rackhand_release::binary::Version;
use rackhand_release::{Pinned, PublicKey};
use sha2::Digest;

use super::MAX_RELEASE_BYTES;

/// Paths under the machine's root (`/` on a machine, a directory in a test).
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn name(self) -> &'static str {
        match self {
            Slot::A => "probe-a",
            Slot::B => "probe-b",
        }
    }

    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub version: String,
    /// Hex.
    pub sha256: String,
    /// Base64 of the `.minisig` text.
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub version: Version,
    pub old: Slot,
    pub new: Slot,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ApplyError {
    pub code: &'static str,
    pub message: String,
}

fn refuse(code: &'static str, message: impl Into<String>) -> ApplyError {
    ApplyError { code, message: message.into() }
}

impl Paths {
    pub fn new(root: &Path) -> Paths {
        Paths { root: root.to_path_buf() }
    }

    /// `/usr/local/lib/rackhand`: root's, with the slots and the link.
    pub fn lib(&self) -> PathBuf {
        self.root.join("usr/local/lib/rackhand")
    }

    /// What the services run: a link to the active slot.
    pub fn link(&self) -> PathBuf {
        self.lib().join("rackhand-probe")
    }

    pub fn slot(&self, slot: Slot) -> PathBuf {
        self.lib().join(slot.name())
    }

    /// The command wrapper: a copy of the probe binary that sudo may run as root (7.3.7).
    pub fn wrapper(&self) -> PathBuf {
        self.lib().join("run")
    }

    pub fn spool_dir(&self) -> PathBuf {
        self.root.join("var/lib/rackhand-probe/update")
    }

    /// The one file the helper reads.
    pub fn spool_file(&self) -> PathBuf {
        self.spool_dir().join("probe")
    }

    /// Which slot the services run now.
    fn active(&self) -> Result<Active, ApplyError> {
        let link = self.link();
        let meta =
            std::fs::symlink_metadata(&link).map_err(|e| refuse("layout", format!("{}: {e}", link.display())))?;
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&link).map_err(|e| refuse("layout", e.to_string()))?;
            return match target.to_str() {
                Some("probe-a") => Ok(Active::Slot(Slot::A)),
                Some("probe-b") => Ok(Active::Slot(Slot::B)),
                _ => Err(refuse("layout", format!("{} points somewhere that isn't a slot", link.display()))),
            };
        }
        if meta.is_file() {
            return Ok(Active::Plain);
        }
        Err(refuse("layout", format!("{} is neither a link nor a file", link.display())))
    }

    /// The spool file, opened without following a link anywhere below the root, and without blocking on a FIFO.
    fn open_spool(&self) -> Result<std::fs::File, ApplyError> {
        use rustix::fs::{CWD, Mode, OFlags, openat};
        let unreadable = |e: rustix::io::Errno| refuse("spool_unreadable", format!("the spool file: {e}"));
        let file = self.spool_file();
        let rel =
            file.strip_prefix(&self.root).map_err(|_| refuse("spool_unreadable", "the spool is outside the root"))?;
        let parts: Vec<&std::ffi::OsStr> = rel.iter().collect();
        let Some((last, dirs)) = parts.split_last() else { return Err(refuse("spool_unreadable", "no spool file")) };
        let mut dir = openat(CWD, &self.root, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
            .map_err(unreadable)?;
        for part in dirs {
            dir = openat(
                &dir,
                *part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(unreadable)?;
        }
        let fd =
            openat(&dir, *last, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())
                .map_err(unreadable)?;
        let stat = rustix::fs::fstat(&fd).map_err(unreadable)?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
            return Err(refuse("spool_unreadable", "the spool file isn't a regular file"));
        }
        if stat.st_size < 0 || stat.st_size as u64 > MAX_RELEASE_BYTES {
            return Err(refuse("too_large", format!("the spool file is over {MAX_RELEASE_BYTES} bytes")));
        }
        Ok(std::fs::File::from(fd))
    }

    /// Puts `bytes` at `path` atomically, the new file's mode as given.
    pub fn replace(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = path.with_extension("new");
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    }

    /// Points the link at `slot`, atomically.
    pub fn point_at(&self, slot: Slot) -> std::io::Result<()> {
        let link = self.link();
        let tmp = link.with_extension("link");
        let _ = std::fs::remove_file(&tmp);
        std::os::unix::fs::symlink(slot.name(), &tmp)?;
        std::fs::rename(&tmp, &link)
    }
}

/// Which slot the services run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Active {
    Slot(Slot),
    /// A file the installer put there, before there were slots.
    Plain,
}

impl Active {
    /// The slot that holds the running version (or will, for a plain file).
    fn old(self) -> Slot {
        match self {
            Active::Slot(s) => s,
            Active::Plain => Slot::A,
        }
    }
}

/// Copies the release in the spool into the inactive slot and checks the copy (not the spool file, which the probe user can
/// change at any moment): the SHA-256 the hub offered, the signature against `keys`, and that the version the key signed is
/// the one asked for and newer than `installed`. A copy that fails any of it is deleted. The services still run what they
/// ran; the guard switches.
pub fn apply(
    paths: &Paths,
    installed: Version,
    request: &Request,
    keys: &[(Pinned, PublicKey)],
) -> Result<Applied, ApplyError> {
    use std::io::Read;
    let claimed = Version::parse(&request.version).ok_or_else(|| refuse("bad_request", "the version isn't x.y.z"))?;
    if request.sha256.len() != 64 || !request.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(refuse("bad_request", "the hash isn't a lower-case SHA-256"));
    }
    let active = paths.active()?;
    let inactive = active.old().other();
    let mut bytes = Vec::new();
    paths
        .open_spool()?
        .take(MAX_RELEASE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| refuse("spool_unreadable", e.to_string()))?;
    if bytes.len() as u64 > MAX_RELEASE_BYTES {
        return Err(refuse("too_large", "the spool file grew past the limit"));
    }
    let target = paths.slot(inactive);
    let fail = |e: ApplyError| {
        let _ = std::fs::remove_file(&target);
        e
    };
    // the copy is not executable until it has been checked
    let _ = std::fs::remove_file(&target);
    Paths::replace(&target, &bytes, 0o600)
        .map_err(|e| fail(refuse("copy_failed", format!("{}: {e}", target.display()))))?;
    let copy = std::fs::read(&target).map_err(|e| fail(refuse("copy_failed", e.to_string())))?;
    let seen = format!("{:x}", sha2::Sha256::digest(&copy));
    if seen != request.sha256 {
        return Err(fail(refuse("bad_hash", "the copy doesn't have the hash the hub gave")));
    }
    let minisig = data_encoding::BASE64
        .decode(request.signature.as_bytes())
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or_else(|| fail(refuse("bad_signature", "the signature isn't base64 of a signature file")))?;
    let (_, signed) = rackhand_release::binary::verify_binary_with(&copy, &minisig, keys, &super::artifact_name())
        .map_err(|e| fail(refuse("bad_signature", e.to_string())))?;
    if signed != claimed {
        return Err(fail(refuse(
            "version_mismatch",
            format!("the request says {claimed} and the signature says {signed}"),
        )));
    }
    if signed <= installed {
        return Err(fail(refuse("downgrade", format!("{signed} isn't newer than the installed {installed}"))));
    }
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| fail(refuse("copy_failed", e.to_string())))?;
    if active == Active::Plain {
        // the file the installer put there becomes slot A, so there is a known-good version to go back to
        let plain = std::fs::read(paths.link()).map_err(|e| fail(refuse("layout", e.to_string())))?;
        Paths::replace(&paths.slot(Slot::A), &plain, 0o755).map_err(|e| fail(refuse("layout", e.to_string())))?;
        paths.point_at(Slot::A).map_err(|e| fail(refuse("layout", e.to_string())))?;
    }
    Ok(Applied { version: signed, old: active.old(), new: inactive })
}

#[cfg(test)]
mod tests;
