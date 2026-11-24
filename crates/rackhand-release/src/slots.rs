//! A/B binary slots (7.3.3, 7.5.7, D73, D91, D98): a program that updates itself keeps two copies of its binary, `x-a` and
//! `x-b`, and its services run one of them. An update is copied into the inactive slot by a privileged process that checks
//! the copy (never the file it was copied from, which the unprivileged side can change at any moment), and a guard running the
//! old, known-good binary makes the services run the new slot and goes back when the new version doesn't come up.
//!
//! What "the services run a slot" means is an [`Activation`]: on Linux a link in the slots' directory that the units run
//! ([`Link`]); on Windows the services' configured binary path. The probe's helper and the hub's updater are two users of
//! this; each has its own [`Layout`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::Digest;

use crate::binary::Version;
use crate::{Pinned, PublicKey};

/// At most this much is downloaded into a spool and copied into a slot.
pub const MAX_RELEASE_BYTES: u64 = 64 << 20;

/// Where one program's slots, spool and signed file name are. `lib` and `spool_dir` are relative to `root` (`/` on a machine,
/// a directory in a test), or absolute.
#[derive(Debug, Clone)]
pub struct Layout {
    pub root: PathBuf,
    /// The directory of the slots (and of the link and the wrapper).
    pub lib: PathBuf,
    /// The slots' file names, A then B.
    pub slots: [&'static str; 2],
    /// The file the services run: on Linux a link to a slot's name; the installer's own file before there were slots.
    pub link: &'static str,
    /// A copy of the binary beside the slots that sudo runs, kept in step with the active slot (the probe's command wrapper).
    pub wrapper: Option<&'static str>,
    /// The spool's directory and the one file in it that is read.
    pub spool_dir: PathBuf,
    pub spool_file: &'static str,
    /// The name the signature's trusted comment gives the release file.
    pub artifact: String,
    /// The largest release this layout takes: the probe's spool holds at most 64 MB ([`MAX_RELEASE_BYTES`]).
    pub max_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

impl Slot {
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

pub fn refuse(code: &'static str, message: impl Into<String>) -> ApplyError {
    ApplyError { code, message: message.into() }
}

/// Which slot a program's services run, and how they are made to run another.
pub trait Activation {
    /// The slot the services run, or `None` when they run the installer's own file (`link` in `lib`).
    fn active(&self, layout: &Layout) -> Result<Option<Slot>, ApplyError>;
    /// Makes the services run `slot` from their next start.
    fn point_at(&self, layout: &Layout, slot: Slot) -> std::io::Result<()>;
}

/// Linux: the services run a link in the slots' directory, which points at a slot by its name.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Link;

#[cfg(unix)]
impl Activation for Link {
    fn active(&self, layout: &Layout) -> Result<Option<Slot>, ApplyError> {
        let link = layout.link();
        let meta =
            std::fs::symlink_metadata(&link).map_err(|e| refuse("layout", format!("{}: {e}", link.display())))?;
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&link).map_err(|e| refuse("layout", e.to_string()))?;
            return match target.to_str().and_then(|t| layout.slot_named(t)) {
                Some(slot) => Ok(Some(slot)),
                None => Err(refuse("layout", format!("{} points somewhere that isn't a slot", link.display()))),
            };
        }
        if meta.is_file() {
            return Ok(None);
        }
        Err(refuse("layout", format!("{} is neither a link nor a file", link.display())))
    }

    fn point_at(&self, layout: &Layout, slot: Slot) -> std::io::Result<()> {
        let link = layout.link();
        let tmp = link.with_extension("link");
        let _ = std::fs::remove_file(&tmp);
        std::os::unix::fs::symlink(layout.slot_name(slot), &tmp)?;
        std::fs::rename(&tmp, &link)
    }
}

impl Layout {
    pub fn lib(&self) -> PathBuf {
        self.root.join(&self.lib)
    }

    /// The file the services run (a link on Linux).
    pub fn link(&self) -> PathBuf {
        self.lib().join(self.link)
    }

    pub fn slot_name(&self, slot: Slot) -> &'static str {
        match slot {
            Slot::A => self.slots[0],
            Slot::B => self.slots[1],
        }
    }

    pub fn slot(&self, slot: Slot) -> PathBuf {
        self.lib().join(self.slot_name(slot))
    }

    pub fn wrapper(&self) -> Option<PathBuf> {
        self.wrapper.map(|w| self.lib().join(w))
    }

    pub fn spool_dir(&self) -> PathBuf {
        self.root.join(&self.spool_dir)
    }

    /// The one file that is read.
    pub fn spool_file(&self) -> PathBuf {
        self.spool_dir().join(self.spool_file)
    }

    /// The slot a name is, if it is one.
    pub fn slot_named(&self, name: &str) -> Option<Slot> {
        if name == self.slots[0] {
            Some(Slot::A)
        } else if name == self.slots[1] {
            Some(Slot::B)
        } else {
            None
        }
    }

    /// Puts `bytes` at `path` atomically; on Linux the new file has `mode`, on Windows the directory's permissions.
    pub fn replace(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
        use std::io::Write;
        let tmp = path.with_extension("new");
        let _ = std::fs::remove_file(&tmp);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let mut f = options.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    }

    /// Another file of the spool, read whole the same way (at most `max` bytes): the hub's update request, the release's signature
    /// and its manifest.
    pub fn read_spool(&self, name: &str, max: u64) -> Result<Vec<u8>, ApplyError> {
        use std::io::Read;
        if name.contains(['/', '\\']) || name == ".." || name.is_empty() {
            return Err(refuse("bad_request", "a spool file is named, not a path"));
        }
        let mut bytes = Vec::new();
        self.open_in_spool(name, max)?
            .take(max + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| refuse("spool_unreadable", e.to_string()))?;
        if bytes.len() as u64 > max {
            return Err(refuse("too_large", format!("{name} is over {max} bytes")));
        }
        Ok(bytes)
    }

    /// The spool file, opened without following a link anywhere below the root, and without blocking on a FIFO.
    #[cfg(unix)]
    pub fn open_in_spool(&self, name: &str, max: u64) -> Result<std::fs::File, ApplyError> {
        use rustix::fs::{CWD, Mode, OFlags, openat};
        let unreadable = |e: rustix::io::Errno| refuse("spool_unreadable", format!("the spool file: {e}"));
        let file = self.spool_dir().join(name);
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
        if stat.st_size < 0 || stat.st_size as u64 > max {
            return Err(refuse("too_large", format!("the spool file is over {max} bytes")));
        }
        Ok(std::fs::File::from(fd))
    }

    /// The spool file on Windows: no directory between the spool and the file, and not the file itself, may be a reparse
    /// point (a junction or a link), and the file is opened as itself rather than as what a reparse point names. What is read
    /// is checked against the signature, so a race here can only make the copy fail.
    #[cfg(windows)]
    pub fn open_in_spool(&self, name: &str, max: u64) -> Result<std::fs::File, ApplyError> {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let reparse = |m: &std::fs::Metadata| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        let dir = self.spool_dir();
        let mut at = PathBuf::new();
        for part in dir.components() {
            at.push(part);
            if matches!(part, std::path::Component::Normal(_)) {
                let m = std::fs::symlink_metadata(&at)
                    .map_err(|e| refuse("spool_unreadable", format!("{}: {e}", at.display())))?;
                if reparse(&m) || !m.is_dir() {
                    return Err(refuse("spool_unreadable", format!("{} is a link, not a directory", at.display())));
                }
            }
        }
        let file = self.spool_dir().join(name);
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&file)
            .map_err(|e| refuse("spool_unreadable", format!("the spool file: {e}")))?;
        let m = f.metadata().map_err(|e| refuse("spool_unreadable", e.to_string()))?;
        if reparse(&m) || !m.is_file() {
            return Err(refuse("spool_unreadable", "the spool file isn't a regular file"));
        }
        if m.len() > max {
            return Err(refuse("too_large", format!("the spool file is over {max} bytes")));
        }
        Ok(f)
    }
}

/// The new file is executable on Linux; on Windows it has the directory's permissions.
fn make_executable(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Copies the release in the spool into the inactive slot and checks the copy (not the spool file): the SHA-256 that was
/// offered, the signature against `keys`, and that the version the key signed is the one asked for and newer than
/// `installed`. A copy that fails any of it is deleted. The services still run what they ran; the guard switches.
pub fn apply(
    layout: &Layout,
    activation: &dyn Activation,
    installed: Version,
    request: &Request,
    keys: &[(Pinned, PublicKey)],
) -> Result<Applied, ApplyError> {
    use std::io::Read;
    let claimed = Version::parse(&request.version).ok_or_else(|| refuse("bad_request", "the version isn't x.y.z"))?;
    if request.sha256.len() != 64 || !request.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(refuse("bad_request", "the hash isn't a lower-case SHA-256"));
    }
    let active = activation.active(layout)?;
    let old = active.unwrap_or(Slot::A);
    let inactive = old.other();
    let mut bytes = Vec::new();
    layout
        .open_in_spool(layout.spool_file, layout.max_bytes)?
        .take(layout.max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| refuse("spool_unreadable", e.to_string()))?;
    if bytes.len() as u64 > layout.max_bytes {
        return Err(refuse("too_large", "the spool file grew past the limit"));
    }
    let target = layout.slot(inactive);
    let fail = |e: ApplyError| {
        let _ = std::fs::remove_file(&target);
        e
    };
    // the copy is not executable until it has been checked
    let _ = std::fs::remove_file(&target);
    Layout::replace(&target, &bytes, 0o600)
        .map_err(|e| fail(refuse("copy_failed", format!("{}: {e}", target.display()))))?;
    let copy = std::fs::read(&target).map_err(|e| fail(refuse("copy_failed", e.to_string())))?;
    let seen = format!("{:x}", sha2::Sha256::digest(&copy));
    if seen != request.sha256 {
        return Err(fail(refuse("bad_hash", "the copy doesn't have the hash that was offered")));
    }
    let minisig = data_encoding::BASE64
        .decode(request.signature.as_bytes())
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or_else(|| fail(refuse("bad_signature", "the signature isn't base64 of a signature file")))?;
    let (_, signed) = crate::binary::verify_binary_with(&copy, &minisig, keys, &layout.artifact)
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
    make_executable(&target).map_err(|e| fail(refuse("copy_failed", e.to_string())))?;
    if active.is_none() {
        // the installer's own file becomes slot A, so there is a known-good version to go back to
        let plain = std::fs::read(layout.link()).map_err(|e| fail(refuse("layout", e.to_string())))?;
        Layout::replace(&layout.slot(Slot::A), &plain, 0o755).map_err(|e| fail(refuse("layout", e.to_string())))?;
        activation.point_at(layout, Slot::A).map_err(|e| fail(refuse("layout", e.to_string())))?;
    }
    Ok(Applied { version: signed, old, new: inactive })
}

// ---- the guard ----

/// How long the new version has to come up.
pub const GUARD_TIMEOUT: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct Plan {
    pub layout: Layout,
    pub old: Slot,
    pub new: Slot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The new version came up; it stays.
    Kept,
    /// It didn't; the old slot runs again.
    RolledBack,
    /// The switch itself failed, before anything was restarted.
    NotSwitched,
}

/// What the guard touches outside the slots, so tests can stand in for the services and the clock.
pub trait Env {
    /// Restarts the services that run the binary.
    fn restart(&self) -> Result<(), String>;
    /// Whether the new version is up (the probe says `connected` with the new version; the hub answers `/healthz`).
    fn up(&self) -> bool;
    /// Called when the new version didn't come up, before the old slot is switched back and restarted: the hub restores its
    /// database here when the new version migrated it.
    fn rolling_back(&self);
    fn sleep(&self, d: Duration);
    /// Since the guard started.
    fn elapsed(&self) -> Duration;
}

/// Makes `slot` the one the services run: the wrapper, if there is one, is its copy, and the activation points at it.
fn switch(layout: &Layout, activation: &dyn Activation, slot: Slot) -> std::io::Result<()> {
    let file = layout.slot(slot);
    if !std::fs::symlink_metadata(&file)?.is_file() {
        return Err(std::io::Error::other(format!("{} isn't a file", file.display())));
    }
    if let Some(wrapper) = layout.wrapper() {
        Layout::replace(&wrapper, &std::fs::read(&file)?, 0o755)?;
    }
    activation.point_at(layout, slot)
}

/// Switches to the new slot, restarts, waits for [`Env::up`] for up to [`GUARD_TIMEOUT`], and otherwise goes back.
pub fn guard(plan: &Plan, activation: &dyn Activation, env: &dyn Env) -> Outcome {
    if let Err(e) = switch(&plan.layout, activation, plan.new) {
        tracing::error!(error = %e, "the update guard couldn't switch to the new slot");
        return Outcome::NotSwitched;
    }
    if let Err(e) = env.restart() {
        tracing::warn!(error = %e, "restarting the services");
    }
    while env.elapsed() < GUARD_TIMEOUT {
        if env.up() {
            tracing::info!("the new version is up; the update stays");
            return Outcome::Kept;
        }
        env.sleep(POLL);
    }
    tracing::warn!("the new version didn't come up in time; going back");
    env.rolling_back();
    if let Err(e) = switch(&plan.layout, activation, plan.old) {
        tracing::error!(error = %e, "the update guard couldn't switch back");
    }
    if let Err(e) = env.restart() {
        tracing::warn!(error = %e, "restarting the services");
    }
    Outcome::RolledBack
}

#[cfg(test)]
#[cfg(unix)]
mod tests;

#[cfg(test)]
#[cfg(windows)]
mod windows_tests;
