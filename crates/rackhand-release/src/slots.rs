//! A/B binary slots (7.3.3, 7.5.7, D73, D91, D98): a program that updates itself keeps two copies of its binary, `x-a` and
//! `x-b`, and a link the services run that points at one. An update is copied into the inactive slot by a root process that
//! checks the copy (never the file it was copied from, which the unprivileged side can change at any moment), and a guard
//! running the old, known-good binary switches the link and goes back when the new version doesn't come up. The probe's
//! helper and the hub's updater are two users of this; each has its own [`Layout`].

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::Digest;

use crate::binary::Version;
use crate::{Pinned, PublicKey};

/// At most this much is downloaded into a spool and copied into a slot.
pub const MAX_RELEASE_BYTES: u64 = 64 << 20;

/// Where one program's slots, link, spool and signed file name are, under the machine's root (`/` on a machine, a directory
/// in a test).
#[derive(Debug, Clone)]
pub struct Layout {
    pub root: PathBuf,
    /// The directory of the slots, the link and the wrapper, relative to the root.
    pub lib: &'static str,
    /// The slots' file names, A then B.
    pub slots: [&'static str; 2],
    /// The link the services run: a link in `lib` to a slot's name.
    pub link: &'static str,
    /// A copy of the binary beside the slots that sudo runs, kept in step with the active slot (the probe's command wrapper).
    pub wrapper: Option<&'static str>,
    /// The spool's directory, relative to the root, and the one file in it that is read.
    pub spool_dir: &'static str,
    pub spool_file: &'static str,
    /// The name the signature's trusted comment gives the release file.
    pub artifact: String,
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

fn refuse(code: &'static str, message: impl Into<String>) -> ApplyError {
    ApplyError { code, message: message.into() }
}

impl Layout {
    pub fn lib(&self) -> PathBuf {
        self.root.join(self.lib)
    }

    /// What the services run: a link to the active slot.
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
        self.root.join(self.spool_dir)
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

    /// Which slot the services run now.
    fn active(&self) -> Result<Active, ApplyError> {
        let link = self.link();
        let meta =
            std::fs::symlink_metadata(&link).map_err(|e| refuse("layout", format!("{}: {e}", link.display())))?;
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&link).map_err(|e| refuse("layout", e.to_string()))?;
            return match target.to_str().and_then(|t| self.slot_named(t)) {
                Some(slot) => Ok(Active::Slot(slot)),
                None => Err(refuse("layout", format!("{} points somewhere that isn't a slot", link.display()))),
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
        std::os::unix::fs::symlink(self.slot_name(slot), &tmp)?;
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

/// Copies the release in the spool into the inactive slot and checks the copy (not the spool file): the SHA-256 that was
/// offered, the signature against `keys`, and that the version the key signed is the one asked for and newer than
/// `installed`. A copy that fails any of it is deleted. The services still run what they ran; the guard switches.
pub fn apply(
    layout: &Layout,
    installed: Version,
    request: &Request,
    keys: &[(Pinned, PublicKey)],
) -> Result<Applied, ApplyError> {
    use std::io::Read;
    let claimed = Version::parse(&request.version).ok_or_else(|| refuse("bad_request", "the version isn't x.y.z"))?;
    if request.sha256.len() != 64 || !request.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(refuse("bad_request", "the hash isn't a lower-case SHA-256"));
    }
    let active = layout.active()?;
    let inactive = active.old().other();
    let mut bytes = Vec::new();
    layout
        .open_spool()?
        .take(MAX_RELEASE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| refuse("spool_unreadable", e.to_string()))?;
    if bytes.len() as u64 > MAX_RELEASE_BYTES {
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
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| fail(refuse("copy_failed", e.to_string())))?;
    if active == Active::Plain {
        // the file the installer put there becomes slot A, so there is a known-good version to go back to
        let plain = std::fs::read(layout.link()).map_err(|e| fail(refuse("layout", e.to_string())))?;
        Layout::replace(&layout.slot(Slot::A), &plain, 0o755).map_err(|e| fail(refuse("layout", e.to_string())))?;
        layout.point_at(Slot::A).map_err(|e| fail(refuse("layout", e.to_string())))?;
    }
    Ok(Applied { version: signed, old: active.old(), new: inactive })
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
    /// backup here when the new version migrated its database.
    fn rolling_back(&self);
    fn sleep(&self, d: Duration);
    /// Since the guard started.
    fn elapsed(&self) -> Duration;
}

/// Makes `slot` the one the services run: the wrapper, if there is one, is its copy and the link points at it.
fn switch(layout: &Layout, slot: Slot) -> std::io::Result<()> {
    let file = layout.slot(slot);
    if !std::fs::symlink_metadata(&file)?.is_file() {
        return Err(std::io::Error::other(format!("{} isn't a file", file.display())));
    }
    if let Some(wrapper) = layout.wrapper() {
        Layout::replace(&wrapper, &std::fs::read(&file)?, 0o755)?;
    }
    layout.point_at(slot)
}

/// Switches to the new slot, restarts, waits for [`Env::up`] for up to [`GUARD_TIMEOUT`], and otherwise goes back.
pub fn guard(plan: &Plan, env: &dyn Env) -> Outcome {
    if let Err(e) = switch(&plan.layout, plan.new) {
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
    if let Err(e) = switch(&plan.layout, plan.old) {
        tracing::error!(error = %e, "the update guard couldn't switch back");
    }
    if let Err(e) = env.restart() {
        tracing::warn!(error = %e, "restarting the services");
    }
    Outcome::RolledBack
}

#[cfg(test)]
mod tests;
