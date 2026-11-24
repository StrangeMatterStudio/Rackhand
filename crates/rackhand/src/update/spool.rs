//! Root writing in a directory an unprivileged user owns (its spool, the hub's data directory): never through a link. The
//! directory is opened one component at a time without following links, a new file is created in it exclusively and without
//! following a link, given the directory's owner, and renamed into place; a file is removed by name in that directory.

use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{AtFlags, CWD, Mode, OFlags, openat, renameat, unlinkat};

fn io(e: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(e.raw_os_error())
}

/// `rel` under `root`, opened as a directory without following a link anywhere below the root.
pub fn open_dir(root: &Path, rel: &Path) -> std::io::Result<OwnedFd> {
    let mut dir = openat(CWD, root, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()).map_err(io)?;
    for part in rel.iter() {
        dir =
            openat(&dir, part, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
                .map_err(io)?;
    }
    Ok(dir)
}

/// Writes `name` in the directory with `bytes`, owned by the directory's owner, mode 0644.
pub fn write_in(root: &Path, rel: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    write_from(root, rel, name, &mut &bytes[..])
}

/// The same, from a reader (a database copy can be large).
pub fn write_from(root: &Path, rel: &Path, name: &str, from: &mut dyn std::io::Read) -> std::io::Result<()> {
    if name.contains('/') || name.is_empty() || name == ".." {
        return Err(std::io::Error::other("a file in the directory is named, not a path"));
    }
    let dir = open_dir(root, rel)?;
    let stat = rustix::fs::fstat(&dir).map_err(io)?;
    let tmp = format!(".{name}.rackhand-tmp");
    let _ = unlinkat(&dir, tmp.as_str(), AtFlags::empty());
    let fd = openat(
        &dir,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )
    .map_err(io)?;
    rustix::fs::fchown(&fd, Some(rustix::fs::Uid::from_raw(stat.st_uid)), Some(rustix::fs::Gid::from_raw(stat.st_gid)))
        .map_err(io)?;
    let mut file = std::fs::File::from(fd);
    std::io::copy(from, &mut file)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    renameat(&dir, tmp.as_str(), &dir, name).map_err(io)
}

/// Removes `name` from the directory, if it is there (a link is removed, not followed).
pub fn remove_in(root: &Path, rel: &Path, name: &str) -> std::io::Result<()> {
    let dir = open_dir(root, rel)?;
    match unlinkat(&dir, name, AtFlags::empty()) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(io(e)),
    }
}
