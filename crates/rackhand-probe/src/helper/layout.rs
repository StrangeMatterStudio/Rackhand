//! The ownership table of 7.3.3 (D91), enforced by the helper when it starts: nothing root reads as a trust anchor or
//! executes is writable by the probe user. Root's directories are created and kept root-owned; root's files are put
//! back to `root 0644` if they exist; the probe's directories are its own. A symlink in the table is never followed.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    Root,
    Probe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dir,
    /// Kept only if it exists (the installer writes it).
    File,
}

/// Path, owner, mode, kind.
pub const TABLE: &[(&str, Owner, u32, Kind)] = &[
    ("run/rackhand-helper", Owner::Root, 0o755, Kind::Dir),
    ("usr/local/lib/rackhand", Owner::Root, 0o755, Kind::Dir),
    ("etc/rackhand-probe", Owner::Root, 0o755, Kind::Dir),
    ("etc/rackhand-probe/probe.toml", Owner::Root, 0o644, Kind::File),
    ("etc/rackhand", Owner::Root, 0o755, Kind::Dir),
    ("etc/rackhand/commands.json", Owner::Root, 0o644, Kind::File),
    ("var/lib/rackhand-helper", Owner::Root, 0o700, Kind::Dir),
    ("var/lib/rackhand-run", Owner::Root, 0o700, Kind::Dir),
    ("run/rackhand-probe", Owner::Probe, 0o755, Kind::Dir),
    ("var/lib/rackhand-probe", Owner::Probe, 0o700, Kind::Dir),
];

/// Applies the table under `root` (`/` on a machine); returns what couldn't be applied.
pub fn enforce(root: &Path, probe: (u32, u32)) -> Vec<String> {
    let mut problems = Vec::new();
    for (rel, owner, mode, kind) in TABLE {
        let path: PathBuf = root.join(rel);
        if let Err(e) = apply(&path, *owner, *mode, *kind, probe) {
            problems.push(format!("{}: {e}", path.display()));
        }
    }
    problems
}

fn apply(path: &Path, owner: Owner, mode: u32, kind: Kind, probe: (u32, u32)) -> std::io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if kind == Kind::File {
                return Ok(());
            }
            std::fs::create_dir_all(path)?;
            std::fs::symlink_metadata(path)?
        }
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() {
        return Err(std::io::Error::other("is a symlink; not followed"));
    }
    if (kind == Kind::Dir) != meta.is_dir() {
        return Err(std::io::Error::other("not the kind of entry the table names"));
    }
    let (uid, gid) = match owner {
        Owner::Root => (0, 0),
        Owner::Probe => probe,
    };
    if meta.uid() != uid || meta.gid() != gid {
        rustix::fs::chown(path, Some(rustix::fs::Uid::from_raw(uid)), Some(rustix::fs::Gid::from_raw(gid)))?;
    }
    if meta.mode() & 0o7777 != mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}
