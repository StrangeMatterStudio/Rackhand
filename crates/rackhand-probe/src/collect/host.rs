//! Where the collectors read from: the real system, or a fixture tree with the same paths (plan T22). A fixture tree
//! also holds `statvfs.txt` (one mount per line: path, total, free and available bytes, inodes and free inodes) and the
//! output of `systemctl list-units` and `list-unit-files` in `units.txt` and `unit-files.txt`.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsStat {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub avail_bytes: u64,
    pub files: u64,
    pub files_free: u64,
}

pub trait Host {
    /// A file under the root, such as `proc/stat`.
    fn read(&self, rel: &str) -> Option<String>;
    /// Directory entries under the root.
    fn list(&self, rel: &str) -> Vec<String>;
    fn statvfs(&self, mount: &str) -> Option<FsStat>;
    /// `systemctl list-units --all --type=service --plain --no-legend`.
    fn units(&self) -> Option<String>;
    /// `systemctl list-unit-files --type=service --plain --no-legend`.
    fn unit_files(&self) -> Option<String>;
}

#[derive(Debug, Clone)]
pub struct RootHost {
    root: PathBuf,
}

impl RootHost {
    pub fn new(root: impl Into<PathBuf>) -> RootHost {
        RootHost { root: root.into() }
    }

    /// A fixture's `statvfs.txt` line for `mount`, read each time, so a test can change a mount's usage.
    fn fixture_statvfs(&self, mount: &str) -> Option<FsStat> {
        self.read("statvfs.txt")?.lines().find_map(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            let n = |i: usize| p.get(i).and_then(|v| v.parse::<u64>().ok());
            (p.first() == Some(&mount)).then_some(())?;
            Some(FsStat { total_bytes: n(1)?, free_bytes: n(2)?, avail_bytes: n(3)?, files: n(4)?, files_free: n(5)? })
        })
    }

    pub fn system() -> RootHost {
        RootHost::new("/")
    }

    fn is_system(&self) -> bool {
        self.root == Path::new("/")
    }
}

fn systemctl(args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("systemctl").args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

impl Host for RootHost {
    fn read(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.root.join(rel)).ok()
    }

    fn list(&self, rel: &str) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.root.join(rel))
            .map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        names.sort();
        names
    }

    fn statvfs(&self, mount: &str) -> Option<FsStat> {
        if self.is_system() {
            return system_statvfs(mount);
        }
        self.fixture_statvfs(mount)
    }

    fn units(&self) -> Option<String> {
        if self.is_system() {
            return systemctl(&["list-units", "--all", "--type=service", "--plain", "--no-legend", "--no-pager"]);
        }
        self.read("units.txt")
    }

    fn unit_files(&self) -> Option<String> {
        if self.is_system() {
            return systemctl(&["list-unit-files", "--type=service", "--plain", "--no-legend", "--no-pager"]);
        }
        self.read("unit-files.txt")
    }
}

#[cfg(target_os = "linux")]
fn system_statvfs(mount: &str) -> Option<FsStat> {
    let s = rustix::fs::statvfs(mount).ok()?;
    let frag = s.f_frsize;
    Some(FsStat {
        total_bytes: s.f_blocks * frag,
        free_bytes: s.f_bfree * frag,
        avail_bytes: s.f_bavail * frag,
        files: s.f_files,
        files_free: s.f_ffree,
    })
}

#[cfg(not(target_os = "linux"))]
fn system_statvfs(_mount: &str) -> Option<FsStat> {
    None
}
