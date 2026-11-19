//! Test VMs for the network and eBPF tiers: a Debian root filesystem (with `qemu-guest-agent`) built in a
//! container, and `vmtest` booting a test kernel with it. `vmtest` runs under `unshare -r` so the guest sees the
//! unprivileged rootfs as root-owned.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::workspace_root;

pub fn cache_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".cache/rackhand-vm")
}

/// Runs a command with inherited output; fails with the command line if it exits non-zero.
pub fn run_checked(cmd: &mut Command) -> Result<()> {
    let status = cmd.status().with_context(|| format!("starting {cmd:?}"))?;
    if !status.success() {
        bail!("command failed ({status}): {cmd:?}");
    }
    Ok(())
}

/// Builds (or reuses) the test VM root filesystem and returns its directory.
pub fn build_rootfs() -> Result<PathBuf> {
    let vm_dir = workspace_root().join("tests/vm");
    let dockerfile = vm_dir.join("rootfs.Dockerfile");
    let recipe = std::fs::read(&dockerfile).with_context(|| format!("reading {}", dockerfile.display()))?;
    let hash: String = Sha256::digest(&recipe).iter().map(|b| format!("{b:02x}")).collect();
    let dir = cache_dir().join("rootfs");
    let stamp = dir.join(".rackhand-rootfs");
    if std::fs::read_to_string(&stamp)
        .map(|s| s.trim() == hash)
        .unwrap_or(false)
    {
        return Ok(dir);
    }
    println!("building the test VM root filesystem");
    run_checked(
        Command::new("docker")
            .args(["build", "-q", "-t", "rackhand-vm-rootfs", "-f"])
            .arg(&dockerfile)
            .arg(&vm_dir),
    )?;
    let out = Command::new("docker").args(["create", "rackhand-vm-rootfs"]).output()?;
    if !out.status.success() {
        bail!("docker create failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let container = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let staging = cache_dir().join("rootfs.new");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(&staging)?;
    let export = format!(
        "docker export {container} | tar -x -C '{}' --no-same-owner --exclude='dev/*'",
        staging.display()
    );
    let result = run_checked(Command::new("sh").args(["-c", &export]));
    run_checked(
        Command::new("docker")
            .args(["rm", "-f", &container])
            .stdout(std::process::Stdio::null()),
    )?;
    result?;
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::rename(&staging, &dir)?;
    std::fs::write(&stamp, &hash)?;
    Ok(dir)
}

/// One command to run as root inside a test VM.
#[derive(Debug)]
pub struct VmRun<'a> {
    pub name: &'a str,
    pub kernel: &'a Path,
    pub command: String,
    pub env: Vec<(&'a str, String)>,
    /// Host directories mounted at the same path in the guest.
    pub mounts: Vec<PathBuf>,
    pub memory: &'a str,
    pub cpus: u32,
}

/// The host PATH without entries a shell would split or choke on, and without the Windows drives in WSL.
fn guest_safe_path() -> String {
    let path = std::env::var("PATH").unwrap_or_default();
    path.split(':')
        .filter(|p| {
            !p.is_empty() && !p.starts_with("/mnt/") && !p.contains(|c: char| c.is_whitespace() || "()'\"$".contains(c))
        })
        .collect::<Vec<_>>()
        .join(":")
}

pub fn run(spec: &VmRun<'_>) -> Result<()> {
    let rootfs = build_rootfs()?;
    let dir = cache_dir().join("vmtest");
    std::fs::create_dir_all(&dir)?;
    let mut toml = format!(
        "[[target]]\nname = {name:?}\nkernel = {kernel:?}\nrootfs = {rootfs:?}\ncommand = {command:?}\n\
         [target.vm]\nnum_cpus = {cpus}\nmemory = {memory:?}\n[target.vm.mounts]\n",
        name = spec.name,
        kernel = spec.kernel.display().to_string(),
        rootfs = rootfs.display().to_string(),
        command = spec.command,
        cpus = spec.cpus,
        memory = spec.memory,
    );
    for mount in &spec.mounts {
        let path = mount.display().to_string();
        toml.push_str(&format!("{path:?} = {{ host_path = {path:?}, writable = false }}\n"));
    }
    let config = dir.join(format!("{}.toml", spec.name.replace(' ', "-")));
    std::fs::write(&config, toml)?;
    let mut cmd = Command::new("unshare");
    cmd.arg("-r").arg("vmtest").arg("-c").arg(&config);
    // vmtest writes PATH unquoted into the guest's init script; WSL's PATH holds Windows directories with spaces and
    // parentheses, which is a shell syntax error there.
    cmd.env("PATH", guest_safe_path());
    for (key, value) in &spec.env {
        cmd.env(key, value);
    }
    run_checked(&mut cmd)
}
