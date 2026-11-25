//! `cargo xtask ebpf build` (T68): builds `crates/rackhand-probe-ebpf` for `bpfel-unknown-none` with the crate's own
//! dated nightly and bpf-linker, outside the workspace, and prints the object's path. Builds of the probe that should
//! carry the capture set `RACKHAND_PROBE_EBPF` to it; others capture by sampling.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::workspace_root;

pub fn crate_dir() -> PathBuf {
    workspace_root().join("crates").join("rackhand-probe-ebpf")
}

fn target_dir() -> PathBuf {
    let base =
        std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|| workspace_root().join("target"));
    base.join("rackhand-probe-ebpf")
}

/// The object a build leaves.
pub fn object_path() -> PathBuf {
    target_dir().join("bpfel-unknown-none").join("release").join("rackhand-probe-ebpf")
}

/// Builds the programs; returns the object.
pub fn build() -> Result<PathBuf> {
    let linker = Command::new("bpf-linker").arg("--version").output();
    if !linker.is_ok_and(|o| o.status.success()) {
        bail!("bpf-linker isn't on PATH: install the v0.13.0 release binary (docs/maintainers/ebpf.md)");
    }
    // `cargo` from PATH (the rustup proxy), so the crate's rust-toolchain.toml picks its nightly; none of this
    // workspace's toolchain settings may leak in
    let status = Command::new("cargo")
        .current_dir(crate_dir())
        .args(["build", "--release", "--locked"])
        .env("CARGO_TARGET_DIR", target_dir())
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()
        .context("running cargo for the eBPF programs")?;
    if !status.success() {
        bail!("building crates/rackhand-probe-ebpf failed");
    }
    let object = object_path();
    let bytes = std::fs::read(&object).with_context(|| format!("reading {}", object.display()))?;
    if !is_bpf_object(&bytes) {
        bail!("{} isn't an eBPF ELF object", object.display());
    }
    Ok(object)
}

/// A little-endian ELF relocatable for the BPF machine (247).
pub fn is_bpf_object(bytes: &[u8]) -> bool {
    bytes.len() > 20 && bytes[..4] == *b"\x7fELF" && bytes[5] == 1 && u16::from_le_bytes([bytes[18], bytes[19]]) == 247
}

pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("build") => {
            println!("{}", build()?.display());
            Ok(())
        }
        _ => bail!("usage: cargo xtask ebpf build"),
    }
}

#[cfg(test)]
mod tests {
    use super::is_bpf_object;

    #[test]
    fn recognizes_bpf_objects_only() {
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[5] = 1;
        elf[18..20].copy_from_slice(&247u16.to_le_bytes());
        assert!(is_bpf_object(&elf));
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        assert!(!is_bpf_object(&elf), "an x86-64 object");
        assert!(!is_bpf_object(b""), "nothing");
    }
}
