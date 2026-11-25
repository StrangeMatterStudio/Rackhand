//! `cargo xtask ebpf build` (T68): builds `crates/rackhand-probe-ebpf` for `bpfel-unknown-none` with the crate's own
//! dated nightly and bpf-linker, outside the workspace, and prints the object's path. Builds of the probe that should
//! carry the capture set `RACKHAND_PROBE_EBPF` to it; others capture by sampling.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::workspace_root;

pub fn crate_dir() -> PathBuf {
    workspace_root().join("crates").join("rackhand-probe-ebpf")
}

/// The flags in the crate's `.cargo/config.toml`, which `CARGO_ENCODED_RUSTFLAGS` would replace.
pub const CONFIG_RUSTFLAGS: [&str; 4] = ["-C", "debuginfo=2", "-C", "link-arg=--btf"];

/// The crate's flags and a release's path remaps (space-separated), as `CARGO_ENCODED_RUSTFLAGS`.
pub fn release_rustflags(remaps: &str) -> String {
    CONFIG_RUSTFLAGS.iter().copied().chain(remaps.split_whitespace()).collect::<Vec<_>>().join("\x1f")
}

/// Whether `binary` holds all of `object` (a probe built with `RACKHAND_PROBE_EBPF` embeds it unchanged).
pub fn carries(binary: &[u8], object: &[u8]) -> bool {
    !object.is_empty() && binary.windows(object.len()).any(|w| w == object)
}

fn target_dir() -> PathBuf {
    let base =
        std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|| workspace_root().join("target"));
    base.join("rackhand-probe-ebpf")
}

/// Builds the programs; returns the object.
pub fn build() -> Result<PathBuf> {
    build_in(&crate_dir(), &target_dir(), None)
}

/// Builds the crate in `dir` into `target`, with a release's path remaps when given; returns the object.
pub fn build_in(dir: &Path, target: &Path, remaps: Option<&str>) -> Result<PathBuf> {
    let linker = Command::new("bpf-linker").arg("--version").output();
    if !linker.is_ok_and(|o| o.status.success()) {
        bail!("bpf-linker isn't on PATH: install the v0.13.0 release binary (docs/maintainers/ebpf.md)");
    }
    // `cargo` from PATH (the rustup proxy), so the crate's rust-toolchain.toml picks its nightly; none of this
    // workspace's toolchain settings may leak in
    let mut cargo = Command::new("cargo");
    cargo
        .current_dir(dir)
        .args(["build", "--release", "--locked"])
        .env("CARGO_TARGET_DIR", target)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS");
    if let Some(remaps) = remaps {
        cargo.env("CARGO_ENCODED_RUSTFLAGS", release_rustflags(remaps));
    }
    let status = cargo.status().context("running cargo for the eBPF programs")?;
    if !status.success() {
        bail!("building {} failed", dir.display());
    }
    let object = target.join("bpfel-unknown-none").join("release").join("rackhand-probe-ebpf");
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
    use super::{CONFIG_RUSTFLAGS, carries, crate_dir, is_bpf_object, release_rustflags};

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

    #[test]
    fn release_flags_keep_the_crates_own_and_add_the_remaps() {
        // CARGO_ENCODED_RUSTFLAGS replaces the crate's configured flags, so a release build must repeat them
        let config = std::fs::read_to_string(crate_dir().join(".cargo/config.toml")).unwrap();
        let configured = config.lines().find_map(|l| l.strip_prefix("rustflags = ")).expect("the crate's rustflags");
        let listed: Vec<String> =
            configured.trim_matches(['[', ']']).split(',').map(|f| f.trim().trim_matches('"').to_string()).collect();
        assert_eq!(listed, CONFIG_RUSTFLAGS);
        let flags = release_rustflags("--remap-path-prefix=/src=/build/src --remap-path-prefix=/c=/build/cargo");
        let parts: Vec<&str> = flags.split('\x1f').collect();
        assert_eq!(&parts[..4], CONFIG_RUSTFLAGS);
        assert_eq!(&parts[4..], ["--remap-path-prefix=/src=/build/src", "--remap-path-prefix=/c=/build/cargo"]);
    }

    #[test]
    fn a_probe_carries_the_object_it_was_built_with() {
        let object = b"\x7fELF the program Dual MIT/GPL".to_vec();
        let mut binary = vec![0u8; 100];
        binary.extend_from_slice(&object);
        binary.extend_from_slice(&[1u8; 50]);
        assert!(carries(&binary, &object));
        assert!(!carries(&binary[..120], &object), "cut short");
        assert!(!carries(&binary, b""), "no object is nothing to carry");
    }
}
