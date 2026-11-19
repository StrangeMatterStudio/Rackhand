//! Test kernels for the eBPF and network tiers: pinned kernel.org tarballs (`tests/ebpf/kernels.toml`), checked
//! against their SHA-256 and built in a container into `~/.cache/rackhand-vm/kernels/`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::vm::{cache_dir, run_checked};
use crate::workspace_root;

#[derive(Debug, Clone, Deserialize)]
pub struct Kernel {
    pub series: String,
    pub version: String,
    pub url: String,
    pub sha256: String,
}

#[derive(Deserialize)]
struct KernelsFile {
    kernel: Vec<Kernel>,
}

pub fn parse_kernels(text: &str) -> Result<Vec<Kernel>> {
    let file: KernelsFile = toml::from_str(text).context("parsing kernels.toml")?;
    Ok(file.kernel)
}

pub fn load() -> Result<Vec<Kernel>> {
    let path = workspace_root().join("tests/ebpf/kernels.toml");
    parse_kernels(&std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?)
}

/// Checks `path` against `expected` (lowercase hex). On a mismatch the file is deleted and an error returned.
pub fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    let mut file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if actual != expected.to_ascii_lowercase() {
        std::fs::remove_file(path).with_context(|| format!("deleting {}", path.display()))?;
        bail!("SHA-256 mismatch for {}: expected {expected}, got {actual}; the file was deleted", path.display());
    }
    Ok(())
}

pub fn image_path(kernel: &Kernel) -> PathBuf {
    cache_dir().join("kernels").join(format!("bzImage-{}", kernel.version))
}

/// Returns the built kernel for `series`, fetching and building it first if needed.
pub fn ensure_series(series: &str) -> Result<PathBuf> {
    let kernel = load()?
        .into_iter()
        .find(|k| k.series == series)
        .with_context(|| format!("kernel series {series} is not in kernels.toml"))?;
    ensure(&kernel)
}

pub fn ensure(kernel: &Kernel) -> Result<PathBuf> {
    let image = image_path(kernel);
    if image.exists() {
        return Ok(image);
    }
    let src = cache_dir().join("src");
    std::fs::create_dir_all(&src)?;
    let tarball = src.join(format!("linux-{}.tar.xz", kernel.version));
    if !tarball.exists() {
        println!("fetching {}", kernel.url);
        run_checked(Command::new("curl").args(["-fsSL", "-o"]).arg(&tarball).arg(&kernel.url))?;
    }
    verify_sha256(&tarball, &kernel.sha256)?;
    build(kernel)?;
    if !image.exists() {
        bail!("kernel build for {} produced no image at {}", kernel.version, image.display());
    }
    Ok(image)
}

fn build(kernel: &Kernel) -> Result<()> {
    let vm_dir = workspace_root().join("tests/vm");
    println!("building kernel {} (a few minutes)", kernel.version);
    run_checked(
        Command::new("docker")
            .args(["build", "-q", "-t", "rackhand-kbuild", "-f"])
            .arg(vm_dir.join("kbuild.Dockerfile"))
            .arg(&vm_dir),
    )?;
    let uid = id_flag("-u")?;
    let gid = id_flag("-g")?;
    run_checked(
        Command::new("docker")
            .args(["run", "--rm", "-u", &format!("{uid}:{gid}"), "-e", "HOME=/tmp"])
            .args(["-e", "KBUILD_BUILD_USER=rackhand", "-e", "KBUILD_BUILD_HOST=rackhand", "-v"])
            .arg(format!("{}:/cache", cache_dir().display()))
            .arg("-v")
            .arg(format!("{}:/cfg:ro", vm_dir.display()))
            .args(["rackhand-kbuild", "sh", "/cfg/build-kernel.sh", &kernel.version]),
    )
}

fn id_flag(flag: &str) -> Result<String> {
    let out = Command::new("id").arg(flag).output().context("running id")?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// `cargo xtask kernels fetch`.
pub fn fetch_all() -> Result<()> {
    for kernel in load()? {
        let image = ensure(&kernel)?;
        println!("{} ready: {}", kernel.version, image.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_mismatch_is_refused() {
        let dir = std::env::temp_dir().join(format!("rackhand-kernels-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("linux-test.tar.xz");
        std::fs::write(&file, b"not the kernel").unwrap();

        let wrong = "0".repeat(64);
        let err = verify_sha256(&file, &wrong).unwrap_err().to_string();
        assert!(err.contains("SHA-256"), "{err}");
        assert!(!file.exists(), "a file with the wrong hash must be deleted");

        std::fs::write(&file, b"abc").unwrap();
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        verify_sha256(&file, abc).unwrap();
        assert!(file.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn kernels_toml_lists_the_three_series() {
        let text = std::fs::read_to_string(workspace_root().join("tests/ebpf/kernels.toml")).unwrap();
        let kernels = parse_kernels(&text).unwrap();
        let series: Vec<&str> = kernels.iter().map(|k| k.series.as_str()).collect();
        assert_eq!(series, ["5.10", "6.1", "7.0"]);
        assert!(kernels.iter().all(|k| k.sha256.len() == 64 && k.url.starts_with("https://cdn.kernel.org/")));
    }
}
