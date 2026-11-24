//! `cargo xtask release build|repro` (design 5.2, 13, D90, T91): release artifacts built the same way wherever they are built.
//!
//! `build` makes static binaries for each target with the flags that keep the build directory out of them (path remapping, the
//! commit's time for anything that wants a date, no incremental state) and `RACKHAND_RELEASE=1`, which makes the lab's
//! `lab-build` feature (the test release keys) fail the build. It writes the files, the rendered installers and an unsigned
//! `manifest.json` to a directory. It never holds a signing key: the maintainer signs offline (`docs/maintainers/signing.md`).
//!
//! `repro` builds a tag twice, from two copies at different paths with different target directories, and compares the hashes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::workspace_root;

pub const LINUX_X86_64: &str = "x86_64-unknown-linux-musl";
pub const LINUX_AARCH64: &str = "aarch64-unknown-linux-musl";
pub const WINDOWS: &str = "x86_64-pc-windows-gnu";

/// What a target builds: package, binary, and the name the release gives it (`<name>-<target>[.exe]`).
fn binaries(target: &str) -> Vec<(&'static str, &'static str, &'static str)> {
    if target == WINDOWS {
        vec![
            ("rackhand-probe", "rackhand-probe", "rackhand-probe"),
            ("rackhand-cli", "rackhand-cli", "rackhand-cli"),
            ("rackhand-release", "rackhand-verify", "rackhand-verify"),
        ]
    } else {
        vec![
            ("rackhand", "rackhand", "rackhand"),
            ("rackhand-probe", "rackhand-probe", "rackhand-probe"),
            ("rackhand-cli", "rackhand-cli", "rackhand-cli"),
            ("rackhand-release", "rackhand-verify", "rackhand-verify"),
        ]
    }
}

fn artifact_name(name: &str, target: &str) -> String {
    if target == WINDOWS { format!("{name}-{target}.exe") } else { format!("{name}-{target}") }
}

/// Where release builds happen: one path, the same on every machine. OpenSSL, built by a build script, keeps the directory it was
/// installed to in the binary (its modules path), so the hub differs byte for byte if its target directory does.
pub fn release_target_dir() -> PathBuf {
    PathBuf::from("/tmp/rackhand-release-target")
}

pub struct Options {
    /// The source tree to build.
    pub src: PathBuf,
    /// Where cargo builds.
    pub target_dir: PathBuf,
    /// Where the release files go.
    pub out: PathBuf,
    pub targets: Vec<String>,
    /// Seconds since the epoch of the commit being built, for `SOURCE_DATE_EPOCH`.
    pub epoch: String,
    /// Only these `<name>` of `<name>-<target>` (for `repro`, which compares the two programs that matter most).
    pub only: Option<Vec<String>>,
}

fn home(var: &str, default: &str) -> PathBuf {
    std::env::var_os(var).map(PathBuf::from).unwrap_or_else(|| {
        let user = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        user.join(default)
    })
}

/// The flags that keep where a build happened out of what it makes: the source tree, the cargo registry and the toolchain are
/// each given a fixed name, for the compiler and for C code built by build scripts.
pub fn rustflags(src: &Path) -> String {
    let (cargo, rustup) = (home("CARGO_HOME", ".cargo"), home("RUSTUP_HOME", ".rustup"));
    format!(
        "--remap-path-prefix={}=/build/src --remap-path-prefix={}=/build/cargo --remap-path-prefix={}=/build/rustup",
        src.display(),
        cargo.display(),
        rustup.display()
    )
}

fn cflags(src: &Path) -> String {
    let (cargo, rustup) = (home("CARGO_HOME", ".cargo"), home("RUSTUP_HOME", ".rustup"));
    [(src, "/build/src"), (cargo.as_path(), "/build/cargo"), (rustup.as_path(), "/build/rustup")]
        .iter()
        .map(|(from, to)| {
            format!("-ffile-prefix-map={}={to} -fdebug-prefix-map={}={to}", from.display(), from.display())
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// `cargo build --release --locked` of one binary for one target, as a release is built; returns its path.
fn cargo_build(o: &Options, target: &str, package: &str, bin: &str) -> Result<PathBuf> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .current_dir(&o.src)
        .args(["build", "--release", "--locked", "-q", "-p", package, "--bin", bin, "--target", target])
        .args(["--message-format=json", "--target-dir"])
        .arg(&o.target_dir)
        .env("RACKHAND_RELEASE", "1")
        .env("SOURCE_DATE_EPOCH", &o.epoch)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_ENCODED_RUSTFLAGS", rustflags(&o.src).replace(' ', "\x1f"))
        .env_remove("RUSTFLAGS")
        .env("CFLAGS", cflags(&o.src))
        .env("ZERO_AR_DATE", "1")
        .env("TZ", "UTC")
        .env("LC_ALL", "C")
        .stderr(Stdio::inherit())
        .output()
        .context("running cargo")?;
    if !out.status.success() {
        bail!("building {bin} for {target} failed");
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == bin)
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
        .with_context(|| format!("cargo made no executable for {bin}"))
}

/// What the program headers of an ELF file say: it asks for no interpreter and needs no shared library.
pub fn elf_is_static(bytes: &[u8]) -> Result<bool, String> {
    let u16_at = |at: usize| bytes.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize);
    let u32_at = |at: usize| bytes.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let u64_at = |at: usize| bytes.get(at..at + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8])) as usize);
    if bytes.get(..4) != Some(b"\x7fELF") || bytes.get(4) != Some(&2) || bytes.get(5) != Some(&1) {
        return Err("not a 64-bit little-endian ELF file".into());
    }
    let (off, size, count) = (u64_at(0x20), u16_at(0x36), u16_at(0x38));
    let (Some(off), Some(size), Some(count)) = (off, size, count) else { return Err("truncated ELF header".into()) };
    const PT_DYNAMIC: u32 = 2;
    const PT_INTERP: u32 = 3;
    const DT_NEEDED: usize = 1;
    for i in 0..count {
        let at = off + i * size;
        let (Some(kind), Some(p_off), Some(p_size)) = (u32_at(at), u64_at(at + 8), u64_at(at + 32)) else {
            return Err("truncated program header".into());
        };
        if kind == PT_INTERP {
            return Ok(false);
        }
        if kind == PT_DYNAMIC {
            let mut entry = p_off;
            while entry + 16 <= p_off + p_size {
                match u64_at(entry) {
                    Some(0) | None => break,
                    Some(DT_NEEDED) => return Ok(false),
                    _ => entry += 16,
                }
            }
        }
    }
    Ok(true)
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for b in data {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// A zip of `files` (name, bytes), stored without compression, in the order given, with the fixed time of 1980-01-01: the same
/// bytes for the same files wherever it is made.
pub fn zip(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    const DOS_TIME: u16 = 0;
    const DOS_DATE: u16 = (1 << 5) | 1;
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let (crc, size, offset) = (crc32(data), data.len() as u32, out.len() as u32);
        let name_bytes = name.as_bytes();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&DOS_TIME.to_le_bytes());
        out.extend_from_slice(&DOS_DATE.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0]);
        central.extend_from_slice(&DOS_TIME.to_le_bytes());
        central.extend_from_slice(&DOS_DATE.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0; 12]);
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }
    let central_at = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&central_at.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// The shipped Windows scripts as the files of the zip the installer unpacks into `C:\Program Files\Rackhand`, sorted by name.
fn windows_scripts(src: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let base = src.join("packaging/windows");
    let mut files = vec![("dispatch.ps1".to_string(), std::fs::read(base.join("dispatch.ps1"))?)];
    for dir in ["scripts", "schemas"] {
        let mut names: Vec<_> =
            std::fs::read_dir(base.join(dir))?.filter_map(|e| e.ok()).map(|e| e.file_name()).collect();
        names.sort();
        for name in names {
            files.push((format!("{dir}/{}", name.to_string_lossy()), std::fs::read(base.join(dir).join(&name))?));
        }
    }
    Ok(files)
}

/// Builds every selected artifact of `o.targets` into `o.out`; returns the file names and hashes.
pub fn build(o: &Options) -> Result<BTreeMap<String, String>> {
    std::fs::create_dir_all(&o.out)?;
    let wanted = |name: &str| o.only.as_ref().is_none_or(|only| only.iter().any(|n| n == name));
    for target in &o.targets {
        for (package, bin, name) in binaries(target) {
            if !wanted(name) {
                continue;
            }
            let built = cargo_build(o, target, package, bin)?;
            // a release binary needs nothing of the machine it runs on (AC43)
            if target != WINDOWS {
                let bytes = std::fs::read(&built).with_context(|| built.display().to_string())?;
                if elf_is_static(&bytes) != Ok(true) {
                    bail!("{bin} for {target} isn't statically linked");
                }
            }
            std::fs::copy(&built, o.out.join(artifact_name(name, target)))
                .with_context(|| format!("copying {}", built.display()))?;
        }
    }
    if o.only.is_none() {
        let packaging = o.src.join("packaging");
        for (from, name) in [
            ("systemd/rackhand-hub.service", "rackhand-hub.service"),
            ("systemd/rackhand-probe.service", "rackhand-probe.service"),
            ("systemd/rackhand-probe-helper.service", "rackhand-probe-helper.service"),
            ("systemd/rackhand-relay.service", "rackhand-relay.service"),
            ("openrc/rackhand-probe", "rackhand-probe.openrc"),
            ("openrc/rackhand-probe-helper", "rackhand-probe-helper.openrc"),
        ] {
            std::fs::copy(packaging.join(from), o.out.join(name)).with_context(|| from.to_string())?;
        }
        let version = std::fs::read_to_string(o.src.join("Cargo.toml"))?
            .lines()
            .find_map(|l| l.strip_prefix("version = ").map(|v| v.trim_matches('"').to_string()))
            .context("the workspace version")?;
        let verify_hash = |target: &str| {
            std::fs::read(o.out.join(artifact_name("rackhand-verify", target)))
                .map(|b| sha256(&b))
                .unwrap_or_else(|_| "0".repeat(64))
        };
        let script = std::fs::read_to_string(packaging.join("install.sh"))?
            .replace("__VERSION__", &version)
            .replace("__VERIFY_SHA256_X86_64__", &verify_hash(LINUX_X86_64))
            .replace("__VERIFY_SHA256_AARCH64__", &verify_hash(LINUX_AARCH64));
        std::fs::write(o.out.join("install.sh"), script)?;
        if o.targets.iter().any(|t| t == WINDOWS) {
            let script = std::fs::read_to_string(packaging.join("windows/install.ps1"))?
                .replace("__VERSION__", &version)
                .replace("__VERIFY_SHA256__", &verify_hash(WINDOWS));
            std::fs::write(o.out.join("install.ps1"), script)?;
            std::fs::write(o.out.join("rackhand-windows-scripts.zip"), zip(&windows_scripts(&o.src)?))?;
        }
        let manifest = rackhand_release::manifest::Manifest::of_dir(&version, &o.out)?;
        std::fs::write(o.out.join(rackhand_release::manifest::NAME), manifest.to_json())?;
    }
    let mut hashes = BTreeMap::new();
    for entry in std::fs::read_dir(&o.out)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            hashes.insert(entry.file_name().to_string_lossy().into_owned(), sha256(&std::fs::read(entry.path())?));
        }
    }
    Ok(hashes)
}

fn commit_epoch(src: &Path) -> Result<String> {
    if let Ok(e) = std::env::var("SOURCE_DATE_EPOCH") {
        return Ok(e);
    }
    let out = Command::new("git").current_dir(src).args(["log", "-1", "--format=%ct"]).output().context("git log")?;
    if !out.status.success() {
        bail!("git log failed; set SOURCE_DATE_EPOCH");
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn parse_targets(args: &[String]) -> Result<Vec<String>> {
    let mut targets = vec![LINUX_X86_64.to_string()];
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--targets" {
            let list = it.next().context("--targets takes a comma-separated list")?;
            targets = list.split(',').map(str::to_string).collect();
        }
    }
    for t in &targets {
        if ![LINUX_X86_64, LINUX_AARCH64, WINDOWS].contains(&t.as_str()) {
            bail!("no release target {t}; targets: {LINUX_X86_64}, {LINUX_AARCH64}, {WINDOWS}");
        }
    }
    Ok(targets)
}

fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

/// `release build [--out <dir>] [--targets <list>]`.
fn build_command(args: &[String]) -> Result<()> {
    let src = workspace_root();
    let out = option(args, "--out").map(PathBuf::from).unwrap_or_else(|| src.join("dist"));
    // a release is built in the fixed directory, clean: another path changes what OpenSSL embeds in the hub
    let target_dir = option(args, "--target-dir").map(PathBuf::from).unwrap_or_else(release_target_dir);
    let o = Options { epoch: commit_epoch(&src)?, src, target_dir, out, targets: parse_targets(args)?, only: None };
    let hashes = build(&o)?;
    for (name, hash) in hashes {
        println!("{hash}  {name}");
    }
    Ok(())
}

/// A copy of the commit's files at `dir` (a tag's source, without a `.git`).
fn export(src: &Path, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let archive = Command::new("git")
        .current_dir(src)
        .args(["archive", "--format=tar", "HEAD"])
        .stdout(Stdio::piped())
        .spawn()
        .context("git archive")?;
    let status = Command::new("tar")
        .arg("-x")
        .arg("-C")
        .arg(dir)
        .stdin(archive.stdout.context("git archive output")?)
        .status()
        .context("tar")?;
    if !status.success() {
        bail!("unpacking the source failed");
    }
    Ok(())
}

/// The artifacts `repro` builds and compares.
pub const REPRO: [&str; 2] = ["rackhand", "rackhand-probe"];

/// Builds [`REPRO`] twice from the last commit, in two directories, and returns each build's hashes.
pub fn repro_hashes() -> Result<(BTreeMap<String, String>, BTreeMap<String, String>)> {
    let src = workspace_root();
    let epoch = commit_epoch(&src)?;
    // RACKHAND_REPRO_KEEP=<dir> leaves both builds there, to find what differs
    let keep = std::env::var_os("RACKHAND_REPRO_KEEP").map(PathBuf::from);
    let base =
        keep.clone().unwrap_or_else(|| std::env::temp_dir().join(format!("rackhand-repro-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&base);
    let mut results = Vec::new();
    for which in ["first", "second-in-another-place"] {
        let dir = base.join(which);
        let tree = dir.join("source");
        export(&src, &tree)?;
        // each build starts from nothing in the same directory, so the only difference between them is where the source is
        let _ = std::fs::remove_dir_all(release_target_dir());
        let o = Options {
            src: tree,
            target_dir: release_target_dir(),
            out: dir.join("out"),
            targets: vec![LINUX_X86_64.to_string()],
            epoch: epoch.clone(),
            only: Some(REPRO.iter().map(|s| s.to_string()).collect()),
        };
        results.push(build(&o)?);
        let _ = std::fs::remove_dir_all(release_target_dir());
    }
    if keep.is_none() {
        let _ = std::fs::remove_dir_all(&base);
    }
    let second = results.pop().context("second build")?;
    let first = results.pop().context("first build")?;
    Ok((first, second))
}

/// `release repro`: prints the hashes of two builds of the last commit and fails when any differs.
fn repro_command() -> Result<()> {
    let (first, second) = repro_hashes()?;
    let mut differ = Vec::new();
    for (name, hash) in &first {
        let other = second.get(name).map(String::as_str).unwrap_or("missing");
        println!("{hash}  {name}\n{other}  {name} (second build)");
        if other != hash {
            differ.push(name.clone());
        }
    }
    if differ.is_empty() { Ok(()) } else { bail!("the two builds differ: {}", differ.join(", ")) }
}

pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("build") => build_command(&args[1..]),
        Some("repro") => repro_command(),
        _ => bail!("usage: cargo xtask release build [--out <dir>] [--targets <list>] | release repro"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal 64-bit little-endian ELF with the given program headers (type, offset, size) and a dynamic section.
    fn elf(headers: &[(u32, u64, u64)], dynamic: &[(u64, u64)]) -> Vec<u8> {
        let phoff = 64usize;
        let data_at = phoff + headers.len() * 56;
        let mut out = vec![0u8; data_at];
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = 2;
        out[5] = 1;
        out[0x20..0x28].copy_from_slice(&(phoff as u64).to_le_bytes());
        out[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        out[0x38..0x3a].copy_from_slice(&(headers.len() as u16).to_le_bytes());
        for (i, (kind, off, size)) in headers.iter().enumerate() {
            let at = phoff + i * 56;
            out[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            out[at + 8..at + 16].copy_from_slice(&(data_at as u64 + off).to_le_bytes());
            out[at + 32..at + 40].copy_from_slice(&size.to_le_bytes());
        }
        for (tag, value) in dynamic {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&value.to_le_bytes());
        }
        out
    }

    #[test]
    fn release_elf_checks_find_an_interpreter_or_a_needed_library() {
        // a static program: loadable segments only
        assert_eq!(elf_is_static(&elf(&[(1, 0, 0)], &[])), Ok(true));
        // static-pie: a dynamic section for its own relocation, naming no library
        assert_eq!(elf_is_static(&elf(&[(1, 0, 0), (2, 0, 32)], &[(0x1d, 0), (0, 0)])), Ok(true));
        // a dynamically linked program: an interpreter, or only a needed library
        assert_eq!(elf_is_static(&elf(&[(3, 0, 0), (1, 0, 0)], &[])), Ok(false));
        assert_eq!(elf_is_static(&elf(&[(2, 0, 32)], &[(1, 1), (0, 0)])), Ok(false));
        assert!(elf_is_static(b"MZ\x90\0").is_err());
        assert!(elf_is_static(&[]).is_err());
    }

    #[test]
    fn the_zip_is_the_same_for_the_same_files_and_unpacks() {
        let files = vec![("a.txt".to_string(), b"hello".to_vec()), ("dir/b.txt".to_string(), vec![0u8; 1000])];
        let first = zip(&files);
        assert_eq!(first, zip(&files), "no time or order of ours in it");
        assert_eq!(&first[..4], b"PK\x03\x04");
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926, "the standard check value");
        // the end record says two entries
        let end = first.len() - 22;
        assert_eq!(&first[end..end + 4], b"PK\x05\x06");
        assert_eq!(u16::from_le_bytes([first[end + 10], first[end + 11]]), 2);
    }

    #[test]
    fn rustflags_name_the_source_the_registry_and_the_toolchain() {
        let flags = rustflags(Path::new("/tmp/some/src"));
        assert!(flags.contains("--remap-path-prefix=/tmp/some/src=/build/src"), "{flags}");
        assert!(flags.contains("=/build/cargo") && flags.contains("=/build/rustup"), "{flags}");
        assert!(cflags(Path::new("/tmp/some/src")).contains("-ffile-prefix-map=/tmp/some/src=/build/src"));
    }

    #[test]
    fn unknown_targets_are_refused() {
        assert!(parse_targets(&["--targets".into(), "i686-pc-windows-msvc".into()]).is_err());
        assert_eq!(parse_targets(&[]).unwrap(), [LINUX_X86_64]);
        assert_eq!(parse_targets(&["--targets".into(), format!("{LINUX_X86_64},{WINDOWS}")]).unwrap().len(), 2);
    }
}

#[cfg(test)]
mod slow_tests {
    use super::*;

    fn target_dir() -> PathBuf {
        std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|| workspace_root().join("target"))
    }

    /// AC43: every artifact of the release is static: no interpreter, no shared library to need. This builds them as a release
    /// is built (`cargo xtask ci release`).
    #[test]
    fn artifacts_are_static() {
        let src = workspace_root();
        let out = std::env::temp_dir().join(format!("rackhand-static-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        let o = Options {
            epoch: commit_epoch(&src).unwrap(),
            src,
            target_dir: target_dir(),
            out: out.clone(),
            targets: vec![LINUX_X86_64.to_string()],
            only: None,
        };
        let hashes = build(&o).unwrap();
        for name in ["rackhand", "rackhand-probe", "rackhand-cli", "rackhand-verify"] {
            let file = format!("{name}-{LINUX_X86_64}");
            assert!(hashes.contains_key(&file), "{file} is a release artifact");
            let bytes = std::fs::read(out.join(&file)).unwrap();
            assert_eq!(elf_is_static(&bytes), Ok(true), "{file} is statically linked");
        }
        // the manifest lists exactly what is there, and the installer has its verifier's hash in it
        let manifest =
            rackhand_release::manifest::Manifest::parse(&std::fs::read_to_string(out.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest.check_dir(&out), Ok(()));
        let install = std::fs::read_to_string(out.join("install.sh")).unwrap();
        assert!(!install.contains("__VERIFY_SHA256") && !install.contains("__VERSION__"), "the installer is rendered");
        let _ = std::fs::remove_dir_all(&out);
    }

    /// AC43: building the same commit in two places gives the same bytes, for the hub and the probe.
    mod repro {
        #[test]
        fn two_builds_identical_hashes() {
            let (first, second) = super::super::repro_hashes().unwrap();
            // the names sort as strings: `rackhand-probe-...` before `rackhand-x86_64-...`
            assert_eq!(
                first.keys().collect::<Vec<_>>(),
                [&format!("rackhand-probe-{}", super::LINUX_X86_64), &format!("rackhand-{}", super::LINUX_X86_64)]
            );
            assert_eq!(first, second, "the hash of each artifact is the same from the other directory");
        }
    }
}
