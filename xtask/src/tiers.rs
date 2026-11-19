//! `cargo xtask ci <tier>`: the test tiers from design 14, run the same way locally and in CI.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::vm::{self, VmRun, run_checked};
use crate::{kernels, workspace_root};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Fast,
    It,
    Net,
    Ebpf,
    Win,
    Perf,
}

const TIERS: &[(&str, Tier, &str)] = &[
    (
        "fast",
        Tier::Fast,
        "fmt, clippy, dependency rules, cargo deny, unit, contract and collector tests",
    ),
    ("it", Tier::It, "integration tests in Docker containers"),
    ("net", Tier::Net, "network namespace tests inside a QEMU VM"),
    (
        "ebpf",
        Tier::Ebpf,
        "kernel tests inside a QEMU VM per kernel in kernels.toml",
    ),
    (
        "win",
        Tier::Win,
        "Windows cross builds and Pester tests of the shipped PowerShell",
    ),
    ("perf", Tier::Perf, "soak, load and fill tests"),
];

impl Tier {
    pub fn parse(name: &str) -> Result<Tier> {
        match TIERS.iter().find(|(n, _, _)| *n == name) {
            Some((_, tier, _)) => Ok(*tier),
            None => {
                let list: Vec<String> = TIERS.iter().map(|(n, _, what)| format!("  {n:<5} {what}")).collect();
                bail!("unknown tier `{name}`; tiers:\n{}", list.join("\n"))
            }
        }
    }
}

fn cargo() -> Command {
    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.current_dir(workspace_root());
    cmd
}

pub fn run(args: &[String]) -> Result<()> {
    let name = args.first().context("usage: cargo xtask ci <tier>")?;
    match Tier::parse(name)? {
        Tier::Fast => fast(),
        Tier::It => it(),
        Tier::Net => net(),
        Tier::Ebpf => ebpf(),
        Tier::Win => win(),
        Tier::Perf => perf(),
    }
}

fn fast() -> Result<()> {
    run_checked(cargo().args(["fmt", "--all", "--check"]))?;
    run_checked(cargo().args(["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"]))?;
    crate::arch::run(&workspace_root())?;
    run_checked(cargo().args(["deny", "--log-level", "error", "check"]))?;
    run_checked(cargo().args(["nextest", "run", "--profile", "ci"]))
}

/// `cargo xtask it-images`: builds every `tests/it/images/<name>/Dockerfile` as `rackhand-it-<name>`.
pub fn build_it_images() -> Result<()> {
    let images = workspace_root().join("tests/it/images");
    if !images.is_dir() {
        return Ok(());
    }
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&images)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join("Dockerfile").exists())
        .collect();
    dirs.sort();
    for dir in dirs {
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        println!("building rackhand-it-{name}");
        run_checked(
            Command::new("docker")
                .args(["build", "-q", "-t", &format!("rackhand-it-{name}")])
                .arg(&dir),
        )?;
    }
    Ok(())
}

fn it() -> Result<()> {
    build_it_images()?;
    run_checked(cargo().args(["nextest", "run", "-p", "rackhand-it", "--profile", "it"]))
}

/// Builds a package's test binaries and returns their paths.
fn test_binaries(package: &str) -> Result<Vec<PathBuf>> {
    let out = cargo()
        .args(["test", "-p", package, "--no-run", "--message-format=json"])
        .stderr(std::process::Stdio::inherit())
        .output()?;
    if !out.status.success() {
        bail!("building the tests of {package} failed");
    }
    let mut bins = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if msg["reason"] == "compiler-artifact" && msg["profile"]["test"] == true {
            if let Some(exe) = msg["executable"].as_str() {
                bins.push(PathBuf::from(exe));
            }
        }
    }
    if bins.is_empty() {
        bail!("{package} has no test binaries");
    }
    Ok(bins)
}

/// The guest command that runs each test binary in turn, one test at a time.
fn guest_command(bins: &[PathBuf]) -> String {
    let list: Vec<String> = bins.iter().map(|b| format!("'{}'", b.display())).collect();
    format!(
        "set -e; cd /tmp; for b in {}; do \"$b\" --test-threads=1; done",
        list.join(" ")
    )
}

fn target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("target"))
}

fn net() -> Result<()> {
    let bins = test_binaries("rackhand-net-tests")?;
    let kernel = kernels::ensure_series("6.1")?;
    vm::run(&VmRun {
        name: "net 6.1",
        kernel: &kernel,
        command: guest_command(&bins),
        env: vec![("RACKHAND_TIER", "net".into())],
        mounts: vec![target_dir()],
        memory: "2G",
        cpus: 2,
    })
}

fn ebpf() -> Result<()> {
    let bins = test_binaries("rackhand-ebpf-tests")?;
    for kernel in kernels::load()? {
        let image = kernels::ensure(&kernel)?;
        println!("== eBPF tier on {}", kernel.version);
        vm::run(&VmRun {
            name: &format!("ebpf {}", kernel.series),
            kernel: &image,
            command: guest_command(&bins),
            env: vec![
                ("RACKHAND_TIER", "ebpf".into()),
                ("RACKHAND_EXPECT_KERNEL", kernel.series.clone()),
            ],
            mounts: vec![target_dir()],
            memory: "2G",
            cpus: 2,
        })?;
    }
    Ok(())
}

fn win() -> Result<()> {
    run_checked(cargo().args([
        "build",
        "--target",
        "x86_64-pc-windows-gnu",
        "-p",
        "rackhand-probe",
        "-p",
        "rackhand-cli",
    ]))?;
    let scripts = workspace_root().join("packaging/windows");
    if scripts.is_dir() {
        run_checked(
            Command::new("pwsh")
                .args(["-NoProfile", "-Command"])
                .arg("$c = New-PesterConfiguration; $c.Run.Path = 'packaging/windows'; $c.Run.Exit = $true; Invoke-Pester -Configuration $c")
                .current_dir(workspace_root()),
        )?;
    } else {
        println!("no packaging/windows scripts yet: Pester tests skipped");
    }
    Ok(())
}

fn perf() -> Result<()> {
    run_checked(cargo().args([
        "nextest",
        "run",
        "-p",
        "rackhand-perf",
        "--profile",
        "perf",
        "--release",
        "--no-tests=pass",
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_tier_fails_with_list_of_tiers() {
        let err = Tier::parse("nope").unwrap_err().to_string();
        for name in ["fast", "it", "net", "ebpf", "win", "perf"] {
            assert!(err.contains(name), "`{err}` should name tier `{name}`");
        }
        assert_eq!(Tier::parse("ebpf").unwrap(), Tier::Ebpf);
    }
}
