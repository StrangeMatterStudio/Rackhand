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
    Live,
    Release,
}

const TIERS: &[(&str, Tier, &str)] = &[
    ("fast", Tier::Fast, "fmt, clippy, dependency rules, cargo deny, unit, contract and collector tests"),
    ("it", Tier::It, "integration tests in Docker containers"),
    ("net", Tier::Net, "network namespace tests inside a QEMU VM"),
    ("ebpf", Tier::Ebpf, "kernel tests inside a QEMU VM per kernel in kernels.toml"),
    ("win", Tier::Win, "Windows cross builds and Pester tests of the shipped PowerShell"),
    ("perf", Tier::Perf, "soak, load and fill tests"),
    ("live", Tier::Live, "the built product in the local lab (--target local) or the real lab (--target real)"),
    ("release", Tier::Release, "static artifacts and a commit built twice in two places with the same hashes"),
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
        Tier::Net => net(&args[1..]),
        Tier::Ebpf => ebpf(&args[1..]),
        Tier::Win => win(),
        Tier::Perf => perf(),
        Tier::Live => live(&args[1..]),
        Tier::Release => release(),
    }
}

/// The live milestones in the order `--milestone all` runs them (plan L1 to L8).
pub const LIVE_MILESTONES: &[&str] = &["lab", "m1", "m2", "m3", "m4", "m5", "m6", "m8"];

/// `cargo xtask ci live --target local|real --milestone <name>|all [--no-deploy]`.
fn live(args: &[String]) -> Result<()> {
    let mut target = "local".to_string();
    let mut milestone = None;
    let mut deploy = true;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                target = args.get(i + 1).context("--target local|real")?.clone();
                i += 1;
            }
            "--milestone" => {
                milestone = Some(args.get(i + 1).context("--milestone <name>")?.clone());
                i += 1;
            }
            "--no-deploy" => deploy = false,
            other => bail!("unknown option `{other}` for ci live"),
        }
        i += 1;
    }
    let milestone = milestone.context("ci live needs --milestone <name>|all")?;
    if target != "local" {
        bail!("--target {target} isn't available yet (L9 adds the real lab)");
    }
    let lab = crate::lab::config::Lab::load()?;
    let list: Vec<&str> = if milestone == "all" {
        LIVE_MILESTONES.to_vec()
    } else if LIVE_MILESTONES.contains(&milestone.as_str()) {
        vec![milestone.as_str()]
    } else {
        bail!("unknown milestone `{milestone}`; milestones: {}, all", LIVE_MILESTONES.join(", "));
    };
    let xtask = std::env::current_exe()?;
    for m in list {
        println!("== live {m} (local)");
        crate::lab::up(&lab, m)?;
        if deploy && m != "lab" {
            crate::lab::deploy::deploy(&lab, "hub")?;
        }
        run_checked(
            cargo()
                .args(["nextest", "run", "-p", "rackhand-live", "--profile", "live", "-E"])
                .arg(format!("test(/^{m}::/)"))
                .env("RACKHAND_XTASK", &xtask)
                .env("RACKHAND_LIVE_TARGET", "local"),
        )?;
    }
    Ok(())
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
        let name = dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        println!("building rackhand-it-{name}");
        run_checked(Command::new("docker").args(["build", "-q", "-t", &format!("rackhand-it-{name}")]).arg(&dir))?;
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
    format!("set -e; cd /tmp; for b in {}; do \"$b\" --test-threads=1; done", list.join(" "))
}

fn target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|| workspace_root().join("target"))
}

/// `--spike <id> [-- <args>]` on the net and eBPF tiers: a throwaway spike crate in `spikes/<id>/` (plan, Spikes).
struct Spike {
    id: String,
    args: Vec<String>,
}

fn parse_spike(args: &[String]) -> Result<Option<Spike>> {
    match args.first().map(String::as_str) {
        None => Ok(None),
        Some("--spike") => {
            let id = args.get(1).context("--spike <id>")?.clone();
            let rest = args.iter().skip(2).skip_while(|a| *a == "--").cloned().collect();
            Ok(Some(Spike { id, args: rest }))
        }
        Some(other) => bail!("unknown option `{other}`; use --spike <id> [-- <args>]"),
    }
}

impl Spike {
    fn root() -> PathBuf {
        vm::cache_dir()
            .parent()
            .map(|p| p.join("rackhand-spikes"))
            .unwrap_or_else(|| PathBuf::from("/tmp/rackhand-spikes"))
    }

    fn out_dir(&self) -> PathBuf {
        Self::root().join(format!("{}-out", self.id))
    }

    fn target_dir(&self) -> PathBuf {
        Self::root().join(&self.id)
    }

    /// Builds `spikes/<id>` (package and binary named `<id>`) and returns the binary.
    fn build(&self) -> Result<PathBuf> {
        let dir = workspace_root().join("spikes").join(&self.id);
        let target = self.target_dir();
        run_checked(
            cargo()
                .args(["build", "--release", "--manifest-path"])
                .arg(dir.join("Cargo.toml"))
                .env("CARGO_TARGET_DIR", &target),
        )?;
        std::fs::create_dir_all(self.out_dir())?;
        Ok(target.join("release").join(&self.id))
    }

    /// Writes the report on the host from what the VM measured: `<bin> report --out <dir> <args>`.
    fn report(&self, bin: &std::path::Path) -> Result<()> {
        run_checked(
            Command::new(bin)
                .arg("report")
                .arg("--out")
                .arg(self.out_dir())
                .args(&self.args)
                .current_dir(workspace_root()),
        )
    }

    fn guest_command(&self, bin: &std::path::Path, extra: &str) -> String {
        format!(
            "set -e; cd /tmp; ip link set lo up; '{}' measure --out '{}' {extra}",
            bin.display(),
            self.out_dir().display()
        )
    }
}

fn net(args: &[String]) -> Result<()> {
    let kernel = kernels::ensure_series("6.1")?;
    if let Some(spike) = parse_spike(args)? {
        let bin = spike.build()?;
        vm::run(&VmRun {
            name: &format!("net spike {}", spike.id),
            kernel: &kernel,
            command: spike.guest_command(&bin, ""),
            env: vec![("RACKHAND_TIER", "net".into())],
            mounts: vec![(target_dir(), false), (spike.target_dir(), false), (spike.out_dir(), true)],
            memory: "2G",
            cpus: 2,
        })?;
        return spike.report(&bin);
    }
    let bins = test_binaries("rackhand-net-tests")?;
    vm::run(&VmRun {
        name: "net 6.1",
        kernel: &kernel,
        command: guest_command(&bins),
        env: vec![("RACKHAND_TIER", "net".into())],
        mounts: vec![(target_dir(), false)],
        memory: "2G",
        cpus: 2,
    })
}

fn ebpf(args: &[String]) -> Result<()> {
    let spike = parse_spike(args)?;
    let spike_bin = spike.as_ref().map(Spike::build).transpose()?;
    let bins = if spike.is_none() { test_binaries("rackhand-ebpf-tests")? } else { Vec::new() };
    for kernel in kernels::load()? {
        let image = kernels::ensure(&kernel)?;
        println!("== eBPF tier on {}", kernel.version);
        let (command, mut mounts) = match (&spike, &spike_bin) {
            (Some(s), Some(bin)) => (
                s.guest_command(bin, &format!("--kernel {}", kernel.series)),
                vec![(s.out_dir(), true), (s.target_dir(), false)],
            ),
            _ => (guest_command(&bins), Vec::new()),
        };
        mounts.push((target_dir(), false));
        vm::run(&VmRun {
            name: &format!("ebpf {}", kernel.series),
            kernel: &image,
            command,
            env: vec![("RACKHAND_TIER", "ebpf".into()), ("RACKHAND_EXPECT_KERNEL", kernel.series.clone())],
            mounts,
            memory: "2G",
            cpus: 2,
        })?;
    }
    if let (Some(s), Some(bin)) = (&spike, &spike_bin) {
        s.report(bin)?;
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

/// `cargo xtask ci release`: the release artifacts are static and a commit builds to the same bytes twice (AC43). Builds the hub
/// and the probe several times, so it is not part of the fast tier.
fn release() -> Result<()> {
    run_checked(cargo().args(["nextest", "run", "-p", "xtask", "--profile", "release", "-E", "test(release::slow_tests::)"]))
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
        for name in ["fast", "it", "net", "ebpf", "win", "perf", "release"] {
            assert!(err.contains(name), "`{err}` should name tier `{name}`");
        }
        assert_eq!(Tier::parse("ebpf").unwrap(), Tier::Ebpf);
    }
}
