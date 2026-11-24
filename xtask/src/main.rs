//! Project automation: `cargo xtask <command>`.

mod arch;
mod ci_guard;
mod kernels;
mod lab;
mod release;
mod tiers;
mod vm;

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask <command>
commands:
  arch-check                 check the dependency rules (design 7.2)
  ci <tier> [args]           run a test tier: fast, it, net, ebpf, win, perf, live, release
  lab <command>              the local lab (see `cargo xtask lab`)
  release build|repro        build the release artifacts, or build a commit twice and compare (T91)
  golden --update            rewrite the wire format's golden files (review the diff)
  ci-guard                   check the workflow guards against the recorded event payloads
  kernels fetch              download, verify and build the test kernels
  rootfs build               build the root filesystem for test VMs
  it-images                  build the integration tier's container images";

pub fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent().map(PathBuf::from).unwrap_or(manifest_dir)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or_default();
    let result = match args.first().map(String::as_str) {
        Some("arch-check") => arch::run(&workspace_root()),
        Some("ci") => tiers::run(rest),
        Some("ci-guard") => ci_guard::run(),
        Some("kernels") if rest.first().map(String::as_str) == Some("fetch") => kernels::fetch_all(),
        Some("rootfs") if rest.first().map(String::as_str) == Some("build") => vm::build_rootfs().map(|_| ()),
        Some("it-images") => tiers::build_it_images(),
        Some("lab") => lab::run(rest),
        Some("release") => release::run(rest),
        Some("golden") if rest.first().map(String::as_str) == Some("--update") => vm::run_checked(
            std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
                .args(["nextest", "run", "-p", "rackhand-proto", "-E", "test(golden::)"])
                .env("RACKHAND_GOLDEN_UPDATE", "1")
                .current_dir(workspace_root()),
        ),
        Some(other) => Err(anyhow::anyhow!("unknown command `{other}`\n{USAGE}")),
        None => Err(anyhow::anyhow!("{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
