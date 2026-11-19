//! Project automation: `cargo xtask <command>`.

mod arch;
mod kernels;
mod tiers;
mod vm;

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask <command>
commands:
  arch-check                 check the dependency rules (design 7.2)
  ci <tier> [args]           run a test tier: fast, it, net, ebpf, win, perf
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
        Some("kernels") if rest.first().map(String::as_str) == Some("fetch") => kernels::fetch_all(),
        Some("rootfs") if rest.first().map(String::as_str) == Some("build") => vm::build_rootfs().map(|_| ()),
        Some("it-images") => tiers::build_it_images(),
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
