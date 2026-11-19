//! Project automation: `cargo xtask <command>`.

mod arch;

use std::path::PathBuf;
use std::process::ExitCode;

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent().map(PathBuf::from).unwrap_or(manifest_dir)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("arch-check") => arch::run(&workspace_root()),
        Some(other) => Err(anyhow::anyhow!("unknown command `{other}`; commands: arch-check")),
        None => Err(anyhow::anyhow!("usage: cargo xtask <command>; commands: arch-check")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
