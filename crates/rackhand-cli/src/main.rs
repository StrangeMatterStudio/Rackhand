//! `rackhand-cli`: the entry point (design 7.2). Every command has `--help` and a failure exits non-zero with a message that
//! names what failed: 2 for a mistake in the command line, 1 for anything that went wrong.

use std::process::ExitCode;

use rackhand_cli::commands;
use rackhand_cli::config::Dirs;
use rackhand_cli::login::{default_name, login};
use rackhand_cli::{Parsed, parse};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--version") {
        println!("rackhand-cli {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let parsed = match parse(&args) {
        Ok(p) => p,
        Err(message) => {
            eprintln!("rackhand-cli: {message}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("rackhand-cli: {e}");
            return ExitCode::FAILURE;
        }
    };
    let dirs = Dirs::default_dir();
    let result: Result<(), String> = runtime.block_on(async {
        match parsed {
            Parsed::Help(text) => {
                println!("{text}");
                Ok(())
            }
            Parsed::Login { invite, name } => {
                let name = name.unwrap_or_else(default_name);
                let hub = login(&dirs, &invite, &name).await?;
                println!("Enrolled as {name} for {} on {} (hub {}).", hub.user, hub.site, &hub.id[..12]);
                Ok(())
            }
            Parsed::Status => commands::status(&dirs).await.map(|text| print!("{text}")),
            Parsed::Connect { target, port } => {
                commands::connect(&dirs, &target, port, tokio::io::stdin(), tokio::io::stdout()).await
            }
            Parsed::Forward { local, target } => commands::forward(&dirs, local, &target).await,
            Parsed::Send { path, target, allow_relay } => {
                commands::send(&dirs, std::path::Path::new(&path), &target, allow_relay).await
            }
            Parsed::Mcp { hub, key_file } => {
                let key = match key_file {
                    Some(file) => std::fs::read_to_string(&file).map_err(|e| format!("{file}: {e}"))?,
                    None => std::env::var("RACKHAND_MCP_KEY").map_err(
                        |_| "the personal MCP key is in --key-file or the environment variable RACKHAND_MCP_KEY",
                    )?,
                };
                commands::mcp(&dirs, &hub, key.trim(), tokio::io::stdin(), tokio::io::stdout()).await
            }
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rackhand-cli: {e}");
            ExitCode::FAILURE
        }
    }
}
