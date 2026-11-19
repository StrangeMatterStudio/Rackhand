//! The command wrapper (7.3.7): the automation user's only sudo entry, `/usr/local/lib/rackhand/run`, is the probe
//! binary in its `run` mode. It executes a request only if it matches `commands.json` exactly, and directly (no
//! shell). Its paths are fixed: nothing a caller passes through sudo can point it at another list.

pub mod install;
pub mod matcher;

use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitCode};

pub const COMMANDS: &str = "/etc/rackhand/commands.json";
pub const PROBE_TOML: &str = "/etc/rackhand-probe/probe.toml";

/// Runs the matched command and returns its standard output (for tests and the hub's own checks).
pub fn spawn_capture(argv: &[String]) -> std::io::Result<String> {
    let (program, rest) = argv.split_first().ok_or_else(|| std::io::Error::other("no command"))?;
    let out = Command::new(program).args(rest).env_clear().env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin").output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// `run <args...>`.
pub fn main(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("install-commands") => install_commands(),
        _ => run(args),
    }
}

fn install_commands() -> ExitCode {
    let mut payload = Vec::new();
    if std::io::stdin().take(4 << 20).read_to_end(&mut payload).is_err() {
        eprintln!("run: couldn't read the payload");
        return ExitCode::from(2);
    }
    let result = install::pinned_hub_key(Path::new(PROBE_TOML))
        .and_then(|key| install::install(Path::new(COMMANDS), &payload, &key, now_ms()));
    match result {
        Ok(version) => {
            println!("installed command list version {version}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("run: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &[String]) -> ExitCode {
    let list = match std::fs::read(COMMANDS).ok().and_then(|b| serde_json::from_slice::<matcher::CommandList>(&b).ok())
    {
        Some(l) => l,
        None => {
            eprintln!("run: no command list at {COMMANDS}");
            return ExitCode::from(126);
        }
    };
    let argv = match matcher::matching(&list, args) {
        Ok(a) => a,
        Err(refusal) => {
            eprintln!("run: {refusal}");
            return ExitCode::from(126);
        }
    };
    exec(&argv)
}

/// Replaces this process with the command, with a clean environment.
#[cfg(unix)]
fn exec(argv: &[String]) -> ExitCode {
    use std::os::unix::process::CommandExt;
    let Some((program, rest)) = argv.split_first() else { return ExitCode::from(126) };
    let err = Command::new(program).args(rest).env_clear().env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin").exec();
    eprintln!("run: {program}: {err}");
    ExitCode::from(127)
}

#[cfg(not(unix))]
fn exec(argv: &[String]) -> ExitCode {
    let Some((program, rest)) = argv.split_first() else { return ExitCode::from(126) };
    match Command::new(program).args(rest).status() {
        Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
        Err(_) => ExitCode::from(127),
    }
}

#[cfg(test)]
mod tests;
