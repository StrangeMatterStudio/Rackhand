//! The command wrapper (7.3.7): the automation user's only sudo entry, `/usr/local/lib/rackhand/run`, is the probe
//! binary in its `run` mode. It executes a request only if it matches `commands.json` exactly, and directly (no
//! shell). Its paths are fixed: nothing a caller passes through sudo can point it at another list.

pub mod detached;
pub mod guest;
pub mod install;
pub mod matcher;
pub mod quarantine;
pub mod receive;

use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitCode};

pub const COMMANDS: &str = "/etc/rackhand/commands.json";
/// The automation user's one sudo entry.
pub const WRAPPER: &str = "/usr/local/lib/rackhand/run";
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

/// `run <args...>`: the built-in subcommands take only ids the hub generated (and, for `job-start`, a command that
/// matches the list); anything else is a command to match.
pub fn main(args: &[String]) -> ExitCode {
    let rest = args.get(1..).unwrap_or(&[]);
    match args.first().map(String::as_str) {
        Some("install-commands") => install_commands(),
        Some("install-keys") => install_keys(),
        Some("install-guest") => install_guest(),
        Some("quarantine") => quarantine::main(rest),
        Some("job-start") => match load_list() {
            Some(list) => detached::start(&list, rest),
            None => no_list(),
        },
        Some("job-supervise") => detached::supervise(rest),
        Some("job-status") => detached::status(rest),
        Some("job-stop") => detached::stop(rest),
        Some("job-clean") => detached::clean(rest),
        Some("receive") => match load_list() {
            Some(list) => {
                let roots = if list.transfer_roots.is_empty() {
                    vec![receive::DEFAULT_ROOT.to_string()]
                } else {
                    list.transfer_roots
                };
                receive::main(rest, &roots)
            }
            None => no_list(),
        },
        _ => run(args),
    }
}

fn load_list() -> Option<matcher::CommandList> {
    std::fs::read(COMMANDS).ok().and_then(|b| serde_json::from_slice::<matcher::CommandList>(&b).ok())
}

fn no_list() -> ExitCode {
    eprintln!("run: no command list at {COMMANDS}");
    ExitCode::from(126)
}

/// `run install-keys` (7.3.3): the hub's key lines for the automation user, from a payload signed by the hub pinned in
/// `probe.toml` that is newer than the last applied one and not expired. The same checks as the helper's `ApplyKeys`.
fn install_keys() -> ExitCode {
    use prost::Message;
    let mut payload = Vec::new();
    if std::io::stdin().take(64 * 1024).read_to_end(&mut payload).is_err() {
        eprintln!("run: couldn't read the payload");
        return ExitCode::from(2);
    }
    let result = rackhand_proto::common::SignedPayload::decode(payload.as_slice())
        .map_err(|_| crate::helper::keys::KeysError::Malformed)
        .and_then(|signed| {
            crate::helper::keys::apply_signed(&crate::helper::keys::Files::default(), &signed, now_ms())
        });
    match result {
        Ok(version) => {
            println!("applied key update version {version}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("run: {e}");
            ExitCode::from(1)
        }
    }
}

/// `run install-guest` (7.3.12): enrolls a guest the hub is provisioning, from a payload signed by the pinned hub.
fn install_guest() -> ExitCode {
    use prost::Message;
    let mut payload = Vec::new();
    if std::io::stdin().take(16 * 1024).read_to_end(&mut payload).is_err() {
        eprintln!("run: couldn't read the payload");
        return ExitCode::from(2);
    }
    let result = rackhand_proto::common::SignedPayload::decode(payload.as_slice())
        .map_err(|_| guest::GuestError::Malformed)
        .and_then(|signed| guest::apply(&guest::GuestFiles::default(), &guest::System, &signed, now_ms()));
    match result {
        Ok(answer) => {
            println!("{answer}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("run: {e}");
            ExitCode::from(1)
        }
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
