//! `rackhand operator ...` (7.3.5): join a hub with an invite, run assistant jobs for the hubs joined, and the MCP bridge a
//! runner starts as its one MCP server.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use rackhand_operator::claude_code::ClaudeCode;
use rackhand_operator::run::Operator;
use rackhand_operator::runner::Runner;
use rackhand_operator::state::Dirs;

pub const USAGE: &str =
    "       rackhand operator join '<ticket>#<secret>' [--name <name>] [--dir <dir>] [--claude <path>]
       rackhand operator join --ticket <ticket> --invite <secret> [--name <name>] [--dir <dir>] [--claude <path>]
       rackhand operator run [--dir <dir>] [--claude <path>] [--max-jobs <n>]
       rackhand operator mcp-bridge --hub <id> --job <job id> [--dir <dir>]";

const DEFAULT_DIR: &str = "/var/lib/rackhand-operator";

/// `<ticket>#<secret>` as two strings.
fn split_invite(invite: &str) -> Option<(String, String)> {
    let (ticket, secret) = invite.split_once('#')?;
    (!ticket.is_empty() && !secret.is_empty()).then(|| (ticket.to_string(), secret.to_string()))
}

/// What this host is called, when `--name` isn't given.
fn host_name() -> Option<String> {
    ["HOSTNAME", "COMPUTERNAME", "HOST"].iter().find_map(|v| std::env::var(v).ok().filter(|n| !n.is_empty()))
}

fn options<'a>(rest: &[&'a str], allowed: &[&str]) -> Option<std::collections::HashMap<String, &'a str>> {
    let mut out = std::collections::HashMap::new();
    let mut it = rest.iter();
    while let Some(flag) = it.next() {
        let name = flag.strip_prefix("--").filter(|n| allowed.contains(n))?;
        out.insert(name.to_string(), *it.next()?);
    }
    Some(out)
}

fn dirs(o: &std::collections::HashMap<String, &str>) -> Dirs {
    Dirs(PathBuf::from(o.get("dir").copied().unwrap_or(DEFAULT_DIR)))
}

/// The runner: Claude Code, or in a lab build a scripted one (`--runner fake:<script.json>`).
fn runner(o: &std::collections::HashMap<String, &str>, dirs: &Dirs) -> Result<Arc<dyn Runner>, String> {
    #[cfg(feature = "lab-build")]
    if let Some(script) = o.get("runner").and_then(|r| r.strip_prefix("fake:")) {
        return Ok(Arc::new(rackhand_operator::fake::Fake::from_file(std::path::Path::new(script))?));
    }
    if o.contains_key("runner") && !cfg!(feature = "lab-build") {
        return Err("`--runner` is for lab builds".into());
    }
    let claude = PathBuf::from(o.get("claude").copied().unwrap_or("claude"));
    Ok(Arc::new(ClaudeCode::new(claude, dirs.runner_config(), dirs.work())))
}

pub fn main(rest: &[&str]) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let failed = |e: String| {
        eprintln!("error: {e}");
        ExitCode::FAILURE
    };
    match rest {
        ["join", rest @ ..] => {
            // `join '<ticket>#<secret>'` as the Add page shows it, or the ticket and the secret as options
            let (given, rest) = match rest.split_first() {
                Some((first, more)) if !first.starts_with("--") => (split_invite(first), more),
                _ => (None, rest),
            };
            let Some(o) = options(rest, &["ticket", "invite", "name", "dir", "claude", "runner"]) else {
                eprintln!("usage:\n{USAGE}");
                return ExitCode::from(2);
            };
            let ticket = given.as_ref().map(|g| g.0.clone()).or_else(|| o.get("ticket").map(|t| t.to_string()));
            let invite = given.as_ref().map(|g| g.1.clone()).or_else(|| o.get("invite").map(|t| t.to_string()));
            let name = o.get("name").map(|n| n.to_string()).or_else(host_name);
            let (Some(ticket), Some(invite), Some(name)) = (ticket.as_deref(), invite.as_deref(), name.as_deref())
            else {
                eprintln!("usage:\n{USAGE}");
                return ExitCode::from(2);
            };
            let dirs = dirs(&o);
            let ticket = match rackhand_net::ticket::Ticket::parse(ticket) {
                Ok(t) => t,
                Err(e) => return failed(e),
            };
            let runner = match runner(&o, &dirs) {
                Ok(r) => r,
                Err(e) => return failed(e),
            };
            let info = runner.info();
            match rt.block_on(rackhand_operator::join::join(&dirs, &ticket, invite, name, &[info])) {
                Ok(hub) => {
                    println!("Joined the hub of site {}.", hub.site);
                    ExitCode::SUCCESS
                }
                Err(e) => failed(e),
            }
        }
        ["run", rest @ ..] => {
            let Some(o) = options(rest, &["dir", "claude", "max-jobs", "runner"]) else {
                eprintln!("usage:\n{USAGE}");
                return ExitCode::from(2);
            };
            crate::logging::init();
            let dirs = dirs(&o);
            let runner = match runner(&o, &dirs) {
                Ok(r) => r,
                Err(e) => return failed(e),
            };
            let max_jobs = o.get("max-jobs").and_then(|n| n.parse().ok()).unwrap_or(2);
            let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rackhand"));
            let op = Arc::new(Operator { dirs, runner, max_jobs, exe, version: crate::VERSION.into() });
            match rt.block_on(rackhand_operator::run::run(op)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => failed(e),
            }
        }
        ["mcp-bridge", rest @ ..] => {
            let Some(o) = options(rest, &["hub", "job", "dir"]) else {
                eprintln!("usage:\n{USAGE}");
                return ExitCode::from(2);
            };
            let Some(job) = o.get("job") else {
                eprintln!("usage:\n{USAGE}");
                return ExitCode::from(2);
            };
            let socket = rackhand_operator::bridge::socket_path(&dirs(&o).sockets(), job);
            match rt.block_on(rackhand_operator::bridge::bridge_main(&socket)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => failed(format!("{}: {e}", socket.display())),
            }
        }
        _ => {
            eprintln!("usage:\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_invite_is_a_ticket_and_a_secret() {
        assert_eq!(
            split_invite("rackhand1:ab@192.0.2.1:7443#SECRET"),
            Some(("rackhand1:ab@192.0.2.1:7443".into(), "SECRET".into()))
        );
        for bad in ["", "no-secret", "#secret", "ticket#"] {
            assert_eq!(split_invite(bad), None, "{bad:?}");
        }
    }
}
