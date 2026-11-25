//! Composition root for the hub, the relay and the operator (design 7.2).

mod hub_cmd;
mod logging;
mod observations;
mod operator_cmd;
mod relay_cmd;
#[cfg(unix)]
mod update;

#[cfg(test)]
#[path = "hub_tests.rs"]
mod hub;

use std::path::PathBuf;
use std::process::ExitCode;

/// This build's version: the workspace's. A lab build can be given another with `RACKHAND_LAB_VERSION` at build time, to play a
/// newer release in the update tests; a release build can't (`lab-build` is refused in one).
#[cfg(not(feature = "lab-build"))]
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(feature = "lab-build")]
pub const VERSION: &str = match option_env!("RACKHAND_LAB_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

const USAGE: &str = "usage: rackhand hub init [--config-dir <dir>] [--data-dir <dir>]
       rackhand hub run [--config <hub.toml>]
       rackhand hub detect replay --machine <id> --from <ms> --to <ms> [--db <path>]
       rackhand hub audit verify [--db <path>]
       rackhand hub runbook check <file>
       rackhand hub restore-library <checkout> [--db <path>]
       rackhand hub backup [--config <hub.toml>]
       rackhand hub metrics-token [--config <hub.toml>]
       rackhand hub peer-backup export <site> <file> [--config <hub.toml>]
       rackhand hub restore <file> --master-key <path> [--config-dir <dir>] [--data-dir <dir>]
       rackhand operator join|run|mcp-bridge ... (rackhand operator for the options)
       rackhand self-update [--config <hub.toml>] [--from <release dir>]
       rackhand relay self-update --from <release dir>
       rackhand operator self-update --from <release dir>
       rackhand update-apply hub|relay|operator
       rackhand update-guard <hub|relay|operator> <old-slot> <new-slot> <version>
       rackhand relay run|key create ... (rackhand relay for the options)";

/// Every command's usage: this binary's own, the operator's and the relay's.
fn all_usage() -> String {
    let own = USAGE.lines().filter(|l| !l.contains("for the options"));
    own.chain(operator_cmd::USAGE.lines()).chain(relay_cmd::USAGE.lines()).collect::<Vec<_>>().join("\n")
}

/// `--help` after a command's words (7.7.3): that command's usage, or every command's when the words name none.
fn help(words: &[&str]) -> Option<String> {
    let at = words.iter().position(|w| *w == "--help")?;
    Some(usage_of("rackhand", &words[..at], &all_usage()))
}

/// The usage of the command `words` name (`bin` and those words, then a space or nothing), or every command's when they
/// name none; continuation lines go with the line before them.
fn usage_of(bin: &str, words: &[&str], usage: &str) -> String {
    let mut entries: Vec<String> = Vec::new();
    for line in usage.lines() {
        let line = line.strip_prefix("usage:").unwrap_or(line);
        let start = line.trim_start();
        if start.starts_with(&format!("{bin} ")) || start == bin {
            entries.push(start.to_string());
        } else if let Some(last) = entries.last_mut() {
            last.push('\n');
            last.push_str(line);
        }
    }
    let prefix = std::iter::once(bin).chain(words.iter().copied()).collect::<Vec<_>>().join(" ");
    let named: Vec<&String> = entries
        .iter()
        .filter(|e| e.strip_prefix(&prefix).is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', '\n'])))
        .collect();
    let shown: Vec<&String> = if words.is_empty() || named.is_empty() { entries.iter().collect() } else { named };
    let lines: Vec<String> = shown.iter().map(|e| e.to_string()).collect();
    format!("usage: {}", lines.join("\n       "))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    if let Some(text) = help(&words) {
        println!("{text}");
        return ExitCode::SUCCESS;
    }
    match words.as_slice() {
        ["--version"] => {
            println!("rackhand {}", VERSION);
            ExitCode::SUCCESS
        }
        #[cfg(unix)]
        ["update-apply", rest @ ..] => update::apply::main(rest),
        #[cfg(unix)]
        ["update-guard", rest @ ..] => update::guard::main(rest),
        #[cfg(unix)]
        ["self-update", rest @ ..] => self_update(rest),
        #[cfg(unix)]
        ["relay", "self-update", rest @ ..] => component_self_update(update::Component::Relay, rest),
        #[cfg(unix)]
        ["operator", "self-update", rest @ ..] => component_self_update(update::Component::Operator, rest),
        ["operator", rest @ ..] => operator_cmd::main(rest),
        ["relay", rest @ ..] => relay_cmd::main(rest),
        ["hub", "init", rest @ ..] => hub_init(rest),
        ["hub", "run", rest @ ..] => hub_run(rest),
        ["hub", "detect", "replay", rest @ ..] => detect_replay(rest),
        ["hub", "audit", "verify", rest @ ..] => audit_verify(rest),
        ["hub", "runbook", "check", file] => runbook_check(file),
        ["hub", "restore-library", checkout, rest @ ..] => restore_library(checkout, rest),
        ["hub", "backup", rest @ ..] => hub_backup(rest),
        ["hub", "metrics-token", rest @ ..] => hub_metrics_token(rest),
        ["hub", "peer-backup", "export", site, file, rest @ ..] => peer_backup_export(site, file, rest),
        ["hub", "restore", file, rest @ ..] => hub_restore(file, rest),
        #[cfg(feature = "lab-build")]
        ["hub", "lab-token", rest @ ..] => hub_lab_token(rest),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Validates a runbook (`.toml`) or a playbook (`.md`), and a runbook's sudo coverage (12).
fn runbook_check(file: &str) -> ExitCode {
    let source = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {file}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if file.ends_with(".md") {
        return match rackhand_runbook::playbook::Playbook::parse(&source) {
            Ok(pb) => {
                println!("{}: valid playbook; {} tools, hosts {:?}", pb.name, pb.tools.len(), pb.hosts);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{file}: {e}");
                ExitCode::FAILURE
            }
        };
    }
    let report = rackhand_runbook::check_cmd::check(&source);
    if report.ok() {
        println!("{}", report.summary());
        ExitCode::SUCCESS
    } else {
        eprintln!("{file}: {}", report.summary());
        ExitCode::FAILURE
    }
}

fn audit_verify(rest: &[&str]) -> ExitCode {
    let db = match rest {
        ["--db", path] => PathBuf::from(path),
        [] => PathBuf::from("/var/lib/rackhand/hub.db"),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let db = match rackhand_store::Db::open(&db) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rackhand_hub::audit::verify(db.readers()) {
        Ok(r) => {
            println!("audit log verified: {} rows, seq {} to {}", r.rows, r.first_seq, r.last_seq);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("audit log verification failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Loads the files of a git mirror checkout into the library as new revisions (7.3.13).
fn restore_library(checkout: &str, rest: &[&str]) -> ExitCode {
    let db = match rest {
        ["--db", path] => PathBuf::from(path),
        [] => PathBuf::from("/var/lib/rackhand/hub.db"),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let db = match rackhand_store::Db::open(&db) {
        Ok(db) => std::sync::Arc::new(db),
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let report = runtime.block_on(async {
        let (lib, _changes) =
            rackhand_hub::library::items::Library::new(db.clone(), rackhand_hub::audit::Audit::new(db.writer()));
        rackhand_hub::library::mirror::restore(&lib, std::path::Path::new(checkout), rackhand_store::ids::now_ms())
            .await
    });
    println!("restored {} files", report.restored);
    for (file, why) in &report.refused {
        eprintln!("refused {file}: {why}");
    }
    if report.refused.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// `--name value` pairs; `None` on anything else.
fn options<'a>(rest: &[&'a str], allowed: &[&str]) -> Option<std::collections::HashMap<String, &'a str>> {
    let mut out = std::collections::HashMap::new();
    let mut it = rest.iter();
    while let Some(flag) = it.next() {
        let name = flag.strip_prefix("--").filter(|n| allowed.contains(n))?;
        out.insert(name.to_string(), *it.next()?);
    }
    Some(out)
}

fn runtime() -> Result<tokio::runtime::Runtime, ExitCode> {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| {
        eprintln!("error: {e}");
        ExitCode::FAILURE
    })
}

fn hub_init(rest: &[&str]) -> ExitCode {
    let Some(o) = options(rest, &["config-dir", "data-dir"]) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let etc = PathBuf::from(o.get("config-dir").copied().unwrap_or("/etc/rackhand"));
    let data = PathBuf::from(o.get("data-dir").copied().unwrap_or("/var/lib/rackhand"));
    let rt = match runtime() {
        Ok(r) => r,
        Err(code) => return code,
    };
    match rt.block_on(hub_cmd::init(&etc, &data)) {
        Ok(made) => {
            println!("Wrote {}.", made.config.display());
            println!("Setup code (for the dashboard's first run, once): {}", made.setup_code);
            println!("Recovery code (keep it safe; it restores the master key): {}", made.recovery_code);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn hub_run(rest: &[&str]) -> ExitCode {
    let Some(o) = options(rest, &["config"]) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    logging::init();
    let path = PathBuf::from(o.get("config").copied().unwrap_or("/etc/rackhand/hub.toml"));
    let config = match hub_cmd::HubConfig::load(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let rt = match runtime() {
        Ok(r) => r,
        Err(code) => return code,
    };
    match rt.block_on(hub_cmd::run(&config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn detect_replay(rest: &[&str]) -> ExitCode {
    let Some(o) = options(rest, &["machine", "from", "to", "db"]) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let (Some(machine), Some(Ok(from)), Some(Ok(to))) =
        (o.get("machine"), o.get("from").map(|v| v.parse::<i64>()), o.get("to").map(|v| v.parse::<i64>()))
    else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let db = PathBuf::from(o.get("db").copied().unwrap_or("/var/lib/rackhand/hub.db"));
    match hub_cmd::detect_replay(&db, machine, from, to) {
        Ok(lines) => {
            for l in &lines {
                println!("{l}");
            }
            if lines.is_empty() {
                println!("nothing would have fired");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `hub backup`: one backup now into the data directory's `backups/` (the newest 2 are kept).
/// `rackhand self-update`: the hub asks for the release in its release directory (or `--from`), as its own user or root.
#[cfg(unix)]
fn self_update(rest: &[&str]) -> ExitCode {
    let Some(o) = options(rest, &["config", "from"]) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let path = PathBuf::from(o.get("config").copied().unwrap_or("/etc/rackhand/hub.toml"));
    let result = hub_cmd::HubConfig::load(&path).and_then(|config| {
        let from = o.get("from").map_or_else(|| config.data_dir.join("release"), PathBuf::from);
        update::ask::ask_hub(&config, &from, rackhand_store::ids::now_ms())
    });
    match result {
        Ok(version) => {
            println!("asked for {version}: the updater checks it, switches, and goes back if the hub doesn't come up");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `rackhand relay self-update --from <dir>` and the operator's: the release in the component's own spool, and the request.
#[cfg(unix)]
fn component_self_update(component: update::Component, rest: &[&str]) -> ExitCode {
    let Some(from) = options(rest, &["from"]).and_then(|o| o.get("from").map(PathBuf::from)) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let spool = update::ask::component_dir(component);
    match update::ask::ask(&from, &spool, &|_| Ok(()), rackhand_store::ids::now_ms()) {
        Ok(version) => {
            println!("asked for {version}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn hub_backup(rest: &[&str]) -> ExitCode {
    let Some(o) = options(rest, &["config"]) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let path = PathBuf::from(o.get("config").copied().unwrap_or("/etc/rackhand/hub.toml"));
    let result = hub_cmd::HubConfig::load(&path)
        .and_then(|config| hub_cmd::backups::backup_now(&config, rackhand_store::ids::now_ms()));
    match result {
        Ok(file) => {
            println!("{}", file.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `hub metrics-token`: prints the bearer token for `/metrics`, for a Prometheus scrape config (7.3.14).
fn hub_metrics_token(rest: &[&str]) -> ExitCode {
    let Some(o) = options(rest, &["config"]) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let path = PathBuf::from(o.get("config").copied().unwrap_or("/etc/rackhand/hub.toml"));
    match hub_cmd::HubConfig::load(&path).and_then(|config| hub_cmd::metrics_token(&config)) {
        Ok(token) => {
            println!("{token}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `hub peer-backup export <site> <file>`: the backup this hub keeps for a peer, to copy to the machine that restores it (9).
fn peer_backup_export(site: &str, file: &str, rest: &[&str]) -> ExitCode {
    let Some(o) = options(rest, &["config"]) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let path = PathBuf::from(o.get("config").copied().unwrap_or("/etc/rackhand/hub.toml"));
    let result = hub_cmd::HubConfig::load(&path).and_then(|config| {
        rackhand_hub::backup::peer::export(
            &rackhand_hub::backup::peer::dir(&config.data_dir),
            site,
            std::path::Path::new(file),
        )
    });
    match result {
        Ok(bytes) => {
            println!(
                "Wrote {file} ({bytes} bytes). Restore it on a new machine with `rackhand hub restore {file} --master-key <path>`."
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `hub restore <file> --master-key <path>`: a hub from its backup, on a machine without one (9, AC47).
fn hub_restore(file: &str, rest: &[&str]) -> ExitCode {
    let Some(o) = options(rest, &["master-key", "config-dir", "data-dir"]) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(key) = o.get("master-key") else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let etc = PathBuf::from(o.get("config-dir").copied().unwrap_or("/etc/rackhand"));
    let data = PathBuf::from(o.get("data-dir").copied().unwrap_or("/var/lib/rackhand"));
    match hub_cmd::backups::restore(std::path::Path::new(file), std::path::Path::new(key), &etc, &data) {
        Ok(toml) => {
            println!("Restored. Wrote {}; start the hub with `rackhand hub run`.", toml.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `hub lab-token --kind machine --access managed|monitor --addr <hub ip> [--name <name>] [--role <role>]`: a pending
/// machine, its one-time token and the hub's ticket, as the Add page (T49) will issue them. Lab builds only (plan L2): a release build has no such command.
#[cfg(feature = "lab-build")]
fn hub_lab_token(rest: &[&str]) -> ExitCode {
    use rackhand_proto::common::{Access, ProbeMode};
    let Some(o) = options(rest, &["kind", "access", "name", "role", "config", "addr"]) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    if o.get("kind").copied() != Some("machine") {
        eprintln!("lab-token: only --kind machine");
        return ExitCode::from(2);
    }
    let access = match o.get("access").copied() {
        Some("managed") => Access::Managed,
        Some("monitor") => Access::Monitor,
        _ => {
            eprintln!("lab-token: --access managed|monitor");
            return ExitCode::from(2);
        }
    };
    let path = PathBuf::from(o.get("config").copied().unwrap_or("/etc/rackhand/hub.toml"));
    let rt = match runtime() {
        Ok(r) => r,
        Err(code) => return code,
    };
    let result = rt.block_on(async {
        let config = hub_cmd::HubConfig::load(&path)?;
        let addr: std::net::IpAddr = o
            .get("addr")
            .and_then(|a| a.parse().ok())
            .ok_or_else(|| "lab-token: --addr <the hub's IP address>".to_string())?;
        let ticket = hub_cmd::ticket(&config, &[addr])?;
        let db = std::sync::Arc::new(rackhand_store::Db::open(&config.db_path()).map_err(|e| e.to_string())?);
        let site: String = db
            .readers()
            .with(|c| c.query_row("SELECT id FROM sites WHERE is_local = 1", [], |r| r.get(0)))
            .map_err(|_| "no site yet: complete first run".to_string())?;
        let registry = rackhand_hub::registry::Registry::load(db).map_err(|e| e.to_string())?;
        let add = rackhand_hub::registry::machines::AddMachine {
            site_id: site,
            name: o.get("name").copied().unwrap_or("target").to_string(),
            kind: "linux".into(),
            access,
            mode: ProbeMode::Local,
            roles: o.get("role").map(|r| vec![r.to_string()]).unwrap_or_default(),
        };
        let (id, token) =
            registry.add_machine(&add, "lab", rackhand_store::ids::now_ms()).await.map_err(|e| e.to_string())?;
        Ok::<_, String>((id, token.as_str().to_string(), ticket))
    });
    match result {
        Ok((id, token, ticket)) => {
            println!(
                "machine={id}
ticket={ticket}
token={token}"
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod help_tests {
    use super::help;

    #[test]
    fn help_names_the_command_before_it() {
        let backup = help(&["hub", "backup", "--help"]).expect("help");
        assert!(backup.contains("rackhand hub backup [--config <hub.toml>]"), "{backup}");
        assert!(!backup.contains("hub init"), "only that command: {backup}");
        let relay = help(&["relay", "run", "--help"]).expect("help");
        assert!(
            relay.contains("rackhand relay run") && relay.contains("[--acme-domain <name>]"),
            "with its options: {relay}"
        );
        assert!(!relay.contains("relay key create"), "{relay}");
        let join = help(&["operator", "join", "--help"]).expect("help");
        assert!(join.contains("rackhand operator join --ticket <ticket>"), "{join}");
        let all = help(&["--help"]).expect("help");
        for each in ["rackhand hub init", "rackhand operator run", "rackhand relay key create", "rackhand hub restore"]
        {
            assert!(all.contains(each), "{each}: {all}");
        }
        assert!(!all.contains("for the options"), "the operator's and relay's own lines instead: {all}");
        assert_eq!(help(&["no-such", "--help"]), help(&["--help"]), "an unknown command: all of it");
        assert_eq!(help(&["hub", "init"]), None, "no --help, no help");
    }
}
