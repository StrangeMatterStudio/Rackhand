//! Composition root for the hub, the relay and the operator (design 7.2).

mod hub_cmd;
mod logging;
mod observations;
mod operator_cmd;
mod relay_cmd;

#[cfg(test)]
#[path = "hub_tests.rs"]
mod hub;

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: rackhand hub init [--config-dir <dir>] [--data-dir <dir>]
       rackhand hub run [--config <hub.toml>]
       rackhand hub detect replay --machine <id> --from <ms> --to <ms> [--db <path>]
       rackhand hub audit verify [--db <path>]
       rackhand hub runbook check <file>
       rackhand hub restore-library <checkout> [--db <path>]
       rackhand hub backup [--config <hub.toml>]
       rackhand hub metrics-token [--config <hub.toml>]
       rackhand hub restore <file> --master-key <path> [--config-dir <dir>] [--data-dir <dir>]
       rackhand operator join|run|mcp-bridge ... (rackhand operator for the options)
       rackhand relay run|key create ... (rackhand relay for the options)";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["--version"] => {
            println!("rackhand {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
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
