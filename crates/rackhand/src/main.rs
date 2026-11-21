//! Composition root for the hub, the relay and the operator (design 7.2).

mod hub_cmd;
mod observations;

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
       rackhand hub restore <file> --master-key <path> [--config-dir <dir>] [--data-dir <dir>]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["--version"] => {
            println!("rackhand {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["hub", "init", rest @ ..] => hub_init(rest),
        ["hub", "run", rest @ ..] => hub_run(rest),
        ["hub", "detect", "replay", rest @ ..] => detect_replay(rest),
        ["hub", "audit", "verify", rest @ ..] => audit_verify(rest),
        ["hub", "runbook", "check", file] => runbook_check(file),
        ["hub", "restore-library", checkout, rest @ ..] => restore_library(checkout, rest),
        ["hub", "backup", rest @ ..] => hub_backup(rest),
        ["hub", "restore", file, rest @ ..] => hub_restore(file, rest),
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
