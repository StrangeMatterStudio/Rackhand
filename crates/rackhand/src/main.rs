//! Composition root for the hub, the relay and the operator (design 7.2).

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: rackhand hub audit verify [--db <path>]\n       rackhand hub runbook check <file>\n       rackhand hub restore-library <checkout> [--db <path>]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["--version"] => {
            println!("rackhand {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["hub", "audit", "verify", rest @ ..] => audit_verify(rest),
        ["hub", "runbook", "check", file] => runbook_check(file),
        ["hub", "restore-library", checkout, rest @ ..] => restore_library(checkout, rest),
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
