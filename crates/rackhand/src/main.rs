//! Composition root for the hub, the relay and the operator (design 7.2).

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: rackhand hub audit verify [--db <path>]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["--version"] => {
            println!("rackhand {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["hub", "audit", "verify", rest @ ..] => audit_verify(rest),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
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
