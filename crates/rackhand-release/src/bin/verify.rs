//! `rackhand-verify <file> <file.minisig>`: checks a release file against the pinned release keys (D105). Exit 0 and
//! `ok current` or `ok standby` when it verifies; exit 1 and the reason when it doesn't.
//!
//! `rackhand-verify --manifest <dir>` checks a whole release directory: `manifest.json` against `manifest.json.minisig`, then
//! every artifact in it against the manifest's hashes, and that nothing else is there (5.2).

use std::path::Path;
use std::process::ExitCode;

use rackhand_release::Pinned;
use rackhand_release::manifest;

fn which(p: Pinned) -> &'static str {
    match p {
        Pinned::Current => "current",
        Pinned::Standby => "standby",
    }
}

fn release_directory(dir: &str) -> ExitCode {
    let dir = Path::new(dir);
    let (Ok(text), Ok(sig)) =
        (std::fs::read(dir.join(manifest::NAME)), std::fs::read_to_string(dir.join(format!("{}.minisig", manifest::NAME))))
    else {
        eprintln!("rackhand-verify: {} has no {} with its signature", dir.display(), manifest::NAME);
        return ExitCode::from(1);
    };
    match manifest::verify_signed(&text, &sig).and_then(|(signed_by, m)| m.check_dir(dir).map(|()| (signed_by, m))) {
        Ok((signed_by, m)) => {
            println!("ok {} ({} artifacts, version {})", which(signed_by), m.artifacts.len(), m.version);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("rackhand-verify: {}: {e}", dir.display());
            ExitCode::from(1)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [flag, dir] = args.as_slice() {
        if flag == "--manifest" {
            return release_directory(dir);
        }
    }
    let [file, sig] = args.as_slice() else {
        eprintln!("usage: rackhand-verify <file> <file.minisig>\n       rackhand-verify --manifest <release directory>");
        return ExitCode::from(2);
    };
    let (Ok(data), Ok(minisig)) = (std::fs::read(file), std::fs::read_to_string(sig)) else {
        eprintln!("rackhand-verify: can't read {file} or {sig}");
        return ExitCode::from(1);
    };
    match rackhand_release::verify(&data, &minisig) {
        Ok(signed_by) => {
            println!("ok {}", which(signed_by));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("rackhand-verify: {file}: {e}");
            ExitCode::from(1)
        }
    }
}
