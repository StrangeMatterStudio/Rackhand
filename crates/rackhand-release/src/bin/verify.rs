//! `rackhand-verify <file> <file.minisig>`: checks a release file against the pinned release keys (D105). Exit 0 and
//! `ok current` or `ok standby` when it verifies; exit 1 and the reason when it doesn't.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [file, sig] = args.as_slice() else {
        eprintln!("usage: rackhand-verify <file> <file.minisig>");
        return ExitCode::from(2);
    };
    let (Ok(data), Ok(minisig)) = (std::fs::read(file), std::fs::read_to_string(sig)) else {
        eprintln!("rackhand-verify: can't read {file} or {sig}");
        return ExitCode::from(1);
    };
    match rackhand_release::verify(&data, &minisig) {
        Ok(rackhand_release::Pinned::Current) => {
            println!("ok current");
            ExitCode::SUCCESS
        }
        Ok(rackhand_release::Pinned::Standby) => {
            println!("ok standby");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("rackhand-verify: {file}: {e}");
            ExitCode::from(1)
        }
    }
}
