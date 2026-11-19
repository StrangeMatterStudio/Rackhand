//! `run receive <dest> <blake3> <offset>` (7.3.11): standard input is appended to `<dest>.rackhand-partial` at the
//! offset (which must equal the partial file's size, or 0 to start over). When the whole file's BLAKE3 matches, it is
//! renamed into place (root, 0640); otherwise the partial file stays for resume. Destinations must be under the
//! `transfer_roots` of the signed command list.

use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

pub const DEFAULT_ROOT: &str = "/var/lib/rackhand-run/incoming";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveError {
    OutsideRoots,
    WrongOffset(u64),
    Io(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Complete,
    Incomplete(u64),
}

/// The destination, if it's a plain absolute path strictly inside one of the roots.
pub fn check_destination(dest: &str, roots: &[String]) -> Result<PathBuf, ReceiveError> {
    let path = Path::new(dest);
    let plain = path.is_absolute()
        && !dest.chars().any(char::is_control)
        && !dest.ends_with('/')
        && !dest.split('/').skip(1).any(|c| c.is_empty() || c == "." || c == "..")
        && path.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
    let inside = roots.iter().any(|r| path.starts_with(r) && path != Path::new(r));
    if plain && inside { Ok(path.to_path_buf()) } else { Err(ReceiveError::OutsideRoots) }
}

fn io(e: std::io::Error) -> ReceiveError {
    ReceiveError::Io(e.to_string())
}

pub fn receive(
    dest: &str,
    expected: &str,
    offset: u64,
    input: &mut dyn Read,
    roots: &[String],
) -> Result<Outcome, ReceiveError> {
    let path = check_destination(dest, roots)?;
    let parent = path.parent().ok_or(ReceiveError::OutsideRoots)?;
    std::fs::create_dir_all(parent).map_err(io)?;
    // No symlink may lead out of the roots.
    let real_parent = parent.canonicalize().map_err(io)?;
    let inside = roots.iter().filter_map(|r| Path::new(r).canonicalize().ok()).any(|r| real_parent.starts_with(r));
    if !inside {
        return Err(ReceiveError::OutsideRoots);
    }
    let partial = PathBuf::from(format!("{}.rackhand-partial", path.display()));
    if std::fs::symlink_metadata(&partial).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(ReceiveError::OutsideRoots);
    }
    let size = std::fs::metadata(&partial).map(|m| m.len()).unwrap_or(0);
    if offset != 0 && offset != size {
        return Err(ReceiveError::WrongOffset(size));
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(offset == 0)
        .append(offset != 0)
        .open(&partial)
        .map_err(io)?;
    std::io::copy(input, &mut file).map_err(io)?;
    drop(file);
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(std::fs::File::open(&partial).map_err(io)?).map_err(io)?;
    let total = std::fs::metadata(&partial).map(|m| m.len()).unwrap_or(0);
    if !hasher.finalize().to_hex().eq_ignore_ascii_case(expected.trim()) {
        return Ok(Outcome::Incomplete(total));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o640)).map_err(io)?;
    }
    std::fs::rename(&partial, &path).map_err(io)?;
    Ok(Outcome::Complete)
}

/// The command-line form; exit 0 complete, 3 incomplete, 4 wrong offset, 126 refused.
pub fn main(args: &[String], roots: &[String]) -> ExitCode {
    let (Some(dest), Some(hash), Some(offset)) =
        (args.first(), args.get(1), args.get(2).and_then(|o| o.parse::<u64>().ok()))
    else {
        eprintln!("usage: receive <dest> <blake3> <offset>");
        return ExitCode::from(2);
    };
    match receive(dest, hash, offset, &mut std::io::stdin().lock(), roots) {
        Ok(Outcome::Complete) => {
            println!("complete");
            ExitCode::SUCCESS
        }
        Ok(Outcome::Incomplete(n)) => {
            eprintln!("run: incomplete: {n} bytes received, hash doesn't match yet");
            ExitCode::from(3)
        }
        Err(ReceiveError::WrongOffset(n)) => {
            eprintln!("run: the partial file has {n} bytes; resume from there");
            ExitCode::from(4)
        }
        Err(ReceiveError::OutsideRoots) => {
            eprintln!("run: refused: the destination isn't under the transfer roots");
            ExitCode::from(126)
        }
        Err(ReceiveError::Io(e)) => {
            eprintln!("run: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ReceiveError, check_destination};

    #[test]
    fn receive_destinations_stay_under_transfer_roots() {
        let roots = vec!["/var/lib/rackhand-run/incoming".to_string()];
        assert!(check_destination("/var/lib/rackhand-run/incoming/backup.tar", &roots).is_ok());
        assert!(check_destination("/var/lib/rackhand-run/incoming/sub/dir/file", &roots).is_ok());
        for bad in [
            "/etc/passwd",
            "/var/lib/rackhand-run/incoming",
            "/var/lib/rackhand-run/incoming/../../../etc/passwd",
            "/var/lib/rackhand-run/incoming-evil/file",
            "relative/file",
            "/var/lib/rackhand-run/incoming/./file",
            "/var/lib/rackhand-run/incoming/file\n",
        ] {
            assert_eq!(check_destination(bad, &roots), Err(ReceiveError::OutsideRoots), "{bad:?}");
        }
    }
}
