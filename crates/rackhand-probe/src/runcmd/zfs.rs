//! `run zfs-send <dataset>@<snapshot>` and `run zfs-recv <dataset>` (7.3.11): the two ends of a backup stream. The first writes
//! a snapshot's stream to standard output, the second reads one from standard input into a dataset. They take one argument
//! each, checked here against a plain dataset-name pattern, and nothing else a caller says reaches `zfs`.

use std::process::{Command, ExitCode, Stdio};

const PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// A dataset or snapshot name: letters, digits and `_ . : - /`, starting with a letter or digit, and no empty or `..` part.
fn plain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.:-/".contains(c))
        && !name.split('/').any(|part| part.is_empty() || part == "..")
}

/// `zfs send <dataset>@<snapshot>`'s arguments, if the request is one.
pub fn send_argv(args: &[String]) -> Option<Vec<String>> {
    let [snapshot] = args else { return None };
    let (dataset, snap) = snapshot.split_once('@')?;
    (plain(dataset) && plain(snap) && !snap.contains('/')).then(|| vec!["send".into(), snapshot.clone()])
}

/// `zfs recv <dataset>`'s arguments, if the request is one.
pub fn recv_argv(args: &[String]) -> Option<Vec<String>> {
    let [dataset] = args else { return None };
    plain(dataset).then(|| vec!["recv".into(), "-u".into(), dataset.clone()])
}

fn run(argv: Option<Vec<String>>, usage: &str) -> ExitCode {
    let Some(argv) = argv else {
        eprintln!("usage: {usage}");
        return ExitCode::from(126);
    };
    match Command::new("zfs")
        .args(&argv)
        .env_clear()
        .env("PATH", PATH)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
    {
        Ok(status) => ExitCode::from(status.code().and_then(|c| u8::try_from(c).ok()).unwrap_or(1)),
        Err(e) => {
            eprintln!("run: zfs: {e}");
            ExitCode::from(127)
        }
    }
}

pub fn send(args: &[String]) -> ExitCode {
    run(send_argv(args), "zfs-send <dataset>@<snapshot>")
}

pub fn recv(args: &[String]) -> ExitCode {
    run(recv_argv(args), "zfs-recv <dataset>")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn only_one_plain_dataset_reaches_zfs() {
        assert_eq!(send_argv(&args(&["tank/data@weekly-1"])), Some(args(&["send", "tank/data@weekly-1"])));
        assert_eq!(recv_argv(&args(&["backup/tank/data"])), Some(args(&["recv", "-u", "backup/tank/data"])));
        for bad in
            ["", "-r", "-Rv tank@s", "tank/../etc", "tank//x", "tank/", "/tank", "tank x", "tank;id", "$(id)", "tank\n"]
        {
            assert_eq!(recv_argv(&args(&[bad])), None, "{bad:?}");
            assert_eq!(send_argv(&args(&[&format!("{bad}@snap")])), None, "{bad:?}");
        }
        // a snapshot needs both halves, and its name is not a path
        for bad in ["tank", "@snap", "tank@", "tank@a/b", "tank@-x", "tank@a@b"] {
            assert_eq!(send_argv(&args(&[bad])), None, "{bad:?}");
        }
        // no more and no fewer arguments than the one
        assert_eq!(send_argv(&args(&[])), None);
        assert_eq!(send_argv(&args(&["tank@a", "-p"])), None);
        assert_eq!(recv_argv(&args(&["a", "b"])), None);
        assert_eq!(recv_argv(&args(&["tank".repeat(60).as_str()])), None, "a name past 200 characters");
    }
}
