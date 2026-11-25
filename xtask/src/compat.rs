//! `cargo xtask compat` (T95): the version-compatibility tests. Until a previous minor release is tagged, they run the
//! current binaries with their reported versions forced to an older minor, which proves the version rules but not
//! schema drift between real releases; the command says which mode it ran in.

use std::process::Command;

use anyhow::{Context, Result};

use crate::vm::run_checked;
use crate::workspace_root;

/// The newest tag `v<major>.<minor - 1>.<patch>` for the workspace's version, if one exists.
pub fn previous_minor(current: &str, tags: &[String]) -> Option<String> {
    let (major, minor, _) = parse(current)?;
    let wanted = minor.checked_sub(1)?;
    tags.iter()
        .filter_map(|t| Some((parse(t.strip_prefix('v')?)?, t)))
        .filter(|((ma, mi, _), _)| *ma == major && *mi == wanted)
        .max_by_key(|(v, _)| *v)
        .map(|(_, t)| t.clone())
}

fn parse(text: &str) -> Option<(u64, u64, u64)> {
    let mut parts = text.split('.');
    let mut next = || parts.next()?.parse::<u64>().ok();
    let v = (next()?, next()?, next()?);
    parts.next().is_none().then_some(v)
}

pub fn run() -> Result<()> {
    let out =
        Command::new("git").args(["tag", "-l", "v*"]).current_dir(workspace_root()).output().context("git tag")?;
    let tags: Vec<String> = String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect();
    let current = env!("CARGO_PKG_VERSION");
    match previous_minor(current, &tags) {
        None => println!(
            "compat: mode forced-version (no release tag one minor before {current}); the version rules are proven, \
             schema drift between real releases is not (AC45 and AC53 stay unverified)"
        ),
        Some(tag) => println!(
            "compat: mode forced-version; {tag} exists, but building it and running its binaries against this hub \
             isn't written yet, so AC45 and AC53 stay unverified"
        ),
    }
    run_checked(
        Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["nextest", "run", "-p", "rackhand-hub", "-E", "test(compat::)"])
            .current_dir(workspace_root()),
    )
}

#[cfg(test)]
mod tests {
    use super::previous_minor;

    fn tags(t: &[&str]) -> Vec<String> {
        t.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_tags_no_previous_release() {
        assert_eq!(previous_minor("0.2.0", &[]), None);
        assert_eq!(previous_minor("0.0.4", &tags(&["v0.0.1"])), None, "minor 0 has none before it");
    }

    #[test]
    fn newest_patch_of_the_minor_before() {
        let t = tags(&["v0.1.0", "v0.1.3", "v0.1.10", "v0.2.0", "v0.0.9", "v1.1.0", "v0.1.2-rc1", "notes"]);
        assert_eq!(previous_minor("0.2.1", &t).as_deref(), Some("v0.1.10"));
        assert_eq!(previous_minor("0.3.0", &t).as_deref(), Some("v0.2.0"));
        assert_eq!(previous_minor("0.4.0", &t), None, "two minors back doesn't count");
    }
}
