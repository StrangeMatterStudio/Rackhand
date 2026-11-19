//! Assistant `exec` commands that always need step-up (7.6.8). Best-effort by design: a determined command can avoid
//! these; scope, levels and approvals are the real controls. When in doubt a pattern matches, which costs a step-up.

/// Command words that change a file they name.
const WRITERS: &[&str] = &["tee", "cp", "mv", "rm", "nano", "vi", "vim", "ed", "install", "truncate", "ln"];

/// Splits a shell command into simple commands at `;`, `&`, `|` and newlines.
fn segments(command: &str) -> impl Iterator<Item = &str> {
    command.split([';', '&', '|', '\n']).map(str::trim).filter(|s| !s.is_empty())
}

/// The words of a simple command, without quotes.
fn words(segment: &str) -> Vec<String> {
    segment.split_whitespace().map(|w| w.trim_matches(|c| c == '\'' || c == '"').to_string()).collect()
}

/// Every word position as the start of a command, with its program as a bare name: wrappers (`sudo -u root`,
/// `env X=1 nohup`, `xargs`, `bash -c '...'`) then don't hide what runs.
fn commands_at_each_word(w: &[String]) -> impl Iterator<Item = Vec<String>> + '_ {
    (0..w.len()).map(move |i| {
        let mut cmd = w[i..].to_vec();
        cmd[0] = cmd[0].rsplit('/').next().unwrap_or("").to_string();
        cmd
    })
}

fn rm_recursive_force_top(w: &[String]) -> bool {
    if w.first().map(String::as_str) != Some("rm") {
        return false;
    }
    let short: String =
        w.iter().filter(|a| a.starts_with('-') && !a.starts_with("--")).flat_map(|a| a.chars().skip(1)).collect();
    let recursive = short.contains(['r', 'R']) || w.iter().any(|a| a == "--recursive");
    let force = short.contains('f') || w.iter().any(|a| a == "--force");
    let top = w.iter().skip(1).filter(|a| !a.starts_with('-')).any(|a| {
        let a = a.trim_end_matches('/');
        a.is_empty() || a == "/*" || (a.starts_with('/') && !a[1..].contains('/'))
    });
    recursive && force && top
}

fn zfs_destroy_not_patch(w: &[String]) -> bool {
    if w.len() < 2 || w[0] != "zfs" || w[1] != "destroy" {
        return false;
    }
    w[2..].iter().filter(|a| !a.starts_with('-')).any(|target| {
        let name = target.rsplit(['@', '/']).next().unwrap_or(target);
        !name.starts_with("rackhand-patch-")
    })
}

fn simple_command_needs_step_up(w: &[String]) -> bool {
    let first = w.first().map(String::as_str).unwrap_or("");
    let second = w.get(1).map(String::as_str).unwrap_or("");
    rm_recursive_force_top(w)
        || first.starts_with("mkfs")
        || (first == "dd" && w.iter().any(|a| a.starts_with("of=/dev/") && a != "of=/dev/null"))
        || (first == "zpool" && second == "destroy")
        || zfs_destroy_not_patch(w)
        || ((first == "qm" || first == "pct") && second == "destroy")
        || first == "do-release-upgrade"
        || first == "shutdown"
        || first == "poweroff"
        || (first == "systemctl" && w.iter().any(|a| a == "poweroff"))
}

fn edits_apt_sources(command: &str) -> bool {
    if !command.contains("/etc/apt/sources.list") {
        return false;
    }
    command.contains('>')
        || segments(command).any(|s| {
            commands_at_each_word(&words(s)).any(|w| {
                let first = w[0].as_str();
                WRITERS.contains(&first) || (first == "sed" && w.iter().any(|a| a.starts_with("-i")))
            })
        })
}

pub fn needs_step_up(command: &str) -> bool {
    segments(command).any(|s| commands_at_each_word(&words(s)).any(|w| simple_command_needs_step_up(&w)))
        || edits_apt_sources(command)
}
