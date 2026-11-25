//! `cargo xtask docs-check` (T99, 7.7.3, G8): every `rackhand`, `rackhand-probe` and `rackhand-cli` command a page of
//! the user documentation shows in a code block exists and answers `--help`; and the pages show documentation addresses
//! only (D71).

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command as Process;

use anyhow::{Context, Result, bail};

use crate::workspace_root;

/// The binaries whose commands the docs show.
pub const BINARIES: [&str; 3] = ["rackhand", "rackhand-probe", "rackhand-cli"];

/// Where each binary's usage text is.
const USAGE_SOURCES: [&str; 5] = [
    "crates/rackhand/src/main.rs",
    "crates/rackhand/src/operator_cmd.rs",
    "crates/rackhand/src/relay_cmd.rs",
    "crates/rackhand-probe/src/main.rs",
    "crates/rackhand-cli/src/lib.rs",
];

/// A command as the docs show it: the binary and its command words (not the options or values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub bin: String,
    pub words: Vec<String>,
}

impl Command {
    pub fn line(&self) -> String {
        std::iter::once(self.bin.as_str()).chain(self.words.iter().map(String::as_str)).collect::<Vec<_>>().join(" ")
    }
}

/// A command word: lowercase letters, digits and dashes, starting with a letter.
fn is_word(t: &str) -> bool {
    t.starts_with(|c: char| c.is_ascii_lowercase())
        && t.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// The command at the start of a line of shell: `[sudo] [<dir>/]<binary> <words>...`.
fn command_of(line: &str) -> Option<Command> {
    let mut tokens = line.split_whitespace().peekable();
    if tokens.peek() == Some(&"sudo") {
        tokens.next();
    }
    let first = tokens.next()?;
    let bin = first.rsplit('/').next().unwrap_or(first);
    if !BINARIES.contains(&bin) {
        return None;
    }
    let words = tokens.take_while(|t| is_word(t)).map(str::to_string).collect();
    Some(Command { bin: bin.to_string(), words })
}

/// The commands in a page's fenced code blocks.
pub fn commands_in(page: &str) -> Vec<Command> {
    let mut in_block = false;
    let mut out = Vec::new();
    for line in page.lines() {
        if line.trim_start().starts_with("```") {
            in_block = !in_block;
            continue;
        }
        if in_block && let Some(c) = command_of(line) {
            out.push(c);
        }
    }
    out
}

/// The user documentation: README.md, docs/*.md and docs/maintainers/*.md (not the designs).
pub fn doc_pages() -> Result<Vec<(String, String)>> {
    let root = workspace_root();
    let mut paths: Vec<PathBuf> = vec![root.join("README.md")];
    for dir in ["docs", "docs/maintainers"] {
        let mut here: Vec<PathBuf> = std::fs::read_dir(root.join(dir))
            .with_context(|| dir.to_string())?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "md"))
            .collect();
        here.sort();
        paths.extend(here);
    }
    paths
        .into_iter()
        .map(|p| {
            let name = p.strip_prefix(&root).unwrap_or(&p).display().to_string();
            Ok((name, std::fs::read_to_string(&p).with_context(|| p.display().to_string())?))
        })
        .collect()
}

/// Every command the docs show, once, in the order they first appear.
pub fn documented() -> Result<Vec<Command>> {
    let mut out: Vec<Command> = Vec::new();
    for (_, text) in doc_pages()? {
        for c in commands_in(&text) {
            if !out.contains(&c) {
                out.push(c);
            }
        }
    }
    Ok(out)
}

/// Every command line the binaries' usage texts name, as `<bin> <words>`.
pub fn usage_names() -> Result<Vec<String>> {
    let root = workspace_root();
    let mut out = Vec::new();
    for file in USAGE_SOURCES {
        let text = std::fs::read_to_string(root.join(file)).with_context(|| file.to_string())?;
        for line in text.lines() {
            let tokens: Vec<&str> =
                line.split_whitespace().map(|t| t.trim_matches(|c: char| "\"'`(),;".contains(c))).collect();
            for (i, t) in tokens.iter().enumerate() {
                if BINARIES.contains(t) {
                    let words: Vec<&str> = tokens[i + 1..].iter().copied().take_while(|w| is_word(w)).collect();
                    out.push(std::iter::once(*t).chain(words).collect::<Vec<_>>().join(" "));
                }
            }
        }
    }
    Ok(out)
}

/// IPv4 and IPv6 literals in a text (a port after an IPv4 address isn't part of it).
pub fn ip_literals(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'))
        .filter(|t| t.contains('.') || t.matches(':').count() >= 2)
        .filter_map(|t| {
            let t = t.trim_matches(|c| c == '.' || c == ':');
            if t.parse::<IpAddr>().is_ok() {
                return Some(t.to_string());
            }
            let (host, port) = t.rsplit_once(':')?;
            (port.chars().all(|c| c.is_ascii_digit()) && host.parse::<std::net::Ipv4Addr>().is_ok())
                .then(|| host.to_string())
        })
        .collect()
}

/// Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), loopback and unspecified.
pub fn is_documentation_address(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            let o = a.octets();
            a.is_loopback()
                || a.is_unspecified()
                || matches!((o[0], o[1], o[2]), (192, 0, 2) | (198, 51, 100) | (203, 0, 113))
        }
        Ok(IpAddr::V6(a)) => {
            let s = a.segments();
            a.is_loopback() || a.is_unspecified() || (s[0] == 0x2001 && s[1] == 0x0db8)
        }
        Err(_) => false,
    }
}

/// `cargo xtask docs-check`: builds the three binaries and runs every documented command with `--help`.
pub fn run() -> Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Process::new(cargo)
        .current_dir(workspace_root())
        .args(["build", "-q", "-p", "rackhand", "-p", "rackhand-probe", "-p", "rackhand-cli"])
        .status()
        .context("building the binaries")?;
    if !status.success() {
        bail!("building the binaries failed");
    }
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|| workspace_root().join("target"));
    let mut failed = Vec::new();
    let commands = documented()?;
    let usage = usage_names()?;
    for c in commands.iter().filter(|c| !usage.contains(&c.line())) {
        println!("BAD {}: in no binary's usage text", c.line());
        failed.push(c.line());
    }
    for c in &commands {
        let out = Process::new(target.join("debug").join(&c.bin))
            .args(&c.words)
            .arg("--help")
            .output()
            .with_context(|| c.line())?;
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        if out.status.success() && text.contains(&c.line()) {
            println!("ok  {} --help", c.line());
        } else {
            println!("BAD {} --help: exit {:?}", c.line(), out.status.code());
            failed.push(c.line());
        }
    }
    let addresses: Vec<String> = doc_pages()?
        .iter()
        .flat_map(|(page, text)| {
            ip_literals(text)
                .into_iter()
                .filter(|ip| !is_documentation_address(ip))
                .map(move |ip| format!("{page}: {ip}"))
        })
        .collect();
    for a in &addresses {
        println!("BAD address {a}");
    }
    println!(
        "{} documented commands, {} failed; {} addresses outside the documentation ranges",
        commands.len(),
        failed.len(),
        addresses.len()
    );
    if failed.is_empty() && addresses.is_empty() { Ok(()) } else { bail!("docs-check failed") }
}

#[cfg(test)]
mod tests;
