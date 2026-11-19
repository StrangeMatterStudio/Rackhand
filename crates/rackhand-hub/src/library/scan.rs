//! The pre-push scan (7.3.13, E40): the mirror refuses content holding a Vault value, a PEM or OpenSSH private key, a
//! Discord webhook URL, an AWS access key, or `password = "..."` with a value that isn't a `secret:` reference.

use std::sync::OnceLock;

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finding {
    VaultValue,
    PrivateKey,
    DiscordWebhook,
    AwsKey,
    Password,
}

/// Vault values shorter than this would match by accident and are left out.
const MIN_VAULT_VALUE: usize = 8;

struct Patterns {
    private_key: Regex,
    discord: Regex,
    aws: Regex,
    password: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        private_key: Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap_or_else(|_| unreachable!()),
        discord: Regex::new(r"discord(app)?\.com/api/webhooks/").unwrap_or_else(|_| unreachable!()),
        aws: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap_or_else(|_| unreachable!()),
        password: Regex::new(r#"(?i)[a-z0-9_]*(password|passwd)\s*=\s*"([^"]*)""#).unwrap_or_else(|_| unreachable!()),
    })
}

pub fn scan(text: &str, vault_values: &[Vec<u8>]) -> Vec<Finding> {
    let p = patterns();
    let mut found = Vec::new();
    let bytes = text.as_bytes();
    if vault_values
        .iter()
        .filter(|v| v.len() >= MIN_VAULT_VALUE)
        .any(|v| bytes.windows(v.len()).any(|w| w == v.as_slice()))
    {
        found.push(Finding::VaultValue);
    }
    if p.private_key.is_match(text) {
        found.push(Finding::PrivateKey);
    }
    if p.discord.is_match(text) {
        found.push(Finding::DiscordWebhook);
    }
    if p.aws.is_match(text) {
        found.push(Finding::AwsKey);
    }
    if p.password
        .captures_iter(text)
        .any(|c| c.get(2).is_some_and(|v| !v.as_str().is_empty() && !v.as_str().starts_with("secret:")))
    {
        found.push(Finding::Password);
    }
    found
}

#[cfg(test)]
#[path = "scan_tests.rs"]
mod tests;
