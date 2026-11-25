//! `config/notifiers.toml` (7.4.3): the notifiers, with secrets only as `secret:<name>` references to the Vault.
//!
//! ```toml
//! [[discord]]
//! name = "ops"
//! webhook = "secret:discord_ops"
//!
//! [[smtp]]
//! name = "mail"
//! host = "smtp.example.net"
//! port = 587
//! security = "starttls"          # or "tls"
//! username = "hub@example.net"
//! password = "secret:smtp_password"
//! from = "hub@example.net"
//! to = ["ops@example.net"]
//! ```

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};

use super::Transport;
use super::discord::Discord;
use super::smtp::{Security, Smtp, SmtpConfig};

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NotifiersFile {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discord: Vec<DiscordSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub smtp: Vec<SmtpSpec>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscordSpec {
    pub name: String,
    /// `secret:<name>`: the webhook URL is a secret.
    pub webhook: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SmtpSpec {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub security: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// `secret:<name>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub from: String,
    pub to: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("notifiers.toml: {0}")]
    Parse(String),
    #[error("notifier {0}: `{1}` must be a `secret:<name>` reference")]
    NotASecret(String, &'static str),
    #[error("notifier {0}: the Vault has no secret `{1}`")]
    MissingSecret(String, String),
    #[error("notifier {0}: security is `starttls` or `tls`")]
    Security(String),
}

pub fn parse(text: &str) -> Result<NotifiersFile, ConfigError> {
    toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))
}

/// The file's text, as `parse` reads it back.
pub fn to_toml(file: &NotifiersFile) -> Result<String, ConfigError> {
    toml::to_string(file).map_err(|e| ConfigError::Parse(e.to_string()))
}

/// Where a build with the `test-smtp-roots` feature (the offline test, plan T97) finds the roots of the test's mail server.
pub const TEST_SMTP_ROOTS: &str = "/etc/rackhand/test-smtp-roots.pem";

/// The roots SMTP trusts besides the public ones: none (D113), or in the offline test's build the certificates of
/// `TEST_SMTP_ROOTS`.
fn extra_roots() -> Vec<CertificateDer<'static>> {
    if cfg!(feature = "test-smtp-roots") { roots_from_pem(std::path::Path::new(TEST_SMTP_ROOTS)) } else { Vec::new() }
}

/// Every certificate in a PEM file; none when it can't be read.
pub fn roots_from_pem(path: &std::path::Path) -> Vec<CertificateDer<'static>> {
    match CertificateDer::pem_file_iter(path) {
        Ok(certs) => certs.filter_map(Result::ok).collect(),
        Err(_) => Vec::new(),
    }
}

/// Builds the notifiers, resolving each `secret:<name>` through `secret`.
pub fn build(
    file: &NotifiersFile,
    secret: &dyn Fn(&str) -> Option<String>,
    dashboard_url: Option<&str>,
) -> Result<Vec<Arc<dyn Transport>>, ConfigError> {
    let resolve = |notifier: &str, field: &'static str, value: &str| -> Result<String, ConfigError> {
        let name = value.strip_prefix("secret:").ok_or_else(|| ConfigError::NotASecret(notifier.into(), field))?;
        secret(name).ok_or_else(|| ConfigError::MissingSecret(notifier.into(), name.into()))
    };
    let mut out: Vec<Arc<dyn Transport>> = Vec::new();
    for d in &file.discord {
        let url = resolve(&d.name, "webhook", &d.webhook)?;
        out.push(Arc::new(Discord::new(&d.name, &url).with_dashboard_url(dashboard_url)));
    }
    for s in &file.smtp {
        let security = match s.security.as_str() {
            "starttls" => Security::StartTls,
            "tls" => Security::Tls,
            _ => return Err(ConfigError::Security(s.name.clone())),
        };
        let password = s.password.as_deref().map(|p| resolve(&s.name, "password", p)).transpose()?;
        let config = SmtpConfig {
            host: s.host.clone(),
            port: s.port,
            security,
            username: s.username.clone(),
            password,
            from: s.from.clone(),
            to: s.to.clone(),
            extra_roots: extra_roots(),
        };
        out.push(Arc::new(Smtp::new(&s.name, config)));
    }
    Ok(out)
}
