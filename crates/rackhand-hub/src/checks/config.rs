//! `config/checks.toml` (7.8): the service checks the hub runs from its site.
//!
//! ```toml
//! [[check]]
//! name = "nas-web"          # a-z, 0-9 and -, unique
//! kind = "http"             # icmp, tcp, http (also https:// URLs), dns, tls
//! target = "https://nas.lab.example/"
//! interval_s = 60           # 15 to 3600, 60 by default (7.8.1)
//! machine = "nas"           # optional: the machine the check belongs to
//! [check.settings]          # the kind's own settings
//! body_contains = "TrueNAS"
//! ```

use rackhand_drivers::{DriverKind, check_driver};
use serde::Deserialize;

pub const MIN_INTERVAL_S: u32 = 15;
pub const MAX_INTERVAL_S: u32 = 3600;
pub const DEFAULT_INTERVAL_S: u32 = 60;

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ChecksFile {
    #[serde(default)]
    pub check: Vec<CheckSpec>,
}

fn default_interval() -> u32 {
    DEFAULT_INTERVAL_S
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CheckSpec {
    pub name: String,
    pub kind: String,
    pub target: String,
    #[serde(default = "default_interval")]
    pub interval_s: u32,
    #[serde(default)]
    pub machine: Option<String>,
    #[serde(default)]
    pub settings: toml::Table,
}

impl CheckSpec {
    pub fn driver_kind(&self) -> DriverKind {
        DriverKind::parse(&self.kind).unwrap_or(DriverKind::Tcp)
    }

    /// The settings as JSON, as the drivers and the `checks` table take them.
    pub fn settings_json(&self) -> serde_json::Value {
        serde_json::to_value(&self.settings).unwrap_or_default()
    }
}

fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The file, every check valid: a known check kind, the interval in range, only the kind's settings, unique names.
pub fn parse(text: &str) -> Result<ChecksFile, String> {
    let file: ChecksFile = toml::from_str(text).map_err(|e| format!("checks.toml: {e}"))?;
    let mut seen = std::collections::BTreeSet::new();
    for c in &file.check {
        let at = format!("check `{}`", c.name);
        if !valid_name(&c.name) {
            return Err(format!("{at}: the name is 1 to 64 of a-z, 0-9 and -"));
        }
        if !seen.insert(c.name.as_str()) {
            return Err(format!("{at} is defined twice"));
        }
        let driver = DriverKind::parse(&c.kind)
            .and_then(check_driver)
            .ok_or_else(|| format!("{at}: the kind is icmp, tcp, http, dns or tls, not `{}`", c.kind))?;
        if !(MIN_INTERVAL_S..=MAX_INTERVAL_S).contains(&c.interval_s) {
            return Err(format!("{at}: interval_s is {MIN_INTERVAL_S} to {MAX_INTERVAL_S}, not {}", c.interval_s));
        }
        if c.target.trim().is_empty() || c.target.len() > 512 {
            return Err(format!("{at}: give a target"));
        }
        let known = driver.known_settings();
        if let Some(k) = c.settings.keys().find(|k| !known.contains(&k.as_str())) {
            return Err(format!("{at}: `{}` checks have no setting `{k}` (they have: {})", c.kind, known.join(", ")));
        }
    }
    Ok(file)
}
