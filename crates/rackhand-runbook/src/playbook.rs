//! The playbook format (7.8.8): TOML front matter between `+++` lines, then Markdown sections an assistant follows.

use serde::Deserialize;

use crate::error::{ModelError, parse_duration};
use crate::runbook::Risk;

/// The sections every playbook has, in order.
pub const SECTIONS: [&str; 5] = ["When", "Read first", "Do", "Done when", "Stop and ask if"];
/// A job's deadline is at most 2 hours (7.3.5).
const MAX_RUNTIME_S: u64 = 2 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Hosts {
    Incident,
    Site,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrontMatter {
    name: String,
    #[serde(default)]
    incident_kinds: Vec<String>,
    autonomy: u8,
    risk: Risk,
    #[serde(default)]
    tools: Vec<String>,
    hosts: Hosts,
    #[serde(default)]
    max_runtime: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Playbook {
    pub name: String,
    pub incident_kinds: Vec<String>,
    pub autonomy: u8,
    pub risk: Risk,
    pub tools: Vec<String>,
    pub hosts: Hosts,
    pub max_runtime: Option<String>,
    /// `(heading, text)` in file order.
    pub sections: Vec<(String, String)>,
}

impl Playbook {
    pub fn parse(source: &str) -> Result<Playbook, ModelError> {
        let body = source.strip_prefix("+++\n").or_else(|| source.strip_prefix("+++\r\n"));
        let body = body.ok_or_else(|| ModelError::new("a playbook starts with a `+++` line", Some(1)))?;
        let end = body.find("\n+++").ok_or_else(|| ModelError::new("the front matter has no closing `+++`", None))?;
        let (front, rest) = (&body[..end + 1], &body[end + 4..]);
        let fm: FrontMatter = toml::from_str(front).map_err(|e| ModelError::from_toml(&e, front, 1))?;
        let max_runtime_s = fm.max_runtime.as_deref().map(parse_duration);
        if matches!(max_runtime_s, Some(None)) {
            return Err(ModelError::new("max_runtime: use a number with s, m or h", None));
        }
        if max_runtime_s.flatten().is_some_and(|s| s > MAX_RUNTIME_S) {
            return Err(ModelError::new("max_runtime is over 2 hours", None));
        }
        let sections = split_sections(rest);
        for want in SECTIONS {
            if !sections.iter().any(|(h, _)| h == want) {
                return Err(ModelError::new(format!("missing section `## {want}`"), None));
            }
        }
        Ok(Playbook {
            name: fm.name,
            incident_kinds: fm.incident_kinds,
            autonomy: fm.autonomy,
            risk: fm.risk,
            tools: fm.tools,
            hosts: fm.hosts,
            max_runtime: fm.max_runtime,
            sections,
        })
    }

    pub fn section(&self, heading: &str) -> Option<&str> {
        self.sections.iter().find(|(h, _)| h == heading).map(|(_, t)| t.as_str())
    }

    pub fn max_runtime_s(&self) -> Option<u64> {
        self.max_runtime.as_deref().and_then(parse_duration)
    }
}

fn split_sections(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            out.push((heading.trim().to_string(), String::new()));
        } else if let Some((_, body)) = out.last_mut() {
            if !body.is_empty() {
                body.push('\n');
            }
            body.push_str(line);
        }
    }
    for (_, body) in &mut out {
        *body = body.trim().to_string();
    }
    out
}
