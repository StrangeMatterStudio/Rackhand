//! The diagnostics allow-list (7.8.3): `builtin/diagnostics.toml`, parsed once. Commands that need root go through the
//! command wrapper; their templates join every command list.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::params::{Param, ParamError, ParamType, check_value};
use crate::templates::{Arg, Template, wrapped};

const BUILTIN: &str = include_str!("../builtin/diagnostics.toml");

/// What the hub keeps of a diagnostic's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keep {
    All,
    Head(usize),
    Tail(usize),
    /// `du` lines, largest first.
    DuSorted,
}

/// A check on a parameter beyond its pattern, made by the hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Bind {
    /// The value names a machine in the same site.
    Site,
    /// The value is a URL of one of the machine's checks.
    Checks,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticParam {
    #[serde(rename = "type")]
    pub kind: ParamType,
    pub pattern: String,
    #[serde(default)]
    pub bind: Option<Bind>,
}

impl DiagnosticParam {
    pub fn param(&self) -> Param {
        Param { kind: self.kind, pattern: Some(self.pattern.clone()), allow_leading_dash: false, description: None }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    name: String,
    #[serde(default)]
    sensitive: bool,
    cmd: Vec<String>,
    #[serde(default)]
    alpine_cmd: Option<Vec<String>>,
    #[serde(default)]
    keep: Option<String>,
    #[serde(default)]
    params: BTreeMap<String, DiagnosticParam>,
}

#[derive(Debug, Deserialize)]
struct File {
    diagnostic: Vec<Raw>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub name: String,
    pub sensitive: bool,
    /// Debian-like machines (systemd, GNU tools).
    pub cmd: Vec<String>,
    /// Alpine (OpenRC, busybox); `None` where the Linux command works there too.
    pub alpine_cmd: Option<Vec<String>>,
    pub keep: Keep,
    pub params: BTreeMap<String, DiagnosticParam>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticError {
    Unknown,
    MissingParam(String),
    ExtraParam(String),
    Param(String, ParamError),
}

impl std::fmt::Display for DiagnosticError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiagnosticError::Unknown => f.write_str("no such diagnostic"),
            DiagnosticError::MissingParam(p) => write!(f, "`{p}` is missing"),
            DiagnosticError::ExtraParam(p) => write!(f, "`{p}` isn't a parameter of this diagnostic"),
            DiagnosticError::Param(p, e) => write!(f, "`{p}`: {e}"),
        }
    }
}

fn keep(text: Option<&str>) -> Keep {
    match text.and_then(|t| t.split_once(':').map(|(k, n)| (k, n.parse::<usize>().ok())).or(Some((t, None)))) {
        Some(("head", Some(n))) => Keep::Head(n),
        Some(("tail", Some(n))) => Keep::Tail(n),
        Some(("du", _)) => Keep::DuSorted,
        _ => Keep::All,
    }
}

/// The built-in diagnostics, in the order of 7.8.3.
pub fn builtin() -> &'static [Diagnostic] {
    static LIST: OnceLock<Vec<Diagnostic>> = OnceLock::new();
    LIST.get_or_init(|| {
        let file: File = toml::from_str(BUILTIN).unwrap_or(File { diagnostic: Vec::new() });
        file.diagnostic
            .into_iter()
            .map(|r| Diagnostic {
                keep: keep(r.keep.as_deref()),
                name: r.name,
                sensitive: r.sensitive,
                cmd: r.cmd,
                alpine_cmd: r.alpine_cmd,
                params: r.params,
            })
            .collect()
    })
}

pub fn find(name: &str) -> Option<&'static Diagnostic> {
    builtin().iter().find(|d| d.name == name)
}

fn substitute(cmd: &[String], args: &BTreeMap<String, String>) -> Vec<String> {
    cmd.iter()
        .map(|a| {
            let name = a.strip_prefix("{{").and_then(|r| r.strip_suffix("}}"));
            name.and_then(|n| args.get(n)).cloned().unwrap_or_else(|| a.clone())
        })
        .collect()
}

impl Diagnostic {
    /// The command for a machine: the Alpine variant on Alpine.
    pub fn command(&self, alpine: bool) -> &[String] {
        match (&self.alpine_cmd, alpine) {
            (Some(a), true) => a,
            _ => &self.cmd,
        }
    }

    /// Checks the arguments (every parameter given, nothing else, each valid as runbook parameters are) and returns
    /// the argument list with them substituted.
    pub fn argv(&self, alpine: bool, args: &BTreeMap<String, String>) -> Result<Vec<String>, DiagnosticError> {
        if let Some(extra) = args.keys().find(|k| !self.params.contains_key(*k)) {
            return Err(DiagnosticError::ExtraParam(extra.clone()));
        }
        for (name, p) in &self.params {
            let value = args.get(name).ok_or_else(|| DiagnosticError::MissingParam(name.clone()))?;
            check_value(&p.param(), value).map_err(|e| DiagnosticError::Param(name.clone(), e))?;
        }
        Ok(substitute(self.command(alpine), args))
    }

    fn template(&self, step: &str, cmd: &[String]) -> Option<Template> {
        let args = wrapped(cmd)?
            .iter()
            .map(|a| {
                let name = a.strip_prefix("{{").and_then(|r| r.strip_suffix("}}"));
                match name.and_then(|n| self.params.get(n).map(|p| (n, p))) {
                    Some((n, p)) => {
                        Arg::Param { name: n.to_string(), regex: p.param().regex(), allow_leading_dash: false }
                    }
                    None => Arg::Literal(a.clone()),
                }
            })
            .collect();
        Some(Template { runbook: "diagnostics".into(), step: step.into(), args })
    }
}

/// The wrapper templates of the diagnostics that run as root, for every command list.
pub fn templates() -> Vec<Template> {
    let mut out = Vec::new();
    for d in builtin() {
        out.extend(d.template(&d.name, &d.cmd));
        if let Some(a) = &d.alpine_cmd {
            out.extend(d.template(&format!("{}-alpine", d.name), a));
        }
    }
    out
}
