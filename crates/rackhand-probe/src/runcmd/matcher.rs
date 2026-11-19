//! Matching a requested argument list against `commands.json` (7.3.7): the same number of arguments, every literal
//! equal, every parameter matching its anchored regex and the leading-dash rule. Nothing else runs.

use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Arg {
    Literal { literal: String },
    Param { param: String, regex: String, allow_leading_dash: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Template {
    pub runbook: String,
    pub step: String,
    pub args: Vec<Arg>,
}

/// The installed `commands.json`: the signed list's version and its templates.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CommandList {
    pub version: u64,
    pub commands: Vec<Template>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No template matches the arguments exactly.
    NoTemplate,
    /// The closest template has a parameter whose value starts with `-` and doesn't allow it.
    LeadingDash,
    Empty,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refusal::NoTemplate => "refused: the command doesn't match the allowed list",
            Refusal::LeadingDash => "refused: a parameter starts with '-'",
            Refusal::Empty => "refused: no command",
        })
    }
}

enum Fit {
    Yes,
    No,
    Dash,
}

fn fits(t: &Template, args: &[String]) -> Fit {
    if t.args.len() != args.len() {
        return Fit::No;
    }
    let mut dash = false;
    for (want, got) in t.args.iter().zip(args) {
        match want {
            Arg::Literal { literal } => {
                if literal != got {
                    return Fit::No;
                }
            }
            Arg::Param { regex, allow_leading_dash, .. } => {
                if got.starts_with('-') && !allow_leading_dash {
                    dash = true;
                    continue;
                }
                // A regex that doesn't compile matches nothing.
                if !Regex::new(regex).is_ok_and(|r| r.is_match(got)) {
                    return Fit::No;
                }
            }
        }
    }
    if dash { Fit::Dash } else { Fit::Yes }
}

/// The argument vector to execute, if a template allows it.
pub fn matching(list: &CommandList, args: &[String]) -> Result<Vec<String>, Refusal> {
    if args.is_empty() {
        return Err(Refusal::Empty);
    }
    let mut dash = false;
    for t in &list.commands {
        match fits(t, args) {
            Fit::Yes => return Ok(args.to_vec()),
            Fit::Dash => dash = true,
            Fit::No => {}
        }
    }
    Err(if dash { Refusal::LeadingDash } else { Refusal::NoTemplate })
}
