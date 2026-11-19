//! Runbook parameters (7.3.7): a value must match its type and its pattern as a whole, and a value starting with `-`
//! is refused unless the parameter allows it, so a parameter can't become an option of the command.

use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamType {
    String,
    Int,
    Bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Param {
    #[serde(rename = "type")]
    pub kind: ParamType,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub allow_leading_dash: bool,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamError {
    LeadingDash,
    WrongType,
    NoMatch,
    BadPattern(String),
}

impl std::fmt::Display for ParamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParamError::LeadingDash => f.write_str("the value starts with `-`"),
            ParamError::WrongType => f.write_str("the value isn't of the parameter's type"),
            ParamError::NoMatch => f.write_str("the value doesn't match the parameter's pattern"),
            ParamError::BadPattern(e) => write!(f, "the pattern doesn't compile: {e}"),
        }
    }
}

/// A pattern anchored at both ends, whatever anchors it already has.
pub fn anchored(pattern: &str) -> String {
    format!("^(?:{pattern})$")
}

impl Param {
    /// The whole-value regular expression: the declared pattern, or the type's own.
    pub fn regex(&self) -> String {
        match (&self.pattern, self.kind) {
            (Some(p), _) => anchored(p),
            (None, ParamType::String) => anchored(".*"),
            (None, ParamType::Int) => anchored("[0-9]+"),
            (None, ParamType::Bool) => anchored("true|false"),
        }
    }

    pub(crate) fn compile(&self) -> Result<Regex, ParamError> {
        Regex::new(&self.regex()).map_err(|e| ParamError::BadPattern(e.to_string()))
    }
}

pub fn check_value(param: &Param, value: &str) -> Result<(), ParamError> {
    if value.starts_with('-') && !param.allow_leading_dash {
        return Err(ParamError::LeadingDash);
    }
    let typed = match param.kind {
        ParamType::String => true,
        ParamType::Int => value.trim_start_matches('-').parse::<u64>().is_ok() && !value.contains('+'),
        ParamType::Bool => value == "true" || value == "false",
    };
    if !typed {
        return Err(ParamError::WrongType);
    }
    if param.pattern.is_some() && !param.compile()?.is_match(value) {
        return Err(ParamError::NoMatch);
    }
    Ok(())
}
