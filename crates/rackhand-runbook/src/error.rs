//! Errors that point at a line of the source, as `rackhand hub runbook check` and the dashboard show them (12).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelError {
    pub message: String,
    /// 1-based line in the source, when known.
    pub line: Option<usize>,
}

impl ModelError {
    pub fn new(message: impl Into<String>, line: Option<usize>) -> ModelError {
        ModelError { message: message.into(), line }
    }

    pub(crate) fn from_toml(e: &toml::de::Error, source: &str, offset_lines: usize) -> ModelError {
        let line = e.span().map(|s| line_of(source, s.start) + offset_lines);
        ModelError::new(e.message().trim().to_string(), line)
    }
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "line {line}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for ModelError {}

/// The 1-based line of a byte offset.
pub(crate) fn line_of(source: &str, offset: usize) -> usize {
    1 + source[..offset.min(source.len())].matches('\n').count()
}

/// Durations as runbooks write them: `30s`, `5m`, `2h`.
pub(crate) fn parse_duration(text: &str) -> Option<u64> {
    let (n, unit) = text.split_at(text.len().checked_sub(1)?);
    let n: u64 = n.parse().ok()?;
    match unit {
        "s" => Some(n),
        "m" => n.checked_mul(60),
        "h" => n.checked_mul(3600),
        _ => None,
    }
}
