//! Dedupe keys (7.5.2): `<machine>:<rule>:<labels>` for condition incidents, `<machine>:<kind>:<subject>` for event
//! incidents, which take later matching events for 24 hours.

/// Later events with the same key join an incident opened within this time.
pub const EVENT_MERGE_MS: i64 = 24 * 3_600_000;

pub fn condition_key(machine: &str, rule: &str, labels: &str) -> String {
    format!("{machine}:{rule}:{labels}")
}

pub fn event_key(machine: &str, kind: &str, subject: &str) -> String {
    format!("{machine}:{kind}:{subject}")
}
