//! Maintenance windows (the `windows` table): for a machine or for every machine with a tag.

use jiff::tz::TimeZone;

use super::rrule::Recurrence;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Machine(String),
    Tag(String),
}

#[derive(Debug, Clone)]
pub struct Window {
    pub id: String,
    pub target: Target,
    pub recurrence: Recurrence,
    pub tz: TimeZone,
}

impl Window {
    pub fn applies_to(&self, machine_id: &str, tags: &[&str]) -> bool {
        match &self.target {
            Target::Machine(id) => id == machine_id,
            Target::Tag(tag) => tags.contains(&tag.as_str()),
        }
    }

    pub fn open_at(&self, at_ms: i64) -> bool {
        self.recurrence.open_at(&self.tz, at_ms).is_some()
    }
}

/// Whether a maintenance window covers the machine at `at_ms`.
pub fn maintenance_active(windows: &[Window], machine_id: &str, tags: &[&str], at_ms: i64) -> bool {
    windows.iter().any(|w| w.applies_to(machine_id, tags) && w.open_at(at_ms))
}
