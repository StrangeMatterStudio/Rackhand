//! Time-based triggers (7.2, Scheduler): patch and maintenance windows in each site's timezone, and the periodic
//! tasks (checks, retention, rollups, backups, intel refresh, git mirror debounce, dead-man calls). Owns
//! `schedule_state`.

pub mod patching;
pub mod rrule;
pub mod tasks;
pub mod windows;

#[cfg(test)]
mod tests;
