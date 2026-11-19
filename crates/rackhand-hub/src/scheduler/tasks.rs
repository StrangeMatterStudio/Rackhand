//! The Scheduler's tasks and their `schedule_state`: each task fires once per scheduled time, across restarts.

use std::collections::HashMap;

use jiff::tz::TimeZone;
use rackhand_store::reader::ReadPool;
use rackhand_store::{Row, WriteCmd};
use rusqlite::types::Value;

use super::rrule::Recurrence;

#[derive(Debug, Clone)]
pub enum Schedule {
    /// Periodic work (retention, rollups, intel refresh): at start, then every period. Runs missed while the hub was
    /// down collapse into one.
    Every { period_ms: i64 },
    /// A window (patch windows): fires at each start; a window still open fires late, one missed entirely is skipped.
    Window { recurrence: Recurrence, tz: TimeZone },
}

#[derive(Debug, Clone)]
pub struct Task {
    pub kind: String,
    pub key: String,
    pub schedule: Schedule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleState {
    pub kind: String,
    pub key: String,
    pub last_run_ms: Option<i64>,
    pub next_run_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fired {
    pub kind: String,
    pub key: String,
    /// The scheduled time (a window's start), not the time it was noticed.
    pub at_ms: i64,
}

#[derive(Debug)]
pub struct Scheduler {
    tasks: Vec<Task>,
    state: HashMap<(String, String), ScheduleState>,
}

impl Scheduler {
    pub fn new(tasks: Vec<Task>, saved: Vec<ScheduleState>, now_ms: i64) -> Self {
        let mut state: HashMap<_, _> = saved.into_iter().map(|s| ((s.kind.clone(), s.key.clone()), s)).collect();
        for t in &tasks {
            let entry = state.entry((t.kind.clone(), t.key.clone())).or_insert_with(|| ScheduleState {
                kind: t.kind.clone(),
                key: t.key.clone(),
                last_run_ms: None,
                next_run_ms: None,
            });
            if entry.next_run_ms.is_none() {
                entry.next_run_ms = Some(first_run(&t.schedule, now_ms));
            }
        }
        Scheduler { tasks, state }
    }

    pub fn state(&self, kind: &str, key: &str) -> Option<&ScheduleState> {
        self.state.get(&(kind.to_string(), key.to_string()))
    }

    /// The tasks due at `now_ms`, in task order. Each fires once; its state moves to the next run.
    pub fn due(&mut self, now_ms: i64) -> Vec<Fired> {
        let mut fired = Vec::new();
        for t in &self.tasks {
            let Some(s) = self.state.get_mut(&(t.kind.clone(), t.key.clone())) else { continue };
            let Some(next) = s.next_run_ms.filter(|n| *n <= now_ms) else { continue };
            match &t.schedule {
                Schedule::Every { period_ms } => {
                    fired.push(Fired { kind: t.kind.clone(), key: t.key.clone(), at_ms: next });
                    s.last_run_ms = Some(next);
                    s.next_run_ms = Some(now_ms + period_ms);
                }
                Schedule::Window { recurrence, tz } => {
                    if now_ms < next + recurrence.duration_ms() {
                        fired.push(Fired { kind: t.kind.clone(), key: t.key.clone(), at_ms: next });
                        s.last_run_ms = Some(next);
                    }
                    s.next_run_ms = Some(recurrence.next_start(tz, next.max(now_ms - recurrence.duration_ms())));
                }
            }
        }
        fired
    }
}

/// With no saved state: periodic work runs now; a window runs from the one open now, else the next.
fn first_run(schedule: &Schedule, now_ms: i64) -> i64 {
    match schedule {
        Schedule::Every { .. } => now_ms,
        Schedule::Window { recurrence, tz } => {
            recurrence.open_at(tz, now_ms).map_or_else(|| recurrence.next_start(tz, now_ms), |(start, _)| start)
        }
    }
}

pub fn load_state(readers: &ReadPool) -> rusqlite::Result<Vec<ScheduleState>> {
    readers.with(|c| {
        let mut stmt = c.prepare("SELECT kind, key, last_run_ms, next_run_ms FROM schedule_state")?;
        let rows = stmt.query_map([], |r| {
            Ok(ScheduleState { kind: r.get(0)?, key: r.get(1)?, last_run_ms: r.get(2)?, next_run_ms: r.get(3)? })
        })?;
        rows.collect()
    })
}

pub fn state_cmd(s: &ScheduleState) -> WriteCmd {
    let opt = |v: Option<i64>| v.map_or(Value::Null, Value::Integer);
    let row: Row = [
        ("kind", Value::Text(s.kind.clone())),
        ("key", Value::Text(s.key.clone())),
        ("last_run_ms", opt(s.last_run_ms)),
        ("next_run_ms", opt(s.next_run_ms)),
    ]
    .into_iter()
    .collect();
    WriteCmd::PutScheduleState(row)
}
