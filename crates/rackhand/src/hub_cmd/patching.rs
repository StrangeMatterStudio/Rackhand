//! What patching asks about machines, from the hub's own systems (7.5.3): whether one is heard from, what it has
//! pending, whether a maintenance window covers it, and, for the reboot step, its policy and whether it started again.
//! Also the loop that takes up patch windows, and what tells Incidents that a machine's silence is expected.

use std::sync::Arc;
use std::time::Duration;

use jiff::tz::TimeZone;
use rackhand_hub::actions::Actions;
use rackhand_hub::actions::patching::driver::{self, Driver, World};
use rackhand_hub::actions::patching::rollback::defaults;
use rackhand_hub::executor::RebootFacts;
use rackhand_hub::incidents::machine_silence::Quiet;
use rackhand_hub::ingest::Ingest;
use rackhand_hub::policy::store;
use rackhand_hub::scheduler::windows::{Target, Window, maintenance_active};
use rackhand_store::Db;
use rackhand_store::ids::now_ms;

/// How often the hub looks for patch windows that opened and for what their runs need next.
pub const WINDOW_POLL: Duration = Duration::from_secs(30);

/// A machine is heard from while its last report is younger than this, or 4 of its intervals if that is longer, as its
/// silence is judged (7.6.3).
const HEARD_MS: i64 = 60_000;

#[derive(Debug, Clone)]
pub struct Machines {
    pub db: Arc<Db>,
    pub ingest: Ingest,
}

impl Machines {
    fn maintenance_windows(&self) -> Vec<Window> {
        let rows = store::windows(&self.db).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "maintenance windows");
            Vec::new()
        });
        rows.into_iter()
            .filter_map(|w| {
                let target = match (w.machine_id, w.tag) {
                    (Some(id), _) => Target::Machine(id),
                    (None, Some(tag)) => Target::Tag(tag),
                    (None, None) => return None,
                };
                Some(Window {
                    id: w.id,
                    target,
                    recurrence: w.rrule.parse().ok()?,
                    tz: TimeZone::get(&w.timezone).ok()?,
                })
            })
            .collect()
    }
}

impl World for Machines {
    fn online(&self, id: &str, now_ms: i64) -> bool {
        let limit = HEARD_MS.max(4 * self.ingest.interval_ms(id));
        self.ingest.last_seen(id).is_some_and(|seen| now_ms - seen < limit)
    }

    fn pending(&self, id: &str) -> (u32, u32) {
        self.ingest.latest(id).and_then(|l| l.updates).map_or((0, 0), |u| (u.security, u.pending))
    }

    fn in_maintenance(&self, id: &str, tags: &[String], now_ms: i64) -> bool {
        let tags: Vec<&str> = tags.iter().map(String::as_str).collect();
        maintenance_active(&self.maintenance_windows(), id, &tags, now_ms)
    }
}

impl RebootFacts for Machines {
    fn auto_reboot(&self, machine: &str) -> bool {
        let row: rusqlite::Result<(Option<bool>, String, String)> = self.db.readers().with(|c| {
            c.query_row(
                "SELECT p.auto_reboot, m.kind, m.roles FROM machines m LEFT JOIN policies p ON p.id = m.policy_id
                 WHERE m.id = ?1",
                [machine],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
        });
        let Ok((policy, kind, roles)) = row else { return false };
        policy.unwrap_or_else(|| {
            let roles: Vec<String> = serde_json::from_str(&roles).unwrap_or_default();
            defaults(&kind, &roles.iter().map(String::as_str).collect::<Vec<_>>()).auto_reboot
        })
    }

    fn back_since(&self, machine: &str, since_ms: i64) -> bool {
        // A sample's time is rounded down to the machine's interval, so its start can look that much earlier.
        let slack = self.ingest.interval_ms(machine);
        let newest = self.ingest.window_series(machine, "uptime_s").into_iter().find_map(|(_, s)| s.last().copied());
        newest.is_some_and(|s| s.at_ms >= since_ms && s.at_ms - (s.value * 1000.0) as i64 + slack > since_ms)
    }

    fn reported_since(&self, machine: &str, since_ms: i64) -> bool {
        self.ingest.last_seen(machine).is_some_and(|seen| seen >= since_ms)
    }
}

/// What Incidents asks before it calls a machine silent (7.6.3).
#[derive(Debug, Clone)]
pub struct Expected {
    pub machines: Arc<Machines>,
    pub actions: Actions,
}

impl Quiet for Expected {
    fn in_maintenance(&self, machine: &str, tags: &[String], now_ms: i64) -> bool {
        World::in_maintenance(&*self.machines, machine, tags, now_ms)
    }

    fn awaiting_reboot(&self, machine: &str) -> bool {
        self.actions.awaiting_reboot(machine)
    }
}

/// Tells the driver which patch windows are open.
pub async fn tick(db: &Db, driver: &Arc<Driver>, now_ms: i64) {
    let open = match rackhand_hub::scheduler::patching::open(db, now_ms) {
        Ok(open) => open,
        Err(e) => return tracing::warn!(error = %e, "patch windows"),
    };
    let open = open
        .into_iter()
        .map(|w| driver::OpenWindow {
            policy: w.policy,
            site: w.site,
            window: if w.full { driver::Window::Full } else { driver::Window::Security },
            starts_ms: w.starts_ms,
            ends_ms: w.ends_ms,
            next_ends_ms: w.next_ends_ms,
        })
        .collect();
    driver.tick(open, now_ms).await;
}

/// Takes up patch windows as they open (7.5.3), every `every`.
pub fn spawn(db: Arc<Db>, driver: Arc<Driver>, every: Duration) {
    tokio::spawn(async move {
        let mut poll = tokio::time::interval(every);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            poll.tick().await;
            tick(&db, &driver, now_ms()).await;
        }
    });
}

#[cfg(test)]
#[path = "patching_tests.rs"]
mod tests;
