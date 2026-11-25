//! Patch windows (7.5.3 step 1): which are open now, by policy and site. A policy's `security_window` (daily 04:00
//! unless it says otherwise) and `full_window` (Sunday 03:00) are `window_length_min` long (180) and in the timezone of
//! the site of its machines. What is open is worked out from the policies each time, so a hub that restarts during a
//! window finds it again and one missed entirely is skipped.

use jiff::tz::TimeZone;
use rackhand_store::Db;

use super::rrule::Recurrence;

pub const SECURITY: &str = "daily 04:00";
pub const FULL: &str = "weekly sun 03:00";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenWindow {
    pub policy: String,
    pub site: String,
    /// The full window, else the security one.
    pub full: bool,
    pub starts_ms: i64,
    pub ends_ms: i64,
    /// When the window after this one ends.
    pub next_ends_ms: i64,
}

struct PolicySite {
    policy: String,
    site: String,
    timezone: String,
    security: Option<String>,
    full: Option<String>,
    length_min: i64,
}

/// The patch windows open at `now_ms`, for each policy that patches and each site with machines under it.
pub fn open(db: &Db, now_ms: i64) -> rusqlite::Result<Vec<OpenWindow>> {
    let rows: Vec<PolicySite> = db.readers().with(|c| {
        let mut s = c.prepare(
            "SELECT DISTINCT p.id, s.id, s.timezone, p.security_window, p.full_window, p.window_length_min
             FROM policies p JOIN machines m ON m.policy_id = p.id JOIN sites s ON s.id = m.site_id
             WHERE p.patch != 'hold' ORDER BY p.id, s.id",
        )?;
        s.query_map([], |r| {
            Ok(PolicySite {
                policy: r.get(0)?,
                site: r.get(1)?,
                timezone: r.get(2)?,
                security: r.get(3)?,
                full: r.get(4)?,
                length_min: r.get(5)?,
            })
        })?
        .collect()
    })?;
    let mut out = Vec::new();
    for p in rows {
        let Ok(tz) = TimeZone::get(&p.timezone) else {
            tracing::warn!(site = %p.site, timezone = %p.timezone, "patch windows: unknown timezone");
            continue;
        };
        for (full, text) in
            [(false, p.security.as_deref().unwrap_or(SECURITY)), (true, p.full.as_deref().unwrap_or(FULL))]
        {
            let Ok(recurrence) = format!("{text} {}m", p.length_min).parse::<Recurrence>() else {
                tracing::warn!(policy = %p.policy, window = %text, "patch windows: unreadable time");
                continue;
            };
            let Some((starts_ms, ends_ms)) = recurrence.open_at(&tz, now_ms) else { continue };
            let next_ends_ms = recurrence.next_start(&tz, starts_ms).saturating_add(recurrence.duration_ms());
            out.push(OpenWindow {
                policy: p.policy.clone(),
                site: p.site.clone(),
                full,
                starts_ms,
                ends_ms,
                next_ends_ms,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "patching_tests.rs"]
mod tests;
