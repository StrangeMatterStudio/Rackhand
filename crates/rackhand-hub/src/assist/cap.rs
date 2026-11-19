//! The daily assistant cap (FR-16, E47, AC51): over it, an incident goes to a person with a note saying why.

use rackhand_store::Db;

/// Assistant jobs started since the start of the day (UTC).
pub(super) fn started_today(db: &Db, now_ms: i64) -> u32 {
    let day_start = now_ms - now_ms.rem_euclid(86_400_000);
    db.readers()
        .with(|c| {
            c.query_row("SELECT count(*) FROM jobs WHERE kind = 'assistant' AND started_at >= ?1", [day_start], |r| {
                r.get::<_, i64>(0)
            })
        })
        .map(|n| n as u32)
        .unwrap_or(u32::MAX)
}
