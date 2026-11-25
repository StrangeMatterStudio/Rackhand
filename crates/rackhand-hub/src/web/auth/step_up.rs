//! Step-up (FR-14, 7.7.2): a fresh TOTP code, valid on the session for the step-up freshness setting (5 minutes by
//! default, 7.8.1).

use rackhand_store::Db;

/// Whether a step-up at `step_up_at` still holds at `now_ms`, for the freshness the hub's settings give.
pub fn fresh(db: &Db, step_up_at: Option<i64>, now_ms: i64) -> bool {
    within(step_up_at, now_ms, crate::library::config::hub_or_default(db).auth.step_up_ms())
}

/// Whether a step-up at `step_up_at` still holds at `now_ms`, for `fresh_ms`.
pub fn within(step_up_at: Option<i64>, now_ms: i64, fresh_ms: i64) -> bool {
    step_up_at.is_some_and(|t| now_ms >= t && now_ms - t <= fresh_ms)
}
