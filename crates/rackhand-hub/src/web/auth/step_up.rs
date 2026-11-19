//! Step-up (FR-14, 7.7.2): a fresh TOTP code, valid for 5 minutes on the session.

pub const STEP_UP_MS: i64 = 5 * 60_000;

/// Whether a step-up at `step_up_at` still holds at `now_ms`.
pub fn fresh(step_up_at: Option<i64>, now_ms: i64) -> bool {
    step_up_at.is_some_and(|t| now_ms >= t && now_ms - t <= STEP_UP_MS)
}
