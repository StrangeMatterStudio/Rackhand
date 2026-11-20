//! Retries (7.3.9): at 1, 5 and 15 minutes after a failure, then the notifier has failed.

use super::Message;

const DELAYS_MS: [i64; 3] = [60_000, 5 * 60_000, 15 * 60_000];

/// A message waiting for another try through one notifier.
#[derive(Debug, Clone)]
pub struct Pending {
    pub transport: usize,
    pub message: Message,
    /// Retries made so far.
    pub attempt: u32,
    pub due_ms: i64,
    /// The `notifications` row.
    pub id: String,
}

/// The wait before the next try after `attempt` retries, or `None` when there are no more.
pub fn next_delay(attempt: u32) -> Option<i64> {
    DELAYS_MS.get(attempt as usize).copied()
}
