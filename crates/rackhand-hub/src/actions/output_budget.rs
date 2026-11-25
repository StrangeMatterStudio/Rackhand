//! The job output and transcript budget (7.4.1, 7.8.1): when the output of job steps and the text of assistant
//! transcripts together pass it, the oldest are trimmed first, before their 90 days are up; the jobs, their steps and
//! the transcripts' turns stay. Enforced when a job ends and with the hourly retention run.

use rackhand_store::{Db, StoreError, WriteCmd};

pub const MB: u64 = 1024 * 1024;
/// 100 MB; a setting from 50 MB to 20 GB (7.8.1).
pub const DEFAULT_BUDGET: u64 = 100 * MB;

/// Trims until the output fits `budget_bytes`; how many steps and transcript turns were trimmed.
pub async fn enforce(db: &Db, budget_bytes: u64) -> Result<usize, StoreError> {
    Ok(db.writer().send(WriteCmd::TrimOutput { budget_bytes }).await?.rows)
}

#[cfg(test)]
mod tests;
