//! Clock offsets (7.3.2): the median of receive time minus sample time over the last 20 live reports.

use std::collections::VecDeque;

const LIVE_REPORTS: usize = 20;
/// An offset past this raises `clock_skew` (E4).
pub const SKEW_MS: i64 = 30_000;

#[derive(Debug, Default)]
pub struct Clock {
    offsets: VecDeque<i64>,
    skew_raised: bool,
}

impl Clock {
    /// Records a live report's offset; returns true when the offset has just passed 30 s.
    pub fn observe(&mut self, offset_ms: i64) -> bool {
        if self.offsets.len() == LIVE_REPORTS {
            self.offsets.pop_front();
        }
        self.offsets.push_back(offset_ms);
        let skewed = self.offset().is_some_and(|o| o.abs() > SKEW_MS);
        let raise = skewed && !self.skew_raised;
        self.skew_raised = skewed;
        raise
    }

    pub fn offset(&self) -> Option<i64> {
        if self.offsets.is_empty() {
            return None;
        }
        let mut sorted: Vec<i64> = self.offsets.iter().copied().collect();
        sorted.sort_unstable();
        Some(sorted[(sorted.len() - 1) / 2])
    }
}
