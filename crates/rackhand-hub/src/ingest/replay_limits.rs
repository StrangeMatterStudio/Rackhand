//! Replay limits (7.3.2): 2 MB/s per probe and 20 MB/s across the hub for stream 2, and 512 MB of staging.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayLimits {
    pub probe_bps: u64,
    pub hub_bps: u64,
    pub staging_bytes: u64,
}

impl Default for ReplayLimits {
    fn default() -> ReplayLimits {
        ReplayLimits { probe_bps: 2_000_000, hub_bps: 20_000_000, staging_bytes: 512_000_000 }
    }
}

/// A token bucket holding at most one second of its rate; a charge may take it below zero.
#[derive(Debug, Default)]
pub struct Bucket {
    tokens: f64,
    at_ms: Option<i64>,
}

impl Bucket {
    pub fn available(&self, rate: u64, now_ms: i64) -> f64 {
        let cap = rate as f64;
        match self.at_ms {
            None => cap,
            Some(at) => (self.tokens + (now_ms - at).max(0) as f64 * cap / 1000.0).min(cap),
        }
    }

    pub fn charge(&mut self, rate: u64, bytes: usize, now_ms: i64) {
        self.tokens = self.available(rate, now_ms) - bytes as f64;
        self.at_ms = Some(now_ms);
    }
}
