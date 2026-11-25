//! Baselines (7.6.4): hour-of-day and hour-of-week buckets per machine and metric, and the deviation warning.
//! Hours are counted in UTC, with hour of week 0 at Monday 00:00.

use crate::rules::Severity;

const MIN_MS: i64 = 60_000;
const HOUR_MS: i64 = 60 * MIN_MS;
const DAY_MS: i64 = 24 * HOUR_MS;
const WEIGHT: f64 = 0.1;
const USABLE_N: u32 = 3;
const SIGMAS: f64 = 4.0;
const SUSTAIN_MS: i64 = 15 * MIN_MS;
/// A baseline learns for this long before it warns, unless it is given the hub's setting (7.8.1).
pub const DEFAULT_LEARNING_MS: i64 = 7 * DAY_MS;
const UNFREEZE_MS: i64 = 2 * HOUR_MS;
/// A deviation clears after this many samples in a row inside the band, as threshold rules do.
const CALM_TO_CLEAR: u32 = 2;

/// The metric's floor: the smallest difference worth a warning, in the metric's own unit (bytes per second for
/// network and disk I/O). `None` for metrics without a baseline.
pub fn floor_for(metric: &str) -> Option<f64> {
    match metric {
        "cpu.busy_pct" => Some(20.0),
        "net.rx_bps" | "net.tx_bps" => Some(5_000_000.0 / 8.0),
        "diskio.read_bps" | "diskio.write_bps" => Some(20_000_000.0),
        "conn.outbound_count" => Some(50.0),
        _ => None,
    }
}

pub fn hour_of_day(at_ms: i64) -> usize {
    (at_ms.div_euclid(HOUR_MS) % 24) as usize
}

pub fn hour_of_week(at_ms: i64) -> usize {
    // 1970-01-01 was a Thursday, day 3 of a week that starts on Monday.
    let day = (at_ms.div_euclid(DAY_MS) + 3) % 7;
    day as usize * 24 + hour_of_day(at_ms)
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Bucket {
    pub mean: f64,
    pub var: f64,
    pub n: u32,
    pub frozen_until_ms: Option<i64>,
}

impl Bucket {
    /// Adds one hourly value: the first seeds the mean with variance 0, later ones move it with weight 0.1. A frozen
    /// bucket doesn't change.
    pub fn update(&mut self, value: f64, now_ms: i64) {
        if self.frozen_until_ms.is_some_and(|f| f > now_ms) {
            return;
        }
        self.frozen_until_ms = None;
        if self.n == 0 {
            self.mean = value;
            self.var = 0.0;
        } else {
            let diff = value - self.mean;
            self.mean += WEIGHT * diff;
            self.var = (1.0 - WEIGHT) * (self.var + WEIGHT * diff * diff);
        }
        self.n = self.n.saturating_add(1);
    }

    fn usable(&self) -> bool {
        self.n >= USABLE_N
    }
}

/// The baseline of one metric on one machine.
#[derive(Debug, Clone, PartialEq)]
pub struct Baseline {
    pub floor: f64,
    pub hod: Vec<Bucket>,
    pub how: Vec<Bucket>,
    pub first_data_ms: Option<i64>,
    pub deviating_since_ms: Option<i64>,
    pub active: bool,
    /// How long the baseline learns before it warns: the hub's baseline learning setting (7.8.1).
    pub learning_ms: i64,
    calm: u32,
}

impl Baseline {
    pub fn new(floor: f64) -> Self {
        Self {
            floor,
            hod: vec![Bucket::default(); 24],
            how: vec![Bucket::default(); 168],
            first_data_ms: None,
            deviating_since_ms: None,
            active: false,
            learning_ms: DEFAULT_LEARNING_MS,
            calm: 0,
        }
    }

    pub fn hod(&self, at_ms: i64) -> &Bucket {
        &self.hod[hour_of_day(at_ms)]
    }
    pub fn how(&self, at_ms: i64) -> &Bucket {
        &self.how[hour_of_week(at_ms)]
    }
    pub fn hod_mut(&mut self, at_ms: i64) -> &mut Bucket {
        &mut self.hod[hour_of_day(at_ms)]
    }
    pub fn how_mut(&mut self, at_ms: i64) -> &mut Bucket {
        &mut self.how[hour_of_week(at_ms)]
    }

    /// The hourly update from the tier-2 average of the hour containing `hour_ms`.
    pub fn hourly_update(&mut self, hour_ms: i64, tier2_avg: f64, now_ms: i64) {
        self.first_data_ms.get_or_insert(hour_ms);
        self.hod_mut(hour_ms).update(tier2_avg, now_ms);
        self.how_mut(hour_ms).update(tier2_avg, now_ms);
    }

    /// The bucket that applies at `at_ms`: hour of week when usable, else hour of day when usable.
    pub fn bucket_for(&self, at_ms: i64) -> Option<&Bucket> {
        [self.how(at_ms), self.hod(at_ms)].into_iter().find(|b| b.usable())
    }

    /// Evaluates one tier-1 sample. A warning while the deviation is active; never critical.
    pub fn evaluate(&mut self, at_ms: i64, value: f64) -> Option<Severity> {
        let first = *self.first_data_ms.get_or_insert(at_ms);
        let learning = at_ms - first < self.learning_ms;
        let Some(bucket) = self.bucket_for(at_ms).copied().filter(|_| !learning) else {
            self.deviating_since_ms = None;
            self.active = false;
            self.calm = 0;
            return None;
        };
        let std = bucket.var.sqrt().max(self.floor / 2.0);
        let diff = (value - bucket.mean).abs();
        if diff > SIGMAS * std && diff > self.floor {
            self.calm = 0;
            let since = *self.deviating_since_ms.get_or_insert(at_ms);
            if at_ms - since >= SUSTAIN_MS {
                self.active = true;
            }
            if self.active {
                let until = Some(at_ms + UNFREEZE_MS);
                self.hod_mut(at_ms).frozen_until_ms = until;
                self.how_mut(at_ms).frozen_until_ms = until;
            }
        } else {
            self.deviating_since_ms = None;
            self.calm += 1;
            if self.calm >= CALM_TO_CLEAR {
                self.active = false;
            }
        }
        self.active.then_some(Severity::Warning)
    }
}
