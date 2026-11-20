//! The recent window (7.4.1, D100): the last 35 minutes of every series in memory.

use std::collections::{BTreeMap, HashMap, VecDeque};

/// A series of one machine: its metric and label set (canonical JSON, as `metric_keys.label_set`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SeriesId {
    pub name: String,
    pub labels: String,
}

impl SeriesId {
    pub fn new(name: &str, labels: &BTreeMap<String, String>) -> SeriesId {
        SeriesId { name: name.to_string(), labels: super::labels_json(labels) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WindowSample {
    /// Corrected and placed on the machine's tick.
    pub at_ms: i64,
    pub value: f64,
    /// Arrived more than 10 minutes after it was sampled: history only, no threshold incidents (E1).
    pub history_only: bool,
}

#[derive(Debug, Default)]
pub struct Window {
    series: HashMap<SeriesId, VecDeque<WindowSample>>,
}

impl Window {
    /// Adds a sample in time order; a sample at a time already held replaces it.
    pub fn add(&mut self, id: SeriesId, sample: WindowSample) {
        let q = self.series.entry(id).or_default();
        match q.iter().rposition(|s| s.at_ms <= sample.at_ms) {
            Some(i) if q[i].at_ms == sample.at_ms => q[i] = sample,
            Some(i) => q.insert(i + 1, sample),
            None => q.push_front(sample),
        }
    }

    /// Drops samples older than `cutoff_ms`, and series left empty.
    pub fn prune(&mut self, cutoff_ms: i64) {
        self.series.retain(|_, q| {
            while q.front().is_some_and(|s| s.at_ms < cutoff_ms) {
                q.pop_front();
            }
            !q.is_empty()
        });
    }

    pub fn samples(&self, id: &SeriesId) -> Vec<WindowSample> {
        self.series.get(id).map(|q| q.iter().copied().collect()).unwrap_or_default()
    }
}
