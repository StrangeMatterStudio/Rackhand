//! Rollups from the recent window and series reads for the dashboard and MCP (7.4.1).

use std::collections::BTreeMap;

use rackhand_store::WriteCmd;
use rackhand_store::rollup::RollupSeries;
use rackhand_store::series::chunk::{SeriesKey, Tier};

use super::window::SeriesId;
use super::{Ingest, IngestError, labels_json};

const MINUTE_MS: i64 = 60_000;
const HOUR_MS: i64 = 3_600_000;
/// Ranges up to this long read tier 0 (its retention), up to [`TIER1_SPAN_MS`] tier 1, longer ones tier 2.
pub const TIER0_SPAN_MS: i64 = 2 * 86_400_000;
pub const TIER1_SPAN_MS: i64 = 30 * 86_400_000;

impl Ingest {
    /// Every minute: the min, max and avg of each series' samples in `[minute_ms, minute_ms + 1 min)` of the recent
    /// window become tier 1 points.
    pub async fn rollup_minute(&self, minute_ms: i64) -> Result<usize, IngestError> {
        let minute_ms = minute_ms - minute_ms.rem_euclid(MINUTE_MS);
        let series: Vec<RollupSeries> = {
            let s = self.state();
            let mut out = Vec::new();
            for (machine, m) in &s.machines {
                for (id, samples) in m.window.all() {
                    let values: Vec<f64> = samples
                        .iter()
                        .filter(|x| (minute_ms..minute_ms + MINUTE_MS).contains(&x.at_ms))
                        .map(|x| x.value)
                        .collect();
                    if values.is_empty() {
                        continue;
                    }
                    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
                    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
                    let avg = values.iter().sum::<f64>() / values.len() as f64;
                    out.push(RollupSeries {
                        machine_id: machine.clone(),
                        name: id.name.clone(),
                        unit: rackhand_proto::catalogue::by_name(&id.name).map(|m| m.unit).unwrap_or_default().into(),
                        label_set: id.labels.clone(),
                        points: vec![(minute_ms, [min, max, avg])],
                    });
                }
            }
            out
        };
        if series.is_empty() {
            return Ok(0);
        }
        Ok(self.inner.writer.send(WriteCmd::PutRollups { tier: 1, series }).await?.rows)
    }

    /// Every hour: tier 2 from tier 1 for `[hour_ms, hour_ms + 1 h)`, then the dirty ranges.
    pub async fn rollup_hour(&self, hour_ms: i64) -> Result<usize, IngestError> {
        let hour_ms = hour_ms - hour_ms.rem_euclid(HOUR_MS);
        Ok(self.inner.writer.send(WriteCmd::Rollup { tier: 2, from_ms: hour_ms, to_ms: hour_ms + HOUR_MS }).await?.rows)
    }

    /// A series over `[from_ms, to_ms]`: tier 0 and the recent window for ranges up to 2 days, tier 1's averages up to
    /// 30 days, tier 2's beyond.
    pub fn series(
        &self,
        machine: &str,
        metric: &str,
        labels: &BTreeMap<String, String>,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<(i64, f64)>, IngestError> {
        let span = to_ms - from_ms;
        let tier = if span <= TIER0_SPAN_MS {
            Tier::Raw
        } else if span <= TIER1_SPAN_MS {
            Tier::Minute
        } else {
            Tier::Hour
        };
        let label_set = labels_json(labels);
        let stored = self.inner.db.readers().with(|c| {
            let id: Option<i64> = c
                .query_row(
                    "SELECT id FROM metric_keys WHERE name = ?1 AND label_set = ?2",
                    rusqlite::params![metric, label_set],
                    |r| r.get(0),
                )
                .ok();
            let Some(metric_key_id) = id else { return Ok(Vec::new()) };
            let key = SeriesKey { machine_id: machine.to_string(), metric_key_id };
            rackhand_store::series::query::range(c, &key, tier, from_ms, to_ms)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
        })?;
        // tiers 1 and 2 hold min, max and avg: the avg is the series' value
        let value_col = if tier == Tier::Raw { 0 } else { 2 };
        let mut points: BTreeMap<i64, f64> = stored.into_iter().map(|(t, v)| (t, v[value_col])).collect();
        if tier == Tier::Raw {
            let id = SeriesId { name: metric.to_string(), labels: label_set };
            for s in self.window(machine, &id) {
                if (from_ms..=to_ms).contains(&s.at_ms) {
                    points.insert(s.at_ms, s.value);
                }
            }
        }
        Ok(points.into_iter().collect())
    }
}
