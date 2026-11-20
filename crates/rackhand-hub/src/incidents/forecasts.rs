//! Forecasts (7.6.2): disk fill from the 6-hour tier 1 fit and the 7-day tier 2 fit, and memory growth since the
//! last boot. A forecast clears after 2 recomputations without it (7.5.2).

use rackhand_detect::forecast::{disk_fill, fit_line, memory_growth};
use rackhand_detect::samples::Sample;

use super::conditions::CondKey;
use super::{Incidents, IncidentsError};
use crate::ingest::Tier;

/// How often forecasts are recomputed.
pub const FORECAST_EVERY_MS: i64 = 5 * 60_000;
const HOUR_MS: i64 = 3_600_000;
const CLEAR_AFTER: u32 = 2;

/// A tier's averages as samples.
fn avgs(points: &[(i64, Vec<f64>)]) -> Vec<Sample> {
    points.iter().map(|(t, v)| Sample { at_ms: *t, value: v.get(2).copied().unwrap_or(v[0]) }).collect()
}

impl Incidents {
    /// One recomputation of every forecast.
    pub async fn evaluate_forecasts(&self, now_ms: i64) -> Result<(), IncidentsError> {
        self.eval().last_forecast_ms = now_ms;
        let ingest = &self.inner.ingest;
        let disks = ingest.stored_series("disk.used_bytes", Tier::Minute, now_ms - 6 * HOUR_MS).map_err(ingest_err)?;
        for (machine, labels, _) in disks {
            let used_6h = avgs(
                &ingest
                    .tier_series(&machine, "disk.used_bytes", &labels, Tier::Minute, now_ms - 6 * HOUR_MS, now_ms)
                    .map_err(ingest_err)?,
            );
            let used_7d = avgs(
                &ingest
                    .tier_series(&machine, "disk.used_bytes", &labels, Tier::Hour, now_ms - 168 * HOUR_MS, now_ms)
                    .map_err(ingest_err)?,
            );
            let total = avgs(
                &ingest
                    .tier_series(&machine, "disk.total_bytes", &labels, Tier::Minute, now_ms - 6 * HOUR_MS, now_ms)
                    .map_err(ingest_err)?,
            );
            let (Some(used), Some(capacity)) = (used_6h.last(), total.last()) else { continue };
            let fits: Vec<_> = [fit_line(&used_6h), fit_line(&used_7d)].into_iter().flatten().collect();
            let forecast = disk_fill(capacity.value, used.value, &fits);
            let mount: String = serde_json::from_str::<std::collections::BTreeMap<String, String>>(&labels)
                .ok()
                .and_then(|l| l.get("mount").cloned())
                .unwrap_or_default();
            let title = forecast.map(|f| f.summary(&mount)).unwrap_or_default();
            let key = CondKey::new(&machine, "disk.fill", &labels);
            self.condition(key, forecast.map(|f| f.severity), CLEAR_AFTER, &title, now_ms).await?;
        }
        let memory = ingest.stored_series("mem.used_pct", Tier::Minute, now_ms - HOUR_MS).map_err(ingest_err)?;
        for (machine, labels, _) in memory {
            let uptime = ingest
                .tier_series(&machine, "uptime_s", "{}", Tier::Minute, now_ms - HOUR_MS, now_ms)
                .map_err(ingest_err)?;
            let Some((at, up)) = uptime.last().map(|(t, v)| (*t, v.get(2).copied().unwrap_or(v[0]))) else { continue };
            let boot_ms = at - (up * 1000.0) as i64;
            let used = avgs(
                &ingest
                    .tier_series(&machine, "mem.used_pct", &labels, Tier::Minute, boot_ms, now_ms)
                    .map_err(ingest_err)?,
            );
            let key = CondKey::new(&machine, "mem.growth", &labels);
            let title = "Memory use grows toward 95% within 7 days";
            self.condition(key, memory_growth(&used, boot_ms), CLEAR_AFTER, title, now_ms).await?;
        }
        Ok(())
    }
}

pub(crate) fn ingest_err(e: crate::ingest::IngestError) -> IncidentsError {
    IncidentsError::Ingest(e.to_string())
}
