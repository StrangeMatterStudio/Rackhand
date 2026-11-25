//! Baselines (7.6.4): hour-of-day and hour-of-week buckets per machine and metric, updated hourly from tier 2 and
//! kept in `baseline_buckets` (through Ingest, its owner); each new tier 1 value is checked against them.

use std::collections::BTreeMap;

use rackhand_detect::baseline::{Baseline, Bucket, floor_for};
use rackhand_store::Row;
use rusqlite::types::Value;

use super::conditions::CondKey;
use super::forecasts::ingest_err;
use super::{Incidents, IncidentsError};
use crate::ingest::Tier;

const METRICS: [&str; 6] =
    ["cpu.busy_pct", "net.rx_bps", "net.tx_bps", "diskio.read_bps", "diskio.write_bps", "conn.outbound_count"];
const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;

/// One baseline and the newest tier 1 point it has checked.
#[derive(Debug, Clone)]
pub(crate) struct Learned {
    pub baseline: Baseline,
    pub checked_ms: i64,
}

fn bucket_row(machine: &str, metric_key_id: i64, kind: &str, index: usize, b: &Bucket) -> Row {
    Row::from([
        ("machine_id", Value::Text(machine.to_string())),
        ("metric_key_id", Value::Integer(metric_key_id)),
        ("kind", Value::Text(kind.into())),
        ("bucket", Value::Integer(index as i64)),
        ("mean", Value::Real(b.mean)),
        ("var", Value::Real(b.var)),
        ("n", Value::Integer(i64::from(b.n))),
        ("frozen_until_ms", b.frozen_until_ms.map(Value::Integer).unwrap_or(Value::Null)),
    ])
}

/// A `baseline_buckets` row with its series.
struct StoredBucket {
    machine: String,
    name: String,
    labels: String,
    kind: String,
    index: i64,
    bucket: Bucket,
}

/// The baselines stored when the hub starts. How long a machine has had data isn't stored; the hour-of-day buckets
/// say it (one update a day each), so learning resumes where it was.
pub(crate) fn load(db: &rackhand_store::Db, now_ms: i64) -> BTreeMap<CondKey, Learned> {
    let rows: Vec<StoredBucket> = db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT b.machine_id, mk.name, mk.label_set, b.kind, b.bucket, b.mean, b.var, b.n, b.frozen_until_ms
                 FROM baseline_buckets b JOIN metric_keys mk ON mk.id = b.metric_key_id",
            )?;
            s.query_map([], |r| {
                Ok(StoredBucket {
                    machine: r.get(0)?,
                    name: r.get(1)?,
                    labels: r.get(2)?,
                    kind: r.get(3)?,
                    index: r.get(4)?,
                    bucket: Bucket {
                        mean: r.get(5)?,
                        var: r.get(6)?,
                        n: r.get::<_, i64>(7)? as u32,
                        frozen_until_ms: r.get(8)?,
                    },
                })
            })?
            .collect()
        })
        .unwrap_or_default();
    let mut out: BTreeMap<CondKey, Learned> = BTreeMap::new();
    for StoredBucket { machine, name, labels, kind, index, bucket } in rows {
        let Some(floor) = floor_for(&name) else { continue };
        let key = CondKey::new(&machine, &format!("baseline.{name}"), &labels);
        let entry = out.entry(key).or_insert_with(|| Learned { baseline: Baseline::new(floor), checked_ms: now_ms });
        let list = if kind == "hour_of_week" { &mut entry.baseline.how } else { &mut entry.baseline.hod };
        if let Some(slot) = list.get_mut(index as usize) {
            *slot = bucket;
        }
    }
    for l in out.values_mut() {
        let days = l.baseline.hod.iter().map(|b| b.n).max().unwrap_or(0);
        if days > 0 {
            l.baseline.first_data_ms = Some(now_ms - i64::from(days) * DAY_MS);
        }
    }
    out
}

impl Incidents {
    /// The hourly update: each baseline metric's tier 2 average for the hour starting at `hour_ms`.
    pub async fn baseline_hourly(&self, hour_ms: i64, now_ms: i64) -> Result<(), IncidentsError> {
        let hour_ms = hour_ms - hour_ms.rem_euclid(HOUR_MS);
        let ingest = &self.inner.ingest;
        let mut rows = Vec::new();
        for metric in METRICS {
            let Some(floor) = floor_for(metric) else { continue };
            for (machine, labels, id) in ingest.stored_series(metric, Tier::Hour, hour_ms).map_err(ingest_err)? {
                let points =
                    ingest.tier_series(&machine, metric, &labels, Tier::Hour, hour_ms, hour_ms).map_err(ingest_err)?;
                let Some(avg) = points.first().map(|(_, v)| v.get(2).copied().unwrap_or(v[0])) else { continue };
                let key = CondKey::new(&machine, &format!("baseline.{metric}"), &labels);
                let mut eval = self.eval();
                let learned = eval
                    .baselines
                    .entry(key)
                    .or_insert_with(|| Learned { baseline: Baseline::new(floor), checked_ms: now_ms });
                learned.baseline.hourly_update(hour_ms, avg, now_ms);
                let hod = rackhand_detect::baseline::hour_of_day(hour_ms);
                let how = rackhand_detect::baseline::hour_of_week(hour_ms);
                rows.push(bucket_row(&machine, id, "hour_of_day", hod, &learned.baseline.hod[hod]));
                rows.push(bucket_row(&machine, id, "hour_of_week", how, &learned.baseline.how[how]));
            }
        }
        ingest.put_baselines(rows).await.map_err(ingest_err)
    }

    /// Checks each baseline's new tier 1 values; a deviation for 15 minutes opens a warning (never critical), and the
    /// baseline itself clears after 2 values back inside its band.
    pub async fn evaluate_baselines(&self, now_ms: i64) -> Result<(), IncidentsError> {
        // how long a baseline learns: the setting of `config/hub.toml` (7.8.1), read before the state is locked
        let learning_ms = crate::library::config::hub_or_default(&self.inner.db).baseline.learning_ms();
        let keys: Vec<CondKey> = self.eval().baselines.keys().cloned().collect();
        for key in keys {
            let Some(metric) = key.rule.strip_prefix("baseline.").map(str::to_string) else { continue };
            let Some(from) = self.eval().baselines.get(&key).map(|l| l.checked_ms + 1) else { continue };
            let points = self
                .inner
                .ingest
                .tier_series(&key.machine, &metric, &key.labels, Tier::Minute, from, now_ms)
                .map_err(ingest_err)?;
            if points.is_empty() {
                continue;
            }
            let severity = {
                let mut eval = self.eval();
                let Some(learned) = eval.baselines.get_mut(&key) else { continue };
                learned.baseline.learning_ms = learning_ms;
                let mut last = None;
                for (t, v) in &points {
                    last = learned.baseline.evaluate(*t, v.get(2).copied().unwrap_or(v[0]));
                    learned.checked_ms = *t;
                }
                last
            };
            let title = format!("{metric} far from its usual level");
            self.condition(key, severity, 1, &title, now_ms).await?;
        }
        Ok(())
    }
}
