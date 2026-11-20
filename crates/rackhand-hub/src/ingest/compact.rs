//! Compaction (7.3.2) and rebuilding the recent window on start (7.4.1, E44).

use std::collections::{BTreeMap, HashMap};

use prost::Message;
use rackhand_proto::probe::Report;
use rackhand_store::WriteCmd;
use rackhand_store::series::chunk::{SeriesKey, Tier};
use rackhand_store::series::compact::{Compaction, LabelRow, SeriesPoints};

use super::window::{SeriesId, WindowSample};
use super::{DEFAULT_INTERVAL_MS, Ingest, IngestError, WINDOW_MS, labels_json, tick};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompactStats {
    pub machines: usize,
    pub reports: usize,
    pub points: usize,
}

struct Staged {
    epoch: i64,
    seq: i64,
    offset_ms: i64,
    frame: Vec<u8>,
}

impl Ingest {
    /// Moves every staged report into chunk rows: one transaction per machine, which also deletes its staged rows.
    pub async fn compact(&self) -> Result<CompactStats, IngestError> {
        let _one = self.inner.compacting.lock().await;
        let staged = self.inner.db.readers().with(|c| {
            let mut stmt = c.prepare(
                "SELECT machine_id, epoch, seq, offset_ms, frame FROM report_staging ORDER BY machine_id, epoch, seq",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    Staged { epoch: r.get(1)?, seq: r.get(2)?, offset_ms: r.get(3)?, frame: r.get(4)? },
                ))
            })?;
            let mut by_machine: BTreeMap<String, Vec<Staged>> = BTreeMap::new();
            for row in rows {
                let (m, s) = row?;
                by_machine.entry(m).or_default().push(s);
            }
            Ok(by_machine)
        })?;
        let mut stats = CompactStats::default();
        for (machine, reports) in staged {
            let compaction = self.prepare(&machine, &reports)?;
            stats.reports += reports.len();
            let ack = self.inner.writer.send(WriteCmd::CompactStaged(compaction)).await?;
            stats.points += ack.rows;
            stats.machines += 1;
        }
        let left: i64 =
            self.inner.db.readers().with(|c| {
                c.query_row("SELECT coalesce(sum(length(frame)), 0) FROM report_staging", [], |r| r.get(0))
            })?;
        self.state().staging_bytes = left.max(0) as u64;
        Ok(stats)
    }

    /// Decodes one machine's staged reports in epoch and seq order (so each label set is defined before it is used)
    /// and places their points at the corrected tick.
    fn prepare(&self, machine: &str, reports: &[Staged]) -> Result<Compaction, IngestError> {
        let mut labels: HashMap<(i64, u32), BTreeMap<String, String>> = HashMap::new();
        self.inner.db.readers().with(|c| {
            let mut stmt = c.prepare("SELECT epoch, labels_id, labels FROM probe_labels WHERE machine_id = ?1")?;
            for row in
                stmt.query_map([machine], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?)))?
            {
                let (epoch, id, set) = row?;
                labels.insert((epoch, id as u32), serde_json::from_str(&set).unwrap_or_default());
            }
            Ok(())
        })?;
        let interval = self.state().machines.get(machine).map_or(DEFAULT_INTERVAL_MS, |m| m.interval_ms);
        let mut new_labels = Vec::new();
        let mut series: BTreeMap<(&'static str, &'static str, String), BTreeMap<i64, f64>> = BTreeMap::new();
        for s in reports {
            let bytes =
                rackhand_proto::zstd::decompress_bounded(&s.frame).map_err(|e| IngestError::Frame(format!("{e:?}")))?;
            let report = Report::decode(bytes.as_slice()).map_err(|e| IngestError::Frame(e.to_string()))?;
            for e in &report.label_sets {
                let set: BTreeMap<String, String> = e.labels.clone().into_iter().collect();
                new_labels.push(LabelRow { epoch: s.epoch, labels_id: e.id as i64, labels: labels_json(&set) });
                labels.insert((s.epoch, e.id), set);
            }
            let at = tick(report.sampled_at_ms + s.offset_ms, interval);
            for sample in &report.vitals {
                let (Some(metric), Some(set)) =
                    (rackhand_proto::catalogue::by_id(sample.metric), labels.get(&(s.epoch, sample.labels_id)))
                else {
                    continue;
                };
                series.entry((metric.name, metric.unit, labels_json(set))).or_default().insert(at, sample.value);
            }
        }
        Ok(Compaction {
            machine_id: machine.to_string(),
            staged: reports.iter().map(|s| (s.epoch, s.seq)).collect(),
            labels: new_labels,
            series: series
                .into_iter()
                .map(|((name, unit, label_set), points)| SeriesPoints {
                    name: name.into(),
                    unit: unit.into(),
                    label_set,
                    points: points.into_iter().collect(),
                })
                .collect(),
        })
    }

    /// Fills the recent window with the last 35 minutes of tier 0 (after compaction, staging is in tier 0).
    pub(super) fn rebuild_window(&self, now_ms: i64) -> Result<(), IngestError> {
        let cutoff = now_ms - WINDOW_MS;
        let found = self.inner.db.readers().with(|c| {
            let mut stmt = c.prepare(
                "SELECT DISTINCT sc.machine_id, sc.metric_key_id, mk.name, mk.label_set FROM series_chunks sc
                 JOIN metric_keys mk ON mk.id = sc.metric_key_id WHERE sc.tier = 0 AND sc.end_ms >= ?1",
            )?;
            let keys: Vec<(String, i64, String, String)> = stmt
                .query_map([cutoff], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<Result<_, _>>()?;
            let mut out = Vec::new();
            for (machine, metric_key_id, name, label_set) in keys {
                let key = SeriesKey { machine_id: machine.clone(), metric_key_id };
                let points = rackhand_store::series::query::range(c, &key, Tier::Raw, cutoff, now_ms)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                out.push((machine, SeriesId { name, labels: label_set }, points));
            }
            Ok(out)
        })?;
        let mut s = self.state();
        for (machine, id, points) in found {
            let m = s.machines.entry(machine).or_default();
            for (at_ms, values) in points {
                m.window.add(id.clone(), WindowSample { at_ms, value: values[0], history_only: false });
            }
            m.window.prune(cutoff);
        }
        Ok(())
    }
}
