//! Receiving reports (7.3.2): label tables, duplicates, the clock, staging before the ack, the recent window, the
//! latest facts and the replay limits.

use std::collections::BTreeMap;

use prost::Message;
use rackhand_proto::common::LabelEntry;
use rackhand_proto::probe::Report;
use rackhand_store::{Row, WriteCmd};
use rusqlite::types::Value;

use super::events::{Event, Severity};
use super::window::{SeriesId, WindowSample};
use super::{HISTORY_ONLY_AFTER_MS, Ingest, IngestError, LatestFacts, Machine, WINDOW_MS, labels_json, tick};
use crate::bus::{BusEvent, MachineId};

/// Committed seq ranges kept per machine and epoch (7.3.2).
const MAX_RANGES: usize = 64;
/// `probe.unknown_labels` at most this often per machine.
const UNKNOWN_LABELS_EVERY_MS: i64 = 3_600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// Stream 1: live reports.
    Live,
    /// Stream 2: replay batches.
    Replay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Receipt {
    /// Staged and committed; `ranges` are every committed seq range of the report's epoch, for the `Ack`.
    Staged { ranges: Vec<(u64, u64)> },
    /// Every report was already committed.
    Duplicate,
}

/// Merged, inclusive seq ranges.
#[derive(Debug, Clone, Default)]
pub struct Ranges(Vec<(u64, u64)>);

impl Ranges {
    pub fn contains(&self, seq: u64) -> bool {
        self.0.iter().any(|&(a, b)| (a..=b).contains(&seq))
    }

    /// Adds a range; returns the gap closed to stay within 64 ranges, if one was.
    pub fn add(&mut self, from: u64, to: u64) -> Option<(u64, u64)> {
        self.0.push((from, to));
        self.0.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.0.len());
        for &(a, b) in &self.0 {
            match merged.last_mut() {
                Some(last) if a <= last.1.saturating_add(1) => last.1 = last.1.max(b),
                _ => merged.push((a, b)),
            }
        }
        self.0 = merged;
        if self.0.len() > MAX_RANGES {
            let gap = (self.0[0].1 + 1, self.0[1].0 - 1);
            self.0[1].0 = self.0[0].0;
            self.0.remove(0);
            return Some(gap);
        }
        None
    }

    pub fn list(&self) -> Vec<(u64, u64)> {
        self.0.clone()
    }
}

/// A report ready to stage.
struct Prepared {
    report: Report,
    offset_ms: i64,
    row: Row,
}

impl Ingest {
    /// A probe's `Hello` (7.3.2): its whole label table for the epoch, kept for reports and compaction.
    pub async fn hello(&self, machine: &str, epoch: u64, table: &[LabelEntry]) -> Result<(), IngestError> {
        let rows = {
            let mut s = self.state();
            let m = s.machines.entry(machine.to_string()).or_default();
            let labels = m.labels.entry(epoch).or_default();
            table
                .iter()
                .map(|e| {
                    let set: BTreeMap<String, String> = e.labels.clone().into_iter().collect();
                    let row = Row::from([
                        ("machine_id", Value::Text(machine.to_string())),
                        ("epoch", Value::Integer(epoch as i64)),
                        ("labels_id", Value::Integer(e.id as i64)),
                        ("labels", Value::Text(labels_json(&set))),
                    ]);
                    labels.insert(e.id, set);
                    row
                })
                .collect::<Vec<_>>()
        };
        self.inner.writer.send(WriteCmd::PutProbeLabels(rows)).await?;
        Ok(())
    }

    /// The probe's `DataDropped`: reports it deleted unsent, closed in the received ranges (7.3.2).
    pub async fn dropped(&self, machine: &str, epoch: u64, from_seq: u64, to_seq: u64) -> Result<(), IngestError> {
        let gap = self
            .state()
            .machines
            .entry(machine.to_string())
            .or_default()
            .received
            .entry(epoch)
            .or_default()
            .add(from_seq, to_seq);
        let mut events = vec![Event::machine(
            machine,
            "probe.data_gap",
            Severity::Info,
            serde_json::json!({ "epoch": epoch, "from_seq": from_seq, "to_seq": to_seq }),
        )];
        if let Some((a, b)) = gap {
            events.push(Event::machine(
                machine,
                "probe.data_gap",
                Severity::Info,
                serde_json::json!({ "epoch": epoch, "from_seq": a, "to_seq": b }),
            ));
        }
        self.raise_events(events).await
    }

    /// Stages reports from one frame (a live report, or a replay batch of `frame_len` bytes) and commits them before
    /// returning the ack. Duplicates are dropped.
    pub async fn receive(
        &self,
        machine: &str,
        stream: Stream,
        reports: Vec<Report>,
        frame_len: usize,
        received_at_ms: i64,
    ) -> Result<Receipt, IngestError> {
        let mut events = Vec::new();
        let prepared = {
            let mut s = self.state();
            if stream == Stream::Replay {
                let rate = self.inner.limits.hub_bps;
                s.hub_replay.charge(rate, frame_len, received_at_ms);
            }
            s.staging_bytes += frame_len as u64;
            let m = s.machines.entry(machine.to_string()).or_default();
            if stream == Stream::Replay {
                m.replay.charge(self.inner.limits.probe_bps, frame_len, received_at_ms);
            }
            let mut prepared = Vec::new();
            for report in reports {
                let epoch = report.epoch;
                if m.received.get(&epoch).is_some_and(|r| r.contains(report.seq)) {
                    continue;
                }
                let labels = m.labels.entry(epoch).or_default();
                for e in &report.label_sets {
                    labels.insert(e.id, e.labels.clone().into_iter().collect());
                }
                if stream == Stream::Live && m.clock.observe(received_at_ms - report.sampled_at_ms) {
                    let offset = m.clock.offset().unwrap_or(0);
                    events.push(Event::machine(
                        machine,
                        "clock_skew",
                        Severity::Warning,
                        serde_json::json!({ "offset_ms": offset }),
                    ));
                }
                let offset_ms = m.clock.offset().unwrap_or(0);
                let frame = rackhand_proto::zstd::compress(&report.encode_to_vec())
                    .map_err(|e| IngestError::Frame(e.to_string()))?;
                let row = Row::from([
                    ("machine_id", Value::Text(machine.to_string())),
                    ("epoch", Value::Integer(epoch as i64)),
                    ("seq", Value::Integer(report.seq as i64)),
                    ("received_at_ms", Value::Integer(received_at_ms)),
                    ("offset_ms", Value::Integer(offset_ms)),
                    ("frame", Value::Blob(frame)),
                ]);
                prepared.push(Prepared { report, offset_ms, row });
            }
            prepared
        };
        if prepared.is_empty() {
            self.raise_events(events).await?;
            return Ok(Receipt::Duplicate);
        }
        // Queue every row, then wait for each commit: commands commit in the order they were queued.
        let mut commits = Vec::with_capacity(prepared.len());
        for p in &prepared {
            commits.push(self.inner.writer.enqueue(WriteCmd::StageReport(p.row.clone())).await?);
        }
        for c in commits {
            c.await.map_err(|_| rackhand_store::StoreError::WriterStopped)??;
        }
        let ranges = {
            let mut s = self.state();
            let m = s.machines.entry(machine.to_string()).or_default();
            for p in &prepared {
                if let Some((a, b)) = m.received.entry(p.report.epoch).or_default().add(p.report.seq, p.report.seq) {
                    events.push(Event::machine(
                        machine,
                        "probe.data_gap",
                        Severity::Info,
                        serde_json::json!({ "epoch": p.report.epoch, "from_seq": a, "to_seq": b }),
                    ));
                }
                if let Some(e) = add_to_window(m, machine, &p.report, p.offset_ms, received_at_ms) {
                    events.push(e);
                }
                if stream == Stream::Live {
                    keep_latest(m, &p.report, p.offset_ms);
                }
            }
            m.window.prune(received_at_ms - WINDOW_MS);
            let last = prepared.last().map(|p| p.report.epoch).unwrap_or_default();
            m.received.get(&last).map(|r| r.list()).unwrap_or_default()
        };
        self.raise_events(events).await?;
        if let Ok(id) = machine.parse::<ulid::Ulid>() {
            self.inner.bus.publish(BusEvent::ReportIngested { machine: MachineId(id.to_bytes()) }).await;
        }
        Ok(Receipt::Staged { ranges })
    }

    /// Whether stream 2 may be read for this probe now: within 2 MB/s for it and 20 MB/s across the hub, staging
    /// under 512 MB, and the disk not nearly full (7.3.2, E32). Stream 1 is never held back.
    pub fn replay_allowed(&self, machine: &str, now_ms: i64) -> bool {
        let limits = self.inner.limits;
        let s = self.state();
        let probe_ok = s.machines.get(machine).is_none_or(|m| m.replay.available(limits.probe_bps, now_ms) > 0.0);
        !s.disk_low
            && probe_ok
            && s.hub_replay.available(limits.hub_bps, now_ms) > 0.0
            && s.staging_bytes < limits.staging_bytes
    }
}

/// Adds a report's samples to the window at their corrected tick; returns `probe.unknown_labels` when samples were
/// dropped for an id the table doesn't hold (at most hourly).
fn add_to_window(m: &mut Machine, machine: &str, r: &Report, offset_ms: i64, received_at_ms: i64) -> Option<Event> {
    let at_ms = tick(r.sampled_at_ms + offset_ms, m.interval_ms);
    let history_only = received_at_ms - at_ms > HISTORY_ONLY_AFTER_MS;
    let mut unknown = 0;
    for sample in &r.vitals {
        let (Some(metric), Some(labels)) = (
            rackhand_proto::catalogue::by_id(sample.metric),
            m.labels.get(&r.epoch).and_then(|t| t.get(&sample.labels_id)),
        ) else {
            unknown += 1;
            continue;
        };
        m.window.add(SeriesId::new(metric.name, labels), WindowSample { at_ms, value: sample.value, history_only });
    }
    if unknown == 0 || received_at_ms - m.unknown_labels_reported_ms < UNKNOWN_LABELS_EVERY_MS {
        return None;
    }
    m.unknown_labels_reported_ms = received_at_ms;
    Some(Event::machine(machine, "probe.unknown_labels", Severity::Info, serde_json::json!({ "dropped": unknown })))
}

/// The newest live report's services and containers, and the last update summary sent.
fn keep_latest(m: &mut Machine, r: &Report, offset_ms: i64) {
    let at = r.sampled_at_ms + offset_ms;
    if m.latest.as_ref().is_some_and(|l| l.reported_at_ms > at) {
        return;
    }
    let updates = r.updates.clone().or_else(|| m.latest.as_ref().and_then(|l| l.updates.clone()));
    m.latest = Some(LatestFacts {
        reported_at_ms: at,
        services: r.services.clone(),
        containers: r.containers.clone(),
        updates,
    });
}
