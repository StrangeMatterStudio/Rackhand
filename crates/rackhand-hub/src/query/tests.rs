use std::collections::BTreeMap;
use std::sync::Arc;

use rackhand_proto::common::LabelEntry;
use rackhand_proto::probe::{Report, Sample};
use rackhand_store::Db;

use super::vitals::{MAX_POINTS, vitals};
use crate::bus::Bus;
use crate::ingest::{DiskSpace, Ingest, Stream};

const M1: &str = "01JD0000000000000000000001";
const T0: i64 = 1_795_068_000_000;

#[derive(Debug)]
struct Roomy;

impl DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

async fn ingest(name: &str) -> Ingest {
    let dir = std::env::temp_dir().join(format!("rackhand-query-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ingest = Ingest::new(Arc::new(Db::open(&dir.join("hub.db")).unwrap()), Bus::new(), Arc::new(Roomy));
    ingest.hello(M1, 1, &[LabelEntry::default()]).await.unwrap();
    ingest
}

async fn report(ingest: &Ingest, seq: u64, at: i64, value: f64) {
    let r = Report {
        epoch: 1,
        seq,
        sampled_at_ms: at,
        vitals: vec![Sample { metric: 1, labels_id: 0, value }],
        ..Default::default()
    };
    ingest.receive(M1, Stream::Live, vec![r], 100, at).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn vitals_merge_window_and_chunks_without_duplicates() {
    let ingest = ingest("merge").await;
    // 20 samples compacted into tier 0, then 10 more only in the recent window; both hold the 20th
    for i in 0..20u64 {
        report(&ingest, i + 1, T0 + i as i64 * 15_000, i as f64).await;
    }
    ingest.compact().await.unwrap();
    for i in 20..30u64 {
        report(&ingest, i + 1, T0 + i as i64 * 15_000, i as f64).await;
    }
    let points = vitals(&ingest, M1, "cpu.busy_pct", &BTreeMap::new(), T0, T0 + 3_600_000);
    let want: Vec<(i64, f64)> = (0..30).map(|i| (T0 + i * 15_000, i as f64)).collect();
    assert_eq!(points, want, "sorted, one point per time");
    // a long range is cut to at most 2000 points
    for i in 30..2_500u64 {
        report(&ingest, i + 1, T0 + i as i64 * 15_000, 1.0).await;
    }
    ingest.compact().await.unwrap();
    let many = vitals(&ingest, M1, "cpu.busy_pct", &BTreeMap::new(), T0, T0 + 2 * 86_400_000);
    assert!(many.len() <= MAX_POINTS && many.len() > 1_000, "{} points", many.len());
}

#[tokio::test(flavor = "multi_thread")]
async fn vitals_visible_before_compaction() {
    let ingest = ingest("fresh").await;
    report(&ingest, 1, T0, 42.0).await;
    // staged a moment ago, not compacted
    let points = vitals(&ingest, M1, "cpu.busy_pct", &BTreeMap::new(), T0 - 60_000, T0 + 1_000);
    assert_eq!(points, vec![(T0, 42.0)]);
}
