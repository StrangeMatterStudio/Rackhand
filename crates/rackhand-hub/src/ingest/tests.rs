use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rackhand_proto::common::LabelEntry;
use rackhand_proto::probe::{Report, Sample, ServiceState, UpdateSummary};
use rackhand_store::Db;

use super::*;
use crate::bus::Bus;

const M1: &str = "01JD0000000000000000000001";
const M2: &str = "01JD0000000000000000000002";
/// A tick of the 15 s grid, at the top of an hour.
const T0: i64 = 1_795_068_000_000;
const MIN: i64 = 60_000;

#[derive(Debug)]
struct Disk(AtomicU64);

impl Disk {
    fn set(&self, free: f64) {
        self.0.store(free.to_bits(), Ordering::Relaxed);
    }
}

impl DiskSpace for Disk {
    fn free_fraction(&self) -> f64 {
        f64::from_bits(self.0.load(Ordering::Relaxed))
    }
}

struct Env {
    db: Arc<Db>,
    disk: Arc<Disk>,
    path: std::path::PathBuf,
}

impl Env {
    fn new(name: &str) -> Env {
        let dir = std::env::temp_dir().join(format!("rackhand-ingest-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hub.db");
        Env { db: Arc::new(Db::open(&path).unwrap()), disk: Arc::new(Disk(AtomicU64::new(0.5f64.to_bits()))), path }
    }

    fn ingest(&self) -> Ingest {
        Ingest::new(self.db.clone(), Bus::new(), self.disk.clone())
    }

    /// The database opened again, as after a restart.
    fn reopen(self) -> Env {
        let Env { db, disk, path } = self;
        drop(db);
        Env { db: Arc::new(Db::open(&path).unwrap()), disk, path }
    }

    fn count(&self, sql: &str) -> i64 {
        self.db.readers().with(|c| c.query_row(sql, [], |r| r.get(0))).unwrap()
    }

    fn events(&self, kind: &str) -> Vec<(String, String)> {
        self.db
            .readers()
            .with(|c| {
                let mut s = c.prepare("SELECT severity, coalesce(machine_id, '') FROM events WHERE kind = ?1")?;
                s.query_map([kind], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
            })
            .unwrap()
    }
}

fn no_labels() -> Vec<LabelEntry> {
    vec![LabelEntry { id: 0, labels: BTreeMap::new() }]
}

/// A live report with one `cpu.busy_pct` sample (label id 0, the empty set).
fn report(epoch: u64, seq: u64, sampled_at_ms: i64, cpu: f64) -> Report {
    Report {
        epoch,
        seq,
        sampled_at_ms,
        vitals: vec![Sample { metric: 1, labels_id: 0, value: cpu }],
        ..Default::default()
    }
}

fn cpu() -> SeriesId {
    SeriesId::new("cpu.busy_pct", &BTreeMap::new())
}

async fn hello(ingest: &Ingest, machine: &str, epoch: u64) {
    ingest.hello(machine, epoch, &no_labels()).await.unwrap();
}

async fn live(ingest: &Ingest, machine: &str, r: Report, received_at_ms: i64) -> Receipt {
    ingest.receive(machine, Stream::Live, vec![r], 1_000, received_at_ms).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn ack_follows_commit() {
    let env = Env::new("ack");
    let ingest = env.ingest();
    hello(&ingest, M1, 9).await;
    let receipt = live(&ingest, M1, report(9, 1, T0, 5.0), T0).await;
    // The ack is given only once the staging row is committed, so a reader sees it the moment the ack exists.
    let staged = env.count("SELECT count(*) FROM report_staging WHERE seq = 1");
    assert_eq!((receipt, staged), (Receipt::Staged { ranges: vec![(1, 1)] }, 1));
    live(&ingest, M1, report(9, 2, T0 + 15_000, 6.0), T0 + 15_000).await;
    let again = live(&ingest, M1, report(9, 1, T0, 5.0), T0 + 16_000).await;
    assert_eq!(again, Receipt::Duplicate, "a seq already committed is dropped");
    let receipt = live(&ingest, M1, report(9, 4, T0 + 45_000, 6.0), T0 + 45_000).await;
    assert_eq!(receipt, Receipt::Staged { ranges: vec![(1, 2), (4, 4)] }, "every committed range");
}

#[tokio::test(flavor = "multi_thread")]
async fn compaction_moves_staged_points_into_open_chunks() {
    let env = Env::new("compact");
    let ingest = env.ingest();
    for m in [M1, M2] {
        hello(&ingest, m, 3).await;
        for i in 0..10u64 {
            let t = T0 + i as i64 * 15_000;
            live(&ingest, m, report(3, i + 1, t, i as f64), t + 200).await;
        }
    }
    let compacted = ingest.compact().await.unwrap();
    assert_eq!(compacted, CompactStats { machines: 2, reports: 20, points: 20 }, "one transaction per machine");
    assert_eq!(env.count("SELECT count(*) FROM report_staging"), 0);
    assert_eq!(env.count("SELECT count(*) FROM series_chunks WHERE tier = 0 AND closed = 0"), 2);
    assert_eq!(env.count("SELECT sum(count) FROM series_chunks"), 20);
    let key = rackhand_store::series::chunk::SeriesKey {
        machine_id: M1.into(),
        metric_key_id: env.count("SELECT id FROM metric_keys WHERE name = 'cpu.busy_pct'"),
    };
    let points = env
        .db
        .readers()
        .with(|c| {
            Ok(rackhand_store::series::query::range(c, &key, Tier::Raw, T0, T0 + 3_600_000)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e))))
        })
        .unwrap()
        .unwrap();
    let want: Vec<(i64, Vec<f64>)> = (0..10).map(|i| (T0 + i * 15_000, vec![i as f64])).collect();
    assert_eq!(points, want, "at their tick, in order");
}

#[tokio::test(flavor = "multi_thread")]
async fn startup_compacts_leftover_staging() {
    let env = Env::new("leftover");
    {
        let ingest = env.ingest();
        hello(&ingest, M1, 4).await;
        for i in 0..5u64 {
            let t = T0 + i as i64 * 15_000;
            live(&ingest, M1, report(4, i + 1, t, 1.0), t).await;
        }
        // the hub stops without compacting
    }
    let env = env.reopen();
    assert_eq!(env.count("SELECT count(*) FROM report_staging"), 5);
    let ingest = env.ingest();
    ingest.start(T0 + 90_000).await.unwrap();
    assert_eq!(env.count("SELECT count(*) FROM report_staging"), 0);
    assert_eq!(env.count("SELECT sum(count) FROM series_chunks WHERE machine_id = '01JD0000000000000000000001'"), 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn recent_window_keeps_35_minutes() {
    let env = Env::new("window");
    let ingest = env.ingest();
    hello(&ingest, M1, 1).await;
    for i in 0..41u64 {
        let t = T0 + i as i64 * MIN;
        live(&ingest, M1, report(1, i + 1, t, i as f64), t).await;
    }
    let w = ingest.window(M1, &cpu());
    let now = T0 + 40 * MIN;
    assert_eq!(w.first().map(|s| s.at_ms), Some(now - 35 * MIN), "nothing older than 35 minutes");
    assert_eq!(w.len(), 36);
    assert!(w.iter().all(|s| !s.history_only));
}

#[tokio::test(flavor = "multi_thread")]
async fn window_rebuilt_from_staging_and_tier0_on_start() {
    let env = Env::new("rebuild");
    {
        let ingest = env.ingest();
        hello(&ingest, M1, 2).await;
        for i in 0..40u64 {
            let t = T0 + i as i64 * MIN;
            live(&ingest, M1, report(2, i + 1, t, i as f64), t).await;
            if i == 25 {
                // the first 26 minutes are compacted into tier 0, the rest stay staged
                ingest.compact().await.unwrap();
            }
        }
    }
    let env = env.reopen();
    let ingest = env.ingest();
    let now = T0 + 39 * MIN + 30_000;
    ingest.start(now).await.unwrap();
    let w = ingest.window(M1, &cpu());
    let want: Vec<i64> = (5..40).map(|i| T0 + i * MIN).collect();
    assert_eq!(w.iter().map(|s| s.at_ms).collect::<Vec<_>>(), want, "the last 35 minutes");
    assert_eq!(w.last().unwrap().value, 39.0);
}

#[tokio::test(flavor = "multi_thread")]
async fn clock_offset_is_median_of_last_20_live_reports() {
    let env = Env::new("clock");
    let ingest = env.ingest();
    hello(&ingest, M1, 5).await;
    let ahead = 3 * 3_600_000;
    for i in 0..25u64 {
        let received = T0 + i as i64 * 15_000;
        // the probe's clock is 3 h ahead, with a little jitter; one report is wildly off
        let jitter = if i == 7 { 900_000 } else { (i as i64 % 3) * 40 };
        live(&ingest, M1, report(5, i + 1, received + ahead + jitter, i as f64), received).await;
    }
    let offset = ingest.clock_offset(M1).unwrap();
    assert!((-ahead - 40..=-ahead).contains(&offset), "median offset {offset}");
    // every report lands at its receive time, except the one sampled 15 minutes off, which lands 15 minutes off
    let w = ingest.window(M1, &cpu());
    let at = |v: f64| w.iter().find(|s| s.value == v).map(|s| s.at_ms);
    assert_eq!(at(24.0), Some(T0 + 24 * 15_000), "placed at receive time");
    assert_eq!(at(3.0), Some(T0 + 3 * 15_000));
    assert_eq!(at(7.0), Some(T0 + 7 * 15_000 + 900_000));
    ingest.compact().await.unwrap();
    let id = env.count("SELECT id FROM metric_keys WHERE name = 'cpu.busy_pct'");
    let key = rackhand_store::series::chunk::SeriesKey { machine_id: M1.into(), metric_key_id: id };
    let stored = env
        .db
        .readers()
        .with(|c| {
            Ok(rackhand_store::series::query::range(c, &key, Tier::Raw, T0 + 24 * 15_000, T0 + 24 * 15_000)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e))))
        })
        .unwrap()
        .unwrap();
    assert_eq!(stored, vec![(T0 + 24 * 15_000, vec![24.0])], "stored at the corrected time too");
}

#[tokio::test(flavor = "multi_thread")]
async fn offset_over_30s_raises_clock_skew() {
    let env = Env::new("skew");
    let ingest = env.ingest();
    hello(&ingest, M1, 6).await;
    for i in 0..10u64 {
        let received = T0 + i as i64 * 15_000;
        live(&ingest, M1, report(6, i + 1, received - 45_000, 1.0), received).await;
    }
    assert_eq!(env.events("clock_skew"), vec![("warning".to_string(), M1.to_string())], "one warning");
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_over_limits_stops_reading_stream2() {
    let env = Env::new("replay");
    let ingest = env.ingest().with_limits(ReplayLimits { staging_bytes: 3_000_000, ..ReplayLimits::default() });
    assert_eq!(
        ReplayLimits::default(),
        ReplayLimits { probe_bps: 2_000_000, hub_bps: 20_000_000, staging_bytes: 512_000_000 }
    );
    hello(&ingest, M1, 7).await;
    let old = T0 - 3_600_000;
    // per probe: 2.1 MB of replay in one second
    let batch = |seq: u64| vec![report(7, seq, old + seq as i64 * 15_000, 1.0)];
    ingest.receive(M1, Stream::Replay, batch(1), 2_100_000, T0).await.unwrap();
    assert!(!ingest.replay_allowed(M1, T0 + 10), "over 2 MB/s for this probe");
    assert!(ingest.replay_allowed(M2, T0 + 10), "another probe still replays");
    let receipt = live(&ingest, M1, report(7, 100, T0 + 20, 1.0), T0 + 20).await;
    assert!(matches!(receipt, Receipt::Staged { .. }), "stream 1 continues");
    assert!(ingest.replay_allowed(M1, T0 + 1_100), "the probe's budget refills");
    // across the hub: 20 MB/s
    let probes: Vec<String> = (0..11).map(|i| format!("01JD00000000000000000001{i:02}")).collect();
    for p in &probes[..10] {
        hello(&ingest, p, 7).await;
        ingest.receive(p, Stream::Replay, batch(1), 1_900_000, T0 + 2_000).await.unwrap();
    }
    hello(&ingest, &probes[10], 7).await;
    ingest.receive(&probes[10], Stream::Replay, batch(1), 1_900_000, T0 + 2_000).await.unwrap();
    assert!(!ingest.replay_allowed(&probes[0], T0 + 2_010), "over 20 MB/s across the hub");
    // staging: past its limit no probe replays until compaction empties it
    assert!(!ingest.replay_allowed(M2, T0 + 10_000), "staging over its limit");
    ingest.compact().await.unwrap();
    assert!(ingest.replay_allowed(M2, T0 + 10_000), "staging emptied");
}

#[tokio::test(flavor = "multi_thread")]
async fn backfill_into_rolled_up_range_marks_dirty() {
    let env = Env::new("dirty");
    let ingest = env.ingest();
    hello(&ingest, M1, 8).await;
    for i in 0..8u64 {
        let t = T0 + i as i64 * 15_000;
        live(&ingest, M1, report(8, i + 10, t, 1.0), t).await;
    }
    ingest.compact().await.unwrap();
    // the first minute is rolled up (a tier 1 row stands in for the rollup task)
    let id = env.count("SELECT id FROM metric_keys WHERE name = 'cpu.busy_pct'");
    let key = rackhand_store::series::chunk::SeriesKey { machine_id: M1.into(), metric_key_id: id };
    {
        let conn = rusqlite::Connection::open(&env.path).unwrap();
        rackhand_store::series::chunk::append(
            &conn,
            &key,
            Tier::Minute,
            None,
            &[T0],
            &[vec![1.0], vec![1.0], vec![1.0]],
        )
        .unwrap();
    }
    // a replayed sample for 15 s into that minute, from before the probe's buffer was sent
    let late = Report { epoch: 8, seq: 2, sampled_at_ms: T0 + 22_000, ..report(8, 2, 0, 9.0) };
    ingest.receive(M1, Stream::Replay, vec![late], 500, T0 + 125_000).await.unwrap();
    ingest.compact().await.unwrap();
    let dirty: (i64, i64, i64) = env
        .db
        .readers()
        .with(|c| {
            c.query_row("SELECT tier, from_ms, to_ms FROM rollup_dirty", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        })
        .unwrap();
    assert_eq!(dirty, (1, T0, T0 + MIN - 1));
}

#[tokio::test(flavor = "multi_thread")]
async fn replayed_sample_older_than_10_min_flagged_history_only() {
    let env = Env::new("history");
    let ingest = env.ingest();
    hello(&ingest, M1, 9).await;
    let now = T0 + 30 * MIN;
    live(&ingest, M1, report(9, 50, now, 1.0), now).await;
    let replay = vec![report(9, 10, now - 15 * MIN, 2.0), report(9, 11, now - 5 * MIN, 3.0)];
    ingest.receive(M1, Stream::Replay, replay, 800, now + 100).await.unwrap();
    let w = ingest.window(M1, &cpu());
    let flags: Vec<(i64, bool)> = w.iter().map(|s| (s.at_ms, s.history_only)).collect();
    assert_eq!(flags, vec![(now - 15 * MIN, true), (now - 5 * MIN, false), (now, false)]);
}

#[tokio::test(flavor = "multi_thread")]
async fn disk_below_2_percent_stops_replay_and_new_jobs() {
    let env = Env::new("disk");
    let ingest = env.ingest();
    hello(&ingest, M1, 10).await;
    env.disk.set(0.019);
    ingest.check_disk().await.unwrap();
    assert!(!ingest.replay_allowed(M1, T0), "stream 2 stops");
    assert!(!ingest.accepting_jobs(), "new jobs stop");
    let receipt = live(&ingest, M1, report(10, 1, T0, 1.0), T0).await;
    assert!(matches!(receipt, Receipt::Staged { .. }), "live ingest continues");
    ingest.check_disk().await.unwrap();
    assert_eq!(env.events("hub.disk_low"), vec![("critical".to_string(), String::new())], "one critical event");
    env.disk.set(0.05);
    ingest.check_disk().await.unwrap();
    assert!(ingest.replay_allowed(M1, T0 + 5_000) && ingest.accepting_jobs(), "both resume with space");
}

#[tokio::test(flavor = "multi_thread")]
async fn latest_report_facts_kept() {
    let env = Env::new("facts");
    let ingest = env.ingest();
    hello(&ingest, M1, 11).await;
    let mut r = report(11, 1, T0, 1.0);
    r.services = vec![ServiceState { name: "nginx".into(), status: 1, enabled: true, since_ms: T0 - 1_000 }];
    r.updates =
        Some(UpdateSummary { pending: 3, security: 1, reboot_required: false, packages: vec!["openssl".into()] });
    live(&ingest, M1, r, T0).await;
    let facts = ingest.latest(M1).unwrap();
    assert_eq!(facts.services[0].name, "nginx");
    // services and containers are sent every interval; updates only every 6 h or on change, so the last ones stay
    live(&ingest, M1, report(11, 2, T0 + 15_000, 1.0), T0 + 15_000).await;
    let facts = ingest.latest(M1).unwrap();
    assert!(facts.services.is_empty());
    assert_eq!(facts.updates.as_ref().map(|u| u.pending), Some(3));
    assert_eq!(facts.reported_at_ms, T0 + 15_000);
    // a replayed report is older news and changes nothing
    let mut old = report(11, 1_000, T0 - 600_000, 1.0);
    old.services = vec![ServiceState { name: "old".into(), status: 3, enabled: true, since_ms: 0 }];
    ingest.receive(M1, Stream::Replay, vec![old], 100, T0 + 16_000).await.unwrap();
    assert!(ingest.latest(M1).unwrap().services.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn minute_rollup_from_window() {
    let env = Env::new("rollup");
    let ingest = env.ingest();
    hello(&ingest, M1, 12).await;
    for (i, v) in [2.0, 4.0, 9.0, 1.0, 7.0].into_iter().enumerate() {
        let t = T0 + i as i64 * 15_000;
        live(&ingest, M1, report(12, i as u64 + 1, t, v), t).await;
    }
    // the minute T0 holds 2, 4, 9 and 1; 7 is in the next minute
    assert_eq!(ingest.rollup_minute(T0 + 5_000).await.unwrap(), 1);
    let id = env.count("SELECT id FROM metric_keys WHERE name = 'cpu.busy_pct'");
    let key = rackhand_store::series::chunk::SeriesKey { machine_id: M1.into(), metric_key_id: id };
    let got = env
        .db
        .readers()
        .with(|c| {
            Ok(rackhand_store::series::query::range(c, &key, Tier::Minute, T0, T0 + MIN)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e))))
        })
        .unwrap()
        .unwrap();
    assert_eq!(got, vec![(T0, vec![1.0, 9.0, 4.0])]);
    // reads pick the tier for the range
    let labels = BTreeMap::new();
    assert_eq!(ingest.series(M1, "cpu.busy_pct", &labels, T0, T0 + 3_600_000).unwrap().len(), 5, "window and tier 0");
    let month = ingest.series(M1, "cpu.busy_pct", &labels, T0 - 10 * 86_400_000, T0 + MIN).unwrap();
    assert_eq!(month, vec![(T0, 4.0)], "tier 1's avg");
}

#[tokio::test(flavor = "multi_thread")]
async fn steady_state_compaction_marks_nothing_dirty() {
    let env = Env::new("steady");
    let ingest = env.ingest();
    hello(&ingest, M1, 13).await;
    // 70 minutes of live reports, with the hub's own schedule: minute rollups each minute, compaction every 5
    // minutes, the hourly rollup on the hour
    let mut seq = 0;
    for minute in 0..70i64 {
        for k in 0..4 {
            seq += 1;
            let t = T0 + minute * MIN + k * 15_000;
            live(&ingest, M1, report(13, seq, t, (seq % 7) as f64), t + 300).await;
        }
        ingest.rollup_minute(T0 + minute * MIN).await.unwrap();
        if minute % 5 == 4 {
            ingest.compact().await.unwrap();
        }
        if minute == 59 {
            ingest.rollup_hour(T0).await.unwrap();
        }
    }
    ingest.compact().await.unwrap();
    assert_eq!(env.count("SELECT count(*) FROM rollup_dirty"), 0, "on-time data is never dirty");
    let rows = |tier: i64| env.count(&format!("SELECT count(*) FROM series_chunks WHERE tier = {tier}"));
    assert_eq!((rows(0), rows(1), rows(2)), (3, 1, 1), "rows by the chunk rule: 280 points, 70 minutes, 1 hour");
}

fn step_ctx(timeout: std::time::Duration) -> crate::actions::runner::StepCtx {
    crate::actions::runner::StepCtx {
        job_id: "j1".into(),
        machine_id: "m1".into(),
        machine_kind: "linux".into(),
        address: None,
        identity: rackhand_runbook::runbook::Identity::Automation,
        timeout,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wait_report_step_waits_for_fresh_report() {
    use crate::actions::runner::{StepOutcome, StepRunner};
    use rackhand_store::ids::now_ms;
    use std::time::{Duration, Instant};
    let env = Env::new("wait-report");
    let ingest = env.ingest();
    hello(&ingest, "m1", 1).await;
    live(&ingest, "m1", report(1, 1, now_ms(), 5.0), now_ms()).await;
    let step: rackhand_runbook::runbook::Step = toml::from_str("id = \"wait\"\nkind = \"wait_report\"\n").unwrap();
    // a report that arrives after the step started completes it
    let sender = ingest.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(600)).await;
        live(&sender, "m1", report(1, 2, now_ms(), 6.0), now_ms()).await;
    });
    let started = Instant::now();
    let done = ingest.run(&step_ctx(Duration::from_secs(5)), &step, None).await;
    assert_eq!(done.outcome, StepOutcome::Succeeded);
    assert!(started.elapsed() >= Duration::from_millis(500), "the report from before the step doesn't count");
    // none arrives
    let done = ingest.run(&step_ctx(Duration::from_millis(800)), &step, None).await;
    assert_eq!(done.outcome, StepOutcome::Failed("timeout".into()));
}

/// Points from the hub's own polling (drivers, service checks) are in the machine's recent window as they are stored,
/// so `/metrics` and the dashboard show them without waiting for a restart (7.4.2).
#[tokio::test(flavor = "multi_thread")]
async fn polled_points_in_the_recent_window() {
    let env = Env::new("polled");
    let ingest = env.ingest();
    let points = |at: i64, value: f64| rackhand_store::series::compact::SeriesPoints {
        name: "truenas.pool.healthy".into(),
        unit: String::new(),
        label_set: "{\"pool\":\"tank1\"}".into(),
        points: vec![(at, value)],
        late: vec![],
    };
    ingest.put_points(M1, vec![points(T0, 1.0)], T0).await.unwrap();
    ingest.put_points(M1, vec![points(T0 + MIN, 0.0)], T0 + MIN).await.unwrap();
    let pool =
        SeriesId::new("truenas.pool.healthy", &[("pool".to_string(), "tank1".to_string())].into_iter().collect());
    let w = ingest.window(M1, &pool);
    assert_eq!(w.iter().map(|s| (s.at_ms, s.value)).collect::<Vec<_>>(), [(T0, 1.0), (T0 + MIN, 0.0)]);
    assert!(
        ingest.latest_values().iter().any(|(m, id, at, v)| m == M1 && *id == pool && *at == T0 + MIN && *v == 0.0),
        "the latest value: {:?}",
        ingest.latest_values()
    );
    assert_eq!(ingest.last_seen(M1), None, "polled points aren't a probe's report");
}

/// D91, 7.3.2: the events a probe reports in a report are stored (as the hub's own events, with the severity the hub
/// gives the kind and the fields in `data`) before compaction deletes the frame; a kind the hub doesn't know is counted
/// and dropped; `conn.overflow` is kept once an hour.
#[tokio::test(flavor = "multi_thread")]
async fn probe_events_stored_before_compaction() {
    use rackhand_proto::probe::ProbeEvent;
    let env = Env::new("probe-events");
    let ingest = env.ingest();
    hello(&ingest, M1, 4).await;
    let event = |kind: &str, at: i64, fields: &[(&str, &str)]| ProbeEvent {
        kind: kind.into(),
        at_ms: at,
        fields: fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    };
    let mut r = report(4, 1, T0, 1.0);
    r.events = vec![
        event("proc.exec_from_tmp", T0, &[("exe", "/tmp/evil"), ("pid", "77")]),
        event("port.new_listener", T0, &[("port", "4444")]),
        event("conn.overflow", T0, &[("folded_tuples", "100")]),
        event("kernel.panic", T0, &[]),
        event("x.y", T0, &[]),
    ];
    live(&ingest, M1, r, T0).await;
    // before any compaction: the report is still only in staging
    assert_eq!(env.count("SELECT count(*) FROM series_chunks"), 0);
    assert_eq!(env.events("proc.exec_from_tmp"), vec![("critical".to_string(), M1.to_string())]);
    assert_eq!(env.events("port.new_listener"), vec![("warning".to_string(), M1.to_string())]);
    assert_eq!(env.events("conn.overflow"), vec![("info".to_string(), M1.to_string())]);
    assert_eq!(
        env.count("SELECT count(*) FROM events WHERE kind IN ('kernel.panic', 'x.y')"),
        0,
        "an unknown kind is dropped"
    );
    assert_eq!(ingest.unknown_probe_events(M1), 2, "and counted");
    let data: String = env
        .db
        .readers()
        .with(|c| c.query_row("SELECT data FROM events WHERE kind = 'proc.exec_from_tmp'", [], |r| r.get(0)))
        .unwrap();
    let data: serde_json::Value = serde_json::from_str(&data).unwrap();
    assert_eq!((data["exe"].as_str(), data["pid"].as_str()), (Some("/tmp/evil"), Some("77")));
    // a second overflow within the hour isn't kept, one after it is
    let mut r2 = report(4, 2, T0 + 15_000, 1.0);
    r2.events = vec![event("conn.overflow", T0 + 15_000, &[])];
    live(&ingest, M1, r2, T0 + 15_000).await;
    let mut r3 = report(4, 3, T0 + 61 * MIN, 1.0);
    r3.events = vec![event("conn.overflow", T0 + 61 * MIN, &[])];
    live(&ingest, M1, r3, T0 + 61 * MIN).await;
    assert_eq!(env.events("conn.overflow").len(), 2);
}

/// 7.3.2, 7.6.5, AC14, AC55: a report's connection records are scored and stored as the report arrives, before compaction
/// deletes its frame: a threat-listed destination is a critical event naming it, a machine's records are kept by its
/// policy (full rows, only counts per ASN, or nothing), and the baseline is learned.
#[tokio::test(flavor = "multi_thread")]
async fn connections_scored_and_stored_by_policy() {
    use rackhand_proto::probe::{ConnRecord, Proto};
    let env = Env::new("connections");
    let intel = crate::intel::Intel::default();
    let source = |id: &str| crate::intel::sources(T0).into_iter().find(|s| s.id == id).unwrap();
    intel.load(&source("feodo"), b"203.0.113.9\n", T0).unwrap();
    let ingest = env.ingest().with_intel(intel);
    {
        let c = rusqlite::Connection::open(&env.path).unwrap();
        c.execute("INSERT INTO sites (id, name, timezone, is_local) VALUES ('s', 'home', 'UTC', 1)", []).unwrap();
        c.execute("INSERT INTO policies (id, name, connections) VALUES ('quiet', 'desktops', 'summary')", []).unwrap();
        c.execute("INSERT INTO policies (id, name, connections) VALUES ('none', 'private', 'off')", []).unwrap();
        for (id, policy) in [(M1, None), (M2, Some("quiet"))] {
            c.execute(
                "INSERT INTO machines (id, site_id, name, kind, state, policy_id) VALUES (?1, 's', ?1, 'linux', 'enrolled', ?2)",
                rusqlite::params![id, policy],
            )
            .unwrap();
        }
        c.execute("INSERT INTO machines (id, site_id, name, kind, state, policy_id) VALUES ('01JD0000000000000000000003', 's', 'off', 'linux', 'enrolled', 'none')", []).unwrap();
    }
    let record = |ip: [u8; 4], port: u32| ConnRecord {
        container: "web".into(),
        exe: "/usr/bin/curl".into(),
        dest_ip: ip.to_vec(),
        dest_port: port,
        proto: Proto::Tcp as i32,
        count: 2,
        bytes: 100,
        pid: 7,
        user: "alice".into(),
        folded: false,
    };
    for (machine, epoch) in [(M1, 1), (M2, 2), ("01JD0000000000000000000003", 3)] {
        hello(&ingest, machine, epoch).await;
        let mut r = report(epoch, 1, T0, 1.0);
        r.connections =
            vec![record([203, 0, 113, 9], 8080), record([93, 184, 216, 34], 443), record([10, 0, 0, 5], 22)];
        live(&ingest, machine, r, T0).await;
    }
    // every machine, whatever its policy, is told of the threat-listed destination, naming it and the container
    for machine in [M1, M2, "01JD0000000000000000000003"] {
        let bad: Vec<(String, String)> = env
            .db
            .readers()
            .with(|c| {
                let mut st =
                    c.prepare("SELECT severity, data FROM events WHERE kind = 'conn.known_bad' AND machine_id = ?1")?;
                st.query_map([machine], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
            })
            .unwrap();
        assert_eq!(bad.len(), 1, "{machine}");
        assert_eq!(bad[0].0, "critical");
        assert!(bad[0].1.contains("203.0.113.9") && bad[0].1.contains("\"container\":\"web\""), "{}", bad[0].1);
    }
    // full: a row for the listed one, the public one and (private skipped) nothing for 10.0.0.5; summary: counts per ASN only;
    // off: nothing at all
    let rows = |machine: &str| -> Vec<(String, i64, String)> {
        env.db
            .readers()
            .with(|c| {
                let mut st = c.prepare("SELECT dest_ip, count, coalesce(verdict, '') FROM conn_records WHERE machine_id = ?1 ORDER BY dest_ip")?;
                st.query_map([machine], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
            })
            .unwrap()
    };
    let full = rows(M1);
    assert_eq!(full.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(), ["203.0.113.9", "93.184.216.34"], "{full:?}");
    assert_eq!(full[0].2, "known_bad");
    assert_eq!(
        rows(M2).iter().map(|r| r.0.as_str()).collect::<Vec<_>>(),
        ["AS0"],
        "counts only, no address: {:?}",
        rows(M2)
    );
    assert!(rows("01JD0000000000000000000003").is_empty(), "off stores nothing");
    // only the full machine learns a baseline, and not from the bad destination
    assert_eq!(env.count("SELECT count(*) FROM conn_baseline WHERE machine_id = '01JD0000000000000000000001'"), 1);
    assert_eq!(env.count("SELECT count(*) FROM conn_baseline WHERE machine_id != '01JD0000000000000000000001'"), 0);
    // the same bucket again adds to its rows
    let mut again = report(1, 2, T0 + 15_000, 1.0);
    again.connections = vec![record([93, 184, 216, 34], 443)];
    live(&ingest, M1, again, T0 + 15_000).await;
    assert_eq!(rows(M1).iter().find(|r| r.0 == "93.184.216.34").unwrap().1, 4, "2 and 2");
}

#[test]
fn the_probe_build_from_the_hello_is_kept_per_machine() {
    let env = Env::new("probe-build");
    let ingest = env.ingest();
    assert_eq!(ingest.probe_build(M1), None, "nothing before a Hello");
    ingest.set_probe_build(M1, "0.1.0", "x86_64");
    ingest.set_probe_build(M2, "0.1.1", "aarch64");
    assert_eq!(ingest.probe_build(M1), Some(("0.1.0".to_string(), "x86_64".to_string())));
    // a probe that updated says so in its next Hello
    ingest.set_probe_build(M1, "0.1.1", "x86_64");
    assert_eq!(ingest.probe_build(M1), Some(("0.1.1".to_string(), "x86_64".to_string())));
    assert_eq!(ingest.probe_build(M2), Some(("0.1.1".to_string(), "aarch64".to_string())));
}
