use std::sync::Arc;

use rackhand_proto::common::LabelEntry;
use rackhand_proto::probe::{Report, Sample};
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use super::*;
use crate::bus::Bus;
use crate::ingest::{DiskSpace, Event, Ingest, Severity as EventSeverity, Stream};

const M1: &str = "01JD0000000000000000000001";
const M2: &str = "01JD0000000000000000000002";
const T0: i64 = 1_795_068_000_000;
const MIN: i64 = 60_000;
const CPU: u32 = 1;
const SWAP: u32 = 15;

#[derive(Debug)]
struct Roomy;

impl DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

struct Env {
    db: Arc<Db>,
    ingest: Ingest,
    incidents: Incidents,
    path: std::path::PathBuf,
    seq: u64,
}

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

impl Env {
    async fn new(name: &str) -> Env {
        let dir = std::env::temp_dir().join(format!("rackhand-incidents-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hub.db");
        let db = Arc::new(Db::open(&path).unwrap());
        let rows = vec![
            RowWrite::insert("sites", Row::from([("id", t("s1")), ("name", t("home")), ("timezone", t("UTC"))])),
            RowWrite::insert(
                "policies",
                Row::from([("id", t("asleep")), ("name", t("desktops")), ("expected_offline", Value::Integer(1))]),
            ),
            RowWrite::insert(
                "machines",
                Row::from([
                    ("id", t(M1)),
                    ("site_id", t("s1")),
                    ("name", t("web")),
                    ("kind", t("linux")),
                    ("tags", t("[\"web\"]")),
                    ("state", t("enrolled")),
                ]),
            ),
            RowWrite::insert(
                "machines",
                Row::from([
                    ("id", t(M2)),
                    ("site_id", t("s1")),
                    ("name", t("nas")),
                    ("kind", t("linux")),
                    ("tags", t("[\"lab\"]")),
                    ("state", t("enrolled")),
                    ("policy_id", t("asleep")),
                ]),
            ),
        ];
        db.writer().send(WriteCmd::Batch(rows)).await.unwrap();
        Env::start(db, path, 0).await
    }

    async fn start(db: Arc<Db>, path: std::path::PathBuf, seq: u64) -> Env {
        let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
        for m in [M1, M2] {
            ingest.hello(m, 1, &[LabelEntry::default()]).await.unwrap();
        }
        let incidents = Incidents::new(db.clone(), ingest.clone(), Bus::new());
        // machine silence stays in its start-up grace unless a test sets when the hub started
        incidents.set_started(i64::MAX / 4);
        Env { db, ingest, incidents, path, seq }
    }

    async fn sample(&mut self, machine: &str, metric: u32, at: i64, value: f64, stream: Stream, received: i64) {
        self.seq += 1;
        let r = Report {
            epoch: 1,
            seq: self.seq,
            sampled_at_ms: at,
            vitals: vec![Sample { metric, labels_id: 0, value }],
            ..Default::default()
        };
        self.ingest.receive(machine, stream, vec![r], 100, received).await.unwrap();
    }

    /// Live samples every 15 s over `[from, from + minutes)`, evaluating after each.
    async fn run(&mut self, machine: &str, metric: u32, from: i64, minutes: i64, value: f64) {
        for i in 0..minutes * 4 {
            let at = from + i * 15_000;
            self.sample(machine, metric, at, value, Stream::Live, at).await;
            self.incidents.evaluate(at).await.unwrap();
        }
    }

    /// (id, state, severity, dedupe key) of every incident, oldest first.
    fn incidents(&self) -> Vec<(String, String, String, String)> {
        self.db
            .readers()
            .with(|c| {
                let mut s =
                    c.prepare("SELECT id, state, severity, dedupe_key FROM incidents ORDER BY opened_at, id")?;
                s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect()
            })
            .unwrap()
    }

    fn events(&self, incident: &str) -> Vec<(String, serde_json::Value)> {
        self.db
            .readers()
            .with(|c| {
                let mut s =
                    c.prepare("SELECT kind, data FROM incident_events WHERE incident_id = ?1 ORDER BY at_ms, rowid")?;
                s.query_map([incident], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap()
            .into_iter()
            .map(|(k, d)| (k, serde_json::from_str(&d).unwrap()))
            .collect()
    }

    fn opened_at(&self, id: &str) -> i64 {
        self.db
            .readers()
            .with(|c| c.query_row("SELECT opened_at FROM incidents WHERE id = ?1", [id], |r| r.get(0)))
            .unwrap()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rule_fire_opens_and_clear_resolves() {
    let mut env = Env::new("open").await;
    // normal before T0, so the 15-minute window holds a normal sample until 15 minutes have passed
    env.run(M1, CPU, T0 - 20 * MIN, 20, 50.0).await;
    env.run(M1, CPU, T0, 14, 95.0).await;
    assert!(env.incidents().is_empty(), "not before 15 minutes over 90%");
    env.run(M1, CPU, T0 + 14 * MIN, 2, 95.0).await;
    let open = env.incidents();
    assert_eq!(open.len(), 1);
    assert_eq!((open[0].1.as_str(), open[0].2.as_str()), ("open", "warning"));
    assert_eq!(open[0].3, format!("{M1}:cpu.busy:{{}}"));
    // two samples under the 88% clear line resolve it
    env.sample(M1, CPU, T0 + 16 * MIN, 50.0, Stream::Live, T0 + 16 * MIN).await;
    env.incidents.evaluate(T0 + 16 * MIN).await.unwrap();
    assert_eq!(env.incidents()[0].1, "open", "one sample isn't enough");
    env.sample(M1, CPU, T0 + 16 * MIN + 15_000, 50.0, Stream::Live, T0 + 16 * MIN + 15_000).await;
    env.incidents.evaluate(T0 + 16 * MIN + 15_000).await.unwrap();
    assert_eq!(env.incidents()[0].1, "resolved");
    let kinds: Vec<String> = env.events(&open[0].0).into_iter().map(|e| e.0).collect();
    assert_eq!(kinds, ["opened", "resolved"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn same_dedupe_key_within_30_min_reopens() {
    let mut env = Env::new("reopen").await;
    env.run(M1, CPU, T0, 16, 95.0).await;
    env.run(M1, CPU, T0 + 16 * MIN, 1, 50.0).await;
    let first = env.incidents();
    assert_eq!(first[0].1, "resolved");
    // 16 minutes later it fires again: within 30 minutes of the resolve, so the same incident reopens
    env.run(M1, CPU, T0 + 17 * MIN, 16, 95.0).await;
    let after = env.incidents();
    assert_eq!(after.len(), 1, "no second incident");
    assert_eq!((after[0].0.clone(), after[0].1.as_str()), (first[0].0.clone(), "open"));
    let kinds: Vec<String> = env.events(&after[0].0).into_iter().map(|e| e.0).collect();
    assert_eq!(kinds, ["opened", "resolved", "reopened"], "the history is kept");
    // resolved again, and firing more than 30 minutes later opens a new one
    env.run(M1, CPU, T0 + 33 * MIN, 1, 50.0).await;
    env.run(M1, CPU, T0 + 64 * MIN, 16, 95.0).await;
    assert_eq!(env.incidents().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn severity_rise_and_fall_without_callout_on_fall() {
    let mut env = Env::new("severity").await;
    env.run(M1, CPU, T0, 31, 99.0).await;
    let inc = env.incidents();
    assert_eq!(inc[0].2, "critical", "critical after 30 minutes over 98%");
    env.run(M1, CPU, T0 + 31 * MIN, 2, 95.0).await;
    assert_eq!(env.incidents()[0].2, "warning", "falls back to warning");
    let events = env.events(&inc[0].0);
    let changes: Vec<(String, String, bool)> = events
        .iter()
        .filter(|e| e.0 == "severity")
        .map(|e| {
            (
                e.1["from"].as_str().unwrap().into(),
                e.1["to"].as_str().unwrap().into(),
                e.1["callout"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        changes,
        vec![("warning".into(), "critical".into(), true), ("critical".into(), "warning".into(), false)]
    );
    assert_eq!(events[0].1["callout"], true, "opening calls out");
}

fn event(machine: &str, kind: &str, subject: &str, severity: EventSeverity, at_ms: i64) -> Event {
    Event {
        machine_id: Some(machine.into()),
        at_ms,
        kind: kind.into(),
        severity,
        subject: Some(subject.into()),
        data: serde_json::json!({}),
        job_id: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn event_incident_merges_for_24_hours() {
    let env = Env::new("events").await;
    env.ingest.raise_event(event(M1, "auth.root_login", "root", EventSeverity::Warning, T0)).await.unwrap();
    env.incidents.evaluate(T0 + 1_000).await.unwrap();
    env.ingest
        .raise_event(event(M1, "auth.root_login", "root", EventSeverity::Critical, T0 + 3_600_000))
        .await
        .unwrap();
    // another subject is another incident
    env.ingest
        .raise_event(event(M1, "auth.root_login", "admin", EventSeverity::Warning, T0 + 3_600_000))
        .await
        .unwrap();
    env.incidents.evaluate(T0 + 3_601_000).await.unwrap();
    let inc = env.incidents();
    assert_eq!(inc.len(), 2);
    assert_eq!(inc[0].3, format!("{M1}:auth.root_login:root"));
    assert_eq!(inc[0].2, "critical", "a worse event raises it");
    let kinds: Vec<String> = env.events(&inc[0].0).into_iter().map(|e| e.0).collect();
    assert_eq!(kinds, ["opened", "event", "severity"]);
    // while it is unresolved it keeps taking them, even a day later (one unresolved incident per key)
    let h = 3_600_000;
    env.ingest.raise_event(event(M1, "auth.root_login", "root", EventSeverity::Warning, T0 + 25 * h)).await.unwrap();
    env.incidents.evaluate(T0 + 25 * h + 1_000).await.unwrap();
    assert_eq!(env.incidents().len(), 2);
    // a person resolves it; a matching event within 24 hours of its last one reopens it
    env.incidents.resolve_by(&inc[0].0, "user:bob", T0 + 26 * h).await.unwrap();
    env.ingest.raise_event(event(M1, "auth.root_login", "root", EventSeverity::Warning, T0 + 40 * h)).await.unwrap();
    env.incidents.evaluate(T0 + 40 * h + 1_000).await.unwrap();
    let after = env.incidents();
    assert_eq!((after.len(), after[0].1.as_str()), (2, "open"), "reopened");
    // resolved again, and an event more than 24 hours after its last one opens a new incident
    env.incidents.resolve_by(&inc[0].0, "user:bob", T0 + 41 * h).await.unwrap();
    env.ingest.raise_event(event(M1, "auth.root_login", "root", EventSeverity::Warning, T0 + 65 * h)).await.unwrap();
    env.incidents.evaluate(T0 + 65 * h + 1_000).await.unwrap();
    assert_eq!(env.incidents().len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn info_events_never_open_incidents() {
    let env = Env::new("info").await;
    env.ingest.raise_event(event(M1, "probe.epoch_changed", "", EventSeverity::Info, T0)).await.unwrap();
    env.incidents.evaluate(T0 + 1_000).await.unwrap();
    assert!(env.incidents().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn silence_suppresses_new_incident_until_end() {
    let mut env = Env::new("silence").await;
    let by_machine = Silence {
        target: SilenceTarget::Machine(M1.into()),
        rule_or_kind: Some("cpu.busy".into()),
        until_ms: T0 + 20 * MIN,
        created_by: "user:bob".into(),
        reason: "load test".into(),
    };
    env.incidents.silence(by_machine.clone(), T0).await.unwrap();
    let by_tag = Silence { target: SilenceTarget::Tag("lab".into()), rule_or_kind: None, ..by_machine.clone() };
    env.incidents.silence(by_tag, T0).await.unwrap();
    let too_long = Silence { until_ms: T0 + 31 * 86_400_000, ..by_machine.clone() };
    assert!(
        matches!(env.incidents.silence(too_long, T0).await, Err(IncidentsError::SilenceTooLong)),
        "at most 30 days"
    );
    env.run(M1, CPU, T0, 19, 95.0).await;
    env.run(M2, CPU, T0, 19, 95.0).await;
    assert!(env.incidents().is_empty(), "both silenced");
    // past its end the condition, still there, opens an incident
    env.run(M1, CPU, T0 + 19 * MIN, 2, 95.0).await;
    env.run(M2, CPU, T0 + 19 * MIN, 2, 95.0).await;
    let open: Vec<String> = env.incidents().into_iter().map(|i| i.3).collect();
    assert_eq!(open.len(), 2, "{open:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn acknowledge_keeps_state() {
    let mut env = Env::new("ack").await;
    env.run(M1, CPU, T0, 16, 95.0).await;
    let id = env.incidents()[0].0.clone();
    env.incidents.acknowledge(&id, "user:bob", T0 + 17 * MIN).await.unwrap();
    let (state, acked_at, acked_by): (String, i64, String) = env
        .db
        .readers()
        .with(|c| {
            c.query_row("SELECT state, acked_at, acked_by FROM incidents WHERE id = ?1", [&id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
        })
        .unwrap();
    assert_eq!((state.as_str(), acked_at, acked_by.as_str()), ("open", T0 + 17 * MIN, "user:bob"));
}

#[tokio::test(flavor = "multi_thread")]
async fn rule_mid_duration_survives_restart() {
    let mut env = Env::new("restart").await;
    // swap over 50% for 30 minutes is a warning; normal before T0, then 20 minutes in, the hub restarts
    env.run(M1, SWAP, T0 - 35 * MIN, 35, 10.0).await;
    env.run(M1, SWAP, T0, 20, 60.0).await;
    env.ingest.compact().await.unwrap();
    let Env { db, path, seq, .. } = env;
    let mut env = Env::start(db, path, seq).await;
    env.ingest.start(T0 + 20 * MIN).await.unwrap();
    env.run(M1, SWAP, T0 + 20 * MIN, 9, 60.0).await;
    assert!(env.incidents().is_empty(), "not before 30 minutes");
    env.run(M1, SWAP, T0 + 29 * MIN, 2, 60.0).await;
    let inc = env.incidents();
    assert_eq!(inc.len(), 1, "opens at 30 minutes, counting the samples from before the restart");
    let opened = env.opened_at(&inc[0].0);
    assert!((T0 + 29 * MIN..=T0 + 30 * MIN + 15_000).contains(&opened), "opened at {}", (opened - T0) / 1000);
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_advances_incident_whose_job_finished() {
    let mut env = Env::new("reconcile").await;
    env.run(M1, CPU, T0, 16, 95.0).await;
    let id = env.incidents()[0].0.clone();
    // a runbook job ran for it and failed, and the JobFinished event was lost
    env.incidents.set_state(&id, State::Automation, T0 + 16 * MIN).await.unwrap();
    let job = Row::from([
        ("id", t("01JD00000000000000000000J1")),
        ("kind", t("runbook")),
        ("name", t("restart-web")),
        ("requested_by", t("incident")),
        ("incident_id", t(&id)),
        ("state", t("failed")),
        ("ended_at", Value::Integer(T0 + 17 * MIN)),
        ("outcome", t("failed")),
    ]);
    env.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("jobs", job)])).await.unwrap();
    assert_eq!(env.incidents.reconcile(T0 + 18 * MIN).await.unwrap(), 1);
    assert_eq!(env.incidents()[0].1, "human", "routing beyond a person comes with playbooks");
    let last = env.events(&id).pop().unwrap();
    assert_eq!((last.0.as_str(), last.1["job_id"].as_str()), ("job_finished", Some("01JD00000000000000000000J1")));
    assert_eq!(env.incidents.reconcile(T0 + 19 * MIN).await.unwrap(), 0, "only once");
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_samples_do_not_open_threshold_incidents() {
    let mut env = Env::new("stale").await;
    // 31 minutes of 99%, each sample arriving 11 minutes after it was taken (a replay); rules are evaluated at the
    // samples' own times, where they would match if the samples counted
    for i in 0..31 * 4 {
        let at = T0 + i * 15_000;
        env.sample(M1, CPU, at, 99.0, Stream::Replay, at + 11 * MIN).await;
        env.incidents.evaluate(at).await.unwrap();
    }
    assert!(env.incidents().is_empty(), "history only");
    // the same samples arriving on time open one
    env.run(M2, CPU, T0, 16, 99.0).await;
    assert_eq!(env.incidents().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn condition_resolves_after_restart() {
    let mut env = Env::new("restart-clear").await;
    env.run(M1, CPU, T0, 16, 95.0).await;
    assert_eq!(env.incidents()[0].1, "open");
    env.ingest.compact().await.unwrap();
    // the hub restarts with the incident open; two samples under the clear line then resolve it
    let Env { db, path, seq, .. } = env;
    let mut env = Env::start(db, path, seq).await;
    env.ingest.start(T0 + 16 * MIN).await.unwrap();
    env.run(M1, CPU, T0 + 16 * MIN, 1, 50.0).await;
    assert_eq!(env.incidents()[0].1, "resolved");
}

const DAY: i64 = 86_400_000;
const H: i64 = 3_600_000;
const GB: f64 = 1e9;

/// Rollup points for one series, as the rollup task writes them.
async fn rollups(env: &Env, tier: u8, name: &str, unit: &str, labels: &str, points: Vec<(i64, f64)>) {
    let series = rackhand_store::rollup::RollupSeries {
        machine_id: M1.into(),
        name: name.into(),
        unit: unit.into(),
        label_set: labels.into(),
        points: points.into_iter().map(|(t, v)| (t, [v, v, v])).collect(),
    };
    env.db.writer().send(WriteCmd::PutRollups { tier, series: vec![series] }).await.unwrap();
}

const DATA: &str = "{\"mount\":\"/data\"}";

/// The worked example of 7.6.2: 400 of 500 GB used; the 6-hour fit rises 1.2 GB/h, the 7-day fit 1.6 GB/h.
async fn filling_disk(env: &Env, now: i64) {
    let minutes: Vec<(i64, f64)> =
        (0..360).map(|i| (now - i * MIN, 400.0 * GB - 1.2 * GB * i as f64 / 60.0)).rev().collect();
    let hours: Vec<(i64, f64)> = (1..168).map(|i| (now - i * H, 400.0 * GB - 1.6 * GB * i as f64)).rev().collect();
    rollups(env, 1, "disk.used_bytes", "bytes", DATA, minutes).await;
    rollups(env, 2, "disk.used_bytes", "bytes", DATA, hours).await;
    rollups(env, 1, "disk.total_bytes", "bytes", DATA, vec![(now, 500.0 * GB)]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn disk_fill_forecast_warns_with_eta() {
    let env = Env::new("forecast").await;
    let now = T0 + 10 * DAY;
    filling_disk(&env, now).await;
    env.incidents.evaluate_forecasts(now).await.unwrap();
    let inc = env.incidents();
    assert_eq!(inc.len(), 1);
    assert_eq!((inc[0].2.as_str(), inc[0].3.clone()), ("warning", format!("{M1}:disk.fill:{DATA}")));
    let title: String =
        env.db.readers().with(|c| c.query_row("SELECT title FROM incidents", [], |r| r.get(0))).unwrap();
    assert_eq!(title, "/data fills in about 2.6 days");
}

#[tokio::test(flavor = "multi_thread")]
async fn forecast_clears_after_2_recomputations() {
    let env = Env::new("forecast-clear").await;
    let now = T0 + 10 * DAY;
    filling_disk(&env, now).await;
    env.incidents.evaluate_forecasts(now).await.unwrap();
    // the disk is grown to 5 TB: no fit reaches it soon
    rollups(&env, 1, "disk.total_bytes", "bytes", DATA, vec![(now + MIN, 5_000.0 * GB)]).await;
    env.incidents.evaluate_forecasts(now + 5 * MIN).await.unwrap();
    assert_eq!(env.incidents()[0].1, "open", "one recomputation isn't enough");
    env.incidents.evaluate_forecasts(now + 10 * MIN).await.unwrap();
    assert_eq!(env.incidents()[0].1, "resolved");
}

#[tokio::test(flavor = "multi_thread")]
async fn baseline_deviation_opens_and_clears() {
    let env = Env::new("baseline").await;
    // 8 days of net.tx_bps around 2 Mbit/s, learned hour by hour from tier 2
    let start = T0 - 8 * DAY;
    let mut rng = 0u64;
    let hours: Vec<(i64, f64)> = (0..8 * 24)
        .map(|i| {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (start + i * H, 250_000.0 + (rng >> 40) as f64 % 25_000.0)
        })
        .collect();
    rollups(&env, 2, "net.tx_bps", "B/s", "{\"iface\":\"eth0\"}", hours.clone()).await;
    for (hour, _) in &hours {
        env.incidents.baseline_hourly(*hour, hour + H).await.unwrap();
    }
    // then 40 Mbit/s: a warning after 15 minutes, and 2 normal minutes clear it
    let mut minutes = Vec::new();
    for i in 0..17 {
        minutes.push((T0 + i * MIN, 5_000_000.0));
    }
    for (t, v) in minutes {
        rollups(&env, 1, "net.tx_bps", "B/s", "{\"iface\":\"eth0\"}", vec![(t, v)]).await;
        env.incidents.evaluate_baselines(t + 1_000).await.unwrap();
    }
    let inc = env.incidents();
    assert_eq!(inc.len(), 1, "warning after 15 minutes");
    assert_eq!(
        (inc[0].2.as_str(), inc[0].3.clone()),
        ("warning", format!("{M1}:baseline.net.tx_bps:{{\"iface\":\"eth0\"}}"))
    );
    for i in 17..19 {
        rollups(&env, 1, "net.tx_bps", "B/s", "{\"iface\":\"eth0\"}", vec![(T0 + i * MIN, 260_000.0)]).await;
        env.incidents.evaluate_baselines(T0 + i * MIN + 1_000).await.unwrap();
    }
    assert_eq!(env.incidents()[0].1, "resolved");
}

#[tokio::test(flavor = "multi_thread")]
async fn silent_machine_warns_after_60s_and_clears_on_report() {
    let mut env = Env::new("silent").await;
    env.incidents.set_started(T0 - 10 * MIN);
    env.sample(M1, CPU, T0, 1.0, Stream::Live, T0).await;
    env.incidents.evaluate(T0 + 59_000).await.unwrap();
    assert!(env.incidents().is_empty(), "not before 60 s");
    env.incidents.evaluate(T0 + 60_000).await.unwrap();
    let inc = env.incidents();
    assert_eq!(inc.len(), 1, "machine 2 expects to be offline: no incident for it");
    assert_eq!((inc[0].2.as_str(), inc[0].3.clone()), ("warning", format!("{M1}:machine.silent:{{}}")));
    env.sample(M1, CPU, T0 + 70_000, 1.0, Stream::Live, T0 + 70_000).await;
    env.incidents.evaluate(T0 + 70_000).await.unwrap();
    assert_eq!(env.incidents()[0].1, "resolved", "the first report resolves it");
}

#[tokio::test(flavor = "multi_thread")]
async fn silence_stays_open_across_a_restart() {
    // the rule says nothing in the hub's first 3 minutes (E44); that isn't the machine reporting again
    let mut env = Env::new("silent-restart").await;
    env.incidents.set_started(T0 - 10 * MIN);
    env.sample(M1, CPU, T0, 1.0, Stream::Live, T0).await;
    env.incidents.evaluate(T0 + 60_000).await.unwrap();
    assert_eq!(env.incidents()[0].1, "open");
    let Env { db, path, seq, .. } = env;
    let mut env = Env::start(db, path, seq).await;
    env.ingest.start(T0 + 2 * MIN).await.unwrap();
    env.incidents.set_started(T0 + 2 * MIN);
    env.incidents.evaluate(T0 + 2 * MIN + 15_000).await.unwrap();
    assert_eq!(env.incidents()[0].1, "open", "still silent, in the start grace");
    env.sample(M1, CPU, T0 + 3 * MIN, 1.0, Stream::Live, T0 + 3 * MIN).await;
    env.incidents.evaluate(T0 + 3 * MIN).await.unwrap();
    assert_eq!(env.incidents()[0].1, "resolved", "its first report resolves it, grace or not");
}

#[tokio::test(flavor = "multi_thread")]
async fn expected_offline_is_info_only() {
    let env = Env::new("asleep").await;
    env.incidents.set_started(T0 - 10 * MIN);
    env.incidents.evaluate(T0).await.unwrap();
    env.incidents.evaluate(T0 + 30_000).await.unwrap();
    let infos: i64 = env
        .db
        .readers()
        .with(|c| {
            c.query_row(
                "SELECT count(*) FROM events WHERE kind = 'machine.silent' AND severity = 'info' AND machine_id = ?1",
                [M2],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(infos, 1, "one info event, once");
    assert!(env.incidents().iter().all(|i| !i.3.starts_with(M2)), "no incident for the sleeping machine");
}

impl Env {
    async fn report(&mut self, machine: &str, at: i64, f: impl FnOnce(&mut Report)) {
        self.seq += 1;
        let mut r = Report { epoch: 1, seq: self.seq, sampled_at_ms: at, ..Default::default() };
        f(&mut r);
        self.ingest.receive(machine, Stream::Live, vec![r], 100, at).await.unwrap();
        self.incidents.evaluate(at).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn watched_service_not_active_2_and_4_reports() {
    let mut env = Env::new("service").await;
    let service = |status: i32| {
        move |r: &mut Report| {
            r.services =
                vec![rackhand_proto::probe::ServiceState { name: "nginx".into(), status, enabled: true, since_ms: 0 }]
        }
    };
    env.report(M1, T0, service(3)).await;
    assert!(env.incidents().is_empty(), "one report isn't enough");
    env.report(M1, T0 + 15_000, service(3)).await;
    assert_eq!(env.incidents()[0].2, "warning");
    assert_eq!(env.incidents()[0].3, format!("{M1}:service.not_active:{{\"service\":\"nginx\"}}"));
    env.report(M1, T0 + 30_000, service(3)).await;
    env.report(M1, T0 + 45_000, service(3)).await;
    assert_eq!(env.incidents()[0].2, "critical", "4 reports");
    env.report(M1, T0 + 60_000, service(1)).await;
    assert_eq!(env.incidents()[0].1, "resolved", "active again");
}

#[tokio::test(flavor = "multi_thread")]
async fn counted_incidents_stay_open_across_a_restart() {
    // the report counts are in memory: after a restart the first report of a service still down counts 1, which
    // isn't the condition clearing (found in the lab, plan L2)
    let mut env = Env::new("counted-restart").await;
    let down = |r: &mut Report| {
        r.services =
            vec![rackhand_proto::probe::ServiceState { name: "nginx".into(), status: 3, enabled: true, since_ms: 0 }];
        r.updates = Some(rackhand_proto::probe::UpdateSummary {
            pending: 5,
            security: 2,
            reboot_required: false,
            packages: vec![],
        });
    };
    env.report(M1, T0, down).await;
    for i in 1..4 {
        env.report(M1, T0 + 8 * DAY + i * 15_000, down).await;
    }
    let open = |env: &Env| {
        let mut v: Vec<(String, String)> =
            env.incidents().into_iter().map(|i| (i.3, format!("{} {}", i.1, i.2))).collect();
        v.sort();
        v
    };
    let service = format!("{M1}:service.not_active:{{\"service\":\"nginx\"}}");
    let updates = format!("{M1}:updates.security:{{}}");
    assert_eq!(open(&env), vec![(service.clone(), "open critical".into()), (updates.clone(), "open warning".into())]);
    let Env { db, path, seq, .. } = env;
    let mut env = Env::start(db, path, seq).await;
    env.ingest.start(T0 + 8 * DAY + MIN).await.unwrap();
    // the first evaluation comes before the machine has reported again: it knows nothing new
    env.incidents.evaluate(T0 + 8 * DAY + MIN + 1).await.unwrap();
    assert_eq!(
        open(&env),
        vec![(service.clone(), "open critical".into()), (updates.clone(), "open warning".into())],
        "no report since the restart isn't the condition clearing"
    );
    env.report(M1, T0 + 8 * DAY + 2 * MIN, down).await;
    assert_eq!(
        open(&env),
        vec![(service.clone(), "open critical".into()), (updates.clone(), "open warning".into())],
        "still down and still pending after the restart: both stay open at their severity"
    );
    env.report(M1, T0 + 8 * DAY + 3 * MIN, |r| {
        r.services =
            vec![rackhand_proto::probe::ServiceState { name: "nginx".into(), status: 1, enabled: true, since_ms: 0 }];
        r.updates = Some(rackhand_proto::probe::UpdateSummary {
            pending: 0,
            security: 0,
            reboot_required: false,
            packages: vec![],
        });
    })
    .await;
    assert_eq!(open(&env), vec![(service, "resolved critical".into()), (updates, "resolved warning".into())]);
}

#[tokio::test(flavor = "multi_thread")]
async fn container_restarts_over_3_in_10_min() {
    let mut env = Env::new("restarts").await;
    for (i, count) in (0..=11u32).enumerate() {
        env.report(M1, T0 + i as i64 * 30_000, |r| {
            r.containers = vec![rackhand_proto::probe::ContainerState {
                id: "c1".into(),
                name: "web".into(),
                restart_count: count,
                ..Default::default()
            }]
        })
        .await;
        let inc = env.incidents();
        match count {
            0..=3 => assert!(inc.is_empty(), "{count} restarts"),
            4..=10 => assert_eq!(inc[0].2, "warning", "{count} restarts"),
            _ => assert_eq!(inc[0].2, "critical", "{count} restarts"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn security_updates_older_than_7_days() {
    let mut env = Env::new("updates").await;
    let pending = |r: &mut Report| {
        r.updates = Some(rackhand_proto::probe::UpdateSummary {
            pending: 5,
            security: 2,
            reboot_required: false,
            packages: vec![],
        })
    };
    env.report(M1, T0, pending).await;
    env.report(M1, T0 + 7 * DAY, |_| {}).await;
    assert!(env.incidents().is_empty(), "7 days isn't older than 7 days");
    env.report(M1, T0 + 8 * DAY, |_| {}).await;
    assert_eq!(env.incidents()[0].2, "warning");
    env.report(M1, T0 + 15 * DAY, |_| {}).await;
    assert_eq!(env.incidents()[0].2, "critical");
    env.report(M1, T0 + 15 * DAY + MIN, |r| {
        r.updates = Some(rackhand_proto::probe::UpdateSummary {
            pending: 0,
            security: 0,
            reboot_required: false,
            packages: vec![],
        })
    })
    .await;
    assert_eq!(env.incidents()[0].1, "resolved", "installed");
}
