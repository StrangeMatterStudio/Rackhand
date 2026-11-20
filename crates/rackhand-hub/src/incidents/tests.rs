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
                "machines",
                Row::from([
                    ("id", t(M1)),
                    ("site_id", t("s1")),
                    ("name", t("web")),
                    ("kind", t("linux")),
                    ("tags", t("[\"web\"]")),
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
