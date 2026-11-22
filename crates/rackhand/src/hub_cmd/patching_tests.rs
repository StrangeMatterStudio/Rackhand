use std::collections::BTreeMap;

use rackhand_hub::bus::Bus;
use rackhand_hub::ingest::{DiskSpace, Stream};
use rackhand_proto::common::LabelEntry;
use rackhand_proto::probe::{Report, Sample, UpdateSummary};
use rackhand_store::ids::now_ms;
use rackhand_store::{Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use super::*;

const M: &str = "01JD0000000000000000000021";

#[derive(Debug)]
struct Roomy;

impl DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

async fn machines(name: &str) -> Machines {
    let dir = std::env::temp_dir().join(format!("rackhand-hub-patching-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let machine = |id: &str, kind: &str, roles: &str, policy: Option<&str>| {
        let mut row = Row::from([
            ("id", t(id)),
            ("site_id", t("s")),
            ("name", t(id)),
            ("kind", t(kind)),
            ("roles", t(roles)),
            ("state", t("enrolled")),
        ]);
        if let Some(p) = policy {
            row.insert("policy_id", t(p));
        }
        RowWrite::insert("machines", row)
    };
    let policy = |id: &str, auto: i64| {
        RowWrite::insert("policies", Row::from([("id", t(id)), ("name", t(id)), ("auto_reboot", Value::Integer(auto))]))
    };
    let window =
        Row::from([("id", t("w")), ("tag", t("db")), ("rrule", t("daily 00:00 1440m")), ("timezone", t("UTC"))]);
    db.writer()
        .send(WriteCmd::Batch(vec![
            RowWrite::insert("sites", Row::from([("id", t("s")), ("name", t("home")), ("timezone", t("UTC"))])),
            policy("yes", 1),
            policy("no", 0),
            machine(M, "linux", "[]", Some("yes")),
            machine("held", "linux", "[]", Some("no")),
            machine("plain", "linux", "[]", None),
            machine("desk", "linux", "[\"desktop\"]", None),
            RowWrite::insert("windows", window),
        ]))
        .await
        .unwrap();
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    ingest.hello(M, 1, &[LabelEntry { id: 1, labels: BTreeMap::new() }]).await.unwrap();
    Machines { db, ingest }
}

/// A report sampled at `at` from a machine up for `uptime_s`.
async fn report(m: &Machines, seq: u64, at: i64, uptime_s: f64, updates: Option<(u32, u32)>) {
    let updates = updates.map(|(security, pending)| UpdateSummary {
        pending,
        security,
        reboot_required: false,
        packages: vec![],
    });
    let vitals = vec![Sample { metric: 30, labels_id: 1, value: uptime_s }];
    let r = Report { epoch: 1, seq, sampled_at_ms: at, vitals, updates, ..Default::default() };
    m.ingest.receive(M, Stream::Live, vec![r], 100, at).await.unwrap();
}

/// What a patch window asks: heard from lately, updates pending from its last summary, in a maintenance window by tag.
#[tokio::test(flavor = "multi_thread")]
async fn window_facts_from_reports_and_maintenance() {
    let m = machines("world").await;
    let now = now_ms();
    assert!(!m.online(M, now), "never heard from");
    assert_eq!(m.pending(M), (0, 0));
    report(&m, 1, now, 1000.0, Some((2, 5))).await;
    assert!(m.online(M, now + 30_000));
    assert!(!m.online(M, now + 5 * 60_000), "silent");
    assert_eq!(m.pending(M), (2, 5));
    assert!(m.in_maintenance(M, &["db".into()], now));
    assert!(!m.in_maintenance(M, &[], now));
}

/// What the reboot step asks: the policy's `auto_reboot`, the 7.5.3 defaults without a policy, and whether a report since
/// came from a machine that started after the reboot was asked for.
#[tokio::test(flavor = "multi_thread")]
async fn reboot_facts_from_the_policy_and_uptime() {
    let m = machines("reboot").await;
    assert!(m.auto_reboot(M) && !m.auto_reboot("held"), "the policy decides");
    assert!(m.auto_reboot("plain") && !m.auto_reboot("desk"), "the defaults without one");
    assert!(!m.auto_reboot("nope"));
    let asked = now_ms() - 300_000;
    assert!(!m.reported_since(M, asked));
    report(&m, 1, asked + 10_000, 86_400.0, None).await;
    assert!(m.reported_since(M, asked), "still up as it goes down");
    assert!(!m.back_since(M, asked), "it hasn't started again");
    report(&m, 2, asked + 90_000, 25.0, None).await;
    assert!(m.back_since(M, asked), "up 25 s, 90 s after the reboot was asked for");
    assert!(!m.back_since(M, asked + 120_000), "no report since");
}
