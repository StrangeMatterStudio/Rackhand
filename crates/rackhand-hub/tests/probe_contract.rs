//! The `rackhand/probe/1` contract (7.3.2): the probe's link and the hub's probe server over real endpoints.

#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use rackhand_hub::bus::Bus;
use rackhand_hub::ingest::probe_server::{ProbeDirectory, ProbeServer, ServerSettings};
use rackhand_hub::ingest::{DiskSpace, Ingest};
use rackhand_net::registry::MemoryRegistry;
use rackhand_probe::buffer::epoch::EpochState;
use rackhand_probe::buffer::segments::{Buffer, Limits};
use rackhand_probe::link::{Link, LinkConfig, Session, Stop};
use rackhand_proto::alpn;
use rackhand_proto::common::LabelEntry;
use rackhand_proto::probe::{Report, Sample};
use rackhand_store::Db;
use rackhand_store::ids::now_ms;

#[derive(Debug)]
struct Roomy;

impl DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

/// Which machine each probe endpoint is enrolled as.
#[derive(Debug, Default)]
struct Directory(Mutex<HashMap<EndpointId, [u8; 16]>>);

impl ProbeDirectory for Directory {
    fn machine_of(&self, endpoint: &EndpointId) -> Option<[u8; 16]> {
        self.0.lock().unwrap().get(endpoint).copied()
    }
}

struct Env {
    db: Arc<Db>,
    ingest: Ingest,
    registry: Arc<MemoryRegistry>,
    directory: Arc<Directory>,
    addr: EndpointAddr,
    relay_url: iroh::RelayUrl,
    dir: std::path::PathBuf,
    server: ProbeServer,
    _relay: iroh_relay::server::Server,
    _hub: Endpoint,
}

const M1: [u8; 16] = [1; 16];
const M2: [u8; 16] = [2; 16];

fn text(id: [u8; 16]) -> String {
    ulid::Ulid::from_bytes(id).to_string()
}

async fn env(name: &str, settings: ServerSettings) -> Env {
    let dir = std::env::temp_dir().join(format!("rackhand-probe-contract-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    let (relay, relay_url) = rackhand_net::testing::local_relay().await;
    let hub = rackhand_net::testing::endpoint(&relay_url, &[alpn::PROBE]).await;
    let registry = Arc::new(MemoryRegistry::default());
    let directory = Arc::new(Directory::default());
    let server = ProbeServer::new(ingest.clone(), directory.clone(), settings);
    let router = rackhand_net::router::Router::new(hub.clone(), registry.clone()).route(alpn::PROBE, server.handler());
    tokio::spawn(router.serve());
    let mut addr = hub.addr();
    addr.addrs.insert(TransportAddr::Relay(relay_url.clone()));
    Env { db, ingest, registry, directory, addr, relay_url, dir, server, _relay: relay, _hub: hub }
}

impl Env {
    /// A probe enrolled as `machine`, with an empty buffer (a new epoch).
    async fn probe(&self, name: &str, machine: [u8; 16]) -> Link {
        self.probe_with(name, machine, None, "0.1.0").await
    }

    async fn probe_with(&self, name: &str, machine: [u8; 16], backlog: Option<(u64, u64)>, version: &str) -> Link {
        let endpoint = rackhand_net::testing::endpoint(&self.relay_url, &[]).await;
        self.registry.allow(alpn::PROBE, endpoint.id());
        self.directory.0.lock().unwrap().insert(endpoint.id(), machine);
        let buffer = Buffer::open(&self.dir.join(format!("buffer-{name}")), Limits::default(), now_ms()).unwrap();
        let cfg = LinkConfig::new(self.addr.clone(), machine, version);
        Link::new(endpoint, cfg, buffer, EpochState::start(backlog))
    }

    fn count(&self, sql: &str) -> i64 {
        self.db.readers().with(|c| c.query_row(sql, [], |r| r.get(0))).unwrap()
    }

    fn events(&self, kind: &str) -> Vec<(String, serde_json::Value)> {
        self.db
            .readers()
            .with(|c| {
                let mut s = c.prepare("SELECT severity, data FROM events WHERE kind = ?1 ORDER BY at_ms")?;
                s.query_map([kind], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap()
            .into_iter()
            .map(|(s, d)| (s, serde_json::from_str(&d).unwrap()))
            .collect()
    }
}

fn table() -> Vec<LabelEntry> {
    vec![LabelEntry { id: 0, labels: BTreeMap::new() }]
}

/// The next report of the probe's epoch: one `cpu.busy_pct` sample.
fn report(link: &mut Link, sampled_at_ms: i64, cpu: f64) -> Report {
    Report {
        epoch: link.epoch(),
        seq: link.next_seq(),
        sampled_at_ms,
        vitals: vec![Sample { metric: 1, labels_id: 0, value: cpu }],
        ..Default::default()
    }
}

const WAIT: Duration = Duration::from_secs(10);

async fn connect(link: &mut Link) -> Session {
    link.connect(&table(), now_ms()).await.unwrap()
}

/// Waits until every buffered report has been acked.
async fn drained(link: &mut Link, s: &mut Session) {
    link.read_acks(s, |b| b.is_empty(), WAIT).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn hello_welcome_ack_round_trip() {
    let env = env("ack", ServerSettings::default()).await;
    let mut link = env.probe("ack", M1).await;
    let mut s = connect(&mut link).await;
    assert_eq!(s.welcome.hub_version.as_ref().map(|v| v.version.as_str()), Some("0.1.0"));
    let r = report(&mut link, now_ms(), 5.0);
    link.send_live(&mut s, r, now_ms()).await.unwrap();
    assert!(!link.buffer.is_empty(), "kept until acked");
    drained(&mut link, &mut s).await;
    // the ack came after the staging commit, so the row is there the moment the probe deletes its copy
    assert_eq!(env.count("SELECT count(*) FROM report_staging"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_seq_is_dropped() {
    let env = env("dup", ServerSettings::default()).await;
    let mut link = env.probe("dup", M1).await;
    let mut s = connect(&mut link).await;
    let r = report(&mut link, now_ms(), 5.0);
    link.send_live(&mut s, r.clone(), now_ms()).await.unwrap();
    drained(&mut link, &mut s).await;
    // sent again without buffering it, as after a lost ack
    s.send_report(&r).await.unwrap();
    let next = report(&mut link, now_ms(), 6.0);
    link.send_live(&mut s, next, now_ms()).await.unwrap();
    drained(&mut link, &mut s).await;
    assert_eq!(env.count("SELECT count(*) FROM report_staging"), 2, "seq 1 once, seq 2 once");
}

#[tokio::test(flavor = "multi_thread")]
async fn live_and_replay_streams_interleave() {
    let env = env("interleave", ServerSettings::default()).await;
    let mut link = env.probe("interleave", M1).await;
    let t = now_ms() - 600_000;
    for i in 0..5 {
        let r = report(&mut link, t + i * 15_000, i as f64);
        link.queue(&r, now_ms()).unwrap();
    }
    let mut s = connect(&mut link).await;
    for i in 0..3 {
        let r = report(&mut link, now_ms() + i, 10.0 + i as f64);
        link.send_live(&mut s, r, now_ms()).await.unwrap();
    }
    assert_eq!(link.replay(&mut s).await.unwrap(), 5, "the backlog goes on stream 2");
    drained(&mut link, &mut s).await;
    assert_eq!(env.count("SELECT count(*) FROM report_staging"), 8);
    assert_eq!(env.count("SELECT count(DISTINCT seq) FROM report_staging"), 8);
}

#[tokio::test(flavor = "multi_thread")]
async fn rollback_epoch_accepted_at_once() {
    let env = env("rollback", ServerSettings::default()).await;
    let mut link = env.probe("rollback-a", M1).await;
    let epoch = link.epoch();
    let mut s = connect(&mut link).await;
    for _ in 0..3 {
        let r = report(&mut link, now_ms(), 1.0);
        link.send_live(&mut s, r, now_ms()).await.unwrap();
    }
    drained(&mut link, &mut s).await;
    drop(s);
    // the guest goes back to a snapshot taken after seq 1: same epoch, next seq 2, which the hub already holds
    let mut rolled = env.probe_with("rollback-b", M1, Some((epoch, 1)), "0.1.0").await;
    let mut s = connect(&mut rolled).await;
    assert_ne!(rolled.epoch(), epoch, "a new epoch at once");
    assert!(rolled.epoch_changed(), "recorded as probe.epoch_changed");
    let r = report(&mut rolled, now_ms(), 2.0);
    rolled.send_live(&mut s, r, now_ms()).await.unwrap();
    drained(&mut rolled, &mut s).await;
    let new_epoch = rolled.epoch() as i64;
    assert_eq!(env.count(&format!("SELECT count(*) FROM report_staging WHERE epoch = {new_epoch} AND seq = 1")), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn label_set_first_seen_during_outage_resolves() {
    let env = env("labels", ServerSettings::default()).await;
    let mut link = env.probe("labels", M1).await;
    let mut s = connect(&mut link).await;
    let mut r = report(&mut link, now_ms(), 1.0);
    r.label_sets = vec![LabelEntry { id: 1, labels: BTreeMap::from([("mount".into(), "/data".into())]) }];
    r.vitals.push(Sample { metric: 16, labels_id: 1, value: 4096.0 });
    link.send_live(&mut s, r, now_ms()).await.unwrap();
    drained(&mut link, &mut s).await;
    env.ingest.compact().await.unwrap();
    let stored = env.count(
        "SELECT count(*) FROM series_chunks sc JOIN metric_keys mk ON mk.id = sc.metric_key_id
         WHERE mk.name = 'disk.used_bytes' AND mk.label_set = '{\"mount\":\"/data\"}'",
    );
    assert_eq!(stored, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_label_id_drops_sample_keeps_report() {
    let env = env("unknown", ServerSettings::default()).await;
    let mut link = env.probe("unknown", M1).await;
    let mut s = connect(&mut link).await;
    let mut r = report(&mut link, now_ms(), 1.0);
    r.vitals.push(Sample { metric: 16, labels_id: 99, value: 4096.0 });
    link.send_live(&mut s, r, now_ms()).await.unwrap();
    drained(&mut link, &mut s).await;
    env.ingest.compact().await.unwrap();
    assert_eq!(env.count("SELECT count(*) FROM metric_keys WHERE name = 'cpu.busy_pct'"), 1, "the rest is stored");
    assert_eq!(env.count("SELECT count(*) FROM metric_keys WHERE name = 'disk.used_bytes'"), 0);
    let events = env.events("probe.unknown_labels");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].1["dropped"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_decompression_closes_0x15() {
    let env = env("oversized", ServerSettings::default()).await;
    let mut link = env.probe("oversized", M1).await;
    let mut s = connect(&mut link).await;
    // 17 MB of zeros compresses to a small frame that expands past the 16 MB limit
    let bomb = rackhand_proto::zstd::compress(&vec![0u8; 17 * 1024 * 1024]).unwrap();
    s.send_live_frame(&bomb).await.unwrap();
    let stop = link.read_acks(&mut s, |_| false, WAIT).await.unwrap_err();
    assert_eq!(stop, Stop::TooLarge);
    assert_eq!(env.count("SELECT count(*) FROM report_staging"), 0, "nothing staged");
}

#[tokio::test(flavor = "multi_thread")]
async fn data_dropped_closes_gap_and_records_event() {
    let env = env("dropped", ServerSettings::default()).await;
    let mut link = env.probe("dropped", M1).await;
    let mut s = connect(&mut link).await;
    let r = report(&mut link, now_ms(), 1.0);
    link.send_live(&mut s, r, now_ms()).await.unwrap();
    // seqs 2 to 4 were deleted unsent (buffer full)
    for _ in 0..3 {
        link.next_seq();
    }
    s.data_dropped(link.epoch(), 2, 4).await.unwrap();
    let r = report(&mut link, now_ms(), 1.0);
    link.send_live(&mut s, r, now_ms()).await.unwrap();
    drained(&mut link, &mut s).await;
    assert_eq!(link.last_ack(), Some((link.epoch(), vec![(1, 5)])), "one range with the gap closed");
    let events = env.events("probe.data_gap");
    assert_eq!(events.len(), 1);
    assert_eq!((events[0].1["from_seq"].clone(), events[0].1["to_seq"].clone()), (2.into(), 4.into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn more_than_64_ranges_closes_oldest_gap() {
    let env = env("ranges", ServerSettings::default()).await;
    let mut link = env.probe("ranges", M1).await;
    let t = now_ms() - 3_600_000;
    // odd seqs only: 65 ranges with a one-seq gap after each
    for i in 1..=129u64 {
        let r = report(&mut link, t + i as i64 * 15_000, 1.0);
        if i % 2 == 1 {
            link.queue(&r, now_ms()).unwrap();
        }
    }
    let mut s = connect(&mut link).await;
    assert_eq!(link.replay(&mut s).await.unwrap(), 65);
    drained(&mut link, &mut s).await;
    let events = env.events("probe.data_gap");
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!((events[0].1["from_seq"].clone(), events[0].1["to_seq"].clone()), (2.into(), 2.into()));
    // seq 2 arrives after its gap was closed: dropped
    let late = Report { seq: 2, epoch: link.epoch(), sampled_at_ms: t + 30_000, ..Default::default() };
    s.send_report(&late).await.unwrap();
    // seq 4 is still an open gap: stored
    let open = Report { seq: 4, epoch: link.epoch(), sampled_at_ms: t + 60_000, ..Default::default() };
    s.send_report(&open).await.unwrap();
    link.read_acks(&mut s, |_| false, Duration::from_secs(2)).await.ok();
    assert_eq!(env.count("SELECT count(*) FROM report_staging WHERE seq = 2"), 0);
    assert_eq!(env.count("SELECT count(*) FROM report_staging WHERE seq = 4"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn second_probe_with_same_machine_id_gets_0x11() {
    let env = env("identity", ServerSettings::default()).await;
    let mut first = env.probe("identity-a", M1).await;
    let _s = connect(&mut first).await;
    // another enrolled probe (machine 2) says it is machine 1
    let mut second = env.probe("identity-b", M2).await;
    second.set_machine_id(M1);
    let stop = second.connect(&table(), now_ms()).await.unwrap_err();
    assert_eq!(stop, Stop::IdentityMismatch);
    let events = env.events("probe.identity_conflict");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, "critical");
    assert_eq!(events[0].1["machine_id"], text(M1));
}

#[tokio::test(flavor = "multi_thread")]
async fn stream1_over_rate_closes_0x14() {
    let env = env("rate", ServerSettings::default()).await;
    let mut link = env.probe("rate", M1).await;
    let mut s = connect(&mut link).await;
    // straight onto stream 1 (no buffer writes), until the hub closes it: a loaded machine can't slow the burst
    // below the refill of one report a second and so never cross the limit
    let started = std::time::Instant::now();
    for _ in 0..50 {
        let r = report(&mut link, now_ms(), 1.0);
        if s.send_report(&r).await.is_err() {
            break;
        }
    }
    let stop = link.read_acks(&mut s, |_| false, WAIT).await.unwrap_err();
    assert_eq!(stop, Stop::RateLimited);
    let refill = started.elapsed().as_secs() as i64 + 1;
    let staged = env.count("SELECT count(*) FROM report_staging");
    assert!((10..=10 + refill).contains(&staged), "a burst of 10 is allowed, then one a second: {staged}");
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_probe_gets_0x13_and_exits_3() {
    let env = env("revoked", ServerSettings::default()).await;
    let mut link = env.probe("revoked", M1).await;
    env.registry.revoke(link.endpoint_id());
    let stop = link.connect(&table(), now_ms()).await.unwrap_err();
    assert_eq!(stop, Stop::Revoked);
    assert_eq!(stop.exit_code(), Some(3), "the probe stops and exits with code 3");
}

#[tokio::test(flavor = "multi_thread")]
async fn unsupported_version_keeps_buffering() {
    let settings = ServerSettings { supports: Arc::new(|v: &str| v != "0.0.1"), ..ServerSettings::default() };
    let env = env("version", settings).await;
    let mut link = env.probe_with("version", M1, None, "0.0.1").await;
    let r = report(&mut link, now_ms(), 1.0);
    link.queue(&r, now_ms()).unwrap();
    let stop = link.connect(&table(), now_ms()).await.unwrap_err();
    assert_eq!(stop, Stop::Unsupported);
    assert_eq!(stop.exit_code(), None, "it keeps running");
    assert!(!link.buffer.is_empty(), "and keeps its reports");
    assert_eq!(stop.retry_after(0, 0.5), Duration::from_secs(3_600), "retried hourly");
    assert_eq!(Stop::Disconnected("x".into()).retry_after(10, 0.0), Duration::from_secs(60), "others back off to 60 s");
    assert_eq!(env.ingest.latest(&text(M1)), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_check_round_trip() {
    use rackhand_hub::actions::runner::{StepCtx, StepOutcome, StepRunner};
    use rackhand_probe::link::Incoming;
    use rackhand_proto::probe::CheckResult;
    let env = env("probe-check", ServerSettings::default()).await;
    let checks = env.server.probe_checks();
    let ctx = StepCtx {
        job_id: "j1".into(),
        machine_id: text(M1),
        machine_kind: "linux".into(),
        address: None,
        identity: rackhand_runbook::runbook::Identity::Automation,
        timeout: Duration::from_secs(5),
    };
    let step: rackhand_runbook::runbook::Step = toml::from_str(
        "id = \"local\"
kind = \"probe_check\"
checks = [\"tcp:127.0.0.1:5432\", \"http:http://127.0.0.1:8080/health\"]
",
    )
    .unwrap();
    // no probe connected for the machine
    assert_eq!(checks.run(&ctx, &step, None).await.outcome, StepOutcome::Failed("probe_not_connected".into()));
    let mut link = env.probe("probe-check", M1).await;
    let mut s = connect(&mut link).await;
    let run = {
        let (checks, ctx, step) = (checks.clone(), ctx.clone(), step.clone());
        tokio::spawn(async move { checks.run(&ctx, &step, None).await })
    };
    // the probe answers each RunCheck on stream 0: the TCP check passes, the HTTP one doesn't
    let mut asked = Vec::new();
    while asked.len() < 2 {
        let msg = tokio::time::timeout(WAIT, s.next_message()).await.unwrap().unwrap();
        if let Incoming::RunCheck(rc) = link.on_message(msg).unwrap() {
            assert!(rc.timeout_ms > 0 && rc.timeout_ms <= 5000, "{}", rc.timeout_ms);
            let ok = rc.check.starts_with("tcp:");
            let detail = if ok { "accepts connections" } else { "status 503, expected 200" };
            asked.push(rc.check.clone());
            s.check_result(CheckResult { id: rc.id, ok, detail: detail.into(), latency_ms: 1.5 }).await.unwrap();
        }
    }
    let result = run.await.unwrap();
    assert_eq!(asked, vec!["tcp:127.0.0.1:5432".to_string(), "http:http://127.0.0.1:8080/health".to_string()]);
    assert_eq!(result.outcome, StepOutcome::Failed("http:http://127.0.0.1:8080/health".into()));
    assert!(String::from_utf8_lossy(&result.stderr).contains("status 503"));
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("tcp:127.0.0.1:5432 passed"),
        "the passed ones are listed"
    );
}
