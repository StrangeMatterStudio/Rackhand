//! The probe daemon (`rackhand_probe::run`, 7.3.2) against the hub's probe server over real endpoints.

#![allow(clippy::unwrap_used)]

mod probe {
    use std::collections::{BTreeMap, HashMap};
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use iroh::{EndpointAddr, EndpointId, TransportAddr};
    use rackhand_hub::bus::Bus;
    use rackhand_hub::ingest::probe_server::{ProbeDirectory, ProbeServer, ServerSettings};
    use rackhand_hub::ingest::{DiskSpace, Ingest};
    use rackhand_net::registry::MemoryRegistry;
    use rackhand_probe::buffer::epoch::EpochState;
    use rackhand_probe::buffer::labels::LabelTable;
    use rackhand_probe::buffer::segments::{Buffer, Limits};
    use rackhand_probe::collect::{Host, RootHost};
    use rackhand_probe::link::{Link, LinkConfig};
    use rackhand_probe::run::{Clock, Daemon, Options, Settings, SystemClock};
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

    #[derive(Debug, Default)]
    struct Directory(Mutex<HashMap<EndpointId, [u8; 16]>>);

    impl ProbeDirectory for Directory {
        fn machine_of(&self, endpoint: &EndpointId) -> Option<[u8; 16]> {
            self.0.lock().unwrap().get(endpoint).copied()
        }
    }

    /// Sleeps are recorded and pass a thousand times faster.
    #[derive(Debug, Default)]
    struct FastClock {
        now: AtomicI64,
        sleeps: Mutex<Vec<Duration>>,
    }

    impl Clock for FastClock {
        fn now_ms(&self) -> i64 {
            now_ms() + self.now.load(Ordering::SeqCst)
        }
        fn mono_ms(&self) -> i64 {
            self.now.load(Ordering::SeqCst)
        }
        fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            self.sleeps.lock().unwrap().push(d);
            self.now.fetch_add(d.as_millis() as i64, Ordering::SeqCst);
            Box::pin(tokio::time::sleep((d / 1000).max(Duration::from_millis(1))))
        }
    }

    const M1: [u8; 16] = [1; 16];

    fn text(id: [u8; 16]) -> String {
        ulid::Ulid::from_bytes(id).to_string()
    }

    struct Env {
        ingest: Ingest,
        db: Arc<Db>,
        registry: Arc<MemoryRegistry>,
        directory: Arc<Directory>,
        addr: EndpointAddr,
        relay_url: iroh::RelayUrl,
        dir: PathBuf,
        _relay: iroh_relay::server::Server,
        _hub: iroh::Endpoint,
    }

    async fn env(name: &str, settings: ServerSettings) -> Env {
        env_with(name, settings, rackhand_hub::ingest::ReplayLimits::default()).await
    }

    async fn env_with(name: &str, settings: ServerSettings, limits: rackhand_hub::ingest::ReplayLimits) -> Env {
        let dir = std::env::temp_dir().join(format!("rackhand-probe-daemon-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
        let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy)).with_limits(limits);
        let (relay, relay_url) = rackhand_net::testing::local_relay().await;
        let hub = rackhand_net::testing::endpoint(&relay_url, &[alpn::PROBE]).await;
        let registry = Arc::new(MemoryRegistry::default());
        let directory = Arc::new(Directory::default());
        let server = ProbeServer::new(ingest.clone(), directory.clone(), settings);
        let router =
            rackhand_net::router::Router::new(hub.clone(), registry.clone()).route(alpn::PROBE, server.handler());
        tokio::spawn(router.serve());
        let mut addr = hub.addr();
        addr.addrs.insert(TransportAddr::Relay(relay_url.clone()));
        Env { ingest, db, registry, directory, addr, relay_url, dir, _relay: relay, _hub: hub }
    }

    fn fixture() -> Arc<dyn Host + Send + Sync> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/proc/rates/b");
        Arc::new(RootHost::new(root))
    }

    impl Env {
        /// A link for a probe enrolled as `machine`, its buffer in `<dir>/<name>`.
        async fn link(&self, name: &str, backlog: Option<(u64, u64)>, version: &str) -> Link {
            let endpoint = rackhand_net::testing::endpoint(&self.relay_url, &[]).await;
            self.registry.allow(alpn::PROBE, endpoint.id());
            self.directory.0.lock().unwrap().insert(endpoint.id(), M1);
            let buffer = Buffer::open(&self.dir.join(name), Limits::default(), now_ms()).unwrap();
            Link::new(endpoint, LinkConfig::new(self.addr.clone(), M1, version), buffer, EpochState::start(backlog))
        }

        fn options(&self, name: &str, clock: Arc<dyn Clock>) -> Options {
            Options {
                host: fixture(),
                settings: Settings::default(),
                data_dir: self.dir.join(name),
                state_file: Some(self.dir.join(format!("{name}.state"))),
                version: "0.1.0".into(),
                clock,
                jitter: Arc::new(|| 0.0),
                helper: None,
            }
        }

        fn state(&self, name: &str) -> serde_json::Value {
            std::fs::read(self.dir.join(format!("{name}.state")))
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default()
        }

        fn count(&self, sql: &str) -> i64 {
            self.db.readers().with(|c| c.query_row(sql, [], |r| r.get(0))).unwrap()
        }
    }

    async fn until(what: &str, f: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !f() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn revoked_daemon_exits_3() {
        let env = env("revoked", ServerSettings::default()).await;
        let link = env.link("revoked", None, "0.1.0").await;
        env.registry.revoke(link.endpoint_id());
        let daemon = Daemon::new(link, env.options("revoked", Arc::new(SystemClock::default()))).unwrap();
        let code = tokio::time::timeout(Duration::from_secs(20), daemon.run()).await.expect("the daemon stops");
        assert_eq!(code, 3, "0x13: the probe stops with exit code 3");
        assert_eq!(env.state("revoked")["state"], "stopped");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unsupported_version_retries_hourly() {
        let settings = ServerSettings { supports: Arc::new(|v: &str| !v.starts_with("99.")), ..Default::default() };
        let env = env("unsupported", settings).await;
        let link = env.link("unsupported", None, "99.0.0").await;
        let clock = Arc::new(FastClock::default());
        let daemon = Daemon::new(link, env.options("unsupported", clock.clone())).unwrap();
        let task = tokio::spawn(daemon.run());
        until("an hourly retry", || clock.sleeps.lock().unwrap().contains(&Duration::from_secs(3_600))).await;
        let s = env.state("unsupported");
        assert_eq!((s["state"].as_str(), s["retry_in_ms"].as_u64()), (Some("disconnected"), Some(3_600_000)), "{s}");
        // the hour passes (fast): collection went on into the buffer, and the probe tries again
        until("the reports collected during the hour", || {
            env.state("unsupported")["buffered"].as_u64().unwrap_or(0) >= 100
        })
        .await;
        let hourly = clock.sleeps.lock().unwrap().iter().filter(|d| **d == Duration::from_secs(3_600)).count();
        assert!(hourly >= 2, "and waits another hour after the next 0x12");
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn new_epoch_defines_every_label_set_again() {
        let env = env("epoch", ServerSettings::default()).await;
        // the hub already holds seqs 1 to 5 of this epoch (the guest was rolled back to a snapshot)
        let mut first = env.link("epoch-first", None, "0.1.0").await;
        let epoch = first.epoch();
        let mut s = first.connect(&[LabelEntry { id: 0, labels: BTreeMap::new() }], now_ms()).await.unwrap();
        for _ in 0..5 {
            let r = Report {
                epoch,
                seq: first.next_seq(),
                sampled_at_ms: now_ms(),
                vitals: vec![Sample { metric: 1, labels_id: 0, value: 1.0 }],
                ..Default::default()
            };
            first.send_live(&mut s, r, now_ms()).await.unwrap();
        }
        first.read_acks(&mut s, |b| b.is_empty(), Duration::from_secs(10)).await.unwrap();
        // the restored probe has a label table for that epoch, and a buffer that ends at seq 2
        let link = env.link("epoch", Some((epoch, 2)), "0.1.0").await;
        let mut old = LabelTable::open(&env.dir.join("epoch"), epoch).unwrap();
        for i in 0..8 {
            old.id_for(&BTreeMap::from([("old".to_string(), i.to_string())]));
        }
        let daemon = Daemon::new(link, env.options("epoch", Arc::new(SystemClock::default()))).unwrap();
        let task = tokio::spawn(daemon.run());
        let m = text(M1);
        until("the new epoch's disk series", || env.ingest.window_series(&m, "disk.used_pct").len() == 2).await;
        task.abort();
        env.ingest.compact().await.unwrap();
        let unknown = env.count("SELECT count(*) FROM events WHERE kind = 'probe.unknown_labels'");
        assert_eq!(unknown, 0, "every sample of the new epoch resolved");
        // every label set the first report uses (no rates yet), defined under the new epoch
        let first_collection = rackhand_probe::collect::collect(
            fixture().as_ref(),
            None,
            now_ms(),
            &Default::default(),
            Default::default(),
        );
        let used: std::collections::BTreeSet<_> = first_collection.series.iter().map(|s| s.labels.clone()).collect();
        let defined = env.count(&format!("SELECT count(*) FROM probe_labels WHERE epoch != {}", epoch as i64));
        assert_eq!(defined, used.len() as i64, "the new epoch's label sets were defined again");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn live_reports_flow_while_replay_is_held_back() {
        // the hub reads stream 2 at one byte a second, so the backlog's stream stalls on flow control
        let limits = rackhand_hub::ingest::ReplayLimits { probe_bps: 1, ..Default::default() };
        let env = env_with("held", ServerSettings::default(), limits).await;
        let mut link = env.link("held", None, "0.1.0").await;
        let epoch = link.epoch();
        LabelTable::open(&env.dir.join("held"), epoch).unwrap().id_for(&BTreeMap::new());
        let uptime = rackhand_proto::catalogue::by_name("uptime_s").unwrap().id;
        let past = now_ms() - 3_600_000;
        // values that don't compress, so the backlog (about 6 MB on the wire) is well past the 1.25 MB stream window
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut noise = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            f64::from_bits((x >> 12) | 0x3ff0_0000_0000_0000)
        };
        for i in 0..300u32 {
            let vitals = (0..2000).map(|_| Sample { metric: uptime, labels_id: 0, value: noise() }).collect();
            let r = Report {
                epoch,
                seq: link.next_seq(),
                sampled_at_ms: past + i64::from(i),
                vitals,
                ..Default::default()
            };
            link.queue(&r, now_ms()).unwrap();
        }
        let mut opts = env.options("held", Arc::new(SystemClock::default()));
        opts.settings.interval = Duration::from_secs(1);
        let daemon = Daemon::new(link, opts).unwrap();
        let task = tokio::spawn(daemon.run());
        // live reports have the seqs after the backlog's 300
        until("three live reports", || env.count("SELECT count(*) FROM report_staging WHERE seq > 300") >= 3).await;
        task.abort();
        let staged = env.count("SELECT count(*) FROM report_staging WHERE seq <= 300");
        assert!(staged < 300, "the backlog is still held back: {staged} of 300 staged");
    }
}
