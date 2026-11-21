use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};

use super::*;

/// A clock whose sleeps are recorded and pass a thousand times faster.
#[derive(Debug, Default)]
pub struct FastClock {
    now: AtomicI64,
    pub sleeps: Mutex<Vec<Duration>>,
}

impl Clock for FastClock {
    fn now_ms(&self) -> i64 {
        1_700_000_000_000 + self.now.load(Ordering::SeqCst)
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

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rackhand-probe-run-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fixture() -> Arc<dyn Host + Send + Sync> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/proc/rates/b");
    Arc::new(collect::RootHost::new(root))
}

/// A daemon whose hub can't be reached: an endpoint id with no address and no relay.
async fn unreachable(name: &str, clock: Arc<FastClock>, jitter: f64) -> (Daemon, PathBuf) {
    let dir = temp(name);
    let key = iroh::SecretKey::from_bytes(&[5; 32]);
    let endpoint = rackhand_net::endpoint::bind(key, &Default::default()).await.unwrap();
    let hub = iroh::EndpointAddr::new(iroh::SecretKey::from_bytes(&[6; 32]).public());
    let buffer =
        crate::buffer::segments::Buffer::open(&dir.join("buffer"), Default::default(), clock.now_ms()).unwrap();
    let link = Link::new(
        endpoint,
        crate::link::LinkConfig::new(hub, [1; 16], "0.1.0"),
        buffer,
        crate::buffer::epoch::EpochState::start(None),
    );
    let state = dir.join("probe.state");
    let opts = Options {
        host: fixture(),
        settings: Settings { interval: Duration::from_secs(299), ..Settings::default() },
        data_dir: dir.join("buffer"),
        state_file: Some(state.clone()),
        version: "0.1.0".into(),
        clock,
        jitter: Arc::new(move || jitter),
        helper: None,
    };
    (Daemon::new(link, opts).unwrap(), state)
}

/// The reconnect waits the clock saw, without the collector's interval.
async fn backoffs(clock: &FastClock, n: usize) -> Vec<f64> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let waits: Vec<f64> = clock
            .sleeps
            .lock()
            .unwrap()
            .iter()
            .filter(|d| **d != Duration::from_secs(299))
            .map(|d| d.as_secs_f64())
            .collect();
        if waits.len() >= n || Instant::now() > deadline {
            return waits.into_iter().take(n).collect();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn backoff_from_1s_to_60s_with_jitter() {
    let clock = Arc::new(FastClock::default());
    let (daemon, state) = unreachable("backoff", clock.clone(), 0.0).await;
    let task = tokio::spawn(daemon.run());
    assert_eq!(backoffs(&clock, 8).await, vec![1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 60.0, 60.0], "doubling to 60 s");
    let s: serde_json::Value = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    assert!(["connecting", "disconnected"].contains(&s["state"].as_str().unwrap()), "{s}");
    task.abort();

    // full jitter takes a quarter off each wait
    let clock = Arc::new(FastClock::default());
    let (daemon, _) = unreachable("jitter", clock.clone(), 1.0).await;
    let task = tokio::spawn(daemon.run());
    assert_eq!(backoffs(&clock, 7).await, vec![0.75, 1.5, 3.0, 6.0, 12.0, 24.0, 45.0]);
    task.abort();
}

#[tokio::test]
async fn disconnected_reports_are_buffered() {
    let clock = Arc::new(FastClock::default());
    let (mut daemon, state) = unreachable("buffered", clock.clone(), 0.0).await;
    daemon.opts.settings.interval = Duration::from_secs(5);
    daemon.settings.send_modify(|s| s.interval = Duration::from_secs(5));
    let task = tokio::spawn(daemon.run());
    let deadline = Instant::now() + Duration::from_secs(20);
    let buffered = loop {
        let s: serde_json::Value =
            std::fs::read(&state).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let n = s["buffered"].as_u64().unwrap_or(0);
        if n >= 5 || Instant::now() > deadline {
            break n;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    task.abort();
    assert!(buffered >= 5, "collection goes on while the hub is away: {buffered}");
}

mod helper {
    use super::*;
    use crate::helper::client::HelperClient;
    use crate::helper::server::{Helper, bind, serve};
    use prost::Message;

    /// A helper of `version` on a socket in `dir`, answering this test's user.
    async fn helper(dir: &std::path::Path, version: &str) -> (PathBuf, Arc<Helper>) {
        let path = dir.join("helper.sock");
        let listener = bind(&path, None).unwrap();
        let h = Helper::new(version);
        tokio::spawn(serve(listener, rustix::process::getuid().as_raw(), h.clone()));
        (path, h)
    }

    /// The reports the daemon buffered.
    fn buffered(dir: &std::path::Path) -> Vec<Report> {
        let b =
            crate::buffer::segments::Buffer::open(&dir.join("buffer"), Default::default(), 1_700_000_000_000).unwrap();
        b.pending().map(|r| Report::decode(b.read(r.epoch, r.seq).unwrap().as_slice()).unwrap()).collect()
    }

    async fn run_until(daemon: Daemon, dir: &std::path::Path, reports: usize) -> Vec<Report> {
        let task = tokio::spawn(daemon.run());
        let deadline = Instant::now() + Duration::from_secs(20);
        while buffered(dir).len() < reports && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        task.abort();
        buffered(dir)
    }

    #[tokio::test]
    async fn version_mismatch_reported_by_probe() {
        let clock = Arc::new(FastClock::default());
        let (mut daemon, _) = unreachable("mismatch", clock.clone(), 0.0).await;
        let dir = daemon.opts.data_dir.parent().unwrap().to_path_buf();
        let (path, h) = helper(&dir, "9.9.9").await;
        h.set_updates(
            rackhand_proto::helper::UpdateSummary { pending: 3, security: 1, reboot_required: false, packages: vec![] },
            1,
        );
        daemon.opts.settings.interval = Duration::from_secs(5);
        daemon.settings.send_modify(|s| s.interval = Duration::from_secs(5));
        daemon.opts.helper = Some(HelperClient::new(&path, "0.1.0"));
        let reports = run_until(daemon, &dir, 3).await;
        assert!(reports.len() >= 3);
        let mismatches: Vec<_> =
            reports.iter().flat_map(|r| &r.events).filter(|e| e.kind == "helper_version_mismatch").collect();
        assert_eq!(mismatches.len(), 1, "reported once: {mismatches:?}");
        assert_eq!(mismatches[0].fields.get("helper").map(String::as_str), Some("9.9.9"));
        assert!(
            reports.iter().all(|r| r.updates.is_none() && r.containers.is_empty()),
            "without the helper's features"
        );
    }

    #[tokio::test]
    async fn matching_helper_gives_updates() {
        let clock = Arc::new(FastClock::default());
        let (mut daemon, _) = unreachable("matching", clock.clone(), 0.0).await;
        let dir = daemon.opts.data_dir.parent().unwrap().to_path_buf();
        let (path, h) = helper(&dir, "0.1.0").await;
        h.set_updates(
            rackhand_proto::helper::UpdateSummary {
                pending: 3,
                security: 1,
                reboot_required: true,
                packages: vec!["openssl".into()],
            },
            1,
        );
        daemon.opts.helper = Some(HelperClient::new(&path, "0.1.0"));
        let reports = run_until(daemon, &dir, 2).await;
        let u = reports[0].updates.clone().expect("the helper's update summary");
        assert_eq!((u.pending, u.security, u.reboot_required), (3, 1, true));
        assert!(reports.iter().all(|r| r.events.iter().all(|e| e.kind != "helper_version_mismatch")));
    }
}
