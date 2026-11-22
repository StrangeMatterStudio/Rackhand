//! A real hub (`rackhand hub run` on the test host) and a probe under its systemd unit in a Debian container (plan
//! T42). The machine is enrolled by writing its row between `hub init` and `hub run`, as a join would; the dashboard
//! is used over HTTPS after first run, and `/metrics` with the token the hub keeps in its Vault.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::support::{Container, binary, musl_binary};

pub const MACHINE: &str = "01JD0000000000000000000042";

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rackhand-it-probe-hub-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn free_port() -> u16 {
    std::net::UdpSocket::bind("0.0.0.0:0").unwrap().local_addr().unwrap().port()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The value of `<input name="<name>" value="...">` in a page.
pub(crate) fn field(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\"");
    let at = html.find(&marker).unwrap_or_else(|| panic!("no field {name}"));
    let tag_start = html[..at].rfind('<').unwrap();
    let tag_end = at + html[at..].find('>').unwrap();
    let tag = &html[tag_start..tag_end];
    let v = tag.find("value=\"").unwrap_or_else(|| panic!("no value for {name}")) + 7;
    tag[v..v + tag[v..].find('"').unwrap()].to_string()
}

pub struct Hub {
    pub dir: PathBuf,
    pub etc: PathBuf,
    pub data: PathBuf,
    pub web: u16,
    pub quic: u16,
    pub setup_code: String,
    /// The hub's endpoint id, as `probe.toml` pins it.
    pub id_hex: String,
    jar: PathBuf,
    child: Option<Child>,
    /// When `start` last ran.
    pub started: Option<Instant>,
}

impl Hub {
    /// `rackhand hub init` into a temporary directory, on free ports.
    pub fn init(name: &str) -> Hub {
        let dir = temp(name);
        let (etc, data) = (dir.join("etc"), dir.join("lib"));
        let out = Command::new(binary("rackhand", "rackhand"))
            .args(["hub", "init", "--config-dir"])
            .arg(&etc)
            .arg("--data-dir")
            .arg(&data)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(out.status.success(), "hub init: {stdout} {}", String::from_utf8_lossy(&out.stderr));
        let setup_code = stdout
            .lines()
            .find_map(|l| l.strip_prefix("Setup code (for the dashboard's first run, once): "))
            .unwrap()
            .trim()
            .to_string();
        let (web, quic) = (free_port(), free_port());
        let toml = etc.join("hub.toml");
        let text = std::fs::read_to_string(&toml).unwrap();
        let text =
            text.replace("0.0.0.0:8443", &format!("0.0.0.0:{web}")).replace("0.0.0.0:7443", &format!("0.0.0.0:{quic}"));
        std::fs::write(&toml, text).unwrap();
        let key: [u8; 32] = std::fs::read(etc.join("node.key")).unwrap().try_into().unwrap();
        let id_hex = hex(iroh::SecretKey::from_bytes(&key).public().as_bytes());
        let jar = dir.join("cookies");
        Hub { dir, etc, data, web, quic, setup_code, id_hex, jar, child: None, started: None }
    }

    /// A hub restored from `file` with `master_key` (`rackhand hub restore`), on the given ports: the same address.
    pub fn restore(name: &str, file: &Path, master_key: &Path, web: u16, quic: u16) -> Hub {
        let dir = temp(name);
        let (etc, data) = (dir.join("etc"), dir.join("lib"));
        let out = Command::new(binary("rackhand", "rackhand"))
            .args(["hub", "restore"])
            .arg(file)
            .arg("--master-key")
            .arg(master_key)
            .arg("--config-dir")
            .arg(&etc)
            .arg("--data-dir")
            .arg(&data)
            .output()
            .unwrap();
        assert!(out.status.success(), "hub restore: {}", String::from_utf8_lossy(&out.stderr));
        let toml = etc.join("hub.toml");
        let text = std::fs::read_to_string(&toml).unwrap();
        let text =
            text.replace("0.0.0.0:8443", &format!("0.0.0.0:{web}")).replace("0.0.0.0:7443", &format!("0.0.0.0:{quic}"));
        std::fs::write(&toml, text).unwrap();
        let key: [u8; 32] = std::fs::read(etc.join("node.key")).unwrap().try_into().unwrap();
        let id_hex = hex(iroh::SecretKey::from_bytes(&key).public().as_bytes());
        let jar = dir.join("cookies");
        Hub { dir, etc, data, web, quic, setup_code: String::new(), id_hex, jar, child: None, started: None }
    }

    /// `rackhand hub backup` while the hub runs; the backup file.
    pub fn backup(&self) -> PathBuf {
        let out = Command::new(binary("rackhand", "rackhand"))
            .args(["hub", "backup", "--config"])
            .arg(self.etc.join("hub.toml"))
            .output()
            .unwrap();
        assert!(out.status.success(), "hub backup: {}", String::from_utf8_lossy(&out.stderr));
        PathBuf::from(String::from_utf8_lossy(&out.stdout).trim())
    }

    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.data.join("hub.db")).unwrap()
    }

    /// Enrolls `machine` with the probe whose node key is `probe_key`, as a join would (before `start`, since the
    /// mesh's admission list is loaded when the hub starts).
    pub fn enroll(&self, machine: &str, probe_key: &[u8; 32]) {
        let endpoint = iroh::SecretKey::from_bytes(probe_key).public().to_string();
        let db = self.db();
        db.execute("INSERT OR IGNORE INTO sites (id, name, timezone) VALUES ('lab-site', 'lab', 'UTC')", []).unwrap();
        db.execute(
            "INSERT INTO machines (id, site_id, name, kind, access, probe_endpoint_id, state) \
             VALUES (?1, 'lab-site', 'web1', 'linux', 'monitor', ?2, 'enrolled')",
            [machine, endpoint.as_str()],
        )
        .unwrap();
    }

    /// `rackhand hub run`, waiting for `/healthz`.
    pub fn start(&mut self) {
        let log = std::fs::OpenOptions::new().create(true).append(true).open(self.dir.join("hub.log")).unwrap();
        let child = Command::new(binary("rackhand", "rackhand"))
            .args(["hub", "run", "--config"])
            .arg(self.etc.join("hub.toml"))
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        self.child = Some(child);
        self.started = Some(Instant::now());
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.curl(&["/healthz"]).trim() != "ok" {
            assert!(Instant::now() < deadline, "the hub didn't start: {}", self.log());
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Stops the hub as its unit would (SIGTERM-like interrupt: staged reports are compacted).
    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = Command::new("kill").args(["-INT", &child.id().to_string()]).status();
            let deadline = Instant::now() + Duration::from_secs(20);
            while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("hub.log")).unwrap_or_default()
    }

    /// `curl` against the dashboard with this hub's cookie jar; the last argument is the path.
    pub fn curl(&self, args: &[&str]) -> String {
        let (path, rest) = args.split_last().unwrap();
        let out = Command::new("curl")
            .args(["-sk", "--max-time", "30", "-b"])
            .arg(&self.jar)
            .arg("-c")
            .arg(&self.jar)
            .args(rest)
            .arg(format!("https://127.0.0.1:{}{path}", self.web))
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    /// The admin's cookies as a `Cookie` header, for a request that names another `Host` (curl matches its jar's
    /// cookies against that name).
    pub fn cookie_header(&self) -> String {
        let jar = std::fs::read_to_string(&self.jar).unwrap_or_default();
        let pairs: Vec<String> = jar
            .lines()
            .filter(|l| !l.is_empty() && (!l.starts_with('#') || l.starts_with("#HttpOnly_")))
            .filter_map(|l| {
                let f: Vec<&str> = l.split('\t').collect();
                (f.len() == 7).then(|| format!("{}={}", f[5], f[6]))
            })
            .collect();
        format!("Cookie: {}", pairs.join("; "))
    }

    /// First run over HTTPS: the admin and the local site; the cookie jar then holds the admin's session.
    pub fn first_run(&self) {
        let page = self.curl(&["/first-run"]);
        let csrf = field(&page, "csrf");
        let form = [
            ("csrf", csrf.as_str()),
            ("setup_code", self.setup_code.as_str()),
            ("admin_name", "admin"),
            ("password", "correct horse battery staple"),
            ("site_name", "home"),
            ("timezone", "UTC"),
        ];
        let mut args: Vec<String> = Vec::new();
        for (k, v) in form {
            args.push("--data-urlencode".into());
            args.push(format!("{k}={v}"));
        }
        args.push("/first-run".into());
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let refused = self.curl(&refs);
        // the second step, open once the details are accepted
        let page = self.curl(&["/first-run/second-factor"]);
        assert!(page.contains("totp_secret"), "first run's details: {refused}");
        let secret = field(&page, "totp_secret");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let code = rackhand_hub::web::totp::code(&rackhand_hub::web::totp::decode_base32(&secret).unwrap(), now);
        let answer = self.curl(&["--data", &format!("csrf={csrf}&totp_code={code}"), "/first-run/second-factor"]);
        assert!(answer.contains("is set up"), "first run: {answer}");
        self.sign_in(&secret);
    }

    /// Signs the admin in: password, then the authenticator code of the next 30-second step (the first run used the
    /// current one, and a code is accepted once).
    fn sign_in(&self, totp_secret: &str) {
        let page = self.curl(&["/sign-in"]);
        let csrf = field(&page, "csrf");
        let form = format!("csrf={csrf}&name=admin&password=correct+horse+battery+staple");
        self.curl(&["--data", &form, "/sign-in"]);
        let page = self.curl(&["/sign-in/code"]);
        let csrf = field(&page, "csrf");
        let next = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64 + 30;
        let code = rackhand_hub::web::totp::code(&rackhand_hub::web::totp::decode_base32(totp_secret).unwrap(), next);
        self.curl(&["--data", &format!("csrf={csrf}&code={code}"), "/sign-in/code"]);
        let overview = self.curl(&["/"]);
        assert!(!overview.is_empty() && !overview.contains("name=\"password\""), "signed in: {overview}");
    }

    /// `GET /metrics` with the token the hub keeps in its Vault (read with the master key, as its admin could).
    pub fn metrics(&self) -> String {
        let token = self.metrics_token();
        self.curl(&["-H", &format!("Authorization: Bearer {token}"), "/metrics"])
    }

    fn metrics_token(&self) -> String {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let key = rackhand_hub::vault::master_key::MasterKey::load(Some(&self.etc.join("master.key"))).unwrap();
            let db = std::sync::Arc::new(rackhand_store::Db::open(&self.data.join("hub.db")).unwrap());
            let vault = rackhand_hub::vault::Vault::new(key, db);
            String::from_utf8_lossy(vault.get("metrics_token").unwrap().expose()).into_owned()
        })
    }

    /// Stores `config/hub.toml` (the hub reads its probe settings when it starts).
    pub fn settings(&self, text: &str) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let db = std::sync::Arc::new(rackhand_store::Db::open(&self.data.join("hub.db")).unwrap());
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
            rackhand_hub::library::config::put(&db, rackhand_hub::library::config::HUB, text, "admin", now)
                .await
                .unwrap();
        });
    }

    /// Stores a revision of `config/<name>.toml`, as the Library or the dashboard would.
    pub fn config(&self, name: &str, text: &str) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let db = std::sync::Arc::new(rackhand_store::Db::open(&self.data.join("hub.db")).unwrap());
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
            rackhand_hub::library::config::put(&db, name, text, "admin", now).await.unwrap();
        });
    }

    /// A read-only look at the hub's database.
    pub fn read_db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open_with_flags(self.data.join("hub.db"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap()
    }

    /// The machine's seqs the hub holds (staged, or kept by compaction), merged into ranges.
    pub fn received(&self) -> Vec<(u64, u64)> {
        let db = self.db();
        let mut seqs: Vec<(u64, u64)> = db
            .prepare("SELECT seq FROM report_staging WHERE machine_id = ?1")
            .unwrap()
            .query_map([MACHINE], |r| r.get::<_, i64>(0))
            .unwrap()
            .map(|s| {
                let s = s.unwrap() as u64;
                (s, s)
            })
            .collect();
        let kept: Vec<String> = db
            .prepare("SELECT ranges FROM probe_ranges WHERE machine_id = ?1")
            .unwrap()
            .query_map([MACHINE], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for k in kept {
            seqs.extend(serde_json::from_str::<Vec<(u64, u64)>>(&k).unwrap_or_default());
        }
        seqs.sort();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (a, b) in seqs {
            match merged.last_mut() {
                Some(last) if a <= last.1 + 1 => last.1 = last.1.max(b),
                _ => merged.push((a, b)),
            }
        }
        merged
    }

    /// When the newest staged report arrived (none right after a compaction).
    pub fn newest_received_ms(&self) -> Option<i64> {
        self.db().query_row("SELECT max(received_at_ms) FROM report_staging", [], |r| r.get(0)).unwrap()
    }

    /// Open incidents: kind and severity.
    pub fn open_incidents(&self) -> Vec<(String, String)> {
        let db = self.db();
        let mut s =
            db.prepare("SELECT kind, severity FROM incidents WHERE state != 'resolved' ORDER BY opened_at").unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
    }

    /// The events of `kind`: their severity and data.
    pub fn events(&self, kind: &str) -> Vec<(String, String)> {
        let db = self.db();
        let mut s = db.prepare("SELECT severity, data FROM events WHERE kind = ?1 ORDER BY at_ms").unwrap();
        s.query_map([kind], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A Debian container with systemd, its probe installed under `packaging/systemd/rackhand-probe.service`, enrolled as
/// `machine` at `hub`. `/data` is a directory of the test host, so the machine has a real mount to report.
pub fn probe_machine(hub: &Hub, probe_key: &[u8; 32], extra: &[&str]) -> Container {
    let data = hub.dir.join("machine-data");
    std::fs::create_dir_all(&data).unwrap();
    let mut args = vec!["-v".to_string(), format!("{}:/data", data.display())];
    args.extend(extra.iter().map(|s| s.to_string()));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let c = Container::start_systemd_with("systemd", &refs);
    c.copy_in(&musl_binary("rackhand-probe", "rackhand-probe"), "/usr/local/lib/rackhand/rackhand-probe");
    let units = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/systemd");
    c.copy_in(&units.join("rackhand-probe.service"), "/etc/systemd/system/rackhand-probe.service");
    c.copy_in(&units.join("rackhand-probe-helper.service"), "/etc/systemd/system/rackhand-probe-helper.service");
    let (_, gateway) = c.ip_and_gateway();
    let toml = format!(
        "[hub]\nid = \"{}\"\naddrs = [\"{gateway}:{}\"]\n\n[machine]\nid = \"{MACHINE}\"\naccess = \"managed\"\n",
        hub.id_hex, hub.quic
    );
    let key = hub.dir.join("probe.key");
    std::fs::write(&key, probe_key).unwrap();
    std::fs::write(hub.dir.join("probe.toml"), toml).unwrap();
    c.copy_in(&hub.dir.join("probe.toml"), "/etc/rackhand-probe/probe.toml");
    let setup = "useradd -r -s /usr/sbin/nologin rackhand-probe \
        && chmod 0755 /usr/local/lib/rackhand/rackhand-probe && chmod 0644 /etc/rackhand-probe/probe.toml \
        && install -d -o rackhand-probe -g rackhand-probe -m 0700 /var/lib/rackhand-probe";
    assert!(c.root(setup).status.success(), "probe user and directories");
    c.copy_in(&key, "/var/lib/rackhand-probe/node.key");
    assert!(
        c.root("chown rackhand-probe: /var/lib/rackhand-probe/node.key && chmod 0600 /var/lib/rackhand-probe/node.key")
            .status
            .success()
    );
    let started = c.root("systemctl daemon-reload && systemctl start rackhand-probe-helper rackhand-probe");
    assert!(started.status.success(), "start: {}", String::from_utf8_lossy(&started.stderr));
    c
}

/// Waits until `f` holds, failing with `what` after `limit`.
pub fn within(limit: Duration, what: &str, mut f: impl FnMut() -> bool) -> Duration {
    let start = Instant::now();
    while !f() {
        assert!(start.elapsed() < limit, "not within {limit:?}: {what}");
        std::thread::sleep(Duration::from_millis(500));
    }
    start.elapsed()
}

/// Every metric name in `/metrics` for the machine.
fn metric_names(metrics: &str) -> std::collections::BTreeSet<String> {
    metrics
        .lines()
        .filter(|l| !l.starts_with('#') && l.contains("machine=\"web1\""))
        .filter_map(|l| l.split('{').next())
        .map(|n| n.trim_start_matches("rackhand_").to_string())
        .collect()
}

#[test]
fn vitals_visible_within_30s() {
    let mut hub = Hub::init("vitals");
    let key = [42u8; 32];
    hub.enroll(MACHINE, &key);
    hub.start();
    hub.first_run();
    let machine = probe_machine(&hub, &key, &[]);
    // the metrics a Debian machine with one mount and one interface reports (7.4.2), but `temp.c`
    let expected: Vec<&str> = rackhand_proto::catalogue::METRICS
        .iter()
        .map(|m| m.name)
        .filter(|n| !["temp.c", "cpu.core_busy_pct"].contains(n))
        .collect();
    let start = Instant::now();
    let missing = loop {
        let names = metric_names(&hub.metrics());
        let missing: Vec<&str> = expected.iter().copied().filter(|n| !names.contains(&n.replace('.', "_"))).collect();
        if missing.is_empty() || start.elapsed() > Duration::from_secs(30) {
            break missing;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    if !missing.is_empty() {
        let m = hub.metrics();
        let probe = machine.root(
            "cat /run/rackhand-probe/probe.state; systemctl status rackhand-probe --no-pager; journalctl -u rackhand-probe --no-pager | tail -20",
        );
        panic!(
            "not on /metrics within 30 s: {missing:?}\n/metrics ({} bytes): {}\nprobe: {}{}\nhub: {}",
            m.len(),
            &m[..m.len().min(400)],
            String::from_utf8_lossy(&probe.stdout),
            String::from_utf8_lossy(&probe.stderr),
            hub.log()
        );
    }
    eprintln!("vitals after {:?}", start.elapsed());
    // services are the watched ones and every failed unit (FR-2): one unit fails
    let unit = "[Service]\\nType=oneshot\\nExecStart=/bin/false\\n";
    machine.root(&format!(
        "printf '{unit}' > /etc/systemd/system/broken.service && systemctl daemon-reload && systemctl start broken; true"
    ));
    within(Duration::from_secs(30), "the failed unit on the machine page", || {
        hub.curl(&[&format!("/machines/{MACHINE}")]).contains("broken.service")
    });
    let state = machine.root("cat /run/rackhand-probe/probe.state");
    assert!(String::from_utf8_lossy(&state.stdout).contains("\"connected\""), "probe.state says connected");
    // the probe service's process (the helper, from the same binary, is the one root process)
    let uid = machine.root("ps -o user= -p $(systemctl show -p MainPID --value rackhand-probe)");
    assert_eq!(String::from_utf8_lossy(&uid.stdout).trim(), "rackhand-probe", "the probe isn't root");
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

/// A hub with a 5 s probe interval and more settings, its machine enrolled and the admin signed in.
fn hub_with(name: &str, key: &[u8; 32], probe_settings: &str) -> Hub {
    let mut hub = Hub::init(name);
    hub.enroll(MACHINE, key);
    hub.start();
    hub.first_run();
    hub.stop();
    hub.settings(probe_settings);
    hub.start();
    hub
}

#[test]
fn outage_backfills_and_live_stays_fresh() {
    let key = [43u8; 32];
    let mut hub = hub_with("outage", &key, "[probe]\ninterval_s = 5\n");
    let machine = probe_machine(&hub, &key, &[]);
    within(Duration::from_secs(60), "live reports", || hub.received().last().is_some_and(|r| r.1 >= 3));
    hub.stop();
    std::thread::sleep(Duration::from_secs(600));
    let state = machine.root("cat /run/rackhand-probe/probe.state; du -sb /var/lib/rackhand-probe/buffer");
    eprintln!("before the restart: {}", String::from_utf8_lossy(&state.stdout));
    hub.start();
    let restarted = Instant::now();
    // the outage's 120 reports come back while live ones keep arriving
    let mut stale = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(900);
    let took = within(Duration::from_secs(905), "the outage filled", || {
        if Instant::now() > deadline {
            let journal =
                machine.root("cat /run/rackhand-probe/probe.state; journalctl -u rackhand-probe --no-pager | tail -15");
            panic!(
                "not filled: received {:?}
probe: {}
hub: {}",
                hub.received(),
                String::from_utf8_lossy(&journal.stdout),
                hub.log().lines().rev().take(15).collect::<Vec<_>>().join(
                    "
"
                )
            );
        }
        if restarted.elapsed() > Duration::from_secs(30) {
            if let Some(at) = hub.newest_received_ms() {
                if now_ms() - at > 30_000 {
                    stale.push(now_ms() - at);
                }
            }
        }
        let r = hub.received();
        r.len() == 1 && r[0].0 == 1 && r[0].1 >= 130
    });
    eprintln!("outage filled {took:?} after the restart; received {:?}", hub.received());
    assert!(stale.is_empty(), "live reports stayed under 30 s old during the replay: {stale:?}");
    let opened: Vec<_> = hub.open_incidents().into_iter().filter(|(k, _)| k != "machine.silent").collect();
    assert!(opened.is_empty(), "replayed samples opened no threshold incident: {opened:?}");
}

#[test]
fn buffer_limit_drops_oldest_with_gap_event() {
    let key = [44u8; 32];
    let mut hub = hub_with("buffer", &key, "[probe]\ninterval_s = 5\nbuffer_max_mb = 1\n");
    let machine = probe_machine(&hub, &key, &[]);
    within(Duration::from_secs(60), "live reports", || hub.received().last().is_some_and(|r| r.1 >= 2));
    // 1500 failed units with long names make each report about 70 KB, so the 1 MB buffer fills in about a minute
    let units = "for i in $(seq -w 1 1500); do printf '[Service]\nType=oneshot\nExecStart=/bin/false\n'         > /etc/systemd/system/rackhand-test-filler-unit-$i.service; done; systemctl daemon-reload;         systemctl start $(seq -f 'rackhand-test-filler-unit-%04g' 1 1500); true";
    machine.root(units);
    let before = hub.received().last().map_or(0, |r| r.1);
    hub.stop();
    std::thread::sleep(Duration::from_secs(180));
    let buffer = machine.root("du -sb /var/lib/rackhand-probe/buffer | cut -f1");
    let bytes: u64 = String::from_utf8_lossy(&buffer.stdout).trim().parse().unwrap_or(0);
    // the cap drops whole segments (a quarter of it each), so a full buffer holds between three quarters and all of it
    assert!((768 * 1024..=1024 * 1024).contains(&bytes), "the buffer filled to its cap: {bytes} bytes");
    hub.start();
    let mut gaps = Vec::new();
    within(Duration::from_secs(180), "probe.data_gap", || {
        gaps = hub.events("probe.data_gap");
        !gaps.is_empty()
    });
    let data: serde_json::Value = serde_json::from_str(&gaps[0].1).unwrap();
    let (from, to) = (data["from_seq"].as_u64().unwrap(), data["to_seq"].as_u64().unwrap());
    assert!(
        from > before.saturating_sub(5) && to >= from,
        "the range names the dropped reports: {data} (before {before})"
    );
    // the hub never holds a seq inside the dropped range
    for (a, b) in hub.received() {
        assert!(b < from || a > to, "{a}..{b} overlaps the dropped {from}..{to}");
    }
}

#[test]
fn stopped_probe_opens_silent_warning_at_60s() {
    let key = [45u8; 32];
    let mut hub = Hub::init("silent");
    hub.enroll(MACHINE, &key);
    hub.start();
    hub.first_run();
    let machine = probe_machine(&hub, &key, &[]);
    within(Duration::from_secs(60), "live reports", || !hub.received().is_empty());
    // no silence for the hub's first 3 minutes (E44)
    let grace = Duration::from_secs(185).saturating_sub(hub.started.unwrap().elapsed());
    std::thread::sleep(grace);
    // silence counts from the last report. Staged reports are compacted away every 5 minutes, so the one just before
    // the stop is remembered.
    let mut before = None;
    within(Duration::from_secs(60), "a report under 1 s old", || {
        before = hub.newest_received_ms().filter(|at| now_ms() - at < 1_000);
        before.is_some()
    });
    machine.root("systemctl stop rackhand-probe");
    std::thread::sleep(Duration::from_secs(1));
    let last_report = hub.newest_received_ms().max(before).expect("a report before the stop");
    let silent = || hub.open_incidents().iter().any(|(k, s)| k == "machine.silent" && s == "warning");
    within(Duration::from_secs(100), "a machine.silent warning", silent);
    let opened: i64 = hub
        .db()
        .query_row("SELECT max(opened_at) FROM incidents WHERE kind = 'machine.silent'", [], |r| r.get(0))
        .unwrap();
    assert!(opened - last_report >= 59_000, "not before 60 s without a report: {} ms", opened - last_report);
    assert!(opened - last_report <= 80_000, "and within the 15 s evaluation after: {} ms", opened - last_report);
    machine.root("systemctl start rackhand-probe");
    within(Duration::from_secs(60), "the first report resolves it", || !silent());
    // a machine whose policy expects it offline gets one info event instead
    let db = hub.db();
    db.execute("INSERT INTO policies (id, name, expected_offline) VALUES ('sleepy', 'sleepy', 1)", []).unwrap();
    db.execute("UPDATE machines SET policy_id = 'sleepy' WHERE id = ?1", [MACHINE]).unwrap();
    let info_before = hub.events("machine.silent").len();
    machine.root("systemctl stop rackhand-probe");
    std::thread::sleep(Duration::from_secs(90));
    let events = hub.events("machine.silent");
    assert!(events.len() > info_before && events.last().unwrap().0 == "info", "an info event: {events:?}");
    assert!(!silent(), "and no warning");
}

#[test]
fn containers_listed_within_30s() {
    let key = [46u8; 32];
    let mut hub = Hub::init("containers");
    hub.enroll(MACHINE, &key);
    hub.start();
    hub.first_run();
    // two containers on an engine the machine's helper reads through its socket (read-only calls)
    let names = [format!("rh-it-web-{}", std::process::id()), format!("rh-it-db-{}", std::process::id())];
    for n in &names {
        let out = Command::new("docker")
            .args(["run", "-d", "--name", n, "rackhand-it-systemd", "sleep", "600"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
    let _cleanup = Cleanup(names.to_vec());
    let _machine = probe_machine(&hub, &key, &["-v", "/var/run/docker.sock:/var/run/docker.sock"]);
    within(Duration::from_secs(30), "both containers on the machine page", || {
        let page = hub.curl(&[&format!("/machines/{MACHINE}")]);
        names.iter().all(|n| page.contains(n.as_str()))
    });
}

struct Cleanup(Vec<String>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for n in &self.0 {
            let _ = Command::new("docker").args(["rm", "-f", n]).output();
        }
    }
}

mod backup {
    use super::*;

    #[test]
    fn restore_on_new_machine_probes_reconnect() {
        let key = [47u8; 32];
        let mut a = Hub::init("backup-a");
        a.enroll(MACHINE, &key);
        a.start();
        a.first_run();
        let machine = probe_machine(&a, &key, &[]);
        within(Duration::from_secs(60), "reports at the first hub", || a.received().last().is_some_and(|r| r.1 >= 2));
        let file = a.backup();
        let toml_before = machine.root("cat /etc/rackhand-probe/probe.toml").stdout;
        a.stop();
        let seen = a.received().last().map_or(0, |r| r.1);
        // a new machine at the same address: the backup, restored with the master key
        let mut b = Hub::restore("backup-b", &file, &a.etc.join("master.key"), a.web, a.quic);
        assert_eq!(b.id_hex, a.id_hex, "the restored hub has the same endpoint id");
        b.start();
        within(Duration::from_secs(120), "the probe reporting to the restored hub", || {
            b.received().last().is_some_and(|r| r.1 > seen)
        });
        assert_eq!(machine.root("cat /etc/rackhand-probe/probe.toml").stdout, toml_before, "without re-enrolling");
        assert!(b.events("machine.identity_conflict").is_empty());
    }
}
