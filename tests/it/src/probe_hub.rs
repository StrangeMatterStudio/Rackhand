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
fn field(html: &str, name: &str) -> String {
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
        Hub { dir, etc, data, web, quic, setup_code, id_hex, jar, child: None }
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
            "INSERT INTO machines (id, site_id, name, kind, probe_endpoint_id, state) \
             VALUES (?1, 'lab-site', 'web1', 'linux', ?2, 'enrolled')",
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
            .args(["-sk", "--max-time", "10", "-b"])
            .arg(&self.jar)
            .arg("-c")
            .arg(&self.jar)
            .args(rest)
            .arg(format!("https://127.0.0.1:{}{path}", self.web))
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    /// First run over HTTPS: the admin and the local site; the cookie jar then holds the admin's session.
    pub fn first_run(&self) {
        let page = self.curl(&["/first-run"]);
        let (csrf, secret, sig) = (field(&page, "csrf"), field(&page, "totp_secret"), field(&page, "totp_sig"));
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let totp = rackhand_hub::web::totp::code(&rackhand_hub::web::totp::decode_base32(&secret).unwrap(), now);
        let form = [
            ("csrf", csrf.as_str()),
            ("setup_code", self.setup_code.as_str()),
            ("admin_name", "admin"),
            ("password", "correct horse battery staple"),
            ("totp_secret", secret.as_str()),
            ("totp_sig", sig.as_str()),
            ("totp_code", totp.as_str()),
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
        let answer = self.curl(&refs);
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

    /// The events of `kind`: their severity and data.
    #[allow(dead_code)]
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
    let unit = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/systemd/rackhand-probe.service");
    c.copy_in(&unit, "/etc/systemd/system/rackhand-probe.service");
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
    let started = c.root("systemctl daemon-reload && systemctl start rackhand-probe");
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
    let uid = machine.root("ps -o user= -C rackhand-probe");
    assert_eq!(String::from_utf8_lossy(&uid.stdout).trim(), "rackhand-probe", "the probe isn't root");
}
