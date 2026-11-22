//! The lab hub as an admin and a monitoring system see it (plan L2): the dashboard through its forwarded port with
//! one cookie jar kept in the lab directory (0600, signed in again only when the session is gone), `/metrics` with the
//! token `rackhand hub metrics-token` prints, and the fixtures the M1 tests share. Each fixture checks first and does
//! its work only when it's missing, so the tests run in any order and again on a lab that already has them.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::{eventually, lab, ok_on, on, xtask};

/// The hub's site A address, which the ticket gives the probes.
pub const HUB_ADDR: &str = "192.0.2.10";
/// The lab release server `cargo xtask lab deploy` starts in WSL, as the machines reach it.
pub const RELEASE_URL: &str = "http://10.0.2.2:8790";
/// The fake Discord webhook on the hub machine (D113 allows plain HTTP to loopback only).
const HOOK_PORT: u16 = 9099;
const HOOK_LOG: &str = "/home/lab/rackhand-live-hook.log";
pub const HOOK_NAME: &str = "live-hook";
/// A unit on `target` the tests make fail and recover.
pub const UNIT: &str = "rackhand-live.service";

pub fn lab_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".cache/rackhand-lab")
}

fn now_s() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// The hub's dashboard port in WSL: its SSH port plus 10000 (`lab/lab.toml`, `xtask::lab::qemu::web_port`).
fn web_port() -> u16 {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../lab/lab.toml")).unwrap();
    let lab: toml::Table = toml::from_str(&text).unwrap();
    let machines = lab["machine"].as_array().unwrap();
    let hub = machines.iter().find(|m| m["name"].as_str() == Some("hub")).expect("lab.toml has a hub");
    (hub["ssh_port"].as_integer().unwrap() + 10_000) as u16
}

/// `key = "value"` lines of `creds`, written by the deploy's first run.
fn cred(key: &str) -> String {
    let text = std::fs::read_to_string(lab_dir().join("creds")).expect("no creds: `cargo xtask lab deploy` first");
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key} = \"")).and_then(|v| v.strip_suffix('"')))
        .unwrap_or_else(|| panic!("creds has no {key}"))
        .to_string()
}

fn base32_decode(s: &str) -> Vec<u8> {
    let (mut bits, mut buf, mut out) = (0u32, 0u64, Vec::new());
    for c in s.trim_end_matches('=').chars() {
        let v = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c.to_ascii_uppercase()).expect("base32") as u64;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

/// The 6-digit TOTP code (RFC 6238, SHA-1, 30 s) for `unix_s`.
fn totp(secret_b32: &str, unix_s: i64) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &base32_decode(secret_b32));
    let tag = ring::hmac::sign(&key, &(unix_s / 30).to_be_bytes());
    let t = tag.as_ref();
    let o = (t[19] & 0x0f) as usize;
    let n = (u32::from_be_bytes([t[o], t[o + 1], t[o + 2], t[o + 3]]) & 0x7fff_ffff) % 1_000_000;
    format!("{n:06}")
}

/// The value of `<input name="<name>" value="...">` in a page.
pub fn field(html: &str, name: &str) -> Option<String> {
    let at = html.find(&format!("name=\"{name}\""))?;
    let start = html[..at].rfind('<')?;
    let end = at + html[at..].find('>')?;
    let tag = &html[start..end];
    let v = tag.find("value=\"")? + 7;
    Some(tag[v..v + tag[v..].find('"')?].to_string())
}

/// The dashboard over HTTPS (the hub's self-signed certificate) with a cookie jar.
pub struct Dash {
    jar: PathBuf,
    port: u16,
}

impl Dash {
    /// The shared session of the live tests.
    pub fn shared() -> Dash {
        Dash::with_jar(lab_dir().join("live-cookies"))
    }

    /// A browser that has never signed in.
    pub fn fresh(name: &str) -> Dash {
        let jar = lab_dir().join(format!("live-cookies-{name}"));
        let _ = std::fs::remove_file(&jar);
        Dash::with_jar(jar)
    }

    fn with_jar(jar: PathBuf) -> Dash {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&jar);
        Dash { jar, port: web_port() }
    }

    pub fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }

    /// The status and body of one request.
    pub fn curl(&self, args: &[&str], path: &str) -> (u16, String) {
        let out = Command::new("curl")
            .args(["-sk", "--max-time", "30", "-w", "\n%{http_code}", "-b"])
            .arg(&self.jar)
            .arg("-c")
            .arg(&self.jar)
            .args(args)
            .arg(self.url(path))
            .output()
            .expect("curl runs");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let (body, code) = text.rsplit_once('\n').unwrap_or(("", "0"));
        (code.trim().parse().unwrap_or(0), body.to_string())
    }

    pub fn get(&self, path: &str) -> (u16, String) {
        self.curl(&[], path)
    }

    /// A form post; the CSRF token comes from `page`, the page the form is on.
    pub fn post(&self, page: &str, action: &str, fields: &[(&str, &str)]) -> (u16, String) {
        let (_, html) = self.get(page);
        let csrf = field(&html, "csrf").unwrap_or_else(|| panic!("no form on {page}"));
        let mut args = vec!["--data-urlencode".to_string(), format!("csrf={csrf}")];
        for (k, v) in fields {
            args.push("--data-urlencode".into());
            args.push(format!("{k}={v}"));
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.curl(&refs, action)
    }

    /// The first factor only: name and password.
    pub fn password_step(&self) -> (u16, String) {
        let (_, page) = self.get("/sign-in");
        let csrf = field(&page, "csrf").expect("the sign-in form");
        let password = cred("password");
        let fields = [format!("csrf={csrf}"), format!("name={}", cred("admin")), format!("password={password}")];
        let mut args = Vec::new();
        for f in &fields {
            args.extend(["--data-urlencode", f.as_str()]);
        }
        self.curl(&args, "/sign-in")
    }

    /// Both factors. A code is accepted once, so a second sign-in in the same 30 s waits for the next code.
    pub fn sign_in(&self) {
        let secret = cred("totp_secret");
        let mut said = String::new();
        for attempt in 0..3 {
            if attempt > 0 {
                std::thread::sleep(Duration::from_secs((30 - now_s() % 30 + 1) as u64));
            }
            let (code, body) = self.password_step();
            let (_, page) = self.get("/sign-in/code");
            let Some(csrf) = field(&page, "csrf") else {
                said = format!("the password step answered {code}: {}", &body[..body.len().min(300)]);
                continue;
            };
            let code = totp(&secret, now_s());
            self.curl(
                &["--data-urlencode", &format!("csrf={csrf}"), "--data", &format!("code={code}")],
                "/sign-in/code",
            );
            if self.get("/").0 == 200 {
                return;
            }
            said = "the code was refused".into();
        }
        panic!("signing in to the lab hub failed: {said}");
    }

    /// A fresh step-up with the next TOTP code, for the actions that ask for one (7.7.2). A code is accepted once, so
    /// one already used for the sign-in waits for the next.
    pub fn step_up(&self) {
        let secret = cred("totp_secret");
        for attempt in 0..3 {
            if attempt > 0 {
                std::thread::sleep(Duration::from_secs((30 - now_s() % 30 + 1) as u64));
            }
            let (_, page) = self.get("/step-up");
            let Some(csrf) = field(&page, "csrf") else { continue };
            let code = totp(&secret, now_s());
            let (status, _) = self
                .curl(&["--data-urlencode", &format!("csrf={csrf}"), "--data", &format!("code={code}")], "/step-up");
            if status == 303 {
                return;
            }
        }
        panic!("the step-up on the lab hub failed");
    }

    /// Signs in when the shared session is gone.
    pub fn signed_in(self) -> Dash {
        if self.get("/").0 != 200 {
            self.sign_in();
        }
        self
    }
}

/// `/healthz` through the forwarded port answers `ok`.
pub fn healthy() -> bool {
    Dash::fresh("health").get("/healthz").1.trim() == "ok"
}

/// Waits for the hub to answer after a restart or reboot.
pub fn wait_healthy(timeout: Duration) {
    assert!(eventually(timeout, healthy), "the hub didn't come back within {timeout:?}");
}

/// The bearer token for `/metrics`, as the owner reads it on the hub.
pub fn metrics_token() -> String {
    on("hub", "sudo /usr/local/bin/rackhand hub metrics-token").trim().to_string()
}

pub fn metrics(token: &str) -> (u16, String) {
    Dash::fresh("metrics").curl(&["-H", &format!("Authorization: Bearer {token}")], "/metrics")
}

/// The value of `rackhand_<metric>{...machine="<machine>"...}` in a scrape.
pub fn series(scrape: &str, metric: &str, machine: &str) -> Option<f64> {
    let name = format!("rackhand_{}{{", metric.replace('.', "_"));
    let label = format!("machine=\"{machine}\"");
    scrape
        .lines()
        .find(|l| l.starts_with(&name) && l.contains(&label))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
}

/// The machine's own uptime now.
pub fn uptime(machine: &str) -> f64 {
    on(machine, "cut -d' ' -f1 /proc/uptime").trim().parse().unwrap()
}

/// How far the hub's latest `uptime_s` of the machine is behind the machine itself, in seconds.
pub fn lag(token: &str, machine: &str) -> Option<f64> {
    let seen = series(&metrics(token).1, "uptime_s", machine)?;
    Some(uptime(machine) - seen)
}

/// Whether the machine's live reports reach the hub: its latest uptime is at most `within` seconds old.
pub fn live(token: &str, machine: &str, within: f64) -> bool {
    lag(token, machine).is_some_and(|l| l <= within)
}

/// The id of a machine of the lab site, from the site page.
pub fn machine_id(dash: &Dash, name: &str) -> Option<String> {
    let (_, overview) = dash.get("/");
    let at = overview.find("href=\"/sites/")? + 6;
    let site = &overview[at..at + overview[at..].find('"')?];
    let (_, page) = dash.get(site);
    let anchor = format!("\">{name}</a>");
    let end = page.find(&anchor)?;
    let start = page[..end].rfind("/machines/")? + 10;
    Some(page[start..end].to_string())
}

/// A machine's state on the site page (`pending` until its probe joins).
pub fn machine_state(dash: &Dash, name: &str) -> Option<String> {
    let id = machine_id(dash, name)?;
    let (_, overview) = dash.get("/");
    let at = overview.find("href=\"/sites/")? + 6;
    let site = &overview[at..at + overview[at..].find('"')?];
    let (_, page) = dash.get(site);
    let row = page.split("<tr>").find(|r| r.contains(&format!("/machines/{id}\"")))?;
    cells(row).get(1).cloned()
}

/// An open incident: title, machine, severity, state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    pub title: String,
    pub machine: String,
    pub severity: String,
    pub state: String,
}

fn cells(row: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = row;
    while let Some(i) = rest.find("<td>") {
        let after = &rest[i + 4..];
        let end = after.find("</td>").unwrap_or(after.len());
        let mut cell = after[..end].to_string();
        while let (Some(a), Some(b)) = (cell.find('<'), cell.find('>')) {
            if b < a {
                break;
            }
            cell.replace_range(a..=b, "");
        }
        out.push(cell.trim().to_string());
        rest = &after[end..];
    }
    out
}

/// The open incidents on the Incidents page.
pub fn open_incidents(dash: &Dash) -> Vec<Open> {
    let (_, page) = dash.get("/incidents");
    let start = page.find("<h2>Open</h2>").expect("the incidents page");
    let end = page.find("<h2>Resolved").unwrap_or(page.len());
    page[start..end]
        .split("<tr>")
        .map(cells)
        .filter(|c| c.len() >= 4)
        .map(|c| Open { title: c[0].clone(), machine: c[1].clone(), severity: c[2].clone(), state: c[3].clone() })
        .collect()
}

/// The titles of the incidents resolved in the last 7 days.
pub fn resolved_titles(dash: &Dash) -> Vec<String> {
    let (_, page) = dash.get("/incidents");
    let start = page.find("<h2>Resolved").expect("the incidents page");
    page[start..].split("<tr>").map(cells).filter(|c| c.len() >= 3).map(|c| format!("{} on {}", c[0], c[1])).collect()
}

/// The x coordinates of a metric's line in the machine's last-hour chart.
pub fn chart_xs(dash: &Dash, id: &str, metric: &str) -> Vec<f64> {
    let (_, partial) = dash.get(&format!("/machines/{id}/vitals"));
    let Some(at) = partial.find(&format!("aria-label=\"{metric} over the last hour\"")) else { return Vec::new() };
    let points = &partial[at..];
    let Some(p) = points.find("points=\"") else { return Vec::new() };
    let list = &points[p + 8..p + 8 + points[p + 8..].find('"').unwrap_or(0)];
    list.split_whitespace().filter_map(|xy| xy.split(',').next()?.parse().ok()).collect()
}

/// The largest step between neighbouring points over the median step: about 1 for a line without a hole.
pub fn gap_ratio(xs: &[f64]) -> f64 {
    let mut steps: Vec<f64> = xs.windows(2).map(|w| w[1] - w[0]).collect();
    if steps.is_empty() {
        return f64::INFINITY;
    }
    let max = steps.iter().copied().fold(0.0, f64::max);
    steps.sort_by(f64::total_cmp);
    let median = steps[steps.len() / 2].max(1e-6);
    max / median
}

/// A machine token and the ticket from `rackhand hub lab-token` (the Add page arrives in T49).
pub fn lab_token(access: &str, name: &str) -> (String, String) {
    let out = on(
        "hub",
        &format!(
            "sudo /usr/local/bin/rackhand hub lab-token --kind machine --access {access} --name {name} --addr {HUB_ADDR}"
        ),
    );
    let value = |k: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap_or_else(|| panic!("lab-token printed no {k}"))
            .to_string()
    };
    (value("ticket"), value("token"))
}

/// The 7.3.12 Linux install command, against the lab release server.
pub fn install_command(release_url: &str, ticket: &str, token: &str) -> String {
    format!(
        "curl -fsSL {release_url}/install.sh | sudo sh -s -- --ticket {ticket} --token {token} --release-url {release_url}"
    )
}

/// What the fixture measured when it installed `target`: seconds from the end of the install command until each
/// part was on the hub.
#[derive(Debug)]
pub struct Install {
    pub machine: String,
    pub vitals_s: f64,
    pub services_s: f64,
    pub updates_s: f64,
    pub access: String,
}

fn install_record() -> PathBuf {
    lab_dir().join("live-install")
}

pub fn read_install() -> Option<Install> {
    let text = std::fs::read_to_string(install_record()).ok()?;
    let v = |k: &str| text.lines().find_map(|l| l.strip_prefix(&format!("{k}="))).map(str::to_string);
    Some(Install {
        machine: v("machine")?,
        vitals_s: v("vitals_s")?.parse().ok()?,
        services_s: v("services_s")?.parse().ok()?,
        updates_s: v("updates_s")?.parse().ok()?,
        access: v("access")?,
    })
}

/// The 7.4.2 vitals a Linux machine reports, as their `/metrics` names.
pub const VITALS: &[&str] =
    &["cpu.busy_pct", "mem.used_pct", "swap.used_pct", "load.1m", "disk.used_pct", "net.rx_bps", "uptime_s"];

/// `target` enrolled as managed and reporting. Installs it when the hub doesn't know it (a lab reset target first
/// when an old probe is pinned to another hub) and records how long each part took to appear.
pub fn ensure_target(dash: &Dash, token: &str) -> String {
    if let Some(id) = machine_id(dash, "target") {
        // D84: a joined managed machine is pending until the hub's SSH test passes, which it retries at each report.
        let enrolled = || machine_state(dash, "target").is_some_and(|s| s != "pending");
        assert!(
            eventually(Duration::from_secs(120), enrolled),
            "the hub has target pending: its install never joined (`cargo xtask lab reset hub`, deploy again) or the              hub's SSH test fails (the Add page says why)"
        );
        let state = machine_state(dash, "target").unwrap_or_default();
        assert!(
            eventually(Duration::from_secs(120), || live(token, "target", 45.0)),
            "the hub knows target ({state}) but it doesn't report: if its join never finished,              `cargo xtask lab reset hub` and `lab reset target`, then run again"
        );
        return id;
    }
    if ok_on("target", "test -e /usr/local/lib/rackhand/rackhand-probe") {
        lab(&["reset", "target"]);
        assert!(eventually(Duration::from_secs(300), || ok_on("target", "true")), "target after reset");
    }
    // A failed unit, so the machine has a service to report (only failed and watched units are reported).
    on(
        "target",
        "sudo systemd-run --unit=rackhand-live-boot /bin/false; sleep 1; systemctl is-failed rackhand-live-boot",
    );
    let (ticket, token_once) = lab_token("managed", "target");
    on("target", &install_command(RELEASE_URL, &ticket, &token_once));
    let done = Instant::now();
    let id = machine_id(dash, "target").expect("the hub lists target after its install");
    let (mut vitals, mut services, mut updates) = (None, None, None);
    let deadline = Instant::now() + Duration::from_secs(300);
    while (vitals.is_none() || services.is_none() || updates.is_none()) && Instant::now() < deadline {
        let scrape = metrics(token).1;
        if vitals.is_none() && VITALS.iter().all(|m| series(&scrape, m, "target").is_some()) {
            vitals = Some(done.elapsed().as_secs_f64());
        }
        let (_, page) = dash.get(&format!("/machines/{id}"));
        if services.is_none() && page.contains("rackhand-live-boot.service") {
            services = Some(done.elapsed().as_secs_f64());
        }
        if updates.is_none() && !page.contains("Updates not reported yet") && page.contains(" pending, ") {
            updates = Some(done.elapsed().as_secs_f64());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    on("target", "sudo systemctl reset-failed rackhand-live-boot");
    assert!(
        eventually(Duration::from_secs(120), || machine_state(dash, "target").is_some_and(|s| s != "pending")),
        "target stayed pending: the hub's SSH test didn't pass (the Add page says why)"
    );
    let (_, page) = dash.get(&format!("/machines/{id}"));
    let access = if page.contains("Access: managed") { "managed" } else { "other" };
    let never = f64::INFINITY;
    let record = format!(
        "machine={id}\nvitals_s={}\nservices_s={}\nupdates_s={}\naccess={access}\n",
        vitals.unwrap_or(never),
        services.unwrap_or(never),
        updates.unwrap_or(never)
    );
    std::fs::write(install_record(), record).unwrap();
    println!("target installed: {:?}", read_install());
    id
}

/// The fake Discord webhook on the hub machine, which appends each post to its log.
pub fn ensure_hook() {
    if ok_on("hub", &format!("curl -s -o /dev/null -X POST --data '{{}}' http://127.0.0.1:{HOOK_PORT}/hook")) {
        return;
    }
    let script = r#"import http.server, sys
port, log = int(sys.argv[1]), sys.argv[2]
class Hook(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with open(log, "ab") as f:
            f.write(body.replace(b"\n", b" ") + b"\n")
        self.send_response(204)
        self.end_headers()
    def log_message(self, *args):
        pass
http.server.HTTPServer(("127.0.0.1", port), Hook).serve_forever()
"#;
    on("hub", &format!("cat > /home/lab/rackhand-live-hook.py <<'EOF'\n{script}EOF"));
    on(
        "hub",
        &format!(
            "setsid nohup python3 /home/lab/rackhand-live-hook.py {HOOK_PORT} {HOOK_LOG} </dev/null >/dev/null 2>&1 &"
        ),
    );
    assert!(
        eventually(Duration::from_secs(20), || ok_on(
            "hub",
            &format!("curl -s -o /dev/null -X POST --data '{{}}' http://127.0.0.1:{HOOK_PORT}/hook")
        )),
        "the fake webhook didn't start"
    );
}

/// The webhook's posts so far.
pub fn hook_posts() -> Vec<String> {
    on("hub", &format!("cat {HOOK_LOG} 2>/dev/null || true")).lines().map(str::to_string).collect()
}

/// The fake webhook added in Settings: Notifiers and running (a saved notifier applies after a restart, T39b).
pub fn ensure_notifier(dash: &Dash) {
    ensure_hook();
    let running = |dash: &Dash| {
        let (_, page) = dash.get("/settings/notifiers");
        page.split("<tr>").any(|row| row.contains(&format!("<td>{HOOK_NAME}</td>")) && row.contains("running"))
    };
    if running(dash) {
        return;
    }
    let webhook = format!("http://127.0.0.1:{HOOK_PORT}/hook");
    let fields = [("kind", "discord"), ("name", HOOK_NAME), ("webhook", webhook.as_str())];
    let (code, body) = dash.post("/settings/notifiers", "/settings/notifiers", &fields);
    assert_eq!(code, 303, "saving the notifier: {body}");
    restart_hub();
    assert!(running(dash), "the notifier runs after the restart");
}

pub fn restart_hub() {
    on("hub", "sudo systemctl restart rackhand-hub");
    wait_healthy(Duration::from_secs(60));
}

/// The unit the callout tests stop: it runs until killed and doesn't restart.
pub fn ensure_unit() {
    let unit = "[Unit]\nDescription=Rackhand live test service\n[Service]\nExecStart=/bin/sleep infinity\nRestart=no\n"
        .to_string();
    on(
        "target",
        &format!(
            "test -e /etc/systemd/system/{UNIT} || {{ printf '{}' | sudo tee /etc/systemd/system/{UNIT} >/dev/null && sudo systemctl daemon-reload; }}",
            unit.replace('\n', "\\n")
        ),
    );
    on("target", &format!("sudo systemctl reset-failed {UNIT} 2>/dev/null; sudo systemctl start {UNIT}"));
}

/// Makes the unit fail (killed, no restart): reported as failed from the next report.
pub fn fail_unit() {
    on("target", &format!("sudo systemctl kill -s KILL {UNIT}; sleep 1; systemctl is-failed {UNIT}"));
}

/// The unit running again: it drops out of the reports, which resolves its incident.
pub fn recover_unit() {
    on("target", &format!("sudo systemctl reset-failed {UNIT}; sudo systemctl start {UNIT}"));
}

/// How long the hub's service has been running, in seconds.
pub fn hub_uptime_s() -> u64 {
    on("hub", "ps -o etimes= -p $(systemctl show -p MainPID --value rackhand-hub)").trim().parse().unwrap_or(0)
}

/// Sets a lab machine's clock from WSL's.
pub fn set_clock(machine: &str) {
    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
    on(machine, &format!("sudo date -u -s @{}.{:03} >/dev/null", now_ms / 1000, now_ms % 1000));
}

/// Reboots a lab machine and waits until it answers SSH from its next boot (a new boot id, so the old system shutting
/// down doesn't count).
pub fn reboot(machine: &str) {
    let boot_id = || on(machine, "cat /proc/sys/kernel/random/boot_id").trim().to_string();
    let before = boot_id();
    on(machine, "sudo systemd-run --on-active=1 --timer-property=AccuracySec=100ms /bin/systemctl reboot");
    let back = eventually(Duration::from_secs(300), || {
        let out = xtask(&["lab", "run", machine, "--", "cat /proc/sys/kernel/random/boot_id"]);
        out.status.success() && String::from_utf8_lossy(&out.stdout).trim() != before
    });
    assert!(back, "{machine} didn't come back from its reboot");
}

/// Reads a file on a lab machine as root, bytes intact (through base64).
pub fn fetch(machine: &str, path: &str) -> Vec<u8> {
    let b64 = on(machine, &format!("sudo base64 -w0 {path}"));
    let mut child =
        Command::new("base64").arg("-d").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("base64 runs");
    std::io::Write::write_all(child.stdin.as_mut().unwrap(), b64.trim().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "base64 -d");
    out.stdout
}

/// Runs `cargo xtask lab deploy <args>` and panics when it fails.
pub fn deploy(args: &[&str]) {
    let mut full = vec!["lab", "deploy"];
    full.extend_from_slice(args);
    let out = xtask(&full);
    assert!(
        out.status.success(),
        "lab deploy {args:?}: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
