//! Offline operation (plan T97, design 5.2, AC41): a hub with no internet, no peers and no operator keeps collecting,
//! alerts by email through a LAN SMTP server, and runs runbooks.
//!
//! Everything is on one Docker network made with `--internal`, so nothing on it has a way out, and the test drives it
//! only through `docker exec` and `docker cp`:
//! - the hub, the real binary under its packaged unit in a Debian container (as the updater's tests run it), built with
//!   the test-only `test-smtp-roots` feature so it trusts the sink's certificate (D113: every other build trusts the public
//!   roots only). Its container counts what it sends with nftables, in an output chain hooked before Docker's DNS
//!   redirection: packets to anywhere outside the network, and DNS. The internal network gives it no route out, and a
//!   packet with no route never reaches a hook, so the hub gets a default route to an address on the network that nothing
//!   answers: any attempt to reach the outside then passes the counters before it dies unanswered;
//! - the LAN mail server, the hub's SMTP sink (`examples/smtp_sink.rs`) with a certificate for its address;
//! - the managed machine, with SSH set up as a join leaves it (the hub's key, the wrapper, a command list signed with the
//!   hub's node key, the pinned host key) and its probe reporting a fixture root (the probe's `--root` test seam, as the
//!   callouts test uses) whose `/data` is 96 % full.
//!
//! The service-restart runbook is a Library copy of the built-in with its unit fixed to a dummy service on the machine,
//! level 2, started automatically for `disk.used`: the built-in has a required `unit` parameter and routing starts
//! runbooks without parameters.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rackhand_hub::audit::Audit;
use rackhand_hub::library::items::{Kind, Library};
use rackhand_hub::ssh::hostkeys::HostKeys;
use rackhand_hub::ssh::keys::{Identity, authorized_keys_line, load_or_create};
use rackhand_hub::vault::Vault;
use rackhand_hub::vault::master_key::MasterKey;
use rackhand_runbook::runbook::Runbook;
use rackhand_store::Db;

use crate::callouts::{copy_dir, set_data_usage};
use crate::probe_hub::{Hub, within};
use crate::support::{Container, musl_binary, musl_binary_with, stripped};

/// The machine at the hub (a ULID: the probe server names it by one).
const MACHINE: &str = "01JD0000000000000000000097";
const MACHINE_NAME: &str = "offline-web1";
const PROBE_KEY: [u8; 32] = [97; 32];
const WRAPPER: &str = "/usr/local/lib/rackhand/run";
const DUMMY: &str = "rackhand-it-dummy.service";
const RUNBOOK_NAME: &str = "offline-dummy-restart";
const SMTP_PORT: u16 = 2525;
const MAIL_DIR: &str = "/srv/rackhand-mail";
const FIXTURE: &str = "/opt/rackhand-fixture";
const TABLE: &str = "rackhand_it_watch";

/// `service-restart` (the built-in) with its unit fixed, for this machine, started automatically for a full disk.
const RUNBOOK: &str = r#"name = "offline-dummy-restart"
description = "Restart rackhand-it-dummy.service and check that it is active (service-restart with its unit fixed)"
targets = { machines = ["offline-web1"] }
identity = "automation"
risk = "low"
autonomy = 2
triggers = { incident_kinds = ["disk.used"], auto = true }

[[step]]
id = "restart"
kind = "ssh"
cmd = ["sudo", "/usr/local/lib/rackhand/run", "/usr/bin/systemctl", "restart", "rackhand-it-dummy.service"]
timeout = "3m"

[[step]]
id = "active"
kind = "ssh"
cmd = ["/usr/bin/systemctl", "is-active", "rackhand-it-dummy.service"]
timeout = "30s"

[[step]]
id = "report"
kind = "wait_report"
timeout = "5m"

[[step]]
id = "verify"
kind = "verify"
checks = ["bound_checks"]
timeout = "5m"
"#;

/// The outside sources as the test runs them: on, and air-gapped mode on, which makes no outside request at all (D65).
const SETTINGS: &str =
    "[sources]\nfeodo = true\nspamhaus = true\ndbip = true\nairgapped = true\n\n[probe]\ninterval_s = 5\n";

const HUB_TEST_DROPIN: &str = "# test containers only: the key through a directory only the hub's user can read\n\
[Service]\n\
LoadCredential=\n\
Environment=CREDENTIALS_DIRECTORY=/run/rackhand-test-credentials\n\
ExecStartPre=+/bin/sh -c 'install -d -m 0500 -o rackhand-hub /run/rackhand-test-credentials && install -m 0400 -o rackhand-hub /etc/rackhand/master.key /run/rackhand-test-credentials/master.key'\n";

fn text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr)
}

/// A root command that must succeed; its standard output, trimmed.
fn sh(c: &Container, script: &str) -> String {
    let out = c.root(script);
    assert!(out.status.success(), "{}: {script}: {}", c.name, text(&out));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn docker(args: &[&str]) -> Output {
    Command::new("docker").args(args).output().unwrap_or_else(|e| panic!("docker {args:?}: {e}"))
}

/// A Docker network with no way out (`--internal`), removed on drop: declared before the containers, so it goes last.
struct Network {
    name: String,
}

impl Network {
    fn internal() -> Network {
        let name = format!("rackhand-it-offline-{}", std::process::id());
        let _ = docker(&["network", "rm", &name]);
        let out = docker(&["network", "create", "--internal", &name]);
        assert!(out.status.success(), "docker network create: {}", text(&out));
        Network { name }
    }

    fn subnet(&self) -> String {
        let out = docker(&["network", "inspect", "-f", "{{range .IPAM.Config}}{{.Subnet}}{{end}}", &self.name]);
        let subnet = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(subnet.contains('/') && !subnet.contains(':'), "an IPv4 subnet: {subnet:?}");
        subnet
    }

    /// The container's address on this network.
    fn ip(&self, c: &Container) -> String {
        let format = format!("{{{{(index .NetworkSettings.Networks \"{}\").IPAddress}}}}", self.name);
        let out = docker(&["inspect", "-f", &format, &c.name]);
        let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(ip.parse::<std::net::Ipv4Addr>().is_ok(), "{}: no address on {}: {ip:?}", c.name, self.name);
        ip
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        let _ = docker(&["network", "rm", &self.name]);
    }
}

/// The last address of the subnet but one: inside it, and nothing on the network has it.
fn unused_address(subnet: &str) -> String {
    let (base, prefix) = subnet.split_once('/').unwrap();
    let base = u32::from(base.parse::<std::net::Ipv4Addr>().unwrap());
    let prefix: u32 = prefix.parse().unwrap();
    let last = base | (u32::MAX >> prefix);
    std::net::Ipv4Addr::from(last - 1).to_string()
}

/// The SMTP sink example, built for this host (Debian 12's glibc is newer than the build host's) without its symbols.
fn sink_binary() -> PathBuf {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["build", "-q", "-p", "rackhand-it", "--example", "smtp_sink", "--message-format=json"])
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|e| panic!("cargo build smtp_sink: {e}"));
    assert!(out.status.success(), "building the smtp_sink example failed");
    let built = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == "smtp_sink")
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
        .unwrap_or_else(|| panic!("no executable for smtp_sink"));
    stripped(&built)
}

/// The counters of the hub container's watch table, by comment: packets.
fn counters(hub: &Container) -> Vec<(String, u64)> {
    let listed = sh(hub, &format!("nft list table inet {TABLE}"));
    listed
        .lines()
        .filter_map(|l| {
            let packets = l.split("counter packets ").nth(1)?.split_whitespace().next()?.parse().ok()?;
            let name = l.split("comment \"").nth(1)?.split('"').next()?.to_string();
            Some((name, packets))
        })
        .collect()
}

fn counter(all: &[(String, u64)], name: &str) -> u64 {
    all.iter().find(|(n, _)| n == name).map(|(_, p)| *p).unwrap_or_else(|| panic!("no counter {name}: {all:?}"))
}

/// A copy of the hub's database as it is now (the files copied out together, then opened here).
fn hub_db(hub: &Container) -> Option<Snapshot> {
    let dir = std::env::temp_dir().join(format!("rackhand-it-offline-db-{}-{}", std::process::id(), rand_suffix()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for f in ["hub.db", "hub.db-wal"] {
        let _ = Command::new("docker")
            .args(["cp", &format!("{}:/var/lib/rackhand/{f}", hub.name)])
            .arg(dir.join(f))
            .output();
    }
    let snapshot = Snapshot { db: rusqlite::Connection::open(dir.join("hub.db")).ok(), dir };
    snapshot.db.as_ref()?.query_row("SELECT count(*) FROM incidents", [], |r| r.get::<_, i64>(0)).ok()?;
    Some(snapshot)
}

/// A copy of the hub's database, removed when dropped (the test polls it every half second).
struct Snapshot {
    db: Option<rusqlite::Connection>,
    dir: PathBuf,
}

impl std::ops::Deref for Snapshot {
    type Target = rusqlite::Connection;

    fn deref(&self) -> &rusqlite::Connection {
        self.db.as_ref().expect("open")
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        drop(self.db.take());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn rand_suffix() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
}

/// The machine's disk incident: id, severity and state.
fn disk_incident(db: &rusqlite::Connection) -> Option<(String, String, String)> {
    db.query_row(
        "SELECT id, severity, state FROM incidents WHERE kind = 'disk.used' AND machine_id = ?1 ORDER BY opened_at LIMIT 1",
        [MACHINE],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .ok()
}

/// The runbook's jobs for the incident: id and state.
fn jobs(db: &rusqlite::Connection, incident: &str) -> Vec<(String, String)> {
    let mut s = db.prepare("SELECT id, state FROM jobs WHERE name = ?1 AND incident_id = ?2 ORDER BY rowid").unwrap();
    s.query_map([RUNBOOK_NAME, incident], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
}

/// The mails the sink has written, each whole.
fn mails(sink: &Container) -> Vec<String> {
    let out = sh(
        sink,
        &format!("for f in {MAIL_DIR}/mail-*.eml; do [ -f \"$f\" ] && cat \"$f\" && printf '\\n=====\\n'; done; true"),
    );
    out.split("\n=====").map(str::trim).filter(|m| !m.is_empty()).map(String::from).collect()
}

fn subject(mail: &str) -> &str {
    mail.lines().find_map(|l| l.strip_prefix("Subject: ")).unwrap_or_default()
}

/// The dummy service's main process and when it last became active.
fn dummy_state(machine: &Container) -> (String, String) {
    let shown = sh(machine, &format!("systemctl show -p MainPID -p ActiveEnterTimestampMonotonic --value {DUMMY}"));
    let mut lines = shown.lines().map(str::to_string);
    (lines.next().unwrap_or_default(), lines.next().unwrap_or_default())
}

/// What everything said, when the test fails.
struct Diag<'a> {
    hub: &'a Container,
    machine: &'a Container,
    sink: &'a Container,
}

impl Drop for Diag<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let hub = self.hub.root(&format!(
            "journalctl -u rackhand-hub --no-pager -n 120 2>&1 | cut -c1-400; nft list table inet {TABLE}; ip route"
        ));
        let machine = self.machine.root(&format!(
            "tail -40 /tmp/rackhand-probe.log; cat /tmp/rackhand-probe.state; systemctl status {DUMMY} --no-pager | head -8; \
             journalctl -u ssh --no-pager -n 30 | cut -c1-300"
        ));
        let sink =
            self.sink.root(&format!("ls -la {MAIL_DIR}; tail -20 /tmp/smtp-sink.log; head -c 3000 {MAIL_DIR}/mail-*"));
        eprintln!(
            "--- the hub ---\n{}\n--- the machine ---\n{}\n--- the sink ---\n{}",
            text(&hub),
            text(&machine),
            text(&sink)
        );
        if let Some(db) = hub_db(self.hub) {
            let rows = |sql: &str| -> Vec<String> {
                let Ok(mut s) = db.prepare(sql) else { return vec![] };
                let n = s.column_count();
                s.query_map([], |r| {
                    Ok((0..n)
                        .map(|i| format!("{:?}", r.get::<_, rusqlite::types::Value>(i).ok()))
                        .collect::<Vec<_>>()
                        .join(" | "))
                })
                .map(|m| m.filter_map(Result::ok).collect())
                .unwrap_or_default()
            };
            eprintln!("incidents: {:#?}", rows("SELECT kind, severity, state, title FROM incidents"));
            eprintln!("incident events: {:#?}", rows("SELECT incident_id, kind, data FROM incident_events"));
            eprintln!("jobs: {:#?}", rows("SELECT name, state, requested_by FROM jobs"));
            eprintln!("steps: {:#?}", rows("SELECT step_id, state, exit_code, stderr FROM job_steps"));
            eprintln!("notifications: {:#?}", rows("SELECT transport, state, error FROM notifications"));
        }
    }
}

/// AC41: with no internet, no peers and no operator, the hub collects, a disk rule fires an email to the LAN mail
/// server, an automatic `service-restart` runbook runs, and nothing it sends is for the outside.
#[test]
fn collects_alerts_by_lan_smtp_and_runs_runbooks() {
    let started = Instant::now();
    let hub_exe = musl_binary_with("rackhand", "rackhand", "test-smtp-roots");
    let probe_exe = musl_binary("rackhand-probe", "rackhand-probe");
    let sink_exe = sink_binary();
    eprintln!("built in {:?}", started.elapsed());

    let network = Network::internal();
    let on_net = ["--network", network.name.as_str()];
    let sink = Container::start_with("sshd", &on_net);
    let machine = Container::start_systemd_with("executor", &on_net);
    let hub_box = Container::start_systemd_with("debian-install-sshd", &on_net);
    let (hub_ip, machine_ip, sink_ip) = (network.ip(&hub_box), network.ip(&machine), network.ip(&sink));
    let subnet = network.subnet();
    let _diag = Diag { hub: &hub_box, machine: &machine, sink: &sink };

    // the LAN mail server, its certificate for its address
    sink.copy_in(&sink_exe, "/usr/local/bin/smtp-sink");
    sink.spawn_detached(
        "root",
        &format!("exec /usr/local/bin/smtp-sink 0.0.0.0:{SMTP_PORT} {sink_ip} {MAIL_DIR} > /tmp/smtp-sink.log 2>&1"),
    );
    within(Duration::from_secs(30), "the sink's certificate", || {
        sink.root(&format!("test -s {MAIL_DIR}/cert.pem")).status.success()
    });
    let sink_cert = sh(&sink, &format!("cat {MAIL_DIR}/cert.pem"));

    // the hub's state, made on this host with the hub stopped: `hub init`, the settings, the notifier, the machine
    // as a join leaves it (managed, its address, its probe, its pinned host key) and the runbook
    let hub = Hub::init("offline");
    hub.settings(SETTINGS);
    hub.config(
        "notifiers",
        &format!(
            "[[smtp]]\nname = \"lan-mail\"\nhost = \"{sink_ip}\"\nport = {SMTP_PORT}\nsecurity = \"starttls\"\n\
                 from = \"rackhand@hub.lan\"\nto = [\"ops@hub.lan\"]\n"
        ),
    );
    let host_key = sh(&machine, "cat /etc/ssh/ssh_host_ed25519_key.pub");
    let authorized = seed(&hub, &machine_ip, &hub_ip, &host_key);

    // the machine: the hub's SSH keys from the hub's address only (both, as a join with the assistant leaves them,
    // which the hub's SSH test checks), the wrapper, the command list signed with the hub's node key, the dummy
    // service, and the probe reporting the fixture root with /data 96 % full
    for (id, line) in &authorized {
        let (user, path) = (id.user(), format!("/home/{}/.ssh/authorized_keys", id.user()));
        let w = machine.exec(
            None,
            &["sh", "-c", &format!("cat > {path} && chown {user}:{user} {path} && chmod 600 {path}")],
            Some(line.as_bytes()),
        );
        assert!(w.status.success(), "{path}: {}", text(&w));
    }
    // the assistant's sudo rule, as the join writes it (`hub_cmd::joins::ASSISTANT_SUDOERS`)
    sh(
        &machine,
        "mkdir -p /var/log/rackhand/sudo-io && printf 'Defaults:rackhand-ai log_output, iolog_dir=/var/log/rackhand/sudo-io\\n\
         rackhand-ai ALL=(ALL) NOPASSWD: ALL\\n' > /etc/sudoers.d/rackhand-ai && chmod 0440 /etc/sudoers.d/rackhand-ai \
         && visudo -c",
    );
    let user = Identity::Automation.user();
    machine.copy_in(&probe_exe, "/usr/local/lib/rackhand/rackhand-probe");
    sh(
        &machine,
        &format!(
            "chmod 0755 /usr/local/lib/rackhand/rackhand-probe && cp /usr/local/lib/rackhand/rackhand-probe {WRAPPER} \
                 && chown root:root {WRAPPER} && chmod 0755 {WRAPPER}"
        ),
    );
    let probe_toml = format!(
        "[hub]\nid = \"{}\"\naddrs = [\"{hub_ip}:7443\"]\n\n[machine]\nid = \"{MACHINE}\"\naccess = \"managed\"\n",
        hub.id_hex
    );
    let put = machine.exec(
        None,
        &["sh", "-c", "cat > /etc/rackhand-probe/probe.toml && chmod 0644 /etc/rackhand-probe/probe.toml"],
        Some(probe_toml.as_bytes()),
    );
    assert!(put.status.success(), "probe.toml: {}", text(&put));
    let node: [u8; 32] = std::fs::read(hub.etc.join("node.key")).unwrap().try_into().unwrap();
    let now = rackhand_store::ids::now_ms();
    let list = rackhand_hub::executor::commands::signed_command_list(
        &ed25519_dalek::SigningKey::from_bytes(&node),
        &[Runbook::parse(RUNBOOK).unwrap()],
        now as u64,
        now,
        3 * 3_600_000,
    );
    let install = machine.exec(Some(user), &["sudo", "-n", WRAPPER, "install-commands"], Some(&list));
    assert!(install.status.success(), "install-commands: {}", text(&install));
    sh(
        &machine,
        &format!(
            "printf '[Unit]\\nDescription=Rackhand offline test dummy\\n[Service]\\nExecStart=/bin/sleep infinity\\n' \
                 > /etc/systemd/system/{DUMMY} && systemctl daemon-reload && systemctl start {DUMMY}"
        ),
    );
    let before = dummy_state(&machine);
    let fixture = hub.dir.join("fixture");
    copy_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/proc/rates/b"), &fixture);
    let mounts = fixture.join("proc/mounts");
    let mut m = std::fs::read_to_string(&mounts).unwrap();
    m.push_str("/dev/sdc1 /data ext4 rw,relatime 0 0\n");
    std::fs::write(&mounts, m).unwrap();
    // no failed units: the disk rule is the one that fires
    std::fs::write(fixture.join("units.txt"), "").unwrap();
    set_data_usage(&fixture, 96);
    machine.copy_in(&fixture, FIXTURE);
    let key = hub.dir.join("probe.key");
    std::fs::write(&key, PROBE_KEY).unwrap();
    sh(
        &machine,
        &format!(
            "useradd -r -s /usr/sbin/nologin rackhand-probe && chmod -R a+rX {FIXTURE} \
                 && install -d -o rackhand-probe -g rackhand-probe -m 0700 /var/lib/rackhand-probe"
        ),
    );
    machine.copy_in(&key, "/var/lib/rackhand-probe/node.key");
    sh(
        &machine,
        "chown rackhand-probe: /var/lib/rackhand-probe/node.key && chmod 0600 /var/lib/rackhand-probe/node.key",
    );

    // the hub's machine: the binary, the packaged unit, its state, the sink's root, the counters and the route
    hub_box.copy_in(&hub_exe, "/usr/local/bin/rackhand");
    let units = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/systemd");
    hub_box.copy_in(&units.join("rackhand-hub.service"), "/etc/systemd/system/rackhand-hub.service");
    let dropin = hub.dir.join("test-dropin.conf");
    std::fs::write(&dropin, HUB_TEST_DROPIN).unwrap();
    sh(&hub_box, "mkdir -p /etc/systemd/system/rackhand-hub.service.d /etc/rackhand /var/lib/rackhand");
    hub_box.copy_in(&dropin, "/etc/systemd/system/rackhand-hub.service.d/test.conf");
    let hub_toml = "web = \"0.0.0.0:8443\"\nquic = \"0.0.0.0:7443\"\ndata_dir = \"/var/lib/rackhand\"\n\
             master_key = \"/etc/rackhand/master.key\"\nnode_key = \"/etc/rackhand/node.key\"\nnames = [\"localhost\"]\n";
    std::fs::write(hub.dir.join("hub-in-container.toml"), hub_toml).unwrap();
    hub_box.copy_in(&hub.dir.join("hub-in-container.toml"), "/etc/rackhand/hub.toml");
    hub_box.copy_in(&hub.etc.join("master.key"), "/etc/rackhand/master.key");
    hub_box.copy_in(&hub.etc.join("node.key"), "/etc/rackhand/node.key");
    // the whole data directory, as `hub init` and the seeding left it
    let copied = docker(&["cp", &format!("{}/.", hub.data.display()), &format!("{}:/var/lib/rackhand", hub_box.name)]);
    assert!(copied.status.success(), "copying the hub's data: {}", text(&copied));
    std::fs::write(hub.dir.join("sink-root.pem"), &sink_cert).unwrap();
    hub_box.copy_in(&hub.dir.join("sink-root.pem"), rackhand_hub::notify::config::TEST_SMTP_ROOTS);
    sh(
        &hub_box,
        &format!(
            "set -e; chmod 0755 /usr/local/bin/rackhand; chmod 0644 {roots}
useradd -r -U -M -d /var/lib/rackhand -s /usr/sbin/nologin rackhand-hub
chown -R rackhand-hub:rackhand-hub /var/lib/rackhand
chown root:root /etc/rackhand/master.key && chmod 0600 /etc/rackhand/master.key
chown rackhand-hub:rackhand-hub /etc/rackhand/node.key && chmod 0600 /etc/rackhand/node.key
chown root:rackhand-hub /etc/rackhand/hub.toml && chmod 0640 /etc/rackhand/hub.toml",
            roots = rackhand_hub::notify::config::TEST_SMTP_ROOTS
        ),
    );
    let dead = unused_address(&subnet);
    sh(
        &hub_box,
        &format!(
            "nft -f - <<'EOF'
table inet {TABLE} {{
  chain out {{
    type filter hook output priority raw; policy accept;
    meta l4proto {{ tcp, udp }} th dport 53 counter comment \"dns\"
    ip daddr != {{ {subnet}, 127.0.0.0/8, 224.0.0.0/4, 255.255.255.255 }} counter comment \"outside4\"
    ip daddr {{ 224.0.0.0/4, 255.255.255.255 }} counter comment \"multicast4\"
    ip6 daddr != {{ ::1, fe80::/10, ff00::/8 }} counter comment \"outside6\"
    ip6 daddr {{ fe80::/10, ff00::/8 }} counter comment \"link6\"
  }}
}}
EOF
ip route add default via {dead}"
        ),
    );
    eprintln!("hub {hub_ip}, machine {machine_ip}, sink {sink_ip}, subnet {subnet}, dead route via {dead}");

    // the machine reports, and the hub starts
    machine.spawn_detached(
        "rackhand-probe",
        &format!(
            "exec /usr/local/lib/rackhand/rackhand-probe run --config /etc/rackhand-probe/probe.toml \
                 --data-dir /var/lib/rackhand-probe --state-file /tmp/rackhand-probe.state --root {FIXTURE} \
                 > /tmp/rackhand-probe.log 2>&1"
        ),
    );
    sh(&hub_box, "systemctl daemon-reload && systemctl enable --now rackhand-hub");
    let hub_started = Instant::now();
    within(Duration::from_secs(60), "the hub answers /healthz", || {
        hub_box.root("curl -sk --max-time 5 https://127.0.0.1:8443/healthz").stdout == b"ok"
    });

    // it collects: the machine's reports arrive
    within(Duration::from_secs(90), "reports from the machine", || {
        hub_db(&hub_box).is_some_and(|db| {
            db.query_row("SELECT count(*) FROM report_staging WHERE machine_id = ?1", [MACHINE], |r| r.get::<_, i64>(0))
                .is_ok_and(|n| n > 0)
        })
    });
    eprintln!("reports after {:?}", hub_started.elapsed());

    // the disk rule fires: a critical incident on the machine, and one email for it at the LAN server
    let mut incident = None;
    within(Duration::from_secs(8 * 60), "a critical disk.used incident", || {
        incident = hub_db(&hub_box).and_then(|db| disk_incident(&db)).filter(|(_, s, _)| s == "critical");
        incident.is_some()
    });
    let (incident, _, _) = incident.unwrap();
    eprintln!("critical after {:?}", hub_started.elapsed());
    let about = |m: &String| subject(m).contains(MACHINE_NAME) && subject(m).to_lowercase().contains("disk");
    within(Duration::from_secs(90), "the critical's email at the LAN server", || mails(&sink).iter().any(about));
    eprintln!("email after {:?}", hub_started.elapsed());

    // the runbook starts by itself and succeeds, and the service was restarted
    let mut state = Vec::new();
    within(Duration::from_secs(5 * 60), "the runbook's job finished", || {
        state = hub_db(&hub_box).map(|db| jobs(&db, &incident)).unwrap_or_default();
        state.iter().any(|(_, s)| !["queued", "running", "waiting_approval"].contains(&s.as_str()))
    });
    assert_eq!(state.len(), 1, "one job for the incident: {state:?}");
    assert_eq!(state[0].1, "succeeded", "{state:?}");
    eprintln!("runbook succeeded after {:?}", hub_started.elapsed());
    let after = dummy_state(&machine);
    assert_eq!(sh(&machine, &format!("systemctl is-active {DUMMY}")), "active");
    assert!(after.0 != before.0 && after.1 != before.1, "the service restarted: {before:?} then {after:?}");

    // a few of the hub's 15-second passes later, still the one email for the incident, sent over TLS
    std::thread::sleep(Duration::from_secs(45));
    let all = mails(&sink);
    let disk: Vec<&String> = all.iter().filter(|m| about(m)).collect();
    eprintln!("mails: {:?}", all.iter().map(|m| subject(m)).collect::<Vec<_>>());
    assert_eq!(
        disk.len(),
        1,
        "exactly one email for the incident: {:?}",
        all.iter().map(|m| subject(m)).collect::<Vec<_>>()
    );
    assert!(disk[0].starts_with("X-Sink-TLS: true"), "over STARTTLS: {}", disk[0]);
    assert!(subject(disk[0]).starts_with("[Rackhand] CRITICAL lab/offline-web1"), "{}", subject(disk[0]));

    // the machine is set up as a join leaves it: the hub's SSH test after its first report passed
    let incidents: Vec<(String, String, String)> = {
        let db = hub_db(&hub_box).expect("the hub's database");
        let mut s = db.prepare("SELECT kind, severity, state FROM incidents ORDER BY opened_at").unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(Result::unwrap).collect()
    };
    eprintln!("incidents: {incidents:?}");
    assert!(incidents.iter().all(|(kind, _, _)| kind != "machine.ssh_test_failed"), "{incidents:?}");

    // nothing the hub sent in all that time was for the outside, nor a DNS question
    let seen = counters(&hub_box);
    eprintln!("the hub's outbound counters after {:?}: {seen:?}", hub_started.elapsed());
    for name in ["outside4", "outside6", "dns", "multicast4"] {
        assert_eq!(counter(&seen, name), 0, "{name} packets from the hub: {seen:?}");
    }
    // and the outside really is out of reach, which the counters see: the check of the test itself
    let out = hub_box.root("curl -s --connect-timeout 5 https://1.1.1.1/ >/dev/null 2>&1; echo $?");
    assert_ne!(String::from_utf8_lossy(&out.stdout).trim(), "0", "the hub's machine reached 1.1.1.1");
    let named = hub_box.root("getent hosts example.com");
    assert!(!named.status.success(), "a name resolved from the hub's machine: {}", text(&named));
    let checked = counters(&hub_box);
    assert!(counter(&checked, "outside4") > 0 && counter(&checked, "dns") > 0, "the counters count: {checked:?}");
    eprintln!("done in {:?} ({:?} after the hub started)", started.elapsed(), hub_started.elapsed());
}

/// The hub's database before its first start: the site, the managed machine, its pinned host key and the runbook. Returns
/// the machine's `authorized_keys` lines for the hub's two keys, each taken from the hub's address only.
fn seed(hub: &Hub, machine_ip: &str, hub_ip: &str, host_key: &str) -> Vec<(Identity, String)> {
    let path = hub.data.join("hub.db");
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute("INSERT INTO sites (id, name, timezone, is_local) VALUES ('lab-site', 'lab', 'UTC', 1)", []).unwrap();
        let endpoint = iroh::SecretKey::from_bytes(&PROBE_KEY).public().to_string();
        c.execute(
            "INSERT INTO machines (id, site_id, name, kind, address, access, probe_endpoint_id, state) \
             VALUES (?1, 'lab-site', ?2, 'linux', ?3, 'managed', ?4, 'enrolled')",
            [MACHINE, MACHINE_NAME, machine_ip, endpoint.as_str()],
        )
        .unwrap();
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let line = rt.block_on(async {
        let db = Arc::new(Db::open(&path).unwrap());
        let now = rackhand_store::ids::now_ms();
        let (library, _changes) = Library::new(db.clone(), Audit::new(db.writer()));
        library.save(Kind::Runbook, RUNBOOK_NAME, RUNBOOK, "admin", now).await.unwrap();
        let (host_keys, _alerts) = HostKeys::new(db.clone());
        let key = russh::keys::PublicKey::from_openssh(host_key).unwrap();
        host_keys.pin_from_join(MACHINE, &[key], now).await.unwrap();
        let vault = Vault::new(MasterKey::load(Some(&hub.etc.join("master.key"))).unwrap(), db.clone());
        let mut lines = Vec::new();
        for id in [Identity::Automation, Identity::Assistant] {
            let key = load_or_create(&vault, id).await.unwrap();
            lines.push((id, authorized_keys_line(key.public_key(), &[hub_ip.to_string()]).unwrap()));
        }
        lines
    });
    drop(rt);
    // everything in the main file before it is copied
    let c = rusqlite::Connection::open(&path).unwrap();
    c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())).unwrap();
    line
}
