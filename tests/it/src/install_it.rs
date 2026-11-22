//! `packaging/install.sh` against a real hub (plan T44, 7.3.12, D105): a release directory served over HTTP holds the
//! verifier (built with the test keys pinned) and the probe and service files signed with the test keys of
//! `tests/keys/`; each test installs on a clean Debian (systemd) or Alpine (OpenRC) container.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rackhand_proto::common::{Access, ProbeMode};

use crate::probe_hub::{Hub, field, within};
use crate::support::{Container, musl_binary, musl_binary_with};

const TARGET: &str = "x86_64-unknown-linux-musl";

fn seed(name: &str) -> SigningKey {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../keys/test-{name}.seed"));
    let hex = std::fs::read_to_string(path).unwrap();
    let bytes: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&hex.trim()[2 * i..2 * i + 2], 16).unwrap()).collect();
    SigningKey::from_bytes(&bytes.try_into().unwrap())
}

fn key_id(name: &str) -> [u8; 8] {
    match name {
        "current" => [1; 8],
        "standby" => [2; 8],
        _ => [3; 8],
    }
}

fn sha256(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(std::fs::read(path).unwrap()).iter().map(|b| format!("{b:02x}")).collect()
}

/// A release directory and the HTTP server in front of it.
struct Release {
    dir: PathBuf,
    port: u16,
    server: Child,
}

impl Drop for Release {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
    }
}

impl Release {
    /// The release files, signed with the test key `signer`; `tamper` changes the probe after signing.
    fn new(name: &str, signer: &str, tamper: bool) -> Release {
        let dir = std::env::temp_dir().join(format!("rackhand-it-release-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let verify = musl_binary_with("rackhand-release", "rackhand-verify", "test-keys");
        std::fs::copy(verify, dir.join(format!("rackhand-verify-{TARGET}"))).unwrap();
        let packaging = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging");
        let files = [
            (musl_binary("rackhand-probe", "rackhand-probe"), format!("rackhand-probe-{TARGET}")),
            (packaging.join("systemd/rackhand-probe.service"), "rackhand-probe.service".into()),
            (packaging.join("systemd/rackhand-probe-helper.service"), "rackhand-probe-helper.service".into()),
            (packaging.join("openrc/rackhand-probe"), "rackhand-probe.openrc".into()),
            (packaging.join("openrc/rackhand-probe-helper"), "rackhand-probe-helper.openrc".into()),
        ];
        for (from, to) in files {
            let data = std::fs::read(&from).unwrap();
            let sig = rackhand_release::signing::sign(&seed(signer), key_id(signer), &data, &format!("file:{to}"));
            std::fs::write(dir.join(&to), &data).unwrap();
            std::fs::write(dir.join(format!("{to}.minisig")), sig).unwrap();
        }
        if tamper {
            let p = dir.join(format!("rackhand-probe-{TARGET}"));
            let mut data = std::fs::read(&p).unwrap();
            let n = data.len() / 2;
            data[n] ^= 0xff;
            std::fs::write(p, data).unwrap();
        }
        let port = std::net::TcpListener::bind("0.0.0.0:0").unwrap().local_addr().unwrap().port();
        let server = Command::new("python3")
            .args(["-m", "http.server", &port.to_string(), "--bind", "0.0.0.0", "--directory"])
            .arg(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(500));
        Release { dir, port, server }
    }

    /// `install.sh` as the release fills it in; `verify_sha256` overrides the verifier's hash.
    fn script(&self, verify_sha256: Option<&str>) -> PathBuf {
        let template = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/install.sh");
        let sha =
            verify_sha256.map_or_else(|| sha256(&self.dir.join(format!("rackhand-verify-{TARGET}"))), str::to_string);
        let text = std::fs::read_to_string(template)
            .unwrap()
            .replace("__VERSION__", "0.1.0")
            .replace("__VERIFY_SHA256__", &sha);
        let out = self.dir.join("install.sh");
        std::fs::write(&out, text).unwrap();
        out
    }
}

/// A hub with its admin signed in and its site named.
fn hub(name: &str) -> Hub {
    let mut hub = Hub::init(name);
    hub.start();
    hub.first_run();
    hub
}

/// The dashboard's Add machine (T49 builds the page): a pending machine and its 60-minute token.
fn add_machine(hub: &Hub, access: Access, roles: &[&str]) -> (String, String) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let db = std::sync::Arc::new(rackhand_store::Db::open(&hub.data.join("hub.db")).unwrap());
        let site: String =
            db.readers().with(|c| c.query_row("SELECT id FROM sites WHERE is_local = 1", [], |r| r.get(0))).unwrap();
        let registry = rackhand_hub::registry::Registry::load(db).unwrap();
        let add = rackhand_hub::registry::machines::AddMachine {
            site_id: site,
            name: "web1".into(),
            kind: "linux".into(),
            access,
            mode: ProbeMode::Local,
            roles: roles.iter().map(|r| r.to_string()).collect(),
        };
        let (id, token) = registry.add_machine(&add, "admin", rackhand_store::ids::now_ms()).await.unwrap();
        (id.to_string(), token.as_str().to_string())
    })
}

/// Runs the installer on `c` as root.
fn install(c: &Container, hub: &Hub, release: &Release, script: &Path, token: &str, extra: &str) -> Output {
    let (_, gateway) = c.ip_and_gateway();
    let ticket = format!("rackhand1:{}@{gateway}:{}", hub.id_hex, hub.quic);
    c.copy_in(script, "/tmp/install.sh");
    c.root(&format!(
        "sh /tmp/install.sh --ticket {ticket} --token {token} --release-url http://{gateway}:{} {extra}",
        release.port
    ))
}

fn ok(out: &Output) {
    assert!(
        out.status.success(),
        "install: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn sh(c: &Container, script: &str) -> String {
    String::from_utf8_lossy(&c.root(script).stdout).trim().to_string()
}

fn reporting(hub: &Hub) {
    within(Duration::from_secs(60), "the machine's reports on /metrics", || hub.metrics().contains("machine=\"web1\""));
}

/// One column of the machine's row in the hub's database.
fn machine_column(hub: &Hub, id: &str, column: &str) -> String {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let _in = rt.enter();
    let db = rackhand_store::Db::open(&hub.data.join("hub.db")).unwrap();
    let sql = format!("SELECT coalesce({column}, '') FROM machines WHERE id = ?1");
    db.readers().with(|c| c.query_row(&sql, [id], |r| r.get(0))).unwrap()
}

/// The hub's SSH tests of the machine, oldest first: the event kind and the account a failure names.
fn ssh_tests(hub: &Hub, id: &str) -> Vec<(String, String)> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let _in = rt.enter();
    let db = rackhand_store::Db::open(&hub.data.join("hub.db")).unwrap();
    db.readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT kind, coalesce(json_extract(data, '$.account'), '') FROM events
                 WHERE machine_id = ?1 AND kind LIKE 'machine.ssh_test_%' ORDER BY at_ms",
            )?;
            s.query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })
        .unwrap()
}

/// What a managed machine must have (7.3.7); `assistant` says whether `rackhand-ai` is one of them.
fn assert_managed(c: &Container, hub_ip: &str, assistant: bool) {
    let keys = sh(c, "cat /home/rackhand/.ssh/authorized_keys");
    assert!(
        keys.starts_with("from=\"") && keys.contains(hub_ip) && keys.contains("no-port-forwarding ssh-ed25519 "),
        "{keys}"
    );
    assert_eq!(sh(c, "stat -c '%a %U' /home/rackhand/.ssh/authorized_keys"), "600 rackhand");
    assert_eq!(sh(c, "id -u rackhand-ai >/dev/null 2>&1 && echo yes || echo no"), if assistant { "yes" } else { "no" });
    let sudoers = sh(c, "cat /etc/sudoers.d/rackhand");
    assert!(sudoers.starts_with("rackhand ALL=(root) NOPASSWD: /usr/local/lib/rackhand/run"), "{sudoers}");
    assert_eq!(sudoers.contains("rackhand-ai"), assistant, "{sudoers}");
    assert!(c.root("visudo -c").status.success(), "visudo -c");
    assert_eq!(
        sh(c, "stat -c '%a %U' /etc/rackhand/commands.json /etc/rackhand-probe/probe.toml"),
        "644 root\n644 root"
    );
}

/// The Alpine machine once OpenRC is in its default runlevel.
fn alpine() -> Container {
    let c = Container::start_with("alpine-install", &[]);
    within(Duration::from_secs(20), "OpenRC's default runlevel", || sh(&c, "rc-status -r 2>/dev/null") == "default");
    c
}

fn nothing_installed(c: &Container) {
    let left = sh(
        c,
        "ls /usr/local/lib/rackhand/rackhand-probe /etc/rackhand-probe/probe.toml 2>/dev/null; id rackhand-probe 2>/dev/null",
    );
    assert_eq!(left, "", "nothing installed");
}

/// HTML text as typed: numeric references (`&#38;`, `&#x27;`) and the named ones a page escapes.
fn unescape(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let end = tail.find(';').filter(|e| *e <= 10);
        let decoded = end.and_then(|e| {
            let name = &tail[1..e];
            let c = match name {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => match name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok().and_then(char::from_u32),
                    None => name.strip_prefix('#').and_then(|d| d.parse().ok()).and_then(char::from_u32),
                },
            };
            c.map(|c| (c, e + 1))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &tail[len..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The Add page's offline command (T49), as the admin copies it from a dashboard reached at `gateway`, with the ticket
/// naming the hub at that address too.
fn offline_command(hub: &Hub, gateway: &str, name: &str) -> String {
    let csrf = field(&hub.curl(&["/add"]), "csrf");
    let form = format!("csrf={csrf}&os=linux&name={name}&access=managed&mode=local");
    let host = format!("Host: {gateway}:{}", hub.web);
    let page = hub.curl(&["-H", &host, "-H", &hub.cookie_header(), "--data", &form, "/add/machine"]);
    let page = unescape(&page);
    let at = page.find("Offline, from this hub").unwrap_or_else(|| panic!("an offline command: {page}"));
    let code = &page[at..];
    let start = code.find("<code>").unwrap() + 6;
    let command = code[start..code.find("</code>").unwrap()].to_string();
    let given = command.split(" --ticket ").nth(1).and_then(|r| r.split(' ').next()).unwrap().to_string();
    command.replace(&given, &format!("rackhand1:{}@{gateway}:{}", hub.id_hex, hub.quic))
}

mod install {
    use super::*;

    /// The offline variant (7.3.12): the hub serves `install.sh` and the release files it holds over its own HTTPS;
    /// the command checks the script against the SHA-256 the page gives before running it.
    #[test]
    fn offline_variant_checks_script_hash() {
        let hub = hub("inst-offline");
        let release = Release::new("offline", "current", false);
        release.script(None);
        let held = hub.data.join("release");
        std::fs::create_dir_all(&held).unwrap();
        for f in std::fs::read_dir(&release.dir).unwrap() {
            let f = f.unwrap();
            std::fs::copy(f.path(), held.join(f.file_name())).unwrap();
        }
        let c = Container::start_systemd_with("debian-install", &[]);
        let (_, gateway) = c.ip_and_gateway();
        let command = offline_command(&hub, &gateway, "web1");
        assert!(command.contains(&format!("https://{gateway}:{}/install.sh", hub.web)), "{command}");
        // a wrong SHA-256 stops it before the script runs
        let sha = command.split("echo '").nth(1).and_then(|r| r.split(' ').next()).unwrap().to_string();
        let bad = command.replace(&sha, &"0".repeat(64));
        let out = c.root(&bad);
        assert!(
            !out.status.success(),
            "{bad}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let said = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(said.contains("FAILED"), "sha256sum said: {said}");
        nothing_installed(&c);
        // the command as given installs from the hub's own files
        ok(&c.root(&command));
        assert_eq!(sh(&c, "systemctl is-active rackhand-probe"), "active");
        reporting(&hub);
    }

    #[test]
    fn debian_managed_enrolls_and_reports() {
        let hub = hub("inst-debian");
        let release = Release::new("debian", "current", false);
        let (_, token) = add_machine(&hub, Access::Managed, &[]);
        let c = Container::start_systemd_with("debian-install", &[]);
        ok(&install(&c, &hub, &release, &release.script(None), &token, ""));
        assert_managed(&c, &c.ip_and_gateway().1, true);
        assert_eq!(sh(&c, "systemctl is-active rackhand-probe rackhand-probe-helper"), "active\nactive");
        reporting(&hub);
    }

    /// The hub's SSH test after a managed machine's first report (7.3.12, AC35): it logs in as `rackhand` (`true`) and
    /// as `rackhand-ai` (`sudo -n true`) with the host key pinned at join, at the address the join came from. With sshd
    /// down the test fails naming the account; once sshd is up the next report is tested again, and the Add page shows
    /// the machine enrolled and healthy.
    #[test]
    fn hub_ssh_test_completes_enrollment() {
        let hub = hub("inst-sshtest");
        let release = Release::new("sshtest", "current", false);
        let (id, token) = add_machine(&hub, Access::Managed, &[]);
        let c = Container::start_systemd_with("debian-install-sshd", &[]);
        within(Duration::from_secs(30), "systemd up", || {
            matches!(sh(&c, "systemctl is-system-running 2>/dev/null || true").as_str(), "running" | "degraded")
        });
        ok(&c.root("systemctl stop ssh.socket ssh.service 2>/dev/null; systemctl stop ssh; true"));
        ok(&install(&c, &hub, &release, &release.script(None), &token, ""));
        reporting(&hub);
        let (ip, _) = c.ip_and_gateway();
        assert_eq!(machine_column(&hub, &id, "address"), ip, "the address the join came from");

        let failed = || ssh_tests(&hub, &id).iter().any(|(k, _)| k == "machine.ssh_test_failed");
        within(Duration::from_secs(60), "the SSH test failed", failed);
        let (_, account) = ssh_tests(&hub, &id).into_iter().find(|(k, _)| k == "machine.ssh_test_failed").unwrap();
        assert_eq!(account, "rackhand", "the failure names the account");
        let add = |hub: &Hub| super::unescape(&hub.curl(&["/add"]));
        assert!(add(&hub).contains("Pending: SSH test failed as rackhand"), "{}", add(&hub));
        assert_eq!(machine_column(&hub, &id, "state"), "pending", "pending until the SSH test passes (D84)");

        ok(&c.root("systemctl start ssh"));
        within(Duration::from_secs(20), "sshd up", || sh(&c, "systemctl is-active ssh") == "active");
        let passed = || ssh_tests(&hub, &id).last().is_some_and(|(k, _)| k == "machine.ssh_test_passed");
        within(Duration::from_secs(90), "the SSH test passed while the machine reports", passed);
        within(Duration::from_secs(20), "the pass enrolls it", || machine_column(&hub, &id, "state") == "enrolled");
        let page = add(&hub);
        let row = page.find("<td>web1</td>").map(|at| &page[at..at + page[at..].find("</tr>").unwrap()]);
        assert!(row.is_some_and(|r| r.contains("Enrolled and healthy")), "{page}");
        let logins = sh(
            &c,
            "journalctl --sync; journalctl -u ssh --no-pager | grep -c 'Accepted publickey for rackhand' || true",
        );
        assert_eq!(logins, "2", "one login per account: {}", sh(&c, "journalctl -u ssh --no-pager"));
    }

    #[test]
    fn alpine_managed_enrolls_and_reports() {
        let hub = hub("inst-alpine");
        let release = Release::new("alpine", "current", false);
        let (_, token) = add_machine(&hub, Access::Managed, &[]);
        let c = alpine();
        ok(&install(&c, &hub, &release, &release.script(None), &token, ""));
        // busybox `command -v` answers for its first name only
        assert_eq!(sh(&c, "command -v sudo && command -v bash"), "/usr/bin/sudo\n/bin/bash", "sudo and bash added");
        assert_managed(&c, &c.ip_and_gateway().1, true);
        reporting(&hub);
    }

    #[test]
    fn openrc_services_run_probe_and_helper() {
        let hub = hub("inst-openrc");
        let release = Release::new("openrc", "current", false);
        let (_, token) = add_machine(&hub, Access::Monitor, &[]);
        let c = alpine();
        ok(&install(&c, &hub, &release, &release.script(None), &token, "--monitor"));
        // each process's owner from /proc (busybox ps cuts user names at 8 characters)
        let owners = r#"for p in $(pgrep -f /usr/local/lib/rackhand/rackhand-probe); do echo "$(stat -c %U /proc/$p) $(tr '\0' ' ' < /proc/$p/cmdline)"; done"#;
        let users = sh(&c, owners);
        assert!(users.contains("rackhand-probe /usr/local/lib/rackhand/rackhand-probe run"), "{users}");
        assert!(users.contains("root /usr/local/lib/rackhand/rackhand-probe helper"), "the helper as root: {users}");
        assert_eq!(
            sh(&c, "stat -c '%a %U' /var/lib/rackhand-probe /run/rackhand-helper"),
            "700 rackhand-probe\n755 root"
        );
        reporting(&hub);
    }

    #[test]
    fn monitor_has_no_accounts_keys_or_command_list() {
        let hub = hub("inst-monitor");
        let release = Release::new("monitor", "current", false);
        let (_, token) = add_machine(&hub, Access::Monitor, &[]);
        let c = Container::start_systemd_with("debian-install", &[]);
        ok(&install(&c, &hub, &release, &release.script(None), &token, "--monitor"));
        let left = sh(
            &c,
            "id rackhand 2>/dev/null; id rackhand-ai 2>/dev/null; ls /etc/sudoers.d/rackhand /etc/rackhand/commands.json 2>/dev/null",
        );
        assert_eq!(left, "", "no hub users, no sudoers file, no command list (D88)");
        assert!(sh(&c, "cat /etc/rackhand-probe/probe.toml").contains("access = \"monitor\""));
        reporting(&hub);
    }

    #[test]
    fn bad_signature_stops_before_installing() {
        let hub = hub("inst-badsig");
        let release = Release::new("badsig", "current", true);
        let (_, token) = add_machine(&hub, Access::Managed, &[]);
        let c = Container::start_systemd_with("debian-install", &[]);
        let out = install(&c, &hub, &release, &release.script(None), &token, "");
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("isn't signed by a pinned release key"));
        nothing_installed(&c);
    }

    #[test]
    fn unpinned_key_signature_refused() {
        let hub = hub("inst-other");
        let release = Release::new("other", "other", false);
        let (_, token) = add_machine(&hub, Access::Managed, &[]);
        let c = Container::start_systemd_with("debian-install", &[]);
        assert!(!install(&c, &hub, &release, &release.script(None), &token, "").status.success());
        nothing_installed(&c);
    }

    #[test]
    fn verifier_hash_mismatch_stops() {
        let hub = hub("inst-verifier");
        let release = Release::new("verifier", "current", false);
        let (_, token) = add_machine(&hub, Access::Managed, &[]);
        let c = Container::start_systemd_with("debian-install", &[]);
        let script = release.script(Some(&"0".repeat(64)));
        let out = install(&c, &hub, &release, &script, &token, "");
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("rackhand-verify doesn't match this installer"));
        nothing_installed(&c);
    }

    #[test]
    fn standby_key_signature_accepted() {
        let hub = hub("inst-standby");
        let release = Release::new("standby", "standby", false);
        let (_, token) = add_machine(&hub, Access::Monitor, &[]);
        let c = Container::start_systemd_with("debian-install", &[]);
        ok(&install(&c, &hub, &release, &release.script(None), &token, "--monitor"));
        reporting(&hub);
    }

    #[test]
    fn role_hub_machine_gets_no_assistant_account() {
        let hub = hub("inst-rolehub");
        let release = Release::new("rolehub", "current", false);
        let (_, token) = add_machine(&hub, Access::Managed, &["hub"]);
        let c = Container::start_systemd_with("debian-install", &[]);
        ok(&install(&c, &hub, &release, &release.script(None), &token, "--role hub"));
        assert_managed(&c, &c.ip_and_gateway().1, false);
    }
}

mod runcmd {
    use super::*;

    #[test]
    fn first_list_arrives_with_join() {
        let hub = hub("inst-list");
        let release = Release::new("list", "current", false);
        let (_, token) = add_machine(&hub, Access::Managed, &[]);
        let c = Container::start_systemd_with("debian-install", &[]);
        ok(&install(&c, &hub, &release, &release.script(None), &token, ""));
        // the hub's list: its library's runbooks' root steps and the diagnostics' root commands (7.3.7, 7.8.3)
        let installed: serde_json::Value = serde_json::from_str(&sh(&c, "cat /etc/rackhand/commands.json")).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let _in = rt.enter();
        let db = rackhand_store::Db::open(&hub.data.join("hub.db")).unwrap();
        let runbooks: Vec<_> = rackhand_hub::library::items::Library::all_current(&db)
            .unwrap()
            .into_iter()
            .filter(|(kind, _, _)| *kind == rackhand_hub::library::items::Kind::Runbook)
            .filter_map(|(_, _, text)| rackhand_runbook::runbook::Runbook::parse(&text).ok())
            .collect();
        let mut expected = rackhand_runbook::templates::command_list(&runbooks);
        expected.commands.extend(rackhand_runbook::diagnostics::templates());
        let expected = serde_json::to_value(&expected).unwrap();
        // the wrapper's file also records the list's signed version beside it
        assert_eq!(installed["commands"], expected["commands"], "commands.json holds the join's list");
        assert!(installed["version"].as_u64().is_some_and(|v| v > 0), "and its version: {}", installed["version"]);
        let refused =
            c.exec(Some("rackhand"), &["sudo", "-n", "/usr/local/lib/rackhand/run", "/bin/rm", "-rf", "/"], None);
        assert!(!refused.status.success(), "a command outside the list is refused");
    }
}
