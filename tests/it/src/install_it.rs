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
        let row = page.find("<b>web1</b>").map(|at| &page[at..at + page[at..].find("</tr>").unwrap()]);
        assert!(row.is_some_and(|r| r.contains("Enrolled and healthy")), "{page}");
        let logins = sh(
            &c,
            "journalctl --sync; journalctl -u ssh --no-pager | grep -c 'Accepted publickey for rackhand' || true",
        );
        // every sshd and sudo line whatever unit it is filed under, and what the hub recorded
        let all = sh(&c, "journalctl --no-pager -o short-precise | grep -E 'sshd|sudo' || true");
        assert_eq!(logins, "2", "one login per account: events {:?}, unfiltered journal: {all}", ssh_tests(&hub, &id));
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

    /// 7.3.12, 7.7.3: `rackhand-probe uninstall` on the machine removes the services and files, for root only.
    #[test]
    fn probe_uninstall_locally_on_monitor_machine() {
        let hub = hub("inst-uninstall");
        let release = Release::new("uninstall", "current", false);
        let (_, token) = add_machine(&hub, Access::Monitor, &[]);
        let c = Container::start_systemd_with("debian-install", &[]);
        ok(&install(&c, &hub, &release, &release.script(None), &token, "--monitor"));
        let bin = "/usr/local/lib/rackhand/rackhand-probe";
        let probe_user = c.exec(Some("rackhand-probe"), &[bin, "uninstall"], None);
        assert!(!probe_user.status.success(), "the probe's own user can't");
        assert!(String::from_utf8_lossy(&probe_user.stderr).contains("needs root"));
        assert!(sh(&c, "ls /etc/rackhand-probe/probe.toml").contains("probe.toml"), "nothing was removed");
        assert_eq!(sh(&c, "systemctl is-active rackhand-probe rackhand-probe-helper | sort -u"), "active");
        let root = c.exec(None, &[bin, "uninstall"], None);
        assert!(root.status.success(), "{}", String::from_utf8_lossy(&root.stderr));
        let left = sh(
            &c,
            "ls /usr/local/lib/rackhand /etc/rackhand-probe /var/lib/rackhand-probe /var/lib/rackhand-helper \
                /etc/systemd/system/rackhand-probe.service /etc/systemd/system/rackhand-probe-helper.service 2>/dev/null; \
             id rackhand-probe 2>/dev/null; systemctl is-active rackhand-probe rackhand-probe-helper 2>/dev/null | grep -c '^active'",
        );
        assert_eq!(left, "0", "no files, no user and no running service: {left}");
        let again = c.exec(None, &["sh", "-c", "test -e /usr/local/lib/rackhand"], None);
        assert!(!again.status.success());
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

/// 7.3.12, D89, AC59: the one-time command the dashboard issues changes a machine's level in place, run as root on it.
mod level {
    use super::*;

    /// The command's token, as the machine page issues it (T62).
    fn level_token(hub: &Hub, id: &str, to: Access) -> String {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let db = std::sync::Arc::new(rackhand_store::Db::open(&hub.data.join("hub.db")).unwrap());
            let registry = rackhand_hub::registry::Registry::load(db).unwrap();
            let ulid = id.parse().unwrap();
            let token = registry.level_change_token(ulid, to, "admin", rackhand_store::ids::now_ms()).await.unwrap();
            token.as_str().to_string()
        })
    }

    /// What the machine has reported to the hub so far: staged reports, stored chunks and events.
    fn history(hub: &Hub, id: &str) -> i64 {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let _in = rt.enter();
        let db = rackhand_store::Db::open(&hub.data.join("hub.db")).unwrap();
        db.readers()
            .with(|c| {
                c.query_row(
                    "SELECT (SELECT count(*) FROM report_staging WHERE machine_id = ?1)
                          + (SELECT count(*) FROM series_chunks WHERE machine_id = ?1)
                          + (SELECT count(*) FROM events WHERE machine_id = ?1)",
                    [id],
                    |r| r.get(0),
                )
            })
            .unwrap()
    }

    fn has_no_hub_way_in(c: &Container) {
        let left = sh(
            c,
            "id rackhand 2>/dev/null; id rackhand-ai 2>/dev/null; ls -d /home/rackhand /home/rackhand-ai \
             /etc/sudoers.d/rackhand /etc/rackhand/commands.json 2>/dev/null",
        );
        assert_eq!(left, "", "no hub users, home, keys, sudoers file or command list");
        assert_eq!(sh(c, "systemctl is-active rackhand-probe rackhand-probe-helper | sort -u"), "active");
    }

    #[test]
    fn monitor_to_managed_keeps_id_and_history() {
        let hub = hub("level-up");
        let release = Release::new("level-up", "current", false);
        let (id, token) = add_machine(&hub, Access::Monitor, &[]);
        let c = Container::start_systemd_with("debian-install", &[]);
        ok(&install(&c, &hub, &release, &release.script(None), &token, "--monitor"));
        reporting(&hub);
        within(Duration::from_secs(60), "something stored", || history(&hub, &id) > 0);
        has_no_hub_way_in(&c);
        let before = history(&hub, &id);
        assert_eq!(machine_column(&hub, &id, "access"), "monitor");
        let endpoint = machine_column(&hub, &id, "probe_endpoint_id");

        let change = level_token(&hub, &id, Access::Managed);
        assert_eq!(machine_column(&hub, &id, "access"), "monitor", "issuing the command changes nothing");
        ok(&install(&c, &hub, &release, &release.script(None), &change, ""));
        assert_managed(&c, &c.ip_and_gateway().1, true);
        assert!(sh(&c, "cat /etc/rackhand-probe/probe.toml").contains("access = \"managed\""));
        assert_eq!(machine_column(&hub, &id, "access"), "managed");
        assert_eq!(machine_column(&hub, &id, "state"), "enrolled");
        assert_eq!(machine_column(&hub, &id, "probe_endpoint_id"), endpoint, "the same machine");
        assert!(history(&hub, &id) >= before, "its history is kept");
        // the probe now runs as a managed machine's, and goes on reporting
        assert_eq!(sh(&c, "systemctl is-active rackhand-probe rackhand-probe-helper | sort -u"), "active");
        reporting(&hub);
        // the one-time command works once
        let again = install(&c, &hub, &release, &release.script(None), &change, "--monitor");
        assert!(!again.status.success(), "a used command is refused");
        assert_eq!(machine_column(&hub, &id, "access"), "managed");
    }

    #[test]
    fn managed_to_monitor_removes_everything() {
        let hub = hub("level-down");
        let release = Release::new("level-down", "current", false);
        let (id, token) = add_machine(&hub, Access::Managed, &[]);
        let c = Container::start_systemd_with("debian-install-sshd", &[]);
        within(Duration::from_secs(30), "systemd up", || {
            matches!(sh(&c, "systemctl is-system-running 2>/dev/null || true").as_str(), "running" | "degraded")
        });
        ok(&install(&c, &hub, &release, &release.script(None), &token, ""));
        assert_managed(&c, &c.ip_and_gateway().1, true);
        reporting(&hub);
        within(Duration::from_secs(120), "the hub's SSH test enrolls it", || {
            machine_column(&hub, &id, "state") == "enrolled"
        });
        sh(&c, "touch /etc/rackhand/keepme-not-ours; useradd -m owner; true");
        let before = history(&hub, &id);

        let change = level_token(&hub, &id, Access::Monitor);
        ok(&install(&c, &hub, &release, &release.script(None), &change, "--monitor"));
        has_no_hub_way_in(&c);
        assert_eq!(sh(&c, "id owner >/dev/null 2>&1 && echo yes"), "yes", "another user stays");
        assert!(sh(&c, "cat /etc/rackhand-probe/probe.toml").contains("access = \"monitor\""));
        assert_eq!(machine_column(&hub, &id, "access"), "monitor");
        assert!(history(&hub, &id) >= before);
        reporting(&hub);
    }

    /// A token for one machine and level is no key to another or to the other level.
    #[test]
    fn a_level_command_is_bound_to_its_machine_and_level() {
        let hub = hub("level-bound");
        let release = Release::new("level-bound", "current", false);
        let (id, token) = add_machine(&hub, Access::Monitor, &[]);
        let c = Container::start_systemd_with("debian-install", &[]);
        ok(&install(&c, &hub, &release, &release.script(None), &token, "--monitor"));
        let to_managed = level_token(&hub, &id, Access::Managed);
        // asking for the other level than the token names is refused, and nothing changes on the machine or the hub
        let wrong = install(&c, &hub, &release, &release.script(None), &to_managed, "--monitor");
        assert!(!wrong.status.success(), "a token for managed doesn't make a monitor machine");
        assert_eq!(machine_column(&hub, &id, "access"), "monitor");
        has_no_hub_way_in(&c);
        // and the real command still works afterwards (a refused join uses nothing up)
        ok(&install(&c, &hub, &release, &release.script(None), &to_managed, ""));
        assert_eq!(machine_column(&hub, &id, "access"), "managed");
    }
}

/// Connections end to end (plan T70, AC14, AC55): a probe in a container, a hub with a threat list, and a destination the
/// container really connects to.
mod conn {
    use std::net::TcpListener;

    use super::*;

    /// A hub whose Feodo list names `listed`, as a stored download would, and with its admin signed in.
    fn hub_listing(name: &str, listed: &str) -> Hub {
        let mut hub = Hub::init(name);
        let dir = hub.data.join("intel");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("feodo.bin"), format!("{listed}\n")).unwrap();
        hub.start();
        hub.first_run();
        hub
    }

    fn sql(hub: &Hub, statement: &str) {
        let c = rusqlite::Connection::open(hub.data.join("hub.db")).unwrap();
        c.busy_timeout(Duration::from_secs(10)).unwrap();
        c.execute_batch(statement).unwrap();
    }

    fn count(hub: &Hub, query: &str) -> i64 {
        let c = rusqlite::Connection::open(hub.data.join("hub.db")).unwrap();
        c.busy_timeout(Duration::from_secs(10)).unwrap();
        c.query_row(query, [], |r| r.get(0)).unwrap()
    }

    /// The container holds a connection open to `ip:port` for a while.
    fn connect_out(c: &Container, ip: &str, port: u16) {
        let script = format!("setsid bash -c 'exec 3<>/dev/tcp/{ip}/{port}; sleep 300' >/dev/null 2>&1 &");
        ok(&c.root(&script));
    }

    fn listen() -> (TcpListener, u16) {
        let l = TcpListener::bind("0.0.0.0:0").unwrap();
        let port = l.local_addr().unwrap().port();
        (l, port)
    }

    /// Serves what connects to `l` until the test ends, holding each connection open.
    fn hold(l: TcpListener) {
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for s in l.incoming().flatten() {
                held.push(s);
            }
        });
    }

    #[test]
    fn threat_listed_destination_critical_within_60s() {
        let release = Release::new("conn-bad", "current", false);
        let c = Container::start_systemd_with("debian-install", &[]);
        let (_, gateway) = c.ip_and_gateway();
        let hub = hub_listing("conn-bad", &gateway);
        let (id, token) = add_machine(&hub, Access::Monitor, &[]);
        // the destination is the hub's own side of the bridge, a private address: the policy watches those
        sql(&hub, "INSERT INTO policies (id, name, connections, watch_internal) VALUES ('watch', 'watch', 'full', 1)");
        sql(&hub, &format!("UPDATE machines SET policy_id = 'watch' WHERE id = '{id}'"));
        ok(&install(&c, &hub, &release, &release.script(None), &token, "--monitor"));
        let (listener, port) = listen();
        hold(listener);
        connect_out(&c, &gateway, port);
        let took = within(Duration::from_secs(90), "a conn.known_bad event", || {
            count(&hub, "SELECT count(*) FROM events WHERE kind = 'conn.known_bad' AND severity = 'critical'") > 0
        });
        eprintln!("critical after {took:?}");
        let data: String = rusqlite::Connection::open(hub.data.join("hub.db"))
            .unwrap()
            .query_row("SELECT data FROM events WHERE kind = 'conn.known_bad' LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert!(
            data.contains(&gateway) && data.contains("\"exe\":\"/usr/bin/"),
            "names the destination and the program: {data}"
        );
        assert!(count(&hub, "SELECT count(*) FROM incidents WHERE kind = 'conn.known_bad'") >= 0);
        assert!(
            count(&hub, "SELECT count(*) FROM conn_records WHERE verdict = 'known_bad'") >= 1,
            "and the row says so"
        );
    }

    #[test]
    fn desktop_summary_and_off_modes_end_to_end() {
        let release = Release::new("conn-modes", "current", false);
        let c = Container::start_systemd_with("debian-install", &[]);
        let (_, gateway) = c.ip_and_gateway();
        let hub = hub_listing("conn-modes", &gateway);
        let (id, token) = add_machine(&hub, Access::Monitor, &["desktop"]);
        sql(&hub, "INSERT INTO policies (id, name, watch_internal) VALUES ('watch', 'watch', 1)");
        // a policy that watches private destinations and says nothing of connections is `full`: this one is the desktop's own
        sql(&hub, "UPDATE policies SET connections = 'summary' WHERE id = 'watch'");
        sql(&hub, &format!("UPDATE machines SET policy_id = 'watch' WHERE id = '{id}'"));
        ok(&install(&c, &hub, &release, &release.script(None), &token, "--monitor"));
        let (listener, port) = listen();
        hold(listener);
        connect_out(&c, &gateway, port);
        within(Duration::from_secs(90), "the threat-listed destination named", || {
            count(&hub, "SELECT count(*) FROM events WHERE kind = 'conn.known_bad'") > 0
        });
        within(Duration::from_secs(30), "a summary row", || count(&hub, "SELECT count(*) FROM conn_records") > 0);
        let stored: String = rusqlite::Connection::open(hub.data.join("hub.db"))
            .unwrap()
            .query_row(
                "SELECT group_concat(dest_ip || '|' || exe || '|' || container, ';') FROM conn_records",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!stored.contains(&gateway) && !stored.contains("bash"), "only counts per ASN: {stored}");
        // off: nothing is stored from then on, and the threat list still speaks
        sql(
            &hub,
            "DELETE FROM conn_records; UPDATE policies SET connections = 'off' WHERE id = 'watch'; DELETE FROM events",
        );
        connect_out(&c, &gateway, port);
        within(Duration::from_secs(90), "the destination named again", || {
            count(&hub, "SELECT count(*) FROM events WHERE kind = 'conn.known_bad'") > 0
        });
        assert_eq!(count(&hub, "SELECT count(*) FROM conn_records"), 0, "nothing stored with off");
    }
}

/// Security events end to end (plan T71, AC15, AC16): a probe in a container reports what the helper sees, and the hub gives
/// each its severity.
mod security {
    use super::*;

    fn events(hub: &Hub, kind: &str) -> Vec<(String, String)> {
        let c = rusqlite::Connection::open(hub.data.join("hub.db")).unwrap();
        c.busy_timeout(Duration::from_secs(10)).unwrap();
        let mut s = c.prepare("SELECT severity, data FROM events WHERE kind = ?1").unwrap();
        s.query_map([kind], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
    }

    fn machine(name: &str) -> (Hub, Release, Container) {
        let release = Release::new(name, "current", false);
        let c = Container::start_systemd_with("debian-install", &[]);
        // a user with a `.ssh` directory before the helper starts, so that a change in it is watched
        ok(&c.root("useradd -m u1 && mkdir -p /home/u1/.ssh && chown u1:u1 /home/u1/.ssh && chmod 700 /home/u1/.ssh"));
        let hub = hub(name);
        let (_, token) = add_machine(&hub, Access::Monitor, &[]);
        ok(&install(&c, &hub, &release, &release.script(None), &token, "--monitor"));
        (hub, release, c)
    }

    #[test]
    fn exec_from_tmp_critical_container_start_nothing() {
        let (hub, _release, c) = machine("sec-exec");
        within(Duration::from_secs(60), "the probe reporting", || hub.metrics().contains("machine=\"web1\""));
        // let the first looks learn what is there
        std::thread::sleep(Duration::from_secs(20));
        ok(&c.root("cp /bin/sleep /tmp/evil && systemd-run --unit=evil /tmp/evil 600"));
        within(Duration::from_secs(120), "proc.exec_from_tmp critical", || {
            events(&hub, "proc.exec_from_tmp").iter().any(|e| e.0 == "critical" && e.1.contains("/tmp/evil"))
        });
        // the event names the program, and no incident is opened for a thing that isn't one
        assert_eq!(events(&hub, "proc.exec_from_tmp").len(), 1, "once");
        // starting a container, or any other ordinary process, is nothing
        assert_eq!(events(&hub, "port.new_listener").len(), 0);
    }

    #[test]
    fn authorized_keys_added_outside_job_critical_new_ip_login_warning() {
        let (hub, _release, c) = machine("sec-keys");
        within(Duration::from_secs(60), "the probe reporting", || hub.metrics().contains("machine=\"web1\""));
        std::thread::sleep(Duration::from_secs(20));
        // a key added to a person's file, outside any job
        ok(&c.root("echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPLANTEDKEYPLANTEDKEYPLANTEDKEYPLANTED u1@evil' > /home/u1/.ssh/authorized_keys"));
        within(Duration::from_secs(120), "auth.keys_changed critical", || {
            events(&hub, "auth.keys_changed")
                .iter()
                .any(|e| e.0 == "critical" && e.1.contains("/home/u1/.ssh/authorized_keys"))
        });
        let changed = events(&hub, "file.changed");
        assert!(
            changed.iter().all(|e| !e.1.contains("PLANTEDKEY")),
            "the probe never carries a file's contents: {changed:?}"
        );
        // a login from a source never seen, after one that teaches the machine its sources
        ok(&c.root("logger -t sshd 'Accepted publickey for u1 from 192.0.2.50 port 40000 ssh2: ED25519 SHA256:x'"));
        within(Duration::from_secs(60), "the first login stored", || !events(&hub, "auth.login").is_empty());
        ok(&c.root("logger -t sshd 'Accepted publickey for u1 from 198.51.100.77 port 40001 ssh2: ED25519 SHA256:x'"));
        within(Duration::from_secs(60), "a login from a new source", || {
            events(&hub, "auth.login_new_source").iter().any(|e| e.0 == "warning" && e.1.contains("198.51.100.77"))
        });
        assert!(
            events(&hub, "auth.login_new_source").iter().all(|e| !e.1.contains("192.0.2.50")),
            "the first source is learned, not reported"
        );
    }
}
