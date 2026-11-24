//! Site bootstrap (plan T94, 7.7.4, AC32): `install.sh --hub` on a fresh Debian container with systemd, from a release
//! directory served over HTTP and signed with the test keys (the verifier pins them); and `rackhand-lxc.sh` with stand-ins
//! for `pct`, `pveam` and `pvesh` that record what they were asked.
//!
//! Systemd in a container can't give a service user its credential directory, so before the installer runs, the hub's unit
//! gets the same test-only drop-in as the updater's tests (`updater_it`); everything else is what the installer puts there.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use rackhand_release::manifest::Manifest;

use crate::install_it::{TARGET, key_id, seed, sh};
use crate::probe_hub::{Hub, field, within};
use crate::support::{Container, musl_binary, musl_binary_with};

const HUB_TEST_DROPIN: &str = "[Service]\n\
LoadCredential=\n\
Environment=CREDENTIALS_DIRECTORY=/run/rackhand-test-credentials\n\
ExecStartPre=+/bin/sh -c 'install -d -m 0500 -o rackhand-hub /run/rackhand-test-credentials && install -m 0400 -o rackhand-hub /etc/rackhand/master.key /run/rackhand-test-credentials/master.key'\n";

/// A hub release in a directory served over HTTP: the verifier, the hub and its units, the signed manifest, `install.sh`.
struct HubRelease {
    dir: PathBuf,
    port: u16,
    server: Child,
}

impl Drop for HubRelease {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
    }
}

impl HubRelease {
    fn new(name: &str) -> HubRelease {
        let dir = std::env::temp_dir().join(format!("rackhand-it-hub-release-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let verify = musl_binary_with("rackhand-release", "rackhand-verify", "test-keys");
        std::fs::copy(&verify, dir.join(format!("rackhand-verify-{TARGET}"))).unwrap();
        let systemd = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/systemd");
        let files = [
            (musl_binary("rackhand", "rackhand"), format!("rackhand-{TARGET}")),
            (systemd.join("rackhand-hub.service"), "rackhand-hub.service".into()),
            (systemd.join("rackhand-updater.path"), "rackhand-updater.path".into()),
            (systemd.join("rackhand-updater.service"), "rackhand-updater.service".into()),
        ];
        let sign = |data: &[u8], name: &str| {
            rackhand_release::signing::sign(
                &seed("current"),
                key_id("current"),
                data,
                &format!("file:{name} version:0.1.0"),
            )
        };
        for (from, to) in files {
            let data = std::fs::read(&from).unwrap();
            std::fs::write(dir.join(&to), &data).unwrap();
            std::fs::write(dir.join(format!("{to}.minisig")), sign(&data, &to)).unwrap();
        }
        let manifest = Manifest::of_dir("0.1.0", &dir).unwrap().to_json();
        std::fs::write(dir.join("manifest.json"), &manifest).unwrap();
        std::fs::write(dir.join("manifest.json.minisig"), sign(manifest.as_bytes(), "manifest.json")).unwrap();
        let sha = {
            use sha2::{Digest, Sha256};
            format!("{:x}", Sha256::digest(std::fs::read(&verify).unwrap()))
        };
        let script = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/install.sh"))
            .unwrap()
            .replace("__VERSION__", "0.1.0")
            .replace("__VERIFY_SHA256_X86_64__", &sha)
            .replace("__VERIFY_SHA256_AARCH64__", &"0".repeat(64));
        std::fs::write(dir.join("install.sh"), script).unwrap();
        let port = std::net::TcpListener::bind("0.0.0.0:0").unwrap().local_addr().unwrap().port();
        let server = Command::new("python3")
            .args(["-m", "http.server", &port.to_string(), "--bind", "0.0.0.0", "--directory"])
            .arg(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(500));
        HubRelease { dir, port, server }
    }
}

/// A Debian container with systemd and the test drop-in in place.
fn debian() -> Container {
    let c = Container::start_systemd_with("debian-install", &[]);
    let dropin = std::env::temp_dir().join(format!("rackhand-bootstrap-dropin-{}.conf", std::process::id()));
    std::fs::write(&dropin, HUB_TEST_DROPIN).unwrap();
    sh(&c, "mkdir -p /etc/systemd/system/rackhand-hub.service.d");
    c.copy_in(&dropin, "/etc/systemd/system/rackhand-hub.service.d/test.conf");
    c
}

fn run_installer(c: &Container, release: &HubRelease) -> std::process::Output {
    let (_, gateway) = c.ip_and_gateway();
    c.copy_in(&release.dir.join("install.sh"), "/tmp/install.sh");
    c.root(&format!("sh /tmp/install.sh --hub --release-url http://{gateway}:{}", release.port))
}

/// The line of an invite in a page: `rackhand1:<id>@<addrs>[!<relays>]#<secret>`.
fn invite_in(page: &str) -> Option<String> {
    let at = page.find("rackhand1:")?;
    let rest = &page[at..];
    let end = rest.find(|c: char| c.is_whitespace() || c == '<' || c == '"' || c == '\'').unwrap_or(rest.len());
    let invite = &rest[..end];
    invite.contains('#').then(|| invite.to_string())
}

mod bootstrap {
    use super::*;

    /// AC32: `install.sh --hub` makes a fresh Debian machine a hub that prints its dashboard's address and a one-time setup
    /// code; the first run is reachable with that code; and an invite from it links to an existing hub.
    #[test]
    fn fresh_debian_becomes_hub_and_links_to_existing() {
        let release = HubRelease::new("fresh");
        let c = debian();
        let out = run_installer(&c, &release);
        let said = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{said}");
        let (ip, _) = c.ip_and_gateway();
        assert!(said.contains(&format!("Dashboard: https://{ip}:8443/")), "{said}");
        let code = said
            .lines()
            .find_map(|l| l.strip_prefix("Setup code (for the dashboard's first run, once): "))
            .unwrap_or_else(|| panic!("a setup code: {said}"))
            .trim()
            .to_string();
        assert!(said.contains("Recovery code"), "the recovery code is shown once too");
        // what the installer laid out
        assert_eq!(sh(&c, "readlink /usr/local/bin/rackhand"), "/usr/local/lib/rackhand-server/rackhand");
        assert_eq!(sh(&c, "readlink /usr/local/lib/rackhand-server/rackhand"), "rackhand-a");
        assert_eq!(sh(&c, "systemctl is-active rackhand-hub rackhand-updater.path"), "active\nactive");
        assert_eq!(sh(&c, "test -f /etc/rackhand/release-manifest.json && echo yes"), "yes");
        let uids = sh(&c, "ps -o uid= -C rackhand");
        assert!(!uids.is_empty() && uids.lines().all(|u| u.trim() != "0"), "the hub isn't root: {uids}");
        // the first run, from outside, with the code it printed
        let new = Hub::attach("boot-new", &ip, 8443, &code);
        new.first_run_as("bootstrapped");
        // an existing hub, linked by an invite from the new one
        let mut existing = Hub::init("boot-existing");
        existing.start();
        existing.first_run_as("main");
        let mut invite = None;
        within(Duration::from_secs(60), "the new hub makes a peer invite", || {
            let csrf = field(&new.curl(&["/add"]), "csrf");
            invite = invite_in(&new.curl(&["--data", &format!("csrf={csrf}&kind=peer"), "/add/invite"]));
            invite.is_some()
        });
        let invite = invite.unwrap();
        let csrf = field(&existing.curl(&["/peers"]), "csrf");
        existing.curl(&[
            "--data-urlencode",
            &format!("csrf={csrf}"),
            "--data-urlencode",
            &format!("invite={invite}"),
            "/peers/join",
        ]);
        within(Duration::from_secs(120), "each hub lists the other as a peer", || {
            existing.curl(&["/peers"]).contains("bootstrapped") && new.curl(&["/peers"]).contains("main")
        });
    }

    /// 7.7.4: the installer says what it needs and installs nothing on Debian 11.
    #[test]
    fn refuses_debian_11() {
        let release = HubRelease::new("debian11");
        let c = debian();
        sh(
            &c,
            "sed -i 's/^VERSION_ID=.*/VERSION_ID=\"11\"/; s/^PRETTY_NAME=.*/PRETTY_NAME=\"Debian GNU\\/Linux 11 (bullseye)\"/' /etc/os-release",
        );
        let out = run_installer(&c, &release);
        let said = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(!out.status.success());
        assert!(said.contains("a hub installs on Debian 12 or later; this is Debian 11"), "{said}");
        assert_eq!(
            sh(&c, "ls /usr/local/bin/rackhand /etc/rackhand 2>/dev/null; id rackhand-hub 2>/dev/null"),
            "",
            "nothing installed"
        );
        // and not on another system
        sh(&c, "sed -i 's/^ID=.*/ID=ubuntu/; s/^PRETTY_NAME=.*/PRETTY_NAME=\"Ubuntu 24.04 LTS\"/' /etc/os-release");
        let out = run_installer(&c, &release);
        assert!(String::from_utf8_lossy(&out.stderr).contains("this is Ubuntu 24.04 LTS"));
    }

    /// AC32: the LXC script, with stand-ins for Proxmox's commands: one Debian 12 container of 2 vCPU, 1 GB RAM and a 20 GB
    /// disk, unprivileged with nesting, started, and the hub installer run in it.
    #[test]
    fn lxc_script_pct_calls_match_spec() {
        let c = Container::start_systemd_with("debian-install", &[]);
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/rackhand-lxc.sh");
        c.copy_in(&script, "/tmp/rackhand-lxc.sh");
        let fakes = r#"set -e
mkdir -p /fake
cat > /fake/pct <<'EOF'
#!/bin/sh
echo "pct $*" >> /tmp/calls
exit 0
EOF
cat > /fake/pveam <<'EOF'
#!/bin/sh
echo "pveam $*" >> /tmp/calls
case "$1" in
  available) echo "system          debian-11-standard_11.7-1_amd64.tar.zst"; echo "system          debian-12-standard_12.2-1_amd64.tar.zst"; echo "system          debian-12-standard_12.7-1_amd64.tar.zst" ;;
esac
exit 0
EOF
cat > /fake/pvesh <<'EOF'
#!/bin/sh
echo "pvesh $*" >> /tmp/calls
echo 123
EOF
chmod +x /fake/*"#;
        let made = c.root(fakes);
        assert!(made.status.success(), "the stand-ins: {}", String::from_utf8_lossy(&made.stderr));
        let out = c.root("PATH=/fake:$PATH sh /tmp/rackhand-lxc.sh --release-url https://releases.example.test/v0.1.0");
        let said = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{said}");
        let calls = sh(&c, "cat /tmp/calls");
        let lines: Vec<&str> = calls.lines().collect();
        assert!(lines.contains(&"pvesh get /cluster/nextid"), "{calls}");
        assert!(
            lines.contains(&"pveam download local debian-12-standard_12.7-1_amd64.tar.zst"),
            "the newest Debian 12: {calls}"
        );
        let create = lines.iter().find(|l| l.starts_with("pct create")).unwrap_or_else(|| panic!("{calls}"));
        assert_eq!(
            *create,
            "pct create 123 local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst --hostname rackhand --cores 2 --memory 1024 \
             --swap 512 --rootfs local-lvm:20 --net0 name=eth0,bridge=vmbr0,ip=dhcp --unprivileged 1 --features nesting=1 --onboot 1"
        );
        assert!(lines.contains(&"pct start 123"), "{calls}");
        let installer = lines.iter().find(|l| l.contains("install.sh")).unwrap_or_else(|| panic!("{calls}"));
        assert!(installer.starts_with("pct exec 123 -- sh -c"), "{installer}");
        assert!(
            installer.contains("curl -fsSL 'https://releases.example.test/v0.1.0/install.sh' | sh -s -- --hub"),
            "{installer}"
        );
        // and it refuses what isn't a container id or a hostname
        let bad = c.root("PATH=/fake:$PATH sh /tmp/rackhand-lxc.sh --vmid 12a");
        assert!(!bad.status.success() && String::from_utf8_lossy(&bad.stderr).contains("--vmid is a number"));
        let bad = c.root("PATH=/fake:$PATH sh /tmp/rackhand-lxc.sh --hostname 'a;b'");
        assert!(!bad.status.success());
    }
}
