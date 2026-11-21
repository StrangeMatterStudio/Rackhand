//! `cargo xtask lab deploy [--hub-on <machine>]` (plan L2): the current build onto the lab.
//!
//! It builds static musl release binaries (the hub with `lab-build`, so the test release keys are pinned and `lab-token`
//! exists; the probe; `rackhand-verify` with the test keys), signs the release files with the test key of
//! `tests/keys/`, renders `install.sh` for them, and serves the directory from WSL, where the machines reach it at the
//! QEMU gateway. Then it installs the hub on its machine with the packaged systemd unit and completes first run with
//! a generated admin, whose password and TOTP secret stay in `~/.cache/rackhand-lab/creds` (0600, never printed).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use super::config::{Lab, Machine};
use super::qemu;

/// The lab release server's port in WSL; the machines reach it at `http://10.0.2.2:<port>`.
pub const RELEASE_PORT: u16 = 8790;
pub const TARGET: &str = "x86_64-unknown-linux-musl";

pub fn release_dir() -> PathBuf {
    super::lab_dir().join("release")
}

pub fn creds_path() -> PathBuf {
    super::lab_dir().join("creds")
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// `cargo build` of one binary for musl; returns its path.
fn build(package: &str, bin: &str, features: &[&str]) -> Result<PathBuf> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(root()).args([
        "build",
        "-q",
        "--release",
        "-p",
        package,
        "--bin",
        bin,
        "--target",
        TARGET,
        "--message-format=json",
    ]);
    if !features.is_empty() {
        cmd.args(["--features", &features.join(",")]);
    }
    let out = cmd.stderr(Stdio::inherit()).output().context("cargo build")?;
    if !out.status.success() {
        bail!("building {bin} failed");
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == bin)
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
        .with_context(|| format!("no executable for {bin}"))
}

fn test_key() -> Result<ed25519_dalek::SigningKey> {
    let hex = std::fs::read_to_string(root().join("tests/keys/test-current.seed"))?;
    let hex = hex.trim();
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)?;
    }
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

fn sha256(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(std::fs::read(path)?).iter().map(|b| format!("{b:02x}")).collect())
}

/// Builds and signs the release files into `dir`; `tamper` changes the probe after signing (a test's bad release).
pub fn build_release(dir: &Path, tamper: bool) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let hub = build("rackhand", "rackhand", &["lab-build"])?;
    let probe = build("rackhand-probe", "rackhand-probe", &[])?;
    let verify = build("rackhand-release", "rackhand-verify", &["test-keys"])?;
    let packaging = root().join("packaging");
    let files = [
        (hub, format!("rackhand-{TARGET}")),
        (probe, format!("rackhand-probe-{TARGET}")),
        (packaging.join("systemd/rackhand-hub.service"), "rackhand-hub.service".into()),
        (packaging.join("systemd/rackhand-probe.service"), "rackhand-probe.service".into()),
        (packaging.join("systemd/rackhand-probe-helper.service"), "rackhand-probe-helper.service".into()),
        (packaging.join("openrc/rackhand-probe"), "rackhand-probe.openrc".into()),
        (packaging.join("openrc/rackhand-probe-helper"), "rackhand-probe-helper.openrc".into()),
    ];
    let key = test_key()?;
    for (from, name) in files {
        let data = std::fs::read(&from).with_context(|| from.display().to_string())?;
        let sig = rackhand_release::signing::sign(&key, [1; 8], &data, &format!("file:{name}"));
        std::fs::write(dir.join(&name), &data)?;
        std::fs::write(dir.join(format!("{name}.minisig")), sig)?;
    }
    std::fs::copy(&verify, dir.join(format!("rackhand-verify-{TARGET}")))?;
    if tamper {
        let p = dir.join(format!("rackhand-probe-{TARGET}"));
        let mut data = std::fs::read(&p)?;
        let n = data.len() / 2;
        data[n] ^= 0xff;
        std::fs::write(p, data)?;
    }
    let verify_sha = sha256(&dir.join(format!("rackhand-verify-{TARGET}")))?;
    let script = std::fs::read_to_string(packaging.join("install.sh"))?
        .replace("__VERSION__", env!("CARGO_PKG_VERSION"))
        .replace("__VERIFY_SHA256__", &verify_sha);
    std::fs::write(dir.join("install.sh"), script)?;
    Ok(())
}

/// Serves `dir` on [`RELEASE_PORT`] (restarted, so it always serves this directory).
pub fn serve(dir: &Path) -> Result<()> {
    let pid_file = super::lab_dir().join("release-server.pid");
    if let Ok(pid) = std::fs::read_to_string(&pid_file) {
        let _ = Command::new("kill").arg(pid.trim()).status();
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    let log = std::fs::File::create(super::lab_dir().join("release-server.log"))?;
    let child = Command::new("python3")
        .args(["-m", "http.server", &RELEASE_PORT.to_string(), "--bind", "0.0.0.0", "--directory"])
        .arg(dir)
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()
        .context("starting the release server")?;
    std::fs::write(&pid_file, child.id().to_string())?;
    std::thread::sleep(std::time::Duration::from_millis(500));
    Ok(())
}

/// The hub on `m` with the packaged unit; `hub init` only the first time. Returns the setup code when it initialized.
fn install_hub(m: &Machine) -> Result<Option<String>> {
    let first = "if [ ! -f /etc/rackhand/master.key ]; then sudo /usr/local/bin/rackhand hub init; fi";
    let out = qemu::ssh(m, &install_script(first))?;
    Ok(out
        .lines()
        .find_map(|l| l.strip_prefix("Setup code (for the dashboard's first run, once): "))
        .map(|s| s.trim().to_string()))
}

/// The install steps around `setup`, which makes the hub's keys and database (`hub init` or `hub restore`).
fn install_script(setup: &str) -> String {
    let url = format!("http://10.0.2.2:{RELEASE_PORT}");
    format!(
        "set -e
curl -fsSL {url}/rackhand-{TARGET} -o /tmp/rackhand
curl -fsSL {url}/rackhand-hub.service -o /tmp/rackhand-hub.service
sudo systemctl stop rackhand-hub 2>/dev/null || true
sudo install -m 0755 /tmp/rackhand /usr/local/bin/rackhand
sudo install -m 0644 /tmp/rackhand-hub.service /etc/systemd/system/rackhand-hub.service
id rackhand-hub >/dev/null 2>&1 || sudo useradd -r -U -M -d /var/lib/rackhand -s /usr/sbin/nologin rackhand-hub
{setup}
sudo chown -R rackhand-hub:rackhand-hub /var/lib/rackhand
sudo chown rackhand-hub:rackhand-hub /etc/rackhand/node.key
sudo chown root:rackhand-hub /etc/rackhand/hub.toml
sudo systemctl daemon-reload
sudo systemctl enable --now rackhand-hub >/dev/null 2>&1
for i in $(seq 1 60); do curl -sk https://127.0.0.1:8443/healthz | grep -q ok && exit 0; sleep 1; done
echo 'the hub did not answer /healthz' >&2; sudo journalctl -u rackhand-hub --no-pager | tail -20 >&2; exit 1"
    )
}

/// `lab deploy --restore <backup> --master-key <key>`: this build onto a machine without a hub, from a hub backup
/// (AC47). The admin of `creds` comes back with the database.
pub fn deploy_restore(lab: &Lab, hub_on: &str, backup: &Path, master_key: &Path) -> Result<()> {
    let m = lab.machine(hub_on)?;
    if !qemu::is_running(&m.name) {
        bail!("{} isn't running: `cargo xtask lab up <profile>` first", m.name);
    }
    let dir = release_dir();
    build_release(&dir, false)?;
    serve(&dir)?;
    qemu::scp_to(m, backup, "/tmp/rackhand-restore.rhbk")?;
    qemu::scp_to(m, master_key, "/tmp/rackhand-restore.key")?;
    let setup = "if [ -f /etc/rackhand/master.key ]; then echo 'this machine has a hub; reset it first' >&2; exit 1; fi
sudo /usr/local/bin/rackhand hub restore /tmp/rackhand-restore.rhbk --master-key /tmp/rackhand-restore.key
rm -f /tmp/rackhand-restore.rhbk /tmp/rackhand-restore.key";
    qemu::ssh(m, &install_script(setup))?;
    println!("hub restored on {} from {}", m.name, backup.display());
    Ok(())
}

/// `curl` against the hub's dashboard through its forwarded port, with a cookie jar; returns the body.
pub fn curl(m: &Machine, jar: &Path, args: &[&str], path: &str) -> Result<String> {
    let out = Command::new("curl")
        .args(["-sk", "--max-time", "30", "-b"])
        .arg(jar)
        .arg("-c")
        .arg(jar)
        .args(args)
        .arg(format!("https://127.0.0.1:{}{path}", qemu::web_port(m)))
        .output()
        .context("curl")?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
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

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let (mut bits, mut buf, mut out) = (0u32, 0u64, Vec::new());
    for c in s.trim_end_matches('=').chars() {
        let v = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c.to_ascii_uppercase())? as u64;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// The 6-digit TOTP code (RFC 6238, SHA-1, 30 s) for `unix_s`.
pub fn totp(secret_b32: &str, unix_s: i64) -> Option<String> {
    let secret = base32_decode(secret_b32)?;
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret),
        &(unix_s / 30).to_be_bytes(),
    );
    let t = tag.as_ref();
    let o = (t[19] & 0x0f) as usize;
    let n = (u32::from_be_bytes([t[o], t[o + 1], t[o + 2], t[o + 3]]) & 0x7fff_ffff) % 1_000_000;
    Some(format!("{n:06}"))
}

fn random_password() -> Result<String> {
    let mut b = [0u8; 18];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// First run with a generated admin; the credentials go to `creds` (0600).
fn first_run(m: &Machine, setup_code: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let jar = super::lab_dir().join("deploy-cookies");
    let _ = std::fs::remove_file(&jar);
    let page = curl(m, &jar, &[], "/first-run")?;
    let (csrf, secret, sig) = (field(&page, "csrf"), field(&page, "totp_secret"), field(&page, "totp_sig"));
    let (Some(csrf), Some(secret), Some(sig)) = (csrf, secret, sig) else {
        bail!("the hub's first-run page has no form")
    };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
    let code = totp(&secret, now).context("the TOTP secret isn't base32")?;
    let password = random_password()?;
    let form = [
        ("csrf", csrf.as_str()),
        ("setup_code", setup_code),
        ("admin_name", "admin"),
        ("password", password.as_str()),
        ("totp_secret", secret.as_str()),
        ("totp_sig", sig.as_str()),
        ("totp_code", code.as_str()),
        ("site_name", "lab"),
        ("timezone", "UTC"),
    ];
    let mut args: Vec<String> = Vec::new();
    for (k, v) in form {
        args.push("--data-urlencode".into());
        args.push(format!("{k}={v}"));
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let answer = curl(m, &jar, &refs, "/first-run")?;
    if !answer.contains("is set up") {
        bail!("first run didn't complete");
    }
    let creds =
        format!("admin = \"admin\"\npassword = \"{password}\"\ntotp_secret = \"{secret}\"\nhub = \"{}\"\n", m.name);
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(creds_path())?;
    std::io::Write::write_all(&mut f, creds.as_bytes())?;
    let _ = std::fs::remove_file(&jar);
    Ok(())
}

/// The whole deploy.
pub fn deploy(lab: &Lab, hub_on: &str) -> Result<()> {
    let m = lab.machine(hub_on)?;
    if !qemu::is_running(&m.name) {
        bail!("{} isn't running: `cargo xtask lab up <profile>` first", m.name);
    }
    let dir = release_dir();
    build_release(&dir, false)?;
    serve(&dir)?;
    println!("release files served from {} on port {RELEASE_PORT}", dir.display());
    match install_hub(m)? {
        Some(code) => {
            first_run(m, &code)?;
            println!("hub installed on {}; first run done (credentials in {})", m.name, creds_path().display());
        }
        None if creds_path().exists() => println!("hub updated on {} (its data kept)", m.name),
        None => bail!(
            "{} has a hub that was initialized without this deploy, so its setup code is unknown: \
             `cargo xtask lab reset {}` and deploy again",
            m.name,
            m.name
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_matches_rfc_6238() {
        // RFC 6238's SHA-1 vectors use the ASCII secret "12345678901234567890" (base32 below), 8 digits; the last 6 are ours
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(totp(secret, 59).unwrap(), "287082");
        assert_eq!(totp(secret, 1_111_111_109).unwrap(), "081804");
    }
}
