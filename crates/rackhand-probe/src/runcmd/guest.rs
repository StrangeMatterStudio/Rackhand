//! `run install-guest` (7.3.12, plan T64): what a hypervisor's wrapper does to enroll a guest the hub is provisioning. The
//! hub's payload, signed with its node key and pinned like every other, names the guest and the installer's address and
//! arguments; the wrapper builds the installer's line itself from a fixed shape, so nothing but those values can reach a
//! shell.
//!
//! - a VM (`qemu`): cloud-init user data in `/var/lib/vz/snippets/rackhand-<vmid>.yml` that runs the installer at first
//!   boot; the answer is the `cicustom` value the hub sets on the VM;
//! - a container (`lxc`): once it runs, `pct exec` runs the installer inside it.
//!
//! A payload that is expired, valid for more than ten minutes, or not newer than the last one is refused, as is every
//! payload on a machine at access level `monitor`.

use std::path::PathBuf;
use std::time::Duration;

use rackhand_proto::common::SignedPayload;
use rackhand_proto::signed::{self, SignedError};
use serde::Deserialize;

use crate::config::ProbeToml;

/// The payload's kind.
pub const KIND: &str = "guest";
const MAX_VALID_MS: i64 = 600_000;
/// The first guest id Proxmox allows.
const MIN_VMID: u64 = 100;
const MAX_VMID: u64 = 999_999_999;
const MAX_ARGS: usize = 24;
/// How long a container is waited for, and how often it is looked at.
const WAIT: Duration = Duration::from_secs(120);
const LOOK: Duration = Duration::from_secs(2);
const SNIPPETS: &str = "/var/lib/vz/snippets";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuestError {
    #[error("this machine is monitored only: it has no hub accounts")]
    MonitorOnly,
    #[error("probe.toml: {0}")]
    Config(String),
    #[error("the signature doesn't verify against the pinned hub")]
    Signature,
    #[error("the payload has expired, or is valid for more than ten minutes")]
    Expired,
    #[error("the payload isn't newer than the last applied one")]
    NotNewer,
    #[error("the payload isn't a signed guest request")]
    Malformed,
    #[error("the payload's body isn't allowed: {0}")]
    Body(String),
    #[error("{0}")]
    Guest(String),
}

/// Where the machine keeps what a request reads and writes.
#[derive(Debug, Clone)]
pub struct GuestFiles {
    pub probe_toml: PathBuf,
    /// The last applied version, in a directory only root can use.
    pub version: PathBuf,
}

impl Default for GuestFiles {
    fn default() -> GuestFiles {
        GuestFiles { probe_toml: crate::config::PATH.into(), version: "/var/lib/rackhand-run/guest.version".into() }
    }
}

/// The hypervisor host, as far as a request touches it.
pub trait Host {
    fn write_snippet(&self, name: &str, data: &str) -> std::io::Result<()>;
    fn lxc_running(&self, vmid: u64) -> bool;
    /// Runs `line` with `sh -c` inside the container; its exit code and what it printed.
    fn lxc_exec(&self, vmid: u64, line: &str) -> std::io::Result<(i32, String)>;
    fn sleep(&self, d: Duration);
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    kind: String,
    vmid: u64,
    script_url: String,
    args: Vec<String>,
    #[serde(default)]
    self_signed: bool,
}

/// An address the installer is fetched from: https, and nothing a shell or YAML would read as more.
fn url_ok(url: &str) -> bool {
    url.strip_prefix("https://").is_some_and(|rest| {
        !rest.is_empty()
            && rest.len() <= 256
            && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~:/%@+-[]".contains(&b))
    })
}

fn arg_ok(arg: &str) -> bool {
    !arg.is_empty()
        && arg.len() <= 512
        && arg.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:@,!/=[]+-".contains(&b))
}

fn checked(body: &[u8]) -> Result<Body, GuestError> {
    let no = |why: &str| Err(GuestError::Body(why.to_string()));
    let body: Body = serde_json::from_slice(body).map_err(|e| GuestError::Body(e.to_string()))?;
    if !["qemu", "lxc"].contains(&body.kind.as_str()) {
        return no("a guest is qemu or lxc");
    }
    if !(MIN_VMID..=MAX_VMID).contains(&body.vmid) {
        return no("the guest id");
    }
    if !url_ok(&body.script_url) {
        return no("the installer's address is https and plain");
    }
    if body.args.is_empty() || body.args.len() > MAX_ARGS || !body.args.iter().all(|a| arg_ok(a)) {
        return no("an argument of the installer");
    }
    Ok(body)
}

/// The installer's line: fetched with whichever of `curl` and `wget` the guest has, run with the arguments.
fn installer_line(body: &Body) -> String {
    let (curl, wget) = if body.self_signed {
        ("curl -fsSLk", "wget -qO- --no-check-certificate")
    } else {
        ("curl -fsSL", "wget -qO-")
    };
    let url = &body.script_url;
    format!("({curl} {url} 2>/dev/null || {wget} {url}) | sh -s -- {}", body.args.join(" "))
}

fn applied_version(path: &std::path::Path) -> Result<u64, GuestError> {
    match std::fs::read_to_string(path) {
        Ok(text) => text.trim().parse().map_err(|_| GuestError::Guest(format!("{}: not a version", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(GuestError::Guest(format!("{}: {e}", path.display()))),
    }
}

fn write_version(path: &std::path::Path, version: u64) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let part = path.with_extension("new");
    std::fs::write(&part, format!("{version}\n"))?;
    std::fs::rename(&part, path)
}

/// Acts on a signed request; the answer is the `cicustom` value of a VM, or what the installer printed in a container.
pub fn apply(
    files: &GuestFiles,
    host: &dyn Host,
    signed_payload: &SignedPayload,
    now_ms: i64,
) -> Result<String, GuestError> {
    let config = ProbeToml::load(&files.probe_toml).map_err(|e| GuestError::Config(e.to_string()))?;
    if config.machine.as_ref().is_some_and(|m| m.access == "monitor") {
        return Err(GuestError::MonitorOnly);
    }
    let pinned =
        crate::runcmd::install::pinned_hub_key(&files.probe_toml).map_err(|e| GuestError::Config(e.to_string()))?;
    let last = applied_version(&files.version)?;
    let env = signed::verify(signed_payload, &pinned, KIND, last, now_ms).map_err(|e| match e {
        SignedError::BadSignature | SignedError::WrongKind => GuestError::Signature,
        SignedError::Malformed => GuestError::Malformed,
        SignedError::Expired => GuestError::Expired,
        SignedError::NotNewer => GuestError::NotNewer,
    })?;
    if env.expires_at_ms.saturating_sub(env.signed_at_ms) > MAX_VALID_MS {
        return Err(GuestError::Expired);
    }
    let body = checked(&env.body)?;
    let line = installer_line(&body);
    // used up before anything is done: a request that fails halfway is made again, not replayed
    write_version(&files.version, env.version)
        .map_err(|e| GuestError::Guest(format!("{}: {e}", files.version.display())))?;
    if body.kind == "qemu" {
        let name = format!("rackhand-{}.yml", body.vmid);
        let data = format!("#cloud-config\nruncmd:\n  - [ sh, -c, \"{line}\" ]\n");
        host.write_snippet(&name, &data).map_err(|e| GuestError::Guest(format!("{name}: {e}")))?;
        return Ok(format!("user=local:snippets/{name}"));
    }
    let mut waited = Duration::ZERO;
    while !host.lxc_running(body.vmid) {
        if waited >= WAIT {
            return Err(GuestError::Guest(format!("container {} isn't running", body.vmid)));
        }
        host.sleep(LOOK);
        waited += LOOK;
    }
    let (code, out) = host.lxc_exec(body.vmid, &line).map_err(|e| GuestError::Guest(format!("pct exec: {e}")))?;
    if code != 0 {
        return Err(GuestError::Guest(format!("the installer in container {} exited with {code}: {out}", body.vmid)));
    }
    Ok(out)
}

/// The machine itself.
#[cfg(unix)]
#[derive(Debug)]
pub struct System;

#[cfg(unix)]
impl Host for System {
    fn write_snippet(&self, name: &str, data: &str) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(SNIPPETS)?;
        let path = std::path::Path::new(SNIPPETS).join(name);
        let part = path.with_extension("new");
        std::fs::write(&part, data)?;
        std::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o644))?;
        std::fs::rename(&part, path)
    }

    fn lxc_running(&self, vmid: u64) -> bool {
        std::process::Command::new("/usr/sbin/pct")
            .args(["status", &vmid.to_string()])
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("running"))
    }

    fn lxc_exec(&self, vmid: u64, line: &str) -> std::io::Result<(i32, String)> {
        let out = std::process::Command::new("/usr/sbin/pct")
            .args(["exec", &vmid.to_string(), "--", "sh", "-c", line])
            .output()?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok((out.status.code().unwrap_or(-1), text))
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

#[cfg(test)]
#[cfg(unix)]
#[path = "guest_tests.rs"]
mod tests;
