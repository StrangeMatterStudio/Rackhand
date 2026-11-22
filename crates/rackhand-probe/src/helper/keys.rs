//! `ApplyKeys` (7.3.3): the hub's keys in the `rackhand` and `rackhand-ai` users' `authorized_keys`, replaced by a payload
//! signed by the hub pinned in `probe.toml`. It can change the key lines and their `from=` of those two users and nothing
//! else: the helper builds the lines itself, with the same restrictions as at the join. A payload that is older than the
//! last applied one, equal to it, expired, or valid for longer than an hour is refused, so a replayed one can't bring
//! rotated keys back. A machine at access level `monitor` has no such users and refuses every payload.
//!
//! The users own their `.ssh` directories, so nothing in them is trusted: no link is followed, and the new file is made
//! beside the old one and renamed over it.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use data_encoding::BASE64;
use rackhand_proto::common::SignedPayload;
use rackhand_proto::signed::{self, SignedError};
use serde::Deserialize;

use crate::config::ProbeToml;

/// The payload's kind.
pub const KIND: &str = "keys";
/// The only users a payload can name.
pub const USERS: [&str; 2] = ["rackhand", "rackhand-ai"];
/// How long after its signing a payload may be valid.
const MAX_VALID_MS: i64 = 3_600_000;
/// During a rotation a user has its old and its new key.
const MAX_KEYS: usize = 4;
const OPTIONS: &str = "no-agent-forwarding,no-X11-forwarding,no-port-forwarding";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeysError {
    #[error("this machine is monitored only: it has no hub accounts")]
    MonitorOnly,
    #[error("probe.toml: {0}")]
    Config(String),
    #[error("the payload isn't a signed key update")]
    Malformed,
    #[error("the signature doesn't verify against the pinned hub")]
    Signature,
    #[error("the payload has expired, or is valid for more than an hour")]
    Expired,
    #[error("the payload isn't newer than the last applied one")]
    NotNewer,
    #[error("the payload's body isn't allowed: {0}")]
    Body(String),
    #[error("{0}")]
    Write(String),
}

impl KeysError {
    /// The code the helper answers with.
    pub fn code(&self) -> &'static str {
        match self {
            KeysError::MonitorOnly => "monitor_only",
            KeysError::Config(_) => "config",
            KeysError::Malformed => "malformed",
            KeysError::Signature => "signature",
            KeysError::Expired => "expired",
            KeysError::NotNewer => "not_newer",
            KeysError::Body(_) => "not_allowed",
            KeysError::Write(_) => "write",
        }
    }
}

/// Where the machine keeps what a key update reads and writes.
#[derive(Debug, Clone)]
pub struct Files {
    pub probe_toml: PathBuf,
    pub passwd: PathBuf,
    /// The last applied version, in a directory only root can use.
    pub version: PathBuf,
}

impl Default for Files {
    fn default() -> Files {
        Files {
            probe_toml: crate::config::PATH.into(),
            passwd: "/etc/passwd".into(),
            version: "/var/lib/rackhand-helper/keys.version".into(),
        }
    }
}

/// What a payload's body says.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    /// The addresses the hub connects from.
    from: Vec<IpAddr>,
    /// Each user's keys, in the OpenSSH form.
    keys: BTreeMap<String, Vec<String>>,
}

/// An `ssh-ed25519` key with an optional comment, and nothing that could end its line or start another field.
fn key_ok(key: &str) -> bool {
    let mut parts = key.split(' ');
    let (Some("ssh-ed25519"), Some(data)) = (parts.next(), parts.next()) else { return false };
    let comment = parts.next().unwrap_or("");
    parts.next().is_none()
        && BASE64
            .decode(data.as_bytes())
            .is_ok_and(|d| d.len() == 51 && d.starts_with(b"\0\0\0\x0bssh-ed25519\0\0\0\x20"))
        && comment.bytes().all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b))
}

fn checked(body: &[u8]) -> Result<Body, KeysError> {
    let no = |why: &str| Err(KeysError::Body(why.to_string()));
    let body: Body = serde_json::from_slice(body).map_err(|e| KeysError::Body(e.to_string()))?;
    if body.from.is_empty() {
        return no("no address to connect from");
    }
    if body.keys.is_empty() {
        return no("no user");
    }
    for (user, keys) in &body.keys {
        if !USERS.contains(&user.as_str()) {
            return no("another user than the hub's");
        }
        if keys.is_empty() || keys.len() > MAX_KEYS || !keys.iter().all(|k| key_ok(k)) {
            return no("a key");
        }
    }
    Ok(body)
}

/// A user's uid, gid and home, from `passwd`.
fn account(passwd: &str, user: &str) -> Option<(u32, u32, PathBuf)> {
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.first() == Some(&user))
            .then(|| Some((f.get(2)?.parse().ok()?, f.get(3)?.parse().ok()?, f.get(5)?.into())))?
    })
}

fn applied_version(path: &Path) -> Result<u64, KeysError> {
    match std::fs::read_to_string(path) {
        // an unreadable version refuses everything rather than accepting a replay
        Ok(text) => text.trim().parse().map_err(|_| KeysError::Write(format!("{}: not a version", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(KeysError::Write(format!("{}: {e}", path.display()))),
    }
}

/// Applies a signed key update; returns its version.
pub fn apply(files: &Files, payload: &str, hub_signature: &str, now_ms: i64) -> Result<u64, KeysError> {
    let decode = |s: &str| BASE64.decode(s.as_bytes()).map_err(|_| KeysError::Malformed);
    let signed = SignedPayload { payload: decode(payload)?, hub_signature: decode(hub_signature)? };
    apply_signed(files, &signed, now_ms)
}

/// The same, from a decoded payload (the wrapper's `install-keys` reads it from standard input).
pub fn apply_signed(files: &Files, signed: &SignedPayload, now_ms: i64) -> Result<u64, KeysError> {
    let config = ProbeToml::load(&files.probe_toml).map_err(|e| KeysError::Config(e.to_string()))?;
    if config.machine.as_ref().is_some_and(|m| m.access == "monitor") {
        return Err(KeysError::MonitorOnly);
    }
    let pinned =
        crate::runcmd::install::pinned_hub_key(&files.probe_toml).map_err(|e| KeysError::Config(e.to_string()))?;
    let last = applied_version(&files.version)?;
    let env = signed::verify(signed, &pinned, KIND, last, now_ms).map_err(|e| match e {
        SignedError::BadSignature | SignedError::WrongKind => KeysError::Signature,
        SignedError::Malformed => KeysError::Malformed,
        SignedError::Expired => KeysError::Expired,
        SignedError::NotNewer => KeysError::NotNewer,
    })?;
    if env.expires_at_ms.saturating_sub(env.signed_at_ms) > MAX_VALID_MS {
        return Err(KeysError::Expired);
    }
    let body = checked(&env.body)?;
    let passwd = std::fs::read_to_string(&files.passwd)
        .map_err(|e| KeysError::Write(format!("{}: {e}", files.passwd.display())))?;
    let from: Vec<String> = body.from.iter().map(ToString::to_string).collect();
    // every account is looked up before any file changes
    let mut accounts = Vec::new();
    for (user, keys) in &body.keys {
        let Some(account) = account(&passwd, user) else {
            return Err(KeysError::Write(format!("no user {user} on this machine")));
        };
        accounts.push((account, keys));
    }
    for ((uid, gid, home), keys) in accounts {
        let lines: Vec<String> = keys.iter().map(|k| format!("from=\"{}\",{OPTIONS} {k}", from.join(","))).collect();
        write::authorized_keys(&home, uid, gid, &lines)
            .map_err(|e| KeysError::Write(format!("{}: {e}", home.display())))?;
    }
    write::version(&files.version, env.version)
        .map_err(|e| KeysError::Write(format!("{}: {e}", files.version.display())))?;
    Ok(env.version)
}

#[cfg(target_os = "linux")]
mod write {
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use rustix::fs::{AtFlags, Gid, Mode, OFlags, Uid, fchmod, fchown, openat, renameat, unlinkat};

    const NAME: &str = "authorized_keys";
    const PART: &str = ".authorized_keys.rackhand";

    /// Replaces the key lines, keeping comments.
    pub fn authorized_keys(home: &Path, uid: u32, gid: u32, lines: &[String]) -> std::io::Result<()> {
        let dir = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let home = rustix::fs::open(home, dir, Mode::empty())?;
        let ssh = openat(&home, ".ssh", dir, Mode::empty())?;
        let mut text = String::new();
        match openat(&ssh, NAME, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())
        {
            Ok(f) => {
                let f = std::fs::File::from(f);
                // a fifo, a device or a hard link to someone else's file in its place isn't read
                let meta = f.metadata()?;
                if meta.is_file() && meta.nlink() == 1 && meta.uid() == uid {
                    f.take(64 * 1024).read_to_string(&mut text)?;
                }
            }
            // a link in its place is replaced, not read
            Err(e) if [rustix::io::Errno::NOENT, rustix::io::Errno::LOOP].contains(&e) => {}
            Err(e) => return Err(e.into()),
        }
        let kept = text.lines().filter(|l| l.trim_start().starts_with('#'));
        let mut new: String = kept.map(|l| format!("{l}\n")).collect();
        for l in lines {
            new.push_str(l);
            new.push('\n');
        }
        let _ = unlinkat(&ssh, PART, AtFlags::empty());
        let create = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut part = std::fs::File::from(openat(&ssh, PART, create, Mode::RUSR | Mode::WUSR)?);
        part.write_all(new.as_bytes())?;
        fchmod(&part, Mode::RUSR | Mode::WUSR)?;
        fchown(&part, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
        part.sync_all()?;
        renameat(&ssh, PART, &ssh, NAME)?;
        Ok(())
    }

    /// The last applied version, written whole.
    pub fn version(path: &Path, version: u64) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let part = path.with_extension("new");
        let mut f = std::fs::File::create(&part)?;
        f.write_all(format!("{version}\n").as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&part, path)
    }
}

#[cfg(not(target_os = "linux"))]
mod write {
    use std::path::Path;

    pub fn authorized_keys(_home: &Path, _uid: u32, _gid: u32, _lines: &[String]) -> std::io::Result<()> {
        Err(std::io::Error::other("not on this platform"))
    }

    pub fn version(_path: &Path, _version: u64) -> std::io::Result<()> {
        Err(std::io::Error::other("not on this platform"))
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
#[path = "keys_tests.rs"]
mod tests;
