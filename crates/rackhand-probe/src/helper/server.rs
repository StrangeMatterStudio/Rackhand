//! The helper's socket (7.3.3): `/run/rackhand-helper/helper.sock`, mode 0660, group `rackhand-probe`, and only the
//! probe user's connections are answered (`SO_PEERCRED`). One JSON request per line, one response per line; anything
//! that isn't exactly a known request is answered with `Error` and the connection stays usable.

use std::sync::{Arc, Mutex};

use rackhand_proto::helper::{HelperRequest, HelperResponse, UpdateSummary, parse_request};

/// A request line longer than this closes the connection (no request comes close).
pub const MAX_LINE: usize = 64 * 1024;

#[derive(Debug, Default)]
#[cfg_attr(windows, allow(dead_code))]
struct State {
    updates: Option<(UpdateSummary, i64)>,
    /// The critical files' hashes as of the last refresh (every 5 minutes and on a change, T66).
    hashes: Option<Vec<rackhand_proto::helper::FileHash>>,
}

/// Where the helper reads the machine from: `/` and `/proc` on a machine, directories in a test.
#[derive(Debug, Clone)]
pub struct Machine {
    #[cfg(unix)]
    pub roots: super::hash::Roots,
    #[cfg(unix)]
    pub proc: std::path::PathBuf,
    #[cfg(unix)]
    pub cgroup: std::path::PathBuf,
    #[cfg(unix)]
    pub passwd: std::path::PathBuf,
}

impl Default for Machine {
    fn default() -> Machine {
        Machine {
            #[cfg(unix)]
            roots: super::hash::Roots::default(),
            #[cfg(unix)]
            proc: "/proc".into(),
            #[cfg(unix)]
            cgroup: "/sys/fs/cgroup".into(),
            #[cfg(unix)]
            passwd: "/etc/passwd".into(),
        }
    }
}

/// The helper's answers; the I/O lives in [`serve`].
#[derive(Debug)]
pub struct Helper {
    version: String,
    state: Mutex<State>,
    /// One key update at a time, so an older one can't end after a newer one.
    #[cfg(unix)]
    keys: Mutex<super::keys::Files>,
    #[cfg(unix)]
    update: super::update::Setup,
    #[cfg(unix)]
    machine: Machine,
}

#[cfg_attr(windows, allow(dead_code))]
fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn error(code: &str, message: impl Into<String>) -> HelperResponse {
    HelperResponse::Error { code: code.into(), message: message.into() }
}

impl Helper {
    #[cfg(unix)]
    pub fn new(version: &str) -> Arc<Helper> {
        Helper::with_keys(version, super::keys::Files::default())
    }

    /// The Windows helper: what it answers needs no files of a Unix machine.
    #[cfg(windows)]
    pub fn new(version: &str) -> Arc<Helper> {
        Arc::new(Helper { version: version.into(), state: Mutex::new(State::default()) })
    }

    /// The same, with key updates applied to `keys`.
    #[cfg(unix)]
    pub fn with_keys(version: &str, keys: super::keys::Files) -> Arc<Helper> {
        Helper::with_machine(version, keys, Machine::default())
    }

    /// The same, reading `machine`.
    #[cfg(unix)]
    pub fn with_machine(version: &str, keys: super::keys::Files, machine: Machine) -> Arc<Helper> {
        Helper::with_update(version, keys, machine, super::update::Setup::system())
    }

    /// The same, with the release keys and the guard's launcher that updates use.
    #[cfg(unix)]
    pub fn with_update(
        version: &str,
        keys: super::keys::Files,
        machine: Machine,
        update: super::update::Setup,
    ) -> Arc<Helper> {
        Arc::new(Helper {
            version: version.into(),
            state: Mutex::new(State::default()),
            keys: Mutex::new(keys),
            update,
            machine,
        })
    }

    /// Hashes the critical files again and keeps the result; returns the warnings about the list.
    #[cfg(unix)]
    pub fn refresh_hashes(&self) -> Vec<String> {
        let (hashes, warnings) = super::hash::hash_all(&self.machine.roots);
        if let Ok(mut s) = self.state.lock() {
            s.hashes = Some(hashes);
        }
        warnings
    }

    /// The directories whose changes mean the critical files may have changed.
    #[cfg(unix)]
    pub fn watch_dirs(&self) -> Vec<std::path::PathBuf> {
        super::hash::watch_dirs(&self.machine.roots)
    }

    #[cfg(unix)]
    fn passwd(&self) -> String {
        std::fs::read_to_string(&self.machine.passwd).unwrap_or_default()
    }

    /// A container's name from its id, as the engine lists them.
    #[cfg(unix)]
    fn container_names(&self) -> impl Fn(&str) -> Option<String> {
        let list = super::containers::list().unwrap_or_default();
        move |id: &str| list.iter().find(|c| !c.id.is_empty() && id.starts_with(&c.id)).map(|c| c.name.clone())
    }

    /// The last package-list refresh.
    pub fn set_updates(&self, summary: UpdateSummary, refreshed_at_ms: i64) {
        if let Ok(mut s) = self.state.lock() {
            s.updates = Some((summary, refreshed_at_ms));
        }
    }

    pub fn answer(&self, line: &str) -> HelperResponse {
        let request = match parse_request(line) {
            Ok(r) => r,
            Err(e) => return error("bad_request", e.to_string()),
        };
        match request {
            HelperRequest::Ping => HelperResponse::Pong { version: self.version.clone() },
            HelperRequest::UpdatesStatus => match self.state.lock().ok().and_then(|s| s.updates.clone()) {
                Some((summary, refreshed_at_ms)) => HelperResponse::Updates { summary, refreshed_at_ms },
                None => error("not_refreshed", "the package lists haven't been refreshed yet"),
            },
            #[cfg(unix)]
            HelperRequest::Containers => match crate::helper::containers::list() {
                Ok(items) => HelperResponse::Containers { items },
                Err(e) => error("containers_unavailable", e),
            },
            #[cfg(unix)]
            HelperRequest::HashFiles => {
                let cached = self.state.lock().ok().and_then(|s| s.hashes.clone());
                match cached {
                    Some(files) => HelperResponse::Hashes { files },
                    None => {
                        self.refresh_hashes();
                        HelperResponse::Hashes {
                            files: self.state.lock().ok().and_then(|s| s.hashes.clone()).unwrap_or_default(),
                        }
                    }
                }
            }
            #[cfg(unix)]
            HelperRequest::AuthEventsSince { cursor } => {
                let root = &self.machine.roots.root;
                let year = 1970 + now_ms() / 31_556_952_000;
                let batch = match super::auth::detect(root) {
                    super::auth::Source::Journal => {
                        super::auth::since_journal(cursor.as_deref(), &super::auth::run_journalctl)
                    }
                    super::auth::Source::File(path) => super::auth::since_file(&path, cursor.as_deref(), year),
                };
                match batch {
                    Ok(b) => HelperResponse::AuthEvents { events: b.events, cursor: b.cursor },
                    Err(e) => error("auth_unavailable", e),
                }
            }
            #[cfg(unix)]
            HelperRequest::SocketOwners { inodes } => {
                if inodes.len() > super::sockets::MAX_IDS {
                    return error("too_many", "too many socket inodes in one request");
                }
                let owners =
                    super::sockets::owners(&self.machine.proc, &self.passwd(), &inodes, &self.container_names());
                HelperResponse::SocketOwners { owners }
            }
            #[cfg(unix)]
            HelperRequest::ContainerOf { cgroup_ids } => {
                if cgroup_ids.len() > super::sockets::MAX_IDS {
                    return error("too_many", "too many cgroup ids in one request");
                }
                let names = super::sockets::container_names(&self.machine.cgroup, &cgroup_ids, &self.container_names());
                HelperResponse::ContainerNames { names }
            }
            #[cfg(unix)]
            HelperRequest::ProcessScan => {
                let boot = std::fs::read_to_string(self.machine.proc.join("stat"))
                    .map(|s| super::procscan::boot_ms(&s))
                    .unwrap_or(0);
                let items = super::procscan::scan(&self.machine.proc, &self.passwd(), boot, 100);
                HelperResponse::Processes { items }
            }
            #[cfg(unix)]
            HelperRequest::ApplyKeys { payload, hub_signature } => {
                let files = self.keys.lock().unwrap_or_else(|e| e.into_inner());
                match super::keys::apply(&files, &payload, &hub_signature, now_ms()) {
                    Ok(version) => {
                        tracing::info!(version, "the hub's keys were replaced");
                        HelperResponse::KeysApplied
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "a key update was refused");
                        error(e.code(), e.to_string())
                    }
                }
            }
            #[cfg(unix)]
            HelperRequest::ApplyUpdate { version, sha256, signature } => super::update::apply_update(
                &self.version,
                &self.machine.roots.root,
                &self.update,
                &version,
                &sha256,
                &signature,
            ),
            #[cfg(windows)]
            _ => error("unsupported", "not provided by this helper version"),
        }
    }
}

/// Binds the socket: its directory root 0755, the socket 0660 with the probe's group.
#[cfg(target_os = "linux")]
pub fn bind(path: &std::path::Path, group: Option<u32>) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    }
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    if let Some(gid) = group {
        rustix::fs::chown(path, None, Some(rustix::fs::Gid::from_raw(gid)))?;
    }
    Ok(listener)
}

/// Answers each connection whose peer is `allowed_uid`; any other peer is closed without an answer.
#[cfg(target_os = "linux")]
pub async fn serve(listener: tokio::net::UnixListener, allowed_uid: u32, helper: Arc<Helper>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let uid = rustix::net::sockopt::socket_peercred(&stream).map(|c| c.uid.as_raw()).ok();
        if uid != Some(allowed_uid) {
            tracing::warn!(?uid, "helper: refused a connection from another user");
            drop(stream);
            continue;
        }
        let helper = helper.clone();
        tokio::spawn(async move { connection(stream, helper).await });
    }
}

#[cfg(target_os = "linux")]
async fn connection(stream: tokio::net::UnixStream, helper: Arc<Helper>) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read);
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut lines).take(MAX_LINE as u64 + 1).read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            Ok(n) if n > MAX_LINE => return,
            Ok(_) => {}
        }
        let mut out = serde_json::to_string(&helper.answer(&line)).unwrap_or_default();
        out.push('\n');
        if write.write_all(out.as_bytes()).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_request_is_an_error_not_a_crash() {
        let h = Helper::new("0.1.0");
        for line in ["not json", "{\"op\":\"format_disk\"}", "{\"op\":\"ping\",\"path\":\"/etc/shadow\"}", ""] {
            assert!(
                matches!(h.answer(line), HelperResponse::Error { ref code, .. } if code == "bad_request"),
                "{line}"
            );
        }
        assert_eq!(h.answer("{\"op\":\"ping\"}\n"), HelperResponse::Pong { version: "0.1.0".into() }, "still answers");
        assert!(
            matches!(h.answer("{\"op\":\"updates_status\"}"), HelperResponse::Error { ref code, .. } if code == "not_refreshed")
        );
    }
}
