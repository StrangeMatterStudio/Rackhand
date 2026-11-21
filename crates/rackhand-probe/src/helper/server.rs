//! The helper's socket (7.3.3): `/run/rackhand-helper/helper.sock`, mode 0660, group `rackhand-probe`, and only the
//! probe user's connections are answered (`SO_PEERCRED`). One JSON request per line, one response per line; anything
//! that isn't exactly a known request is answered with `Error` and the connection stays usable.

use std::sync::{Arc, Mutex};

use rackhand_proto::helper::{HelperRequest, HelperResponse, UpdateSummary, parse_request};

/// A request line longer than this closes the connection (no request comes close).
pub const MAX_LINE: usize = 64 * 1024;

#[derive(Debug, Default)]
struct State {
    updates: Option<(UpdateSummary, i64)>,
}

/// The helper's answers; the I/O lives in [`serve`].
#[derive(Debug)]
pub struct Helper {
    version: String,
    state: Mutex<State>,
}

fn error(code: &str, message: impl Into<String>) -> HelperResponse {
    HelperResponse::Error { code: code.into(), message: message.into() }
}

impl Helper {
    pub fn new(version: &str) -> Arc<Helper> {
        Arc::new(Helper { version: version.into(), state: Mutex::new(State::default()) })
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
