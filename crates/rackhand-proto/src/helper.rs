//! The probe-helper socket protocol: newline-delimited JSON, one request per line (7.3.3). Requests carry no paths or
//! URLs; unknown requests and unknown fields are refused.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperRequest {
    Ping,
    /// The list is compiled in plus a root-owned extras file; never from the socket.
    HashFiles,
    AuthEventsSince {
        cursor: Option<String>,
    },
    Containers,
    SocketOwners {
        inodes: Vec<u64>,
    },
    ContainerOf {
        cgroup_ids: Vec<u64>,
    },
    ProcessScan,
    UpdatesStatus,
    /// The file is read from the probe's fixed spool path. `sha256` is hex, `signature` base64 (minisign).
    ApplyUpdate {
        version: String,
        sha256: String,
        signature: String,
    },
    /// A `SignedPayload` (base64 parts) signed by the pinned hub key.
    ApplyKeys {
        payload: String,
        hub_signature: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileHash {
    pub path: String,
    pub exists: bool,
    pub sha256: Option<String>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    SshLogin,
    SshFailed,
    Sudo,
    Su,
    UserAdded,
    GroupChanged,
    Logon,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthEvent {
    pub at_ms: i64,
    pub kind: AuthKind,
    pub user: String,
    pub source_ip: Option<String>,
    pub method: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub health: Option<String>,
    pub restart_count: u32,
    pub started_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketOwner {
    pub inode: u64,
    pub pid: u32,
    pub exe: String,
    pub user: String,
    pub container: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub exe: String,
    pub user: String,
    pub started_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSummary {
    pub pending: u32,
    pub security: u32,
    pub reboot_required: bool,
    pub packages: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperResponse {
    Pong { version: String },
    Hashes { files: Vec<FileHash> },
    AuthEvents { events: Vec<AuthEvent>, cursor: String },
    Containers { items: Vec<ContainerInfo> },
    SocketOwners { owners: Vec<SocketOwner> },
    ContainerNames { names: Vec<(u64, String)> },
    Processes { items: Vec<ProcInfo> },
    Updates { summary: UpdateSummary, refreshed_at_ms: i64 },
    UpdateStarted,
    KeysApplied,
    Error { code: String, message: String },
}

/// Parses one request line; anything not exactly a known request is an error. Serde doesn't refuse unknown fields
/// on a unit variant of a tagged enum (`{"op":"ping","path":...}`), so the line's fields must also be exactly the
/// fields of the request it parses to.
pub fn parse_request(line: &str) -> Result<HelperRequest, serde_json::Error> {
    use serde::de::Error;
    let value: serde_json::Value = serde_json::from_str(line.trim_end_matches(['\r', '\n']))?;
    let request: HelperRequest = serde_json::from_value(value.clone())?;
    let known = serde_json::to_value(&request)?;
    let expected = known.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
    if value.as_object().is_some_and(|o| o.keys().any(|k| !expected.contains(k))) {
        return Err(serde_json::Error::custom("unknown field in request"));
    }
    Ok(request)
}
