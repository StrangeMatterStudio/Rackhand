//! The probe's side of the helper socket (7.3.3). Probe and helper must be the same version: on a mismatch the probe
//! runs without the helper's features and reports `helper_version_mismatch` (once, until the versions match again).

use std::path::PathBuf;
use std::time::Duration;

use rackhand_proto::helper::{ContainerInfo, HelperRequest, HelperResponse, UpdateSummary};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct HelperClient {
    path: PathBuf,
    version: String,
}

/// What the helper gave for one collection.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HelperData {
    pub containers: Vec<ContainerInfo>,
    pub updates: Option<UpdateSummary>,
    /// The helper answered with another version (`helper_version_mismatch`).
    pub mismatch: Option<String>,
}

impl HelperClient {
    /// A client for the helper at `path`, expecting `version` (the probe's own).
    pub fn new(path: impl Into<PathBuf>, version: &str) -> HelperClient {
        HelperClient { path: path.into(), version: version.into() }
    }

    pub async fn request(&self, request: &HelperRequest) -> Result<HelperResponse, String> {
        tokio::time::timeout(TIMEOUT, async {
            let stream = tokio::net::UnixStream::connect(&self.path).await.map_err(|e| e.to_string())?;
            let (read, mut write) = stream.into_split();
            let mut line = serde_json::to_string(request).map_err(|e| e.to_string())?;
            line.push('\n');
            write.write_all(line.as_bytes()).await.map_err(|e| e.to_string())?;
            let mut answer = String::new();
            BufReader::new(read).read_line(&mut answer).await.map_err(|e| e.to_string())?;
            serde_json::from_str(&answer).map_err(|e| e.to_string())
        })
        .await
        .map_err(|_| "the helper didn't answer".to_string())?
    }

    /// The owners of these socket inodes (executable, user, container name).
    pub async fn socket_owners(&self, inodes: &[u64]) -> Result<Vec<rackhand_proto::helper::SocketOwner>, String> {
        match self.request(&HelperRequest::SocketOwners { inodes: inodes.to_vec() }).await? {
            HelperResponse::SocketOwners { owners } => Ok(owners),
            HelperResponse::Error { code, message } => Err(format!("{code}: {message}")),
            _ => Err("not a socket-owners answer".into()),
        }
    }

    /// The critical files' hashes (7.8.4).
    pub async fn hash_files(&self) -> Result<Vec<rackhand_proto::helper::FileHash>, String> {
        match self.request(&HelperRequest::HashFiles).await? {
            HelperResponse::Hashes { files } => Ok(files),
            HelperResponse::Error { code, message } => Err(format!("{code}: {message}")),
            _ => Err("not a hashes answer".into()),
        }
    }

    /// The authentication events after `cursor` (none the first time), and the cursor to ask from next.
    pub async fn auth_events_since(
        &self,
        cursor: Option<&str>,
    ) -> Result<(Vec<rackhand_proto::helper::AuthEvent>, String), String> {
        match self.request(&HelperRequest::AuthEventsSince { cursor: cursor.map(str::to_string) }).await? {
            HelperResponse::AuthEvents { events, cursor } => Ok((events, cursor)),
            HelperResponse::Error { code, message } => Err(format!("{code}: {message}")),
            _ => Err("not an auth-events answer".into()),
        }
    }

    /// The processes running from a temporary directory or a deleted file.
    pub async fn process_scan(&self) -> Result<Vec<rackhand_proto::helper::ProcInfo>, String> {
        match self.request(&HelperRequest::ProcessScan).await? {
            HelperResponse::Processes { items } => Ok(items),
            HelperResponse::Error { code, message } => Err(format!("{code}: {message}")),
            _ => Err("not a process-scan answer".into()),
        }
    }

    /// The helper's version, then its containers and updates when it matches; nothing when it doesn't answer.
    pub async fn collect(&self) -> HelperData {
        match self.request(&HelperRequest::Ping).await {
            Ok(HelperResponse::Pong { version }) if version == self.version => {}
            Ok(HelperResponse::Pong { version }) => {
                return HelperData { mismatch: Some(version), ..HelperData::default() };
            }
            _ => return HelperData::default(),
        }
        let containers = match self.request(&HelperRequest::Containers).await {
            Ok(HelperResponse::Containers { items }) => items,
            _ => Vec::new(),
        };
        let updates = match self.request(&HelperRequest::UpdatesStatus).await {
            Ok(HelperResponse::Updates { summary, .. }) => Some(summary),
            _ => None,
        };
        HelperData { containers, updates, mismatch: None }
    }
}
