//! The probe's side of the helper socket (7.3.3). Probe and helper must be the same version: on a mismatch the probe
//! runs without the helper's features and reports `helper_version_mismatch` (once, until the versions match again).

use std::path::PathBuf;
use std::time::Duration;

use rackhand_proto::helper::{ContainerInfo, HelperRequest, HelperResponse, UpdateSummary};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

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
            let (read, mut write) = connect(&self.path).await.map_err(|e| e.to_string())?;
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

    /// The containers of these cgroup ids (the eBPF capture's, D103); a cgroup that is no container isn't listed.
    pub async fn container_of(&self, cgroup_ids: &[u64]) -> Result<Vec<(u64, String)>, String> {
        match self.request(&HelperRequest::ContainerOf { cgroup_ids: cgroup_ids.to_vec() }).await? {
            HelperResponse::ContainerNames { names } => Ok(names),
            HelperResponse::Error { code, message } => Err(format!("{code}: {message}")),
            _ => Err("not a container-names answer".into()),
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

    /// The eBPF capture's maps (D196): the helper loads and attaches the program the first time and passes the maps'
    /// descriptors; why not, when it doesn't (no helper is a refusal: the probe samples).
    #[cfg(target_os = "linux")]
    pub async fn ebpf_capture(&self) -> Result<crate::security::ebpf::Capture, crate::security::ebpf::LoadError> {
        use crate::security::ebpf::{Capture, LoadError};
        let asked = tokio::time::timeout(TIMEOUT, async {
            let stream = tokio::net::UnixStream::connect(&self.path).await.map_err(|e| e.to_string())?;
            let mut line = serde_json::to_string(&HelperRequest::EbpfCapture).map_err(|e| e.to_string())?;
            line.push('\n');
            super::fdpass::send_line(&stream, line.as_bytes(), &[]).await.map_err(|e| e.to_string())?;
            let (answer, fds) =
                super::fdpass::recv_line(&stream, super::server::MAX_LINE).await.map_err(|e| e.to_string())?;
            Ok::<_, String>((serde_json::from_str::<HelperResponse>(&answer).map_err(|e| e.to_string())?, fds))
        })
        .await
        .unwrap_or_else(|_| Err("it didn't answer".into()));
        match asked.map_err(|e| LoadError::Refused(format!("the helper: {e}")))? {
            (HelperResponse::EbpfMaps { maps }, fds) => Capture::from_fds(fds, &maps),
            (HelperResponse::Error { code, message }, _) => Err(LoadError::from_answer(&code, message)),
            _ => Err(LoadError::Refused("the helper: not an eBPF answer".into())),
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

type Halves = (Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>);

/// The helper's local socket on Unix.
#[cfg(unix)]
async fn connect(path: &std::path::Path) -> std::io::Result<Halves> {
    let (read, write) = tokio::net::UnixStream::connect(path).await?.into_split();
    Ok((Box::new(read), Box::new(write)))
}

/// The helper's named pipe on Windows (7.3.3): only `NT SERVICE\RackhandProbe` may open it.
#[cfg(windows)]
async fn connect(path: &std::path::Path) -> std::io::Result<Halves> {
    let pipe = tokio::net::windows::named_pipe::ClientOptions::new().open(path)?;
    let (read, write) = tokio::io::split(pipe);
    Ok((Box::new(read), Box::new(write)))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::HelperClient;
    use crate::helper::server::{Helper, Machine, bind, serve};
    use crate::security::ebpf::LoadError;

    #[tokio::test]
    async fn ebpf_capture_brings_back_the_helpers_reason() {
        let dir = std::env::temp_dir().join(format!("rackhand-client-ebpf-{}", std::process::id()));
        let socket = dir.join("helper.sock");
        let listener = bind(&socket, None).unwrap();
        let machine = Machine { ebpf: &[], ..Machine::default() };
        let helper = Helper::with_machine("0.1.0", crate::helper::keys::Files::default(), machine);
        tokio::spawn(serve(listener, rustix::process::getuid().as_raw(), helper));
        let client = HelperClient::new(&socket, "0.1.0");
        assert_eq!(client.ebpf_capture().await.unwrap_err(), LoadError::NoProgram);
        let gone = HelperClient::new(dir.join("missing.sock"), "0.1.0");
        assert!(matches!(gone.ebpf_capture().await.unwrap_err(), LoadError::Refused(_)), "no helper: sampling");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
