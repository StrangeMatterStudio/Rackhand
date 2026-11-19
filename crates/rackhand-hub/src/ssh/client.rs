//! Running commands on machines over SSH (7.3.7, FR-12): as the automation or assistant identity, with the host key
//! checked against the pin, stdout and stderr each capped at 1 MiB with a marker.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use russh::ChannelMsg;
use russh::client::{self, AuthResult};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};

use super::hostkeys::{HostKeyError, HostKeys};
use super::keys::Identity;

/// Output kept per stream and step.
pub const OUTPUT_CAP: usize = 1 << 20;
pub const TRUNCATED: &str = "\n[rackhand: output truncated at 1 MiB]\n";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SshError {
    #[error("the machine's host key isn't pinned (it comes with the join)")]
    HostKeyNotPinned,
    #[error("the machine's host key changed; an admin must accept the new one")]
    HostKeyChanged,
    #[error("the machine refused the hub's key for {0}")]
    AuthRefused(&'static str),
    #[error("ssh: {0}")]
    Transport(String),
    #[error("the command didn't finish in time")]
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub exit_code: Option<u32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

struct Checker {
    machine_id: String,
    keys: Arc<HostKeys>,
    verdict: Arc<std::sync::Mutex<Option<HostKeyError>>>,
}

impl client::Handler for Checker {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else { return Ok(false) };
        match self.keys.check(&self.machine_id, key) {
            Ok(()) => Ok(true),
            Err(e) => {
                if let Ok(mut v) = self.verdict.lock() {
                    *v = Some(e);
                }
                Ok(false)
            }
        }
    }
}

fn append_capped(buf: &mut Vec<u8>, data: &[u8], truncated: &mut bool) {
    if *truncated {
        return;
    }
    let room = OUTPUT_CAP - buf.len();
    if data.len() <= room {
        buf.extend_from_slice(data);
    } else {
        buf.extend_from_slice(&data[..room]);
        buf.extend_from_slice(TRUNCATED.as_bytes());
        *truncated = true;
    }
}

/// Connects as `identity` and runs `command` (an already-quoted command line).
pub async fn run(
    addr: SocketAddr,
    machine_id: &str,
    keys: Arc<HostKeys>,
    identity: Identity,
    key: &PrivateKey,
    command: &str,
    timeout: Duration,
) -> Result<Output, SshError> {
    let verdict = Arc::new(std::sync::Mutex::new(None));
    let checker = Checker { machine_id: machine_id.into(), keys, verdict: verdict.clone() };
    let config = Arc::new(client::Config { inactivity_timeout: Some(timeout), ..client::Config::default() });
    let connected = tokio::time::timeout(Duration::from_secs(20), client::connect(config, addr, checker)).await;
    let mut session = match connected {
        Err(_) => return Err(SshError::Timeout),
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(match verdict.lock().ok().and_then(|v| v.clone()) {
                Some(HostKeyError::NotPinned) => SshError::HostKeyNotPinned,
                Some(HostKeyError::Changed) => SshError::HostKeyChanged,
                None => SshError::Transport(e.to_string()),
            });
        }
    };
    let auth = session
        .authenticate_publickey(identity.user(), PrivateKeyWithHashAlg::new(Arc::new(key.clone()), None))
        .await
        .map_err(|e| SshError::Transport(e.to_string()))?;
    if !matches!(auth, AuthResult::Success) {
        return Err(SshError::AuthRefused(identity.user()));
    }
    let mut channel = session.channel_open_session().await.map_err(|e| SshError::Transport(e.to_string()))?;
    channel.exec(true, command).await.map_err(|e| SshError::Transport(e.to_string()))?;
    let mut out = Output { exit_code: None, stdout: Vec::new(), stderr: Vec::new() };
    let (mut cut_out, mut cut_err) = (false, false);
    let collect = async {
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => append_capped(&mut out.stdout, &data, &mut cut_out),
                ChannelMsg::ExtendedData { data, ext: 1 } => append_capped(&mut out.stderr, &data, &mut cut_err),
                ChannelMsg::ExitStatus { exit_status } => out.exit_code = Some(exit_status),
                _ => {}
            }
        }
    };
    tokio::time::timeout(timeout, collect).await.map_err(|_| SshError::Timeout)?;
    let _ = session.disconnect(russh::Disconnect::ByApplication, "", "en").await;
    Ok(out)
}
