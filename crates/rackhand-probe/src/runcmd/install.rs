//! `run install-commands` (7.3.7, 7.3.3): writes `commands.json` only from a list signed by the hub pinned in
//! `probe.toml`, newer than the installed one and not expired. Anything else leaves the file as it was.

use std::path::Path;

use ed25519_dalek::VerifyingKey;
use prost::Message;
use rackhand_proto::common::SignedPayload;
use rackhand_proto::signed::{self, SignedError};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstallError {
    #[error("the payload isn't a signed list")]
    Malformed,
    #[error("the signature doesn't verify against the pinned hub")]
    Signature,
    #[error("the list has expired")]
    Expired,
    #[error("the list isn't newer than the installed one")]
    NotNewer,
    #[error("the list's body isn't a command list")]
    Body,
    #[error("probe.toml: {0}")]
    Config(String),
    #[error("writing {0}")]
    Write(String),
}

/// The hub key pinned in `probe.toml`.
pub fn pinned_hub_key(path: &Path) -> Result<VerifyingKey, InstallError> {
    let cfg = crate::config::ProbeToml::load(path).map_err(|e| InstallError::Config(e.to_string()))?;
    let bytes = cfg.hub_key().map_err(|e| InstallError::Config(e.to_string()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| InstallError::Config("hub.id isn't a key".into()))
}

fn installed_version(target: &Path) -> u64 {
    std::fs::read(target)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v["version"].as_u64())
        .unwrap_or(0)
}

/// Verifies and installs a signed command list (the protobuf `SignedPayload` bytes).
pub fn install(target: &Path, payload: &[u8], pinned: &VerifyingKey, now_ms: i64) -> Result<u64, InstallError> {
    let signed = SignedPayload::decode(payload).map_err(|_| InstallError::Malformed)?;
    let env = signed::verify(&signed, pinned, "commands", installed_version(target), now_ms).map_err(|e| match e {
        SignedError::BadSignature | SignedError::WrongKind => InstallError::Signature,
        SignedError::Malformed => InstallError::Malformed,
        SignedError::Expired => InstallError::Expired,
        SignedError::NotNewer => InstallError::NotNewer,
    })?;
    let mut list: serde_json::Value = serde_json::from_slice(&env.body).map_err(|_| InstallError::Body)?;
    if !list["commands"].is_array() {
        return Err(InstallError::Body);
    }
    list["version"] = serde_json::Value::from(env.version);
    let text = serde_json::to_vec_pretty(&list).map_err(|_| InstallError::Body)?;
    // Write beside the file, then rename: the wrapper never reads a half-written list.
    let tmp = target.with_extension("json.new");
    std::fs::write(&tmp, &text).map_err(|e| InstallError::Write(e.to_string()))?;
    set_mode(&tmp);
    std::fs::rename(&tmp, target).map_err(|e| InstallError::Write(e.to_string()))?;
    Ok(env.version)
}

#[cfg(unix)]
fn set_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
}

#[cfg(not(unix))]
fn set_mode(_path: &Path) {}
