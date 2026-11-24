//! The probe's download of a release into its spool (7.3.3, E65). The probe, not the helper, fetches the file, so no network
//! access happens as root and no URL or path crosses the helper's socket. What it saves is one file; the helper copies it into
//! a slot and checks the copy, so nothing here is trusted, but a download that isn't the offered hash is dropped early.

use std::path::Path;
use std::time::Duration;

use rackhand_proto::helper::HelperRequest;
use rackhand_proto::probe::{ProbeEvent, UpdateAvailable};
use rackhand_release::binary::Version;
use sha2::{Digest, Sha256};

use super::MAX_RELEASE_BYTES;

/// A signature file is a few hundred bytes.
const MAX_SIGNATURE: usize = 1024;
const FILE: &str = "probe";
const PARTIAL: &str = "probe.partial";

/// An `UpdateAvailable` that is well formed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub version: Version,
    pub url: String,
    pub sha256: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// No route to the URL, or no answer: the machine stays on its version and shows as `update_unreachable` (info, E65).
    Unreachable(String),
    /// What came wasn't the offered file, or the helper refused it.
    Refused(String),
}

impl Failure {
    /// The event the next report carries.
    pub fn event(&self, version: Version, at_ms: i64) -> ProbeEvent {
        let (kind, detail) = match self {
            Failure::Unreachable(why) => ("update_unreachable", why),
            Failure::Refused(why) => ("update_refused", why),
        };
        ProbeEvent {
            kind: kind.into(),
            at_ms,
            fields: [("version".to_string(), version.to_string()), ("detail".to_string(), detail.clone())]
                .into_iter()
                .collect(),
        }
    }
}

pub fn parse_offer(update: &UpdateAvailable) -> Result<Offer, String> {
    let version = update
        .version
        .as_ref()
        .and_then(|v| Version::parse(&v.version))
        .ok_or("the offer has no version of the form x.y.z")?;
    let sha256: [u8; 32] = update.sha256.as_slice().try_into().map_err(|_| "the hash isn't a SHA-256")?;
    if update.signature.is_empty() || update.signature.len() > MAX_SIGNATURE {
        return Err("the offer has no signature of a plausible size".into());
    }
    Ok(Offer { version, url: update.url.clone(), sha256, signature: update.signature.clone() })
}

/// An offer of the version the probe runs, or an older one, is ignored.
pub fn worth_trying(running: Version, offered: Version) -> bool {
    offered > running
}

impl Offer {
    /// What the helper is asked: the version, the hash and the signature, never the URL or a path.
    pub fn request(&self) -> HelperRequest {
        use data_encoding::{BASE64, HEXLOWER};
        HelperRequest::ApplyUpdate {
            version: self.version.to_string(),
            sha256: HEXLOWER.encode(&self.sha256),
            signature: BASE64.encode(&self.signature),
        }
    }
}

/// Clears `spool`, downloads the offered release into `probe` there (at most 64 MB, `timeout` for all of it), and checks it is
/// the file whose hash was offered.
pub async fn fetch(spool: &Path, offer: &Offer, timeout: Duration) -> Result<(), Failure> {
    let refused = |e: String| Failure::Refused(e);
    std::fs::create_dir_all(spool).map_err(|e| refused(format!("the spool: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(spool, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| refused(format!("the spool: {e}")))?;
    }
    for entry in std::fs::read_dir(spool).map_err(|e| refused(format!("the spool: {e}")))?.flatten() {
        let _ = std::fs::remove_file(entry.path());
    }
    let partial = spool.join(PARTIAL);
    let mut out = tokio::fs::File::create(&partial).await.map_err(|e| refused(format!("the spool: {e}")))?;
    let got = rackhand_drivers::fetch::download(&offer.url, MAX_RELEASE_BYTES, timeout, &mut out).await;
    drop(out);
    let result = match got {
        Ok(_) => std::fs::read(&partial).map_err(|e| refused(format!("the spool: {e}"))).and_then(|bytes| {
            if Sha256::digest(&bytes).as_slice() == offer.sha256 {
                std::fs::rename(&partial, spool.join(FILE)).map_err(|e| refused(format!("the spool: {e}")))
            } else {
                Err(refused("the download isn't the file whose hash the hub offered".into()))
            }
        }),
        Err(rackhand_drivers::fetch::FetchError::Write(e)) => Err(refused(format!("the spool: {e}"))),
        Err(rackhand_drivers::fetch::FetchError::TooLarge(_)) => {
            Err(refused(format!("the release is over {MAX_RELEASE_BYTES} bytes")))
        }
        Err(e) => Err(Failure::Unreachable(e.to_string())),
    };
    if result.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    result
}

#[cfg(test)]
mod tests;
