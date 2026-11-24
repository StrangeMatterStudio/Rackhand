//! The release manifest (5.2, 13, D90): one JSON file that lists every artifact of a release with its SHA-256 and size, signed by
//! the maintainer with the same keys as the artifacts. Builds are reproducible, so the manifest is a function of the files:
//! artifacts sorted by name, a fixed layout, a trailing newline. Whoever verifies a release checks the manifest's signature
//! against the pinned keys, then that every listed file has the listed hash and that no other file is there.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Pinned, PublicKey, VerifyError, verify_with};

/// The manifest's own name in a release, and its signature's.
pub const NAME: &str = "manifest.json";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("the manifest isn't one: {0}")]
    Malformed(String),
    #[error("the manifest's signature: {0}")]
    Signature(VerifyError),
    #[error("{0} isn't in the manifest")]
    NotListed(String),
    #[error("{0} is in the manifest and isn't there")]
    Missing(String),
    #[error("{0} doesn't have the hash the manifest lists")]
    HashMismatch(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub name: String,
    /// Lower-case hex SHA-256.
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: String,
    pub artifacts: Vec<Artifact>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// A file name that stays in the release's directory.
fn plain_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 255 && !name.contains(['/', '\\', '\0']) && name != "." && name != ".."
}

/// Files that sit beside the artifacts without being artifacts: signatures and the manifest itself.
fn beside(name: &str) -> bool {
    name == NAME || name.ends_with(".minisig")
}

impl Manifest {
    /// The manifest of `files`, sorted by name.
    pub fn new<'a>(version: &str, files: impl IntoIterator<Item = (String, &'a [u8])>) -> Manifest {
        let mut artifacts: Vec<Artifact> = files
            .into_iter()
            .map(|(name, bytes)| Artifact { name, sha256: sha256_hex(bytes), size: bytes.len() as u64 })
            .collect();
        artifacts.sort_by(|a, b| a.name.cmp(&b.name));
        Manifest { version: version.to_string(), artifacts }
    }

    /// The manifest of the artifacts in a directory (signatures and an earlier manifest are left out).
    pub fn of_dir(version: &str, dir: &Path) -> std::io::Result<Manifest> {
        let mut contents = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type()?.is_file() && !beside(&name) {
                contents.push((name, std::fs::read(entry.path())?));
            }
        }
        Ok(Manifest::new(version, contents.iter().map(|(n, b)| (n.clone(), b.as_slice()))))
    }

    /// The manifest as it is signed and published: pretty JSON, artifacts in name order, a final newline.
    pub fn to_json(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).unwrap_or_default();
        text.push('\n');
        text
    }

    pub fn parse(text: &str) -> Result<Manifest, ManifestError> {
        let m: Manifest = serde_json::from_str(text).map_err(|e| ManifestError::Malformed(e.to_string()))?;
        for (i, a) in m.artifacts.iter().enumerate() {
            if !plain_name(&a.name) {
                return Err(ManifestError::Malformed(format!("`{}` isn't a file name", a.name)));
            }
            if a.sha256.len() != 64 || !a.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                return Err(ManifestError::Malformed(format!("`{}`: the hash isn't a SHA-256", a.name)));
            }
            if m.artifacts[..i].iter().any(|b| b.name == a.name) {
                return Err(ManifestError::Malformed(format!("`{}` is listed twice", a.name)));
            }
        }
        Ok(m)
    }

    /// `bytes` is the artifact `name` the manifest lists.
    pub fn check(&self, name: &str, bytes: &[u8]) -> Result<(), ManifestError> {
        let listed =
            self.artifacts.iter().find(|a| a.name == name).ok_or_else(|| ManifestError::NotListed(name.into()))?;
        if listed.size != bytes.len() as u64 || listed.sha256 != sha256_hex(bytes) {
            return Err(ManifestError::HashMismatch(name.into()));
        }
        Ok(())
    }

    /// Every listed artifact is in `dir` with its hash, and nothing else is but signatures and the manifest.
    pub fn check_dir(&self, dir: &Path) -> Result<(), ManifestError> {
        let io = |e: std::io::Error| ManifestError::Malformed(format!("{}: {e}", dir.display()));
        for entry in std::fs::read_dir(dir).map_err(io)? {
            let entry = entry.map_err(io)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type().map_err(io)?.is_file()
                && !beside(&name)
                && !self.artifacts.iter().any(|a| a.name == name)
            {
                return Err(ManifestError::NotListed(name));
            }
        }
        for a in &self.artifacts {
            let bytes = std::fs::read(dir.join(&a.name)).map_err(|_| ManifestError::Missing(a.name.clone()))?;
            self.check(&a.name, &bytes)?;
        }
        Ok(())
    }
}

/// A signed manifest, checked against `keys`: which key signed it, and the manifest.
pub fn verify_signed_with(
    manifest: &[u8],
    minisig: &str,
    keys: &[(Pinned, PublicKey)],
) -> Result<(Pinned, Manifest), ManifestError> {
    let which = verify_with(manifest, minisig, keys).map_err(ManifestError::Signature)?;
    let text = std::str::from_utf8(manifest).map_err(|_| ManifestError::Malformed("not UTF-8".into()))?;
    Ok((which, Manifest::parse(text)?))
}

/// The same against the keys this build pins.
pub fn verify_signed(manifest: &[u8], minisig: &str) -> Result<(Pinned, Manifest), ManifestError> {
    let keys = crate::pinned();
    if keys.is_empty() {
        return Err(ManifestError::Signature(VerifyError::NoKeys));
    }
    verify_signed_with(manifest, minisig, &keys)
}
