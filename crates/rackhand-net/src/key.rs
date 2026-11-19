//! The node key: an Ed25519 secret key that is the node's iroh endpoint id, stored 0600 (7.1).

use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use iroh::SecretKey;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("node key {0} is readable by other users (mode {1:o}); it must be 0600")]
    TooOpen(String, u32),
    #[error("node key {0} is not 32 bytes")]
    Malformed(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Loads the key at `path`, or creates it (mode 0600, parent directory 0700) if it doesn't exist.
pub fn load_or_create(path: &Path) -> Result<SecretKey, KeyError> {
    match std::fs::File::open(path) {
        Ok(mut file) => {
            let mode = file.metadata()?.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(KeyError::TooOpen(path.display().to_string(), mode));
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| KeyError::Malformed(path.display().to_string()))?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let mut bytes = [0u8; 32];
            std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        Err(e) => Err(e.into()),
    }
}
