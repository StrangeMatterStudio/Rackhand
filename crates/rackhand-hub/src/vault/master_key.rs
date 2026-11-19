//! The master key (7.1): 256 bits held outside the database, handed to the hub as a service credential
//! (`$CREDENTIALS_DIRECTORY/master.key`). The recovery code shown at first run restores it (7.7.1, E34).

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{Secret, VaultError};

pub struct MasterKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey(redacted, fingerprint {})", self.fingerprint())
    }
}

/// A sealed value as stored in `secrets`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl MasterKey {
    pub fn generate() -> MasterKey {
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&key);
        MasterKey(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> MasterKey {
        MasterKey(Zeroizing::new(bytes))
    }

    /// Loads `master.key` from the service manager's credential directory, or from `fallback` (tests, manual runs).
    pub fn load(fallback: Option<&std::path::Path>) -> Result<MasterKey, VaultError> {
        let path = match std::env::var_os("CREDENTIALS_DIRECTORY") {
            Some(dir) => std::path::PathBuf::from(dir).join("master.key"),
            None => fallback.ok_or(VaultError::NoMasterKey)?.to_path_buf(),
        };
        let bytes = Zeroizing::new(std::fs::read(&path).map_err(|_| VaultError::NoMasterKey)?);
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| VaultError::NoMasterKey)?;
        Ok(MasterKey::from_bytes(arr))
    }

    /// A short, non-secret identifier for the key (first 8 bytes of its SHA-256).
    pub fn fingerprint(&self) -> String {
        Sha256::digest(self.0.as_slice())[..8].iter().map(|b| format!("{b:02x}")).collect()
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(self.0.as_slice().into())
    }

    /// Encrypts with a fresh random 192-bit nonce; the secret's name is bound as associated data.
    pub fn seal(&self, name: &str, plaintext: &[u8]) -> Result<Sealed, VaultError> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher()
            .encrypt(&nonce, Payload { msg: plaintext, aad: name.as_bytes() })
            .map_err(|_| VaultError::Encrypt)?;
        Ok(Sealed { nonce: nonce.into(), ciphertext })
    }

    pub fn open(&self, name: &str, sealed: &Sealed) -> Result<Secret, VaultError> {
        let nonce = XNonce::from_slice(&sealed.nonce);
        let plain = self
            .cipher()
            .decrypt(nonce, Payload { msg: &sealed.ciphertext, aad: name.as_bytes() })
            .map_err(|_| VaultError::Decrypt(name.to_string()))?;
        Ok(Secret::new(plain))
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32

/// The recovery code: the key plus a 2-byte checksum, Crockford base32, in groups of five.
pub fn recovery_code(key: &MasterKey) -> String {
    let mut data = key.bytes().to_vec();
    data.extend_from_slice(&Sha256::digest(key.bytes())[..2]);
    let mut bits = 0u32;
    let mut nbits = 0;
    let mut out = String::new();
    for byte in data {
        bits = (bits << 8) | u32::from(byte);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPHABET[((bits >> nbits) & 31) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(ALPHABET[((bits << (5 - nbits)) & 31) as usize] as char);
    }
    out.as_bytes().chunks(5).map(|c| String::from_utf8_lossy(c).to_string()).collect::<Vec<_>>().join("-")
}

pub fn restore_from_recovery_code(code: &str) -> Result<MasterKey, VaultError> {
    let mut bits = 0u32;
    let mut nbits = 0;
    let mut data = Vec::new();
    for c in code.chars().filter(|c| *c != '-' && !c.is_whitespace()) {
        let c = match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        let v = ALPHABET.iter().position(|&a| a as char == c).ok_or(VaultError::BadRecoveryCode)? as u32;
        bits = (bits << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            data.push(((bits >> nbits) & 0xff) as u8);
        }
    }
    if data.len() != 34 {
        return Err(VaultError::BadRecoveryCode);
    }
    let key: [u8; 32] = data[..32].try_into().map_err(|_| VaultError::BadRecoveryCode)?;
    if Sha256::digest(key)[..2] != data[32..] {
        return Err(VaultError::BadRecoveryCode);
    }
    Ok(MasterKey::from_bytes(key))
}
