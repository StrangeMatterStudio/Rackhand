//! Release signatures (13, D90, D105): every binary and installer pins two public keys, the current one and a standby,
//! and installs only what one of them signed. Signatures are minisign's format: a `.minisig` file with the signature
//! over the file (prehashed with BLAKE2b-512, or the legacy unhashed form) and a global signature over the signature
//! and its trusted comment.
//!
//! The pinned keys are `keys/current.pub` and `keys/standby.pub` (minisign public key files), which the maintainer
//! creates offline before the first release (T91); until then nothing verifies. The `test-keys` feature pins the test
//! keys of `tests/keys/` instead; a release build never enables it.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use blake2::{Blake2b512, Digest};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("no release keys are pinned in this build")]
    NoKeys,
    #[error("the signature file is malformed: {0}")]
    Malformed(&'static str),
    #[error("signed by a key that isn't pinned")]
    UnknownKey,
    #[error("the signature doesn't match the file")]
    BadSignature,
    #[error("the trusted comment's signature doesn't match")]
    BadGlobalSignature,
}

/// Which pinned key a release was signed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pinned {
    Current,
    Standby,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub key_id: [u8; 8],
    pub key: VerifyingKey,
}

impl PublicKey {
    /// A minisign public key file (an untrusted comment line, then base64 of `Ed`, the key id and the key).
    pub fn parse(text: &str) -> Result<PublicKey, VerifyError> {
        let line = text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"));
        let raw = STANDARD
            .decode(line.ok_or(VerifyError::Malformed("no key line"))?)
            .map_err(|_| VerifyError::Malformed("key isn't base64"))?;
        if raw.len() != 42 || &raw[..2] != b"Ed" {
            return Err(VerifyError::Malformed("not an Ed25519 minisign key"));
        }
        let key_id: [u8; 8] = raw[2..10].try_into().map_err(|_| VerifyError::Malformed("key id"))?;
        let bytes: [u8; 32] = raw[10..].try_into().map_err(|_| VerifyError::Malformed("key"))?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| VerifyError::Malformed("not a valid key"))?;
        Ok(PublicKey { key_id, key })
    }

    /// The key as a minisign public key file.
    pub fn to_file(&self) -> String {
        let mut raw = b"Ed".to_vec();
        raw.extend_from_slice(&self.key_id);
        raw.extend_from_slice(self.key.as_bytes());
        let id: String = self.key_id.iter().rev().map(|b| format!("{b:02X}")).collect();
        format!("untrusted comment: minisign public key {id}\n{}\n", STANDARD.encode(raw))
    }
}

/// The keys this build pins: current, then standby.
pub fn pinned() -> Vec<(Pinned, PublicKey)> {
    let mut keys = Vec::new();
    for (which, text) in [(Pinned::Current, CURRENT), (Pinned::Standby, STANDBY)] {
        if let Some(Ok(k)) = text.map(PublicKey::parse) {
            keys.push((which, k));
        }
    }
    keys
}

#[cfg(not(feature = "test-keys"))]
const CURRENT: Option<&str> = release_key(include_str!("../keys/current.pub"));
#[cfg(not(feature = "test-keys"))]
const STANDBY: Option<&str> = release_key(include_str!("../keys/standby.pub"));
#[cfg(feature = "test-keys")]
const CURRENT: Option<&str> = Some(include_str!("../../../tests/keys/test-current.pub"));
#[cfg(feature = "test-keys")]
const STANDBY: Option<&str> = Some(include_str!("../../../tests/keys/test-standby.pub"));

/// A key file that is still the placeholder (no key line) pins nothing.
#[cfg(not(feature = "test-keys"))]
const fn release_key(text: &'static str) -> Option<&'static str> {
    if text.is_empty() { None } else { Some(text) }
}

/// Checks `data` against a `.minisig` file and the pinned keys; returns which key signed it.
pub fn verify(data: &[u8], minisig: &str) -> Result<Pinned, VerifyError> {
    let keys = pinned();
    if keys.is_empty() {
        return Err(VerifyError::NoKeys);
    }
    verify_with(data, minisig, &keys)
}

pub fn verify_with(data: &[u8], minisig: &str, keys: &[(Pinned, PublicKey)]) -> Result<Pinned, VerifyError> {
    let lines: Vec<&str> = minisig.lines().map(str::trim_end).collect();
    let [_untrusted, sig_line, trusted_line, global_line, ..] = lines.as_slice() else {
        return Err(VerifyError::Malformed("four lines expected"));
    };
    let raw = STANDARD.decode(sig_line).map_err(|_| VerifyError::Malformed("signature isn't base64"))?;
    if raw.len() != 74 {
        return Err(VerifyError::Malformed("signature length"));
    }
    let prehashed = match &raw[..2] {
        b"ED" => true,
        b"Ed" => false,
        _ => return Err(VerifyError::Malformed("not an Ed25519 signature")),
    };
    let key_id: [u8; 8] = raw[2..10].try_into().map_err(|_| VerifyError::Malformed("key id"))?;
    let sig_bytes: [u8; 64] = raw[10..].try_into().map_err(|_| VerifyError::Malformed("signature"))?;
    let (which, key) = keys.iter().find(|(_, k)| k.key_id == key_id).ok_or(VerifyError::UnknownKey)?;
    let signature = Signature::from_bytes(&sig_bytes);
    let message = if prehashed { Blake2b512::digest(data).to_vec() } else { data.to_vec() };
    key.key.verify(&message, &signature).map_err(|_| VerifyError::BadSignature)?;
    let comment = trusted_line.strip_prefix("trusted comment: ").ok_or(VerifyError::Malformed("trusted comment"))?;
    let global: [u8; 64] = STANDARD
        .decode(global_line)
        .ok()
        .and_then(|g| g.try_into().ok())
        .ok_or(VerifyError::Malformed("global signature"))?;
    let mut signed = sig_bytes.to_vec();
    signed.extend_from_slice(comment.as_bytes());
    key.key.verify(&signed, &Signature::from_bytes(&global)).map_err(|_| VerifyError::BadGlobalSignature)?;
    Ok(*which)
}

/// Making signatures, for tests and the maintainer's offline signing.
#[cfg(any(test, feature = "signing"))]
pub mod signing {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// The public key of a signing key, with its key id.
    pub fn public(key: &SigningKey, key_id: [u8; 8]) -> PublicKey {
        PublicKey { key_id, key: key.verifying_key() }
    }

    /// A prehashed `.minisig` for `data`.
    pub fn sign(key: &SigningKey, key_id: [u8; 8], data: &[u8], trusted_comment: &str) -> String {
        let sig = key.sign(&Blake2b512::digest(data));
        let mut raw = b"ED".to_vec();
        raw.extend_from_slice(&key_id);
        raw.extend_from_slice(&sig.to_bytes());
        let mut global_msg = sig.to_bytes().to_vec();
        global_msg.extend_from_slice(trusted_comment.as_bytes());
        let global = key.sign(&global_msg);
        format!(
            "untrusted comment: signature from rackhand\n{}\ntrusted comment: {trusted_comment}\n{}\n",
            STANDARD.encode(raw),
            STANDARD.encode(global.to_bytes())
        )
    }
}

#[cfg(test)]
mod tests;
