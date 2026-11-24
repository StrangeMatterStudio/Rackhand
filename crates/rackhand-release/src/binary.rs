//! A signed binary names its file and its version in the signature's trusted comment, `file:<name> version:<x.y.z>`. The
//! comment is under the global signature, so whoever checks a file (the helper before it swaps a probe, the updater before
//! it swaps the hub) takes the version from what the key signed, never from the request that brought the file: an older
//! release that was once signed can't be passed off as a newer one.

use crate::{Pinned, PublicKey, VerifyError, verify_with_comment};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BinaryError {
    #[error("the signature: {0}")]
    Signature(VerifyError),
    #[error("the signature is for {signed}, not {expected}")]
    NotThisFile { signed: String, expected: String },
    #[error("the signed comment doesn't name a version (`file:<name> version:<x.y.z>`): `{0}`")]
    NoVersion(String),
}

/// `major.minor.patch`, compared as numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u64, pub u64, pub u64);

impl Version {
    /// Three numbers without signs or leading zeros, and nothing else.
    pub fn parse(text: &str) -> Option<Version> {
        let mut parts = text.split('.');
        let mut next = || {
            let p = parts.next()?;
            let ok = !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && (p == "0" || !p.starts_with('0'));
            if ok { p.parse::<u64>().ok() } else { None }
        };
        let v = Version(next()?, next()?, next()?);
        parts.next().is_none().then_some(v)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// The name and version a trusted comment signs.
fn claim(comment: &str) -> Result<(&str, Version), BinaryError> {
    let none = || BinaryError::NoVersion(comment.chars().take(80).collect());
    let rest = comment.strip_prefix("file:").ok_or_else(none)?;
    let (name, version) = rest.split_once(" version:").ok_or_else(none)?;
    Ok((name, Version::parse(version).ok_or_else(none)?))
}

/// `data` is the file `expected` signed with a version, by one of `keys`: which key, and the version.
pub fn verify_binary_with(
    data: &[u8],
    minisig: &str,
    keys: &[(Pinned, PublicKey)],
    expected: &str,
) -> Result<(Pinned, Version), BinaryError> {
    let (which, comment) = verify_with_comment(data, minisig, keys).map_err(BinaryError::Signature)?;
    let (name, version) = claim(&comment)?;
    if name != expected {
        return Err(BinaryError::NotThisFile { signed: name.to_string(), expected: expected.to_string() });
    }
    Ok((which, version))
}

/// The same against the keys this build pins.
pub fn verify_binary(data: &[u8], minisig: &str, expected: &str) -> Result<(Pinned, Version), BinaryError> {
    let keys = crate::pinned();
    if keys.is_empty() {
        return Err(BinaryError::Signature(VerifyError::NoKeys));
    }
    verify_binary_with(data, minisig, &keys, expected)
}
