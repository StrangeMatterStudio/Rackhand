//! The helper's named pipe (7.3.3): `\\.\pipe\rackhand-helper`, whose ACL lets only the probe's service account open it. The
//! account is `NT SERVICE\RackhandProbe`, a virtual account with no password and no rights beyond its service, and its SID is
//! derived from the service's name: the SHA-1 of the upper-cased name in UTF-16, as five little-endian numbers after
//! `S-1-5-80`. The helper itself runs as SYSTEM.

use sha1::{Digest, Sha1};

/// The service's name as `sc.exe` and `NT SERVICE\...` know it.
pub const PROBE_SERVICE: &str = "RackhandProbe";

/// The SID of `NT SERVICE\<name>`.
pub fn service_sid(name: &str) -> String {
    let utf16: Vec<u8> = name.to_uppercase().encode_utf16().flat_map(u16::to_le_bytes).collect();
    let hash = Sha1::digest(&utf16);
    let parts: Vec<String> =
        hash.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]).to_string()).collect();
    format!("S-1-5-80-{}", parts.join("-"))
}

/// The pipe's security descriptor: a protected DACL (no inherited entries) with SYSTEM and the service, and nobody else, so
/// everyone else is refused.
pub fn sddl(service: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GRGW;;;{})", service_sid(service))
}
