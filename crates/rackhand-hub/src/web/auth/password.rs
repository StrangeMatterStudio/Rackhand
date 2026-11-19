//! Argon2id password hashes (7.4.1 `credentials`), with the crate's default parameters.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

pub const MIN_LENGTH: usize = 12;

pub fn hash(password: &str) -> Result<String, String> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| e.to_string())?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| e.to_string())?;
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub fn verify(stored: &str, password: &str) -> bool {
    PasswordHash::new(stored).is_ok_and(|h| argon2::Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
}

/// A hash to verify against when the account doesn't exist, so a missing user takes as long as a wrong password.
pub fn dummy() -> &'static str {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash("not a password of anyone's").unwrap_or_default())
}
