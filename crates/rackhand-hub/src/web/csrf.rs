//! CSRF tokens (10): an HMAC of the session (or, before sign-in, the anonymous cookie) under the hub's CSRF key. Every
//! state-changing route checks it before its handler runs.

use ring::hmac;

/// What a token is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    Session([u8; 32]),
    Anonymous(String),
}

fn message(binding: &Binding) -> Vec<u8> {
    match binding {
        Binding::Session(h) => [b"session:".as_slice(), h.as_slice()].concat(),
        Binding::Anonymous(id) => [b"anon:".as_slice(), id.as_bytes()].concat(),
    }
}

pub fn token(key: &[u8; 32], binding: &Binding) -> String {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), &message(binding));
    tag.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn verify(key: &[u8; 32], binding: &Binding, presented: &str) -> bool {
    let Some(bytes) = decode_hex(presented) else { return false };
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key), &message(binding), &bytes).is_ok()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}
