//! Hub-signed, versioned payloads with an expiry: `KeysUpdate`, command lists and the join response's command list
//! (7.3.3, 7.3.7, D92). The signature covers a domain-separated encoding of the envelope.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use prost::Message;

use crate::common::{SignedEnvelope, SignedPayload};

const DOMAIN: &[u8] = b"rackhand-signed-payload-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignedError {
    #[error("signature doesn't verify against the pinned hub key")]
    BadSignature,
    #[error("payload is malformed")]
    Malformed,
    #[error("payload is for another kind")]
    WrongKind,
    #[error("payload has expired")]
    Expired,
    #[error("payload version is not newer than the last applied one")]
    NotNewer,
}

fn signed_bytes(payload: &[u8]) -> Vec<u8> {
    [DOMAIN, payload].concat()
}

pub fn sign(key: &SigningKey, kind: &str, version: u64, now_ms: i64, expires_at_ms: i64, body: &[u8]) -> SignedPayload {
    let payload =
        SignedEnvelope { kind: kind.to_string(), version, signed_at_ms: now_ms, expires_at_ms, body: body.to_vec() }
            .encode_to_vec();
    let sig: Signature = key.sign(&signed_bytes(&payload));
    SignedPayload { payload, hub_signature: sig.to_bytes().to_vec() }
}

/// Verifies the signature first, then kind, expiry and that the version is above `last_applied`.
pub fn verify(
    signed: &SignedPayload,
    key: &VerifyingKey,
    kind: &str,
    last_applied: u64,
    now_ms: i64,
) -> Result<SignedEnvelope, SignedError> {
    let sig = Signature::from_slice(&signed.hub_signature).map_err(|_| SignedError::BadSignature)?;
    key.verify(&signed_bytes(&signed.payload), &sig).map_err(|_| SignedError::BadSignature)?;
    let env = SignedEnvelope::decode(signed.payload.as_slice()).map_err(|_| SignedError::Malformed)?;
    if env.kind != kind {
        return Err(SignedError::WrongKind);
    }
    if now_ms > env.expires_at_ms {
        return Err(SignedError::Expired);
    }
    if env.version <= last_applied {
        return Err(SignedError::NotNewer);
    }
    Ok(env)
}
