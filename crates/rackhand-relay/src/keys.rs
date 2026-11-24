//! Relay keys (7.3.10): a token the relay signs with its own key and an operator hands to a hub. It names the key, its
//! priority at capacity, how many endpoints may use it (it is bound to the first ones that do) and when it expires. The relay
//! checks the signature on every connection; nothing but its own key can make one.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "rk1.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    /// Not keyed: admitted last at capacity.
    #[serde(skip)]
    None,
    Normal,
    High,
}

impl Priority {
    pub fn parse(s: &str) -> Option<Priority> {
        match s {
            "normal" => Some(Priority::Normal),
            "high" => Some(Priority::High),
            _ => None,
        }
    }
}

/// What a key says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBody {
    pub name: String,
    pub priority: Priority,
    pub max_endpoints: u32,
    pub expires_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("the relay key isn't one of this relay's")]
    Invalid,
    #[error("the relay key has expired")]
    Expired,
}

/// A token for `body`, signed with the relay's key.
pub fn create(signing: &SigningKey, body: &KeyBody) -> String {
    let payload = serde_json::to_vec(body).unwrap_or_default();
    let signature = signing.sign(&payload);
    format!("{PREFIX}{}.{}", B64.encode(&payload), B64.encode(signature.to_bytes()))
}

/// What a token says, if this relay signed it and it hasn't expired.
pub fn verify(verifying: &VerifyingKey, token: &str, now_ms: i64) -> Result<KeyBody, KeyError> {
    let rest = token.strip_prefix(PREFIX).ok_or(KeyError::Invalid)?;
    let (payload, signature) = rest.split_once('.').ok_or(KeyError::Invalid)?;
    let payload = B64.decode(payload).map_err(|_| KeyError::Invalid)?;
    let signature: [u8; 64] =
        B64.decode(signature).map_err(|_| KeyError::Invalid)?.try_into().map_err(|_| KeyError::Invalid)?;
    verifying.verify(&payload, &Signature::from_bytes(&signature)).map_err(|_| KeyError::Invalid)?;
    let body: KeyBody = serde_json::from_slice(&payload).map_err(|_| KeyError::Invalid)?;
    if body.expires_ms <= now_ms {
        return Err(KeyError::Expired);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn body() -> KeyBody {
        KeyBody { name: "home".into(), priority: Priority::High, max_endpoints: 2, expires_ms: 2_000_000 }
    }

    #[test]
    fn a_token_is_signed_by_the_relay_and_says_what_it_was_made_to_say() {
        let relay = key(1);
        let token = create(&relay, &body());
        assert_eq!(verify(&relay.verifying_key(), &token, 1_000_000), Ok(body()));
        // another relay's key, a changed body, a cut token and plain text are all refused
        assert_eq!(verify(&key(2).verifying_key(), &token, 1_000_000), Err(KeyError::Invalid));
        let other = create(&relay, &KeyBody { max_endpoints: 200, ..body() });
        let forged = format!("{}.{}", other.rsplit_once('.').unwrap().0, token.rsplit_once('.').unwrap().1);
        assert_eq!(verify(&relay.verifying_key(), &forged, 1_000_000), Err(KeyError::Invalid));
        for bad in ["", "rk1.", "rk1.abc", "rk1.abc.def", "hello", &token[..token.len() - 3]] {
            assert_eq!(verify(&relay.verifying_key(), bad, 1_000_000), Err(KeyError::Invalid), "{bad:?}");
        }
        // an expired key says so
        assert_eq!(verify(&relay.verifying_key(), &token, 2_000_000), Err(KeyError::Expired));
    }
}
