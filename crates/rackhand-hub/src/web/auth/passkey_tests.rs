use axum::body::Body;
use axum::http::{Response, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use sha2::{Digest, Sha256};

use super::super::tests::{App, Browser, PASSWORD, app_with, body};
use crate::web::session;

const RP_ID: &str = "hub.example.test";
const ORIGIN: &str = "https://hub.example.test";

/// CBOR (RFC 8949): just what an attestation object and a COSE key need.
fn cbor_head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend([m | 24, n as u8]),
        _ => {
            out.push(m | 25);
            out.extend((n as u16).to_be_bytes());
        }
    }
}

fn cbor_int(v: i64, out: &mut Vec<u8>) {
    if v >= 0 { cbor_head(0, v as u64, out) } else { cbor_head(1, (-1 - v) as u64, out) }
}

fn cbor_bytes(b: &[u8], out: &mut Vec<u8>) {
    cbor_head(2, b.len() as u64, out);
    out.extend_from_slice(b);
}

fn cbor_text(t: &str, out: &mut Vec<u8>) {
    cbor_head(3, t.len() as u64, out);
    out.extend_from_slice(t.as_bytes());
}

/// A software passkey: a P-256 key and a credential id, as a platform authenticator holds them.
struct SoftPasskey {
    key: EcdsaKeyPair,
    cred_id: Vec<u8>,
    user_handle: Vec<u8>,
    counter: u32,
}

impl SoftPasskey {
    fn new() -> SoftPasskey {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        SoftPasskey { key, cred_id: b"soft-passkey-credential-1".to_vec(), user_handle: Vec::new(), counter: 0 }
    }

    fn client_data(kind: &str, challenge: &str) -> Vec<u8> {
        serde_json::json!({ "type": kind, "challenge": challenge, "origin": ORIGIN, "crossOrigin": false })
            .to_string()
            .into_bytes()
    }

    fn auth_data(&self, flags: u8, attested: bool) -> Vec<u8> {
        let mut d = Sha256::digest(RP_ID.as_bytes()).to_vec();
        d.push(flags);
        d.extend(self.counter.to_be_bytes());
        if attested {
            d.extend([0u8; 16]);
            d.extend((self.cred_id.len() as u16).to_be_bytes());
            d.extend(&self.cred_id);
            let point = self.key.public_key().as_ref();
            let mut cose = Vec::new();
            cbor_head(5, 5, &mut cose);
            for (k, v) in [(1, 2), (3, -7), (-1, 1)] {
                cbor_int(k, &mut cose);
                cbor_int(v, &mut cose);
            }
            cbor_int(-2, &mut cose);
            cbor_bytes(&point[1..33], &mut cose);
            cbor_int(-3, &mut cose);
            cbor_bytes(&point[33..65], &mut cose);
            d.extend(cose);
        }
        d
    }

    /// `navigator.credentials.create()`: user present and verified, attestation `none`.
    fn create(&mut self, options: &serde_json::Value) -> String {
        let pk = &options["publicKey"];
        assert_eq!(pk["rp"]["id"], RP_ID);
        self.user_handle = B64.decode(pk["user"]["id"].as_str().unwrap()).unwrap();
        let client = Self::client_data("webauthn.create", pk["challenge"].as_str().unwrap());
        let mut att = Vec::new();
        cbor_head(5, 3, &mut att);
        cbor_text("fmt", &mut att);
        cbor_text("none", &mut att);
        cbor_text("attStmt", &mut att);
        cbor_head(5, 0, &mut att);
        cbor_text("authData", &mut att);
        cbor_bytes(&self.auth_data(0x45, true), &mut att);
        serde_json::json!({
            "id": B64.encode(&self.cred_id),
            "rawId": B64.encode(&self.cred_id),
            "type": "public-key",
            "extensions": {},
            "response": { "attestationObject": B64.encode(att), "clientDataJSON": B64.encode(client) },
        })
        .to_string()
    }

    /// `navigator.credentials.get()`: signs the authenticator data and the client data's hash.
    fn get(&mut self, options: &serde_json::Value) -> String {
        let pk = &options["publicKey"];
        assert_eq!(pk["rpId"], RP_ID);
        self.counter += 1;
        let client = Self::client_data("webauthn.get", pk["challenge"].as_str().unwrap());
        let auth = self.auth_data(0x05, false);
        let mut signed = auth.clone();
        signed.extend(Sha256::digest(&client));
        let sig = self.key.sign(&SystemRandom::new(), &signed).unwrap();
        serde_json::json!({
            "id": B64.encode(&self.cred_id),
            "rawId": B64.encode(&self.cred_id),
            "type": "public-key",
            "extensions": {},
            "response": {
                "authenticatorData": B64.encode(auth),
                "clientDataJSON": B64.encode(client),
                "signature": B64.encode(sig.as_ref()),
                "userHandle": B64.encode(&self.user_handle),
            },
        })
        .to_string()
    }
}

async fn json(resp: Response<Body>) -> serde_json::Value {
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get(header::CONTENT_TYPE).unwrap(), "application/json");
    serde_json::from_str(&body(resp).await).unwrap()
}

/// Signs in with password and code, then steps up with a code (adding a factor needs a fresh step-up).
async fn signed_in_and_stepped_up(app: &App) -> Browser {
    let mut b = Browser::at("192.0.2.40");
    assert!(b.sign_in(app, PASSWORD, &app.code()).await);
    app.clock.fetch_add(30_000, std::sync::atomic::Ordering::SeqCst);
    let resp = b.post(app, "/step-up", "/step-up", &[("code", app.code().as_str())]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    b
}

#[tokio::test(flavor = "multi_thread")]
async fn not_offered_with_self_signed_certificate() {
    // The default: the hub's own certificate, no passkey configuration.
    let app = app_with("passkey-off", |web| web).await;
    let mut b = signed_in_and_stepped_up(&app).await;
    let resp = b.post(&app, "/account/passkeys/options", "/account", &[]).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "no registration options");
    let (_, account) = b.page(&app, "/account").await;
    assert!(!account.contains("data-passkey"), "no passkey button");
    assert!(account.contains("trusted certificate"), "says why");
}

#[tokio::test(flavor = "multi_thread")]
async fn register_and_assert_with_software_authenticator() {
    let app = app_with("passkey-on", |web| web.with_passkeys(RP_ID, ORIGIN).unwrap()).await;
    let mut b = signed_in_and_stepped_up(&app).await;
    let mut key = SoftPasskey::new();
    // Register.
    let options = json(b.post(&app, "/account/passkeys/options", "/account", &[]).await).await;
    let credential = key.create(&options);
    let resp = b.post(&app, "/account/passkeys", "/account", &[("credential", credential.as_str())]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{}", body(resp).await);
    let (_, account) = b.page(&app, "/account").await;
    assert!(account.contains("1 passkey"), "{account}");
    // Sign in on another browser: password, then the passkey instead of a code.
    let mut other = Browser::at("192.0.2.41");
    assert_eq!(other.password(&app, "admin", PASSWORD).await.status(), StatusCode::SEE_OTHER);
    let (_, code_page) = other.page(&app, "/sign-in/code").await;
    assert!(code_page.contains("data-passkey"), "offered on the code step");
    let options = json(other.post(&app, "/sign-in/passkey/options", "/sign-in/code", &[]).await).await;
    let assertion = key.get(&options);
    let resp = other.post(&app, "/sign-in/passkey", "/sign-in/code", &[("credential", assertion.as_str())]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{}", body(resp).await);
    assert!(other.has(session::COOKIE));
    let (status, _) = other.page(&app, "/").await;
    assert_eq!(status, StatusCode::OK);
    // The same answer again is refused: its challenge was used.
    let mut third = Browser::at("192.0.2.42");
    assert_eq!(third.password(&app, "admin", PASSWORD).await.status(), StatusCode::SEE_OTHER);
    let _ = json(third.post(&app, "/sign-in/passkey/options", "/sign-in/code", &[]).await).await;
    let replay = third.post(&app, "/sign-in/passkey", "/sign-in/code", &[("credential", assertion.as_str())]).await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    assert!(!third.has(session::COOKIE));
    // A fresh challenge with a signature that doesn't verify is refused too.
    assert_eq!(third.password(&app, "admin", PASSWORD).await.status(), StatusCode::SEE_OTHER);
    let options = json(third.post(&app, "/sign-in/passkey/options", "/sign-in/code", &[]).await).await;
    let mut forged: serde_json::Value = serde_json::from_str(&key.get(&options)).unwrap();
    let mut sig = B64.decode(forged["response"]["signature"].as_str().unwrap()).unwrap();
    let last = sig.len() - 1;
    sig[last] ^= 1;
    forged["response"]["signature"] = B64.encode(sig).into();
    let forged = forged.to_string();
    let resp = third.post(&app, "/sign-in/passkey", "/sign-in/code", &[("credential", forged.as_str())]).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "a bad signature");
    assert!(!third.has(session::COOKIE));
    // Step-up with the passkey.
    let options = json(other.post(&app, "/step-up/passkey/options", "/step-up", &[]).await).await;
    let assertion = key.get(&options);
    let resp = other.post(&app, "/step-up/passkey", "/step-up", &[("credential", assertion.as_str())]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let token = other.cookies.iter().find(|(k, _)| k == session::COOKIE).unwrap().1.clone();
    let user = session::lookup(&app.db, &token, app.now()).unwrap().unwrap();
    assert!(crate::web::auth::step_up::fresh(user.step_up_at, app.now()));
    // The passkey's counter was stored.
    let stored: Vec<u8> = app
        .db
        .readers()
        .with(|c| c.query_row("SELECT data FROM credentials WHERE kind = 'passkey'", [], |r| r.get(0)))
        .unwrap();
    assert!(!stored.is_empty());
}
