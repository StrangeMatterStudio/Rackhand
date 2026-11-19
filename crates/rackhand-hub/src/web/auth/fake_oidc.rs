//! An in-process OIDC provider for tests (plan T38): discovery, JWKS and a token endpoint over plain HTTP on loopback,
//! signing ID tokens with its own P-256 key. `authorize` stands in for the provider's sign-in page.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Response, StatusCode, header};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use sha2::{Digest, Sha256};

/// Ways the provider can get an ID token wrong.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Misbehave {
    #[default]
    None,
    WrongIssuer,
    WrongNonce,
    WrongAudience,
    Expired,
    BadSignature,
    UnknownKid,
    AlgNone,
}

struct Grant {
    nonce: String,
    challenge: String,
    sub: String,
}

struct State {
    issuer: String,
    client_id: String,
    client_secret: String,
    key: EcdsaKeyPair,
    codes: HashMap<String, Grant>,
    misbehave: Misbehave,
    clock_ms: Arc<AtomicI64>,
}

#[derive(Clone)]
pub(crate) struct FakeOidc {
    pub issuer: String,
    state: Arc<Mutex<State>>,
}

impl std::fmt::Debug for FakeOidc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeOidc").field("issuer", &self.issuer).finish()
    }
}

fn json(value: serde_json::Value) -> Response<Body> {
    let mut resp = Response::new(Body::from(value.to_string()));
    resp.headers_mut().insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    resp
}

fn query_of(url: &str) -> HashMap<String, String> {
    let q = url.split_once('?').map_or("", |(_, q)| q);
    form_urlencoded::parse(q.as_bytes()).into_owned().collect()
}

impl FakeOidc {
    pub(crate) async fn start(client_id: &str, client_secret: &str, clock_ms: Arc<AtomicI64>) -> FakeOidc {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let state = Arc::new(Mutex::new(State {
            issuer: issuer.clone(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            key,
            codes: HashMap::new(),
            misbehave: Misbehave::None,
            clock_ms,
        }));
        let s1 = state.clone();
        let s2 = state.clone();
        let s3 = state.clone();
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let iss = s1.lock().unwrap().issuer.clone();
                    async move {
                        json(serde_json::json!({
                            "issuer": iss,
                            "authorization_endpoint": format!("{iss}/authorize"),
                            "token_endpoint": format!("{iss}/token"),
                            "jwks_uri": format!("{iss}/jwks"),
                            "response_types_supported": ["code"],
                            "subject_types_supported": ["public"],
                            "id_token_signing_alg_values_supported": ["ES256"],
                        }))
                    }
                }),
            )
            .route(
                "/jwks",
                get(move || {
                    let point = s2.lock().unwrap().key.public_key().as_ref().to_vec();
                    async move {
                        json(serde_json::json!({ "keys": [{
                            "kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
                            "x": B64.encode(&point[1..33]), "y": B64.encode(&point[33..65]),
                        }]}))
                    }
                }),
            )
            .route(
                "/token",
                post(move |headers: HeaderMap, body: String| {
                    let state = s3.clone();
                    async move { token(&state, &headers, &body) }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        FakeOidc { issuer, state }
    }

    pub(crate) fn misbehave(&self, m: Misbehave) {
        self.state.lock().unwrap().misbehave = m;
    }

    /// The person signs in at the provider: given the URL the hub sent the browser to, returns the callback path and
    /// query the provider sends the browser back to.
    pub(crate) fn authorize(&self, url: &str, sub: &str) -> String {
        let q = query_of(url);
        let mut s = self.state.lock().unwrap();
        assert!(url.starts_with(&format!("{}/authorize?", s.issuer)), "{url}");
        assert_eq!(q.get("client_id"), Some(&s.client_id));
        assert_eq!(q.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(q.get("code_challenge_method").map(String::as_str), Some("S256"));
        assert!(q.get("scope").is_some_and(|sc| sc.split(' ').any(|x| x == "openid")));
        let code = format!("code-{}", s.codes.len() + 1);
        s.codes.insert(
            code.clone(),
            Grant { nonce: q["nonce"].clone(), challenge: q["code_challenge"].clone(), sub: sub.into() },
        );
        let redirect = &q["redirect_uri"];
        let path = redirect.split_once("://").and_then(|(_, rest)| rest.find('/').map(|i| &rest[i..])).unwrap();
        let back: String = form_urlencoded::Serializer::new(String::new())
            .append_pair("code", &code)
            .append_pair("state", &q["state"])
            .finish();
        format!("{path}?{back}")
    }
}

fn token(state: &Mutex<State>, headers: &HeaderMap, body: &str) -> Response<Body> {
    let s = state.lock().unwrap();
    let f: HashMap<String, String> = form_urlencoded::parse(body.as_bytes()).into_owned().collect();
    let basic = format!("Basic {}", STANDARD.encode(format!("{}:{}", s.client_id, s.client_secret)));
    if headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) != Some(basic.as_str()) {
        let mut r = json(serde_json::json!({ "error": "invalid_client" }));
        *r.status_mut() = StatusCode::UNAUTHORIZED;
        return r;
    }
    let Some(grant) = f.get("code").and_then(|c| s.codes.get(c)) else {
        let mut r = json(serde_json::json!({ "error": "invalid_grant" }));
        *r.status_mut() = StatusCode::BAD_REQUEST;
        return r;
    };
    let verifier = f.get("code_verifier").map(String::as_str).unwrap_or("");
    if B64.encode(Sha256::digest(verifier.as_bytes())) != grant.challenge {
        let mut r = json(serde_json::json!({ "error": "invalid_grant", "error_description": "pkce" }));
        *r.status_mut() = StatusCode::BAD_REQUEST;
        return r;
    }
    let now = s.clock_ms.load(Ordering::SeqCst) / 1000;
    let m = s.misbehave;
    let claims = serde_json::json!({
        "iss": if m == Misbehave::WrongIssuer { "https://elsewhere.example.test".to_string() } else { s.issuer.clone() },
        "sub": grant.sub,
        "aud": if m == Misbehave::WrongAudience { "someone-else".to_string() } else { s.client_id.clone() },
        "iat": now,
        "exp": if m == Misbehave::Expired { now - 600 } else { now + 300 },
        "nonce": if m == Misbehave::WrongNonce { "not-the-nonce".to_string() } else { grant.nonce.clone() },
    });
    let header = match m {
        Misbehave::AlgNone => serde_json::json!({ "alg": "none", "kid": "k1" }),
        Misbehave::UnknownKid => serde_json::json!({ "alg": "ES256", "kid": "k9" }),
        _ => serde_json::json!({ "alg": "ES256", "kid": "k1", "typ": "JWT" }),
    };
    let signing_input = format!("{}.{}", B64.encode(header.to_string()), B64.encode(claims.to_string()));
    let mut sig = s.key.sign(&SystemRandom::new(), signing_input.as_bytes()).unwrap().as_ref().to_vec();
    if m == Misbehave::BadSignature {
        sig[0] ^= 1;
    }
    let id_token = if m == Misbehave::AlgNone {
        format!("{signing_input}.")
    } else {
        format!("{signing_input}.{}", B64.encode(sig))
    };
    json(serde_json::json!({ "access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": id_token }))
}
