//! OIDC sign-in (7.7.2, D49): the authorization code flow with PKCE, `state` bound to the browser that started it and
//! used once, and the ID token checked here with ring (RS256, ES256, EdDSA): signature against the provider's JWKS,
//! issuer, audience, expiry and nonce. The provider signs a person in; step-up still takes their local factor.
//!
//! An account is matched by its `sub` claim: an admin creates it first (settings, with the subject), and nobody else
//! gets in through the provider.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderValue, Method, Request, Response, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64};
use hyper_util::rt::TokioIo;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::Url;

use super::devices;
use super::flow::audit;
use super::limits::Attempt;
use crate::library::config;
use crate::web::pages::{html_text, status};
use crate::web::session::{self, random_token};
use crate::web::{Ctx, Web};

/// The Vault name of the client secret; the settings hold `secret:` and this.
pub const SECRET_NAME: &str = "oidc.client_secret";
/// The cookie that binds a sign-in's `state` to the browser that started it.
const FLOW_COOKIE: &str = "rh_oidc";
const FLOW_MS: i64 = 10 * 60_000;
/// Clock difference allowed between the hub and the provider.
const SKEW_S: i64 = 60;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE: usize = 1 << 20;

/// A sign-in started at the provider.
#[derive(Debug, Clone)]
pub(crate) struct Flow {
    nonce: String,
    verifier: String,
    browser: String,
    created_ms: i64,
}

#[derive(Debug, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct JwsHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Claims {
    pub sub: String,
}

/// Plain HTTP only to a provider on this host (tests, a provider beside the hub); anything else is HTTPS.
pub(crate) fn allowed_url(url: &str) -> bool {
    let Ok(u) = Url::parse(url) else { return false };
    match u.scheme() {
        "https" => u.host_str().is_some(),
        "http" => matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")),
        _ => false,
    }
}

fn tls() -> Result<tokio_rustls::TlsConnector, String> {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

async fn send<I>(io: I, req: Request<Body>) -> Result<(StatusCode, Vec<u8>), String>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(io)).await.map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
    let code = resp.status();
    let bytes = axum::body::to_bytes(Body::new(resp.into_body()), MAX_RESPONSE).await.map_err(|e| e.to_string())?;
    Ok((code, bytes.to_vec()))
}

/// One HTTP/1.1 request to the provider, with a timeout and a size limit.
async fn fetch(method: Method, url: &str, headers: &[(&str, String)], body: Vec<u8>) -> Result<Vec<u8>, String> {
    if !allowed_url(url) {
        return Err(format!("not an allowed provider URL: {url}"));
    }
    let u = Url::parse(url).map_err(|e| e.to_string())?;
    let host = u.host_str().ok_or("no host")?.trim_start_matches('[').trim_end_matches(']').to_string();
    let port = u.port_or_known_default().ok_or("no port")?;
    let target = match u.query() {
        Some(q) => format!("{}?{q}", u.path()),
        None => u.path().to_string(),
    };
    let authority = match u.port() {
        Some(p) => format!("{}:{p}", u.host_str().unwrap_or_default()),
        None => u.host_str().unwrap_or_default().to_string(),
    };
    let mut req = Request::builder()
        .method(method)
        .uri(target)
        .header(header::HOST, authority)
        .header(header::USER_AGENT, "rackhand")
        .header(header::ACCEPT, "application/json");
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let req = req.body(Body::from(body)).map_err(|e| e.to_string())?;
    let work = async {
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await.map_err(|e| e.to_string())?;
        if u.scheme() == "https" {
            let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
            let stream = tls()?.connect(name, tcp).await.map_err(|e| e.to_string())?;
            send(stream, req).await
        } else {
            send(tcp, req).await
        }
    };
    let (code, bytes) = tokio::time::timeout(HTTP_TIMEOUT, work).await.map_err(|_| "the provider timed out")??;
    if !code.is_success() {
        return Err(format!("the provider answered {code}"));
    }
    Ok(bytes)
}

async fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, String> {
    let bytes = fetch(Method::GET, url, &[], Vec::new()).await?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{url}: {e}"))
}

async fn discover(issuer: &str) -> Result<Discovery, String> {
    let d: Discovery = get_json(&format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'))).await?;
    // The issuer in the document must be the one configured, exactly (OIDC Discovery 4.3).
    if d.issuer != issuer {
        return Err("the discovery document names another issuer".into());
    }
    Ok(d)
}

fn b64(text: &str) -> Option<Vec<u8>> {
    B64.decode(text.trim_end_matches('=')).ok()
}

fn check_signature(alg: &str, key: &Jwk, message: &[u8], sig: &[u8]) -> bool {
    if key.alg.as_deref().is_some_and(|a| a != alg) {
        return false;
    }
    match (alg, key.kty.as_str()) {
        ("RS256", "RSA") => {
            let (Some(n), Some(e)) = (key.n.as_deref().and_then(b64), key.e.as_deref().and_then(b64)) else {
                return false;
            };
            RsaPublicKeyComponents { n: &n, e: &e }.verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, sig).is_ok()
        }
        ("ES256", "EC") if key.crv.as_deref() == Some("P-256") => {
            let (Some(x), Some(y)) = (key.x.as_deref().and_then(b64), key.y.as_deref().and_then(b64)) else {
                return false;
            };
            let point = [&[4u8][..], &x, &y].concat();
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point).verify(message, sig).is_ok()
        }
        ("EdDSA", "OKP") if key.crv.as_deref() == Some("Ed25519") => {
            let Some(x) = key.x.as_deref().and_then(b64) else { return false };
            UnparsedPublicKey::new(&signature::ED25519, x).verify(message, sig).is_ok()
        }
        _ => false,
    }
}

/// Checks an ID token: the signature against the provider's keys, then issuer, audience, expiry and nonce.
pub(crate) fn verify_id_token(
    token: &str,
    keys: &[Jwk],
    issuer: &str,
    client_id: &str,
    nonce: &str,
    now_s: i64,
) -> Result<Claims, String> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err("not a signed JWT".into());
    };
    let header: JwsHeader =
        b64(h).and_then(|b| serde_json::from_slice(&b).ok()).ok_or("the token's header is unreadable")?;
    if !matches!(header.alg.as_str(), "RS256" | "ES256" | "EdDSA") {
        return Err(format!("signing algorithm {} isn't accepted", header.alg));
    }
    let sig = b64(s).filter(|s| !s.is_empty()).ok_or("no signature")?;
    let candidates: Vec<&Jwk> = match &header.kid {
        Some(kid) => keys.iter().filter(|k| k.kid.as_deref() == Some(kid)).collect(),
        None => keys.iter().collect(),
    };
    let message = format!("{h}.{p}");
    if !candidates.iter().any(|k| check_signature(&header.alg, k, message.as_bytes(), &sig)) {
        return Err("the signature doesn't verify against the provider's keys".into());
    }
    let claims: serde_json::Value =
        b64(p).and_then(|b| serde_json::from_slice(&b).ok()).ok_or("the token's claims are unreadable")?;
    if claims["iss"].as_str() != Some(issuer) {
        return Err("wrong issuer".into());
    }
    let audiences: Vec<&str> = match &claims["aud"] {
        serde_json::Value::String(a) => vec![a.as_str()],
        serde_json::Value::Array(a) => a.iter().filter_map(|v| v.as_str()).collect(),
        _ => Vec::new(),
    };
    if !audiences.contains(&client_id) {
        return Err("the token is for another client".into());
    }
    if audiences.len() > 1 && claims["azp"].as_str() != Some(client_id) {
        return Err("the token's authorized party is another client".into());
    }
    let exp = claims["exp"].as_i64().ok_or("no expiry")?;
    if now_s > exp + SKEW_S {
        return Err("the token has expired".into());
    }
    if claims["iat"].as_i64().is_some_and(|iat| iat > now_s + SKEW_S) {
        return Err("the token is issued in the future".into());
    }
    if claims["nonce"].as_str() != Some(nonce) {
        return Err("wrong nonce".into());
    }
    let sub = claims["sub"].as_str().filter(|s| !s.is_empty()).ok_or("no subject")?;
    Ok(Claims { sub: sub.to_string() })
}

fn random() -> Option<String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).ok()?;
    Some(B64.encode(b))
}

fn settings(web: &Web) -> Option<config::Oidc> {
    config::hub(&web.0.db).ok()?.oidc
}

pub(crate) fn configured(web: &Web) -> bool {
    settings(web).is_some()
}

fn redirect_to(url: &str, cookies: &[String]) -> Response<Body> {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(v) = HeaderValue::from_str(url) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp
}

/// `GET /sign-in/oidc`: off to the provider.
pub(crate) async fn start(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(cfg) = settings(web) else { return status(StatusCode::NOT_FOUND, "OIDC sign-in isn't set up") };
    let discovery = match discover(&cfg.issuer).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "oidc discovery");
            return status(StatusCode::BAD_GATEWAY, "The identity provider couldn't be reached");
        }
    };
    let (Some(state), Some(nonce), Some(verifier), Ok(cookie)) = (random(), random(), random(), random_token()) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "No randomness");
    };
    let challenge = B64.encode(Sha256::digest(verifier.as_bytes()));
    let flow = Flow { nonce: nonce.clone(), verifier, browser: devices::hash_hex(&cookie), created_ms: ctx.now_ms };
    if let Ok(mut flows) = web.0.oidc_flows.lock() {
        flows.retain(|_, f| ctx.now_ms - f.created_ms < FLOW_MS);
        flows.insert(state.clone(), flow);
    }
    let query: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", &cfg.client_id)
        .append_pair("redirect_uri", &cfg.redirect_url)
        .append_pair("scope", "openid")
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    let sep = if discovery.authorization_endpoint.contains('?') { '&' } else { '?' };
    // Lax, not Strict: the provider sends the browser back from another site, and a Strict cookie wouldn't come along.
    let bind = format!("{FLOW_COOKIE}={cookie}; Path=/sign-in/oidc; Max-Age=600; Secure; HttpOnly; SameSite=Lax");
    redirect_to(&format!("{}{sep}{query}", discovery.authorization_endpoint), &[bind])
}

async fn refuse(web: &Web, ctx: &Ctx, reason: &str) -> Response<Body> {
    tracing::info!(reason, "oidc sign-in refused");
    let attempt = Attempt { source: &ctx.source, account: None, known_device: None };
    if let Ok(mut l) = web.0.limits.lock() {
        l.fail(&attempt, ctx.now_ms);
    }
    audit(
        web,
        "oidc",
        "auth.sign_in_failed",
        serde_json::json!({ "source": ctx.source, "reason": format!("oidc: {reason}") }),
    )
    .await;
    status(StatusCode::UNAUTHORIZED, "The sign-in through your identity provider wasn't accepted")
}

/// The code for tokens, then the ID token's subject.
async fn exchange(web: &Web, cfg: &config::Oidc, code: &str, flow: &Flow, now_ms: i64) -> Result<Claims, String> {
    let discovery = discover(&cfg.issuer).await?;
    let secret_name = cfg.client_secret.strip_prefix("secret:").ok_or("the client secret isn't a Vault reference")?;
    let secret = web.0.vault.get(secret_name).map_err(|e| e.to_string())?;
    let enc = |v: &str| form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>();
    let basic = STANDARD.encode(format!("{}:{}", enc(&cfg.client_id), enc(&String::from_utf8_lossy(secret.expose()))));
    let body: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", &cfg.redirect_url)
        .append_pair("code_verifier", &flow.verifier)
        .finish();
    let headers = [
        ("authorization", format!("Basic {basic}")),
        ("content-type", "application/x-www-form-urlencoded".to_string()),
    ];
    let tokens: serde_json::Value =
        serde_json::from_slice(&fetch(Method::POST, &discovery.token_endpoint, &headers, body.into_bytes()).await?)
            .map_err(|e| e.to_string())?;
    let id_token = tokens["id_token"].as_str().ok_or("no ID token")?;
    let jwks: Jwks = get_json(&discovery.jwks_uri).await?;
    verify_id_token(id_token, &jwks.keys, &cfg.issuer, &cfg.client_id, &flow.nonce, now_ms / 1000)
}

/// `GET /sign-in/oidc/callback`: the provider sends the browser back with a code.
pub(crate) async fn callback(web: &Web, ctx: &Ctx) -> Response<Body> {
    let source_only = Attempt { source: &ctx.source, account: None, known_device: None };
    if !web.0.limits.lock().map(|mut l| l.try_attempt(&source_only, ctx.now_ms)).unwrap_or(false) {
        return status(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many failed sign-ins from here; wait a minute and try again",
        );
    }
    let Some(cfg) = settings(web) else { return status(StatusCode::NOT_FOUND, "OIDC sign-in isn't set up") };
    let state = ctx.query.get("state").cloned().unwrap_or_default();
    // Used once, whatever happens next.
    let flow = web.0.oidc_flows.lock().ok().and_then(|mut f| f.remove(&state));
    let Some(flow) = flow.filter(|f| ctx.now_ms - f.created_ms < FLOW_MS) else {
        return refuse(web, ctx, "unknown or expired state").await;
    };
    let browser = ctx.cookies.get(FLOW_COOKIE).map(|c| devices::hash_hex(c));
    if browser.as_deref() != Some(flow.browser.as_str()) {
        return refuse(web, ctx, "another browser").await;
    }
    if let Some(err) = ctx.query.get("error") {
        return refuse(web, ctx, &format!("the provider said {err}")).await;
    }
    let Some(code) = ctx.query.get("code").filter(|c| !c.is_empty()) else { return refuse(web, ctx, "no code").await };
    let claims = match exchange(web, &cfg, code, &flow, ctx.now_ms).await {
        Ok(c) => c,
        Err(e) => return refuse(web, ctx, &e).await,
    };
    let found: Option<(String, String)> = web
        .0
        .db
        .readers()
        .with(|c| {
            c.query_row(
                "SELECT id, name FROM users WHERE auth = 'oidc' AND oidc_subject = ?1 AND disabled_at IS NULL",
                [&claims.sub],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
        })
        .ok()
        .flatten();
    let Some((user_id, name)) = found else { return refuse(web, ctx, "no account for this subject").await };
    let Ok(token) = session::create(&web.0.db, &user_id, ctx.now_ms).await else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The session couldn't be started");
    };
    audit(web, &name, "auth.sign_in", serde_json::json!({ "source": ctx.source, "method": "oidc" })).await;
    // A page, not a redirect: the browser arrived from the provider's site, and the session cookie (Strict) goes along
    // only on the next navigation from this one.
    let mut resp = html_text(StatusCode::OK, "Signed in", "Signed in through your identity provider.", Some("/"));
    for c in [
        session::cookie(session::COOKIE, &token, session::ABSOLUTE_MS / 1000),
        format!("{FLOW_COOKIE}=; Path=/sign-in/oidc; Max-Age=0; Secure; HttpOnly; SameSite=Lax"),
    ] {
        if let Ok(v) = HeaderValue::from_str(&c) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp
}

/// What the settings hold in place of the client secret.
pub fn secret_reference() -> String {
    format!("secret:{SECRET_NAME}")
}

#[cfg(test)]
#[path = "oidc_tests.rs"]
mod tests;
