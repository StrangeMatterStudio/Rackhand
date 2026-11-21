//! The Proxmox VE API client: HTTPS to the node with the certificate pinned by its SHA-256 fingerprint, accepted when
//! the host was added (7.3.12, like an SSH host key), and an API token (`PVEAPIToken=<user>@<realm>!<id>=<secret>`).
//! A certificate that isn't the pinned one fails the handshake, before any request is sent.

use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::Value;

use crate::driver::{DriverError, DriverTarget, settings, text};

const MAX_BODY: usize = 8 << 20;

/// `AA:BB:...` (or without the colons, any case) as 32 bytes.
fn parse_fingerprint(f: &str) -> Option<[u8; 32]> {
    let hex: String = f.chars().filter(|c| *c != ':').collect();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn show(fp: &[u8]) -> String {
    fp.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// Accepts exactly the pinned certificate, and checks the handshake's signatures with it.
#[derive(Debug)]
struct Pinned {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let seen = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        if seen.as_ref() == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "the certificate's fingerprint {} isn't the pinned {}",
                show(seen.as_ref()),
                show(&self.fingerprint)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// One segment of a path, escaped (a task's UPID has `:` in it).
pub(crate) fn segment(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub(crate) struct Client {
    host: String,
    port: u16,
    token: String,
    timeout: std::time::Duration,
    tls: tokio_rustls::TlsConnector,
    /// The `node` setting, when the host is one node of a cluster the token sees more of.
    pub node: Option<String>,
}

impl Client {
    pub const SETTINGS: &'static [&'static str] = &["token", "fingerprint", "node"];

    pub fn new(target: &DriverTarget) -> Result<Client, DriverError> {
        let s = settings(&target.settings, Client::SETTINGS)?;
        let token = text(s, "token")?.ok_or_else(|| DriverError::Invalid("the API token (`token`)".into()))?;
        if !token.contains('!') || !token.contains('=') {
            return Err(DriverError::Invalid("the token is <user>@<realm>!<id>=<secret>".into()));
        }
        let pin = text(s, "fingerprint")?
            .ok_or_else(|| DriverError::Invalid("the certificate's fingerprint (`fingerprint`) to pin".into()))?;
        let fingerprint =
            parse_fingerprint(pin).ok_or_else(|| DriverError::Invalid("the fingerprint is a SHA-256 in hex".into()))?;
        let raw =
            if target.target.contains("://") { target.target.clone() } else { format!("https://{}", target.target) };
        let url = url::Url::parse(&raw).map_err(|e| DriverError::Invalid(format!("the address: {e}")))?;
        if url.scheme() != "https" {
            return Err(DriverError::Invalid("the Proxmox API is https".into()));
        }
        let host = url.host_str().ok_or_else(|| DriverError::Invalid("the address has no host".into()))?.to_string();
        let port = url.port().unwrap_or(8006);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| DriverError::Failed(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned { fingerprint, provider }))
            .with_no_client_auth();
        Ok(Client {
            host,
            port,
            token: token.to_string(),
            timeout: target.timeout,
            tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
            node: text(s, "node")?.map(str::to_string),
        })
    }

    /// One request; returns the answer's `data`. `form` is the request's form body (or nothing).
    pub async fn call(&self, method: &str, path: &str, form: &[(String, String)]) -> Result<Value, DriverError> {
        let attempt = async {
            let addr = crate::driver::resolve(&format!("{}:{}", self.host, self.port)).await?;
            let tcp = tokio::net::TcpStream::connect(addr).await.map_err(|e| format!("{addr}: {e}"))?;
            let bare = self.host.trim_start_matches('[').trim_end_matches(']').to_string();
            let name = ServerName::try_from(bare).map_err(|e| e.to_string())?;
            let tls = self.tls.connect(name, tcp).await.map_err(|e| format!("TLS: {e}"))?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(tls))
                .await
                .map_err(|e| e.to_string())?;
            tokio::spawn(conn);
            let body: String = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(form).finish();
            let mut req = hyper::Request::builder()
                .method(method)
                .uri(format!("/api2/json{path}"))
                .header(hyper::header::HOST, &self.host)
                .header(hyper::header::AUTHORIZATION, format!("PVEAPIToken={}", self.token));
            if !body.is_empty() {
                req = req.header(hyper::header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            }
            let req = req.body(Full::new(Bytes::from(body))).map_err(|e| e.to_string())?;
            let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let bytes = Limited::new(resp.into_body(), MAX_BODY).collect().await.map_err(|e| e.to_string())?.to_bytes();
            Ok::<_, String>((status, bytes))
        };
        let (status, bytes) = match tokio::time::timeout(self.timeout, attempt).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(DriverError::Failed(e)),
            Err(_) => return Err(DriverError::Failed(format!("{method} {path}: no answer within {:?}", self.timeout))),
        };
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if !(200..300).contains(&status) {
            let why = json["message"].as_str().map(str::trim).unwrap_or("").to_string();
            return Err(DriverError::Failed(format!("{method} {path}: {status} {why}").trim().to_string()));
        }
        Ok(json["data"].clone())
    }
}
