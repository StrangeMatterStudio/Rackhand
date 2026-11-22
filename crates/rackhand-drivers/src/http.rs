//! HTTP(S) checks: one GET, the status (200 unless `status` says otherwise) and, with `body_contains`, the body.
//! Redirects aren't followed: a redirect is the answer. HTTPS trusts the public roots only, as the notifiers do (D113),
//! unless `fingerprint` pins the one certificate to accept (its SHA-256, as an appliance's is pinned), for a self-signed
//! internal service (owner review, 2026-11-21).

use std::sync::Arc;
use std::time::Instant;

use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;

use crate::driver::{Driver, DriverError, DriverKind, DriverReading, DriverTarget, millis, resolve, settings, text};

const MAX_BODY: usize = 1 << 20;

pub struct Http {
    tls: tokio_rustls::TlsConnector,
}

impl std::fmt::Debug for Http {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http").finish_non_exhaustive()
    }
}

impl Default for Http {
    fn default() -> Http {
        Http::new()
    }
}

impl Http {
    pub fn new() -> Http {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Http { tls: tokio_rustls::TlsConnector::from(Arc::new(config)) }
    }
}

async fn get<I>(io: I, host: &str, path: &str) -> Result<(u16, Vec<u8>), String>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(io)).await.map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let req = hyper::Request::get(path)
        .header(hyper::header::HOST, host)
        .header(hyper::header::USER_AGENT, concat!("rackhand-check/", env!("CARGO_PKG_VERSION")))
        .body(Empty::new())
        .map_err(|e| e.to_string())?;
    let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let body = Limited::new(resp.into_body(), MAX_BODY).collect().await.map_err(|e| e.to_string())?.to_bytes();
    Ok((status, body.to_vec()))
}

#[async_trait::async_trait]
impl Driver for Http {
    fn kind(&self) -> DriverKind {
        DriverKind::Http
    }

    fn known_settings(&self) -> &'static [&'static str] {
        &["status", "body_contains", "fingerprint"]
    }

    async fn poll(&self, target: &DriverTarget) -> Result<DriverReading, DriverError> {
        let s = settings(&target.settings, self.known_settings())?;
        let expect = match s.and_then(|m| m.get("status")) {
            None => 200,
            Some(v) => v
                .as_u64()
                .filter(|c| (100..600).contains(c))
                .ok_or_else(|| DriverError::Invalid("`status` is an HTTP status code".into()))?
                as u16,
        };
        let contains = text(s, "body_contains")?;
        let pin = text(s, "fingerprint")?;
        let url = url::Url::parse(&target.target).map_err(|e| DriverError::Invalid(format!("the URL: {e}")))?;
        let https = match url.scheme() {
            "http" => false,
            "https" => true,
            other => return Err(DriverError::Invalid(format!("an http:// or https:// URL, not {other}://"))),
        };
        let pinned = match (pin, https) {
            (None, _) => None,
            (Some(_), false) => return Err(DriverError::Invalid("`fingerprint` is for https:// URLs".into())),
            (Some(fp), true) => Some(crate::pinned::connector(Some(fp))?),
        };
        let tls = pinned.as_ref().unwrap_or(&self.tls);
        let host = url.host_str().ok_or_else(|| DriverError::Invalid("the URL has no host".into()))?.to_string();
        let port = url.port_or_known_default().unwrap_or(if https { 443 } else { 80 });
        let path = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_string(),
        };
        let bare = host.trim_start_matches('[').trim_end_matches(']').to_string();
        let started = Instant::now();
        let attempt = async {
            let addr = resolve(&format!("{host}:{port}")).await?;
            let tcp = tokio::net::TcpStream::connect(addr).await.map_err(|e| format!("{addr}: {e}"))?;
            if https {
                let name = rustls::pki_types::ServerName::try_from(bare.clone()).map_err(|e| e.to_string())?;
                let tls = tls.connect(name, tcp).await.map_err(|e| format!("TLS: {e}"))?;
                get(tls, &host, &path).await
            } else {
                get(tcp, &host, &path).await
            }
        };
        let (status, body) = match tokio::time::timeout(target.timeout, attempt).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Ok(DriverReading::down(e, vec![])),
            Err(_) => return Ok(DriverReading::down(format!("no answer within {:?}", target.timeout), vec![])),
        };
        let reading = DriverReading::up(
            millis(started),
            format!("status {status}"),
            vec![("check.status_code".into(), status as f64)],
        );
        if status != expect {
            return Ok(reading.failed(format!("status {status}, expected {expect}")));
        }
        if let Some(needle) = contains {
            if !String::from_utf8_lossy(&body).contains(needle) {
                return Ok(reading.failed(format!("status {status}, but the body doesn't contain {needle:?}")));
            }
        }
        Ok(reading)
    }
}
