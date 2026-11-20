//! One HTTP/1.1 request over rustls (ring, webpki roots), for hub systems that call out: notifiers now, threat lists
//! and the dead-man URL later. Plain HTTP only to loopback (local tests and relays).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, header};
use hyper_util::rt::TokioIo;
use webauthn_rs::prelude::Url;

const MAX_RESPONSE: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

fn loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

pub fn tls(extra_roots: &[rustls::pki_types::CertificateDer<'static>]) -> Result<tokio_rustls::TlsConnector, String> {
    let mut roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    for c in extra_roots {
        roots.add(c.clone()).map_err(|e| e.to_string())?;
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

async fn send<I>(io: I, req: Request<Body>) -> Result<Response, String>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(io)).await.map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
        .collect();
    let body = axum::body::to_bytes(Body::new(resp.into_body()), MAX_RESPONSE).await.map_err(|e| e.to_string())?;
    Ok(Response { status, headers, body: body.to_vec() })
}

/// Sends one request and returns whatever status came back; errors are only for requests that got no answer.
pub async fn request(
    method: Method,
    url: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
    timeout: Duration,
) -> Result<Response, String> {
    let u = Url::parse(url).map_err(|e| e.to_string())?;
    let host_str = u.host_str().ok_or("no host")?.to_string();
    let host = host_str.trim_start_matches('[').trim_end_matches(']').to_string();
    match u.scheme() {
        "https" => {}
        "http" if loopback(&host_str) => {}
        _ => return Err(format!("not an allowed URL: {url}")),
    }
    let port = u.port_or_known_default().ok_or("no port")?;
    let target = match u.query() {
        Some(q) => format!("{}?{q}", u.path()),
        None => u.path().to_string(),
    };
    let authority = match u.port() {
        Some(p) => format!("{host_str}:{p}"),
        None => host_str.clone(),
    };
    let mut req = Request::builder()
        .method(method)
        .uri(target)
        .header(header::HOST, authority)
        .header(header::USER_AGENT, "rackhand");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req.body(Body::from(body)).map_err(|e| e.to_string())?;
    let work = async {
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await.map_err(|e| e.to_string())?;
        if u.scheme() == "https" {
            let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
            let stream = tls(&[])?.connect(name, tcp).await.map_err(|e| e.to_string())?;
            send(stream, req).await
        } else {
            send(tcp, req).await
        }
    };
    tokio::time::timeout(timeout, work).await.map_err(|_| "timed out".to_string())?
}
