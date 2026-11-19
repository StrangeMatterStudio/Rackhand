//! HTTPS on 8443 (7.7.1, D49): a self-signed certificate generated at first start and kept in the Vault, served with
//! rustls on the ring provider.

use std::sync::Arc;

use axum::Router;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::vault::{Secret, Vault, VaultError};

const CERT: &str = "web.tls.cert";
const KEY: &str = "web.tls.key";

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("certificate generation: {0}")]
    Generate(#[from] rcgen::Error),
    #[error("TLS configuration: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("PEM: {0}")]
    Pem(String),
    #[error(transparent)]
    Vault(#[from] VaultError),
}

/// A new self-signed certificate for the names (host names and IP addresses), as PEM.
pub fn generate(names: &[String]) -> Result<(String, String), TlsError> {
    let cert = rcgen::generate_simple_self_signed(names.to_vec())?;
    Ok((cert.cert.pem(), cert.signing_key.serialize_pem()))
}

/// The certificate and key from the Vault, generated on first use.
pub async fn load_or_create(vault: &Vault, names: &[String]) -> Result<(String, String), TlsError> {
    if let (Ok(cert), Ok(key)) = (vault.get(CERT), vault.get(KEY)) {
        let text = |s: Secret| String::from_utf8_lossy(s.expose()).into_owned();
        return Ok((text(cert), text(key)));
    }
    let (cert, key) = generate(names)?;
    vault.put(CERT, &Secret::from(cert.as_str())).await?;
    vault.put(KEY, &Secret::from(key.as_str())).await?;
    Ok((cert, key))
}

pub fn server_config(cert_pem: &str, key_pem: &str) -> Result<Arc<ServerConfig>, TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Pem(e.to_string()))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|e| TlsError::Pem(e.to_string()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Serves the dashboard over TLS until the listener fails.
pub async fn serve(listener: TcpListener, app: Router, config: Arc<ServerConfig>) {
    let acceptor = TlsAcceptor::from(config);
    loop {
        let Ok((tcp, peer)) = listener.accept().await else { return };
        let (acceptor, app) = (acceptor.clone(), app.clone());
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(tcp).await else {
                tracing::debug!(%peer, "TLS handshake failed");
                return;
            };
            let service =
                TowerToHyperService::new(app.layer(axum::Extension(crate::web::auth::client_addr::PeerAddr(peer))));
            if let Err(e) =
                hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), service).await
            {
                tracing::debug!(%peer, error = %e, "connection ended");
            }
        });
    }
}

/// A minimal HTTPS GET that trusts only `cert_pem`, for tests of the listener.
#[cfg(test)]
pub async fn test_client_get(
    addr: std::net::SocketAddr,
    host: &str,
    cert_pem: &str,
    path: &str,
) -> Result<String, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(cert_pem.as_bytes()) {
        roots.add(c.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let mut tls = connector.connect(name, tcp).await.map_err(|e| e.to_string())?;
    tls.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out).await;
    Ok(String::from_utf8_lossy(&out).into_owned())
}
