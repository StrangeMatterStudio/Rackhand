//! TLS to an appliance's API with its certificate pinned by SHA-256 fingerprint, accepted when it was added (7.3.12,
//! like an SSH host key): Proxmox, TrueNAS and Redfish. A certificate that isn't the pinned one fails the handshake,
//! before any request is sent; the handshake's signatures are still checked with it.

use std::sync::Arc;

use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use crate::driver::DriverError;

/// `AA:BB:...` (or without the colons, any case) as 32 bytes.
pub fn parse_fingerprint(f: &str) -> Option<[u8; 32]> {
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

/// The fingerprint as `AA:BB:...`.
pub fn show(fp: &[u8]) -> String {
    fp.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

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

/// A connector that accepts only the certificate with `fingerprint` (the `fingerprint` setting, as text).
pub fn connector(fingerprint: Option<&str>) -> Result<tokio_rustls::TlsConnector, DriverError> {
    let pin = fingerprint
        .ok_or_else(|| DriverError::Invalid("the certificate's fingerprint (`fingerprint`) to pin".into()))?;
    let fingerprint =
        parse_fingerprint(pin).ok_or_else(|| DriverError::Invalid("the fingerprint is a SHA-256 in hex".into()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| DriverError::Failed(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned { fingerprint, provider }))
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// A TLS stream to `host:port`, the certificate pinned.
pub async fn connect(
    tls: &tokio_rustls::TlsConnector,
    host: &str,
    port: u16,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, String> {
    let addr = crate::driver::resolve(&format!("{host}:{port}")).await?;
    let tcp = tokio::net::TcpStream::connect(addr).await.map_err(|e| format!("{addr}: {e}"))?;
    let bare = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let name = ServerName::try_from(bare).map_err(|e| e.to_string())?;
    tls.connect(name, tcp).await.map_err(|e| format!("TLS: {e}"))
}

/// Takes whatever certificate is presented and remembers its fingerprint; the handshake's signatures are still checked.
#[derive(Debug)]
struct Presented {
    seen: std::sync::Mutex<Option<[u8; 32]>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Presented {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut fp = [0u8; 32];
        fp.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref()).as_ref());
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Some(fp);
        Ok(ServerCertVerified::assertion())
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

/// The fingerprint of the certificate `host:port` presents, for the admin to accept before it is pinned (7.3.12).
/// Only the handshake happens: no request, and so no credential, is sent.
pub async fn presented(host: &str, port: u16, timeout: std::time::Duration) -> Result<String, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(Presented { seen: std::sync::Mutex::new(None), provider: provider.clone() });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config));
    let mut stream = tokio::time::timeout(timeout, connect(&tls, host, port))
        .await
        .map_err(|_| format!("{host}:{port}: no answer in {} s", timeout.as_secs()))??;
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
    let seen = *verifier.seen.lock().unwrap_or_else(|e| e.into_inner());
    seen.map(|f| show(&f)).ok_or_else(|| "no certificate was presented".to_string())
}

/// A simulator's self-signed certificate and key, with its fingerprint (for the simulators' servers).
#[cfg(any(test, feature = "sim"))]
pub fn test_server() -> (tokio_rustls::TlsAcceptor, String) {
    let key = rcgen::KeyPair::generate().expect("a key");
    let cert = rcgen::CertificateParams::new(vec!["appliance.lab.test".to_string()])
        .expect("params")
        .self_signed(&key)
        .expect("a certificate");
    let der = cert.der().to_vec();
    let fingerprint = show(ring::digest::digest(&ring::digest::SHA256, &der).as_ref());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(der)],
            rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).expect("a key"),
        )
        .expect("the server config");
    (tokio_rustls::TlsAcceptor::from(Arc::new(config)), fingerprint)
}

/// A connector that takes whatever certificate the server presents (the handshake's signatures are still checked), for a
/// download whose content is verified by a signature instead (`crate::fetch`).
pub fn accept_any_certificate() -> tokio_rustls::TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(Presented { seen: std::sync::Mutex::new(None), provider: provider.clone() });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}
