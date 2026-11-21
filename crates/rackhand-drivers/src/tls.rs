//! TLS checks: the days until the server's certificate expires (`check.cert_days`). The certificate is read whoever
//! signed it, since its expiry is what's being watched (a self-signed one expires too); the check fails once it has
//! expired, and the warning at 14 days and the critical at 3 are the hub's rule (7.6.2). Target `host:port`, with
//! `server_name` when the name to ask for isn't the host.

use std::sync::Arc;
use std::time::Instant;

use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use crate::driver::{Driver, DriverError, DriverKind, DriverReading, DriverTarget, millis, resolve, settings, text};

const DAY_S: i64 = 86_400;

/// Accepts any certificate (only its dates are read) but still checks the handshake's signatures with it.
#[derive(Debug)]
struct ReadOnly(Arc<CryptoProvider>);

impl ServerCertVerifier for ReadOnly {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub struct Tls {
    connector: tokio_rustls::TlsConnector,
}

impl std::fmt::Debug for Tls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls").finish_non_exhaustive()
    }
}

impl Default for Tls {
    fn default() -> Tls {
        Tls::new()
    }
}

impl Tls {
    pub fn new() -> Tls {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ReadOnly(provider)))
            .with_no_client_auth();
        Tls { connector: tokio_rustls::TlsConnector::from(Arc::new(config)) }
    }
}

/// The leaf certificate's `notAfter`, in Unix seconds.
fn not_after(der: &[u8]) -> Result<i64, String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| format!("the certificate: {e}"))?;
    Ok(cert.validity().not_after.timestamp())
}

#[async_trait::async_trait]
impl Driver for Tls {
    fn kind(&self) -> DriverKind {
        DriverKind::Tls
    }

    async fn poll(&self, target: &DriverTarget) -> Result<DriverReading, DriverError> {
        let s = settings(&target.settings, &["server_name"])?;
        let host = target.target.rsplit_once(':').map(|(h, _)| h).unwrap_or(&target.target);
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let name = text(s, "server_name")?.unwrap_or(host).to_string();
        let server_name = ServerName::try_from(name.clone())
            .map_err(|_| DriverError::Invalid(format!("`{name}` isn't a server name")))?;
        let started = Instant::now();
        let attempt = async {
            let addr = resolve(&target.target).await?;
            let tcp = tokio::net::TcpStream::connect(addr).await.map_err(|e| format!("{addr}: {e}"))?;
            let tls = self.connector.connect(server_name, tcp).await.map_err(|e| format!("TLS with {addr}: {e}"))?;
            let (_, conn) = tls.get_ref();
            let leaf = conn.peer_certificates().and_then(|c| c.first()).ok_or("no certificate")?;
            not_after(leaf.as_ref())
        };
        let expires = match tokio::time::timeout(target.timeout, attempt).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => return Ok(DriverReading::down(e, vec![])),
            Err(_) => return Ok(DriverReading::down(format!("no answer within {:?}", target.timeout), vec![])),
        };
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        let days = (expires - now).div_euclid(DAY_S);
        let metrics = vec![("check.cert_days".into(), days as f64)];
        let reading = DriverReading::up(millis(started), format!("the certificate expires in {days} days"), metrics);
        if expires <= now {
            return Ok(reading.failed(format!("the certificate expired {} days ago", -days)));
        }
        Ok(reading)
    }
}
