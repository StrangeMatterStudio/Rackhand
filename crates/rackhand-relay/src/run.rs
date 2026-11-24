//! `rackhand relay run` (7.3.10): the iroh relay server with Rackhand's admission and one rate for every connection (S2, D110).
//! HTTPS on 443 with a certificate from Let's Encrypt or provided files, and iroh's QUIC address discovery port.

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use iroh::EndpointId;
use iroh_relay::server::{
    AcmeConfig, CertConfig, ClientRateLimit, Limits, QuicConfig, RelayConfig, RelayService, Server, ServerConfig,
    TlsConfig,
};
use rustls::pki_types::pem::PemObject;

use crate::admission::{Admission, Evictor, Mode};

/// 1 Mbit/s: the default rate of a `public` relay, in bits per second.
pub const PUBLIC_RATE_BITS: u32 = 1_000_000;

#[derive(Debug, Clone)]
pub enum Certificate {
    /// Let's Encrypt for these domains, with the certificates cached in the data directory.
    Acme { domains: Vec<String>, contact: Vec<String>, production: bool },
    /// A certificate chain and key in PEM files.
    Files { cert: PathBuf, key: PathBuf },
    /// No TLS: plain HTTP, for a relay behind something that terminates it, or on a private network.
    None,
}

#[derive(Debug, Clone)]
pub struct RelayRun {
    pub data_dir: PathBuf,
    pub mode: Mode,
    pub http: SocketAddr,
    pub https: SocketAddr,
    pub quic: SocketAddr,
    pub certificate: Certificate,
    /// Bits per second for every connection; none in `private` mode unless set, 1 Mbit/s in `public` mode.
    pub rate_bits: Option<u32>,
    /// The endpoints served at once ([`crate::admission::CAPACITY`]; fewer in tests).
    pub capacity: usize,
}

/// The relay's signing key: made the first time, and what `relay key create` signs with.
pub fn signing_key(data_dir: &Path) -> Result<SigningKey, String> {
    let key = rackhand_net::key::load_or_create(&data_dir.join("relay.key"))
        .map_err(|e| format!("{}: {e}", data_dir.join("relay.key").display()))?;
    Ok(SigningKey::from_bytes(&key.to_bytes()))
}

/// The service's way to end a connection.
#[derive(Debug)]
struct Disconnect(RelayService);

impl Evictor for Disconnect {
    fn evict(&self, endpoint: EndpointId) {
        self.0.clients().disconnect(endpoint, None);
    }
}

fn rate(config: &RelayRun) -> Option<ClientRateLimit> {
    let bits = config.rate_bits.or((config.mode == Mode::Public).then_some(PUBLIC_RATE_BITS))?;
    NonZeroU32::new(bits / 8).map(ClientRateLimit::new)
}

fn manual(cert: &Path, key: &Path) -> Result<rustls::ServerConfig, String> {
    let chain: Vec<_> = rustls::pki_types::CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("{}: {e}", cert.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    let key = rustls::pki_types::PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| e.to_string())
}

/// Starts the relay, and the admission it uses.
pub async fn run(config: &RelayRun) -> Result<(Server, Arc<Admission>), String> {
    std::fs::create_dir_all(&config.data_dir).map_err(|e| format!("{}: {e}", config.data_dir.display()))?;
    let signing = signing_key(&config.data_dir)?;
    let admission = Arc::new(
        Admission::new(config.mode, signing.verifying_key())
            .with_capacity(config.capacity)
            .with_bindings(config.data_dir.join("bindings.json")),
    );
    let mut relay = RelayConfig::new(config.http);
    let mut limits = Limits::default();
    limits.client_rx = rate(config);
    relay.limits = limits;
    relay.access = admission.clone();
    let mut quic = None;
    match &config.certificate {
        Certificate::None => {}
        Certificate::Files { cert, key } => {
            let tls = manual(cert, key)?;
            let mut q = QuicConfig::new(config.quic);
            q.server_config = Some(tls.clone());
            quic = Some(q);
            relay.tls = Some(TlsConfig::new(config.https, CertConfig::Manual { server_config: tls }));
        }
        Certificate::Acme { domains, contact, production } => {
            let acme = AcmeConfig::letsencrypt(*production)
                .domains(domains.clone())
                .contact(contact.clone())
                .cache_path(config.data_dir.join("acme"));
            let builder =
                rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_safe_default_protocol_versions()
                    .map_err(|e| e.to_string())?
                    .with_no_client_auth();
            relay.tls = Some(TlsConfig::new(
                config.https,
                CertConfig::LetsEncrypt { acme_config: acme, server_config_builder: builder },
            ));
            quic = Some(QuicConfig::new(config.quic));
        }
    }
    let mut server_config = ServerConfig::default();
    server_config.relay = Some(relay);
    server_config.quic = quic;
    let server = Server::spawn(server_config).await.map_err(|e| e.to_string())?;
    if let Some(service) = server.relay_service() {
        admission.set_evictor(Arc::new(Disconnect(service.clone())));
    }
    Ok((server, admission))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(mode: Mode, rate_bits: Option<u32>) -> RelayRun {
        let any = SocketAddr::from(([127, 0, 0, 1], 0));
        RelayRun {
            data_dir: PathBuf::new(),
            mode,
            http: any,
            https: any,
            quic: any,
            certificate: Certificate::None,
            rate_bits,
            capacity: 1,
        }
    }

    /// The rate in bytes per second, as the relay's limiter holds it.
    fn bytes_per_second(config: &RelayRun) -> Option<String> {
        rate(config).map(|r| format!("{r:?}"))
    }

    #[test]
    fn one_rate_for_every_connection_set_by_the_operator() {
        // public: 1 Mbit/s unless the operator says otherwise; private: no limit unless the operator sets one
        let public = bytes_per_second(&config(Mode::Public, None)).expect("public mode has a default rate");
        assert!(public.contains("125000"), "1 Mbit/s is 125 000 bytes a second: {public}");
        assert_eq!(bytes_per_second(&config(Mode::Private, None)), None);
        let set = bytes_per_second(&config(Mode::Private, Some(8_000_000))).expect("the operator's rate");
        assert!(set.contains("1000000"), "{set}");
        let faster = bytes_per_second(&config(Mode::Public, Some(16_000_000))).expect("the operator's rate");
        assert!(faster.contains("2000000"), "{faster}");
    }
}
