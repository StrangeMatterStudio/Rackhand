//! In-process endpoint pairs with a local relay, for contract suites (feature `testing`).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, RelayUrl, SecretKey, TransportAddr};
use iroh_relay::server::{RelayConfig as ServerRelayConfig, Server, ServerConfig};

use crate::endpoint::{EndpointConfig, bind};
use crate::registry::MemoryRegistry;
use crate::relays::RelayConfig;
use crate::router::{Router, handler};

fn random_key() -> SecretKey {
    let mut bytes = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut f, &mut bytes);
    }
    SecretKey::from_bytes(&bytes)
}

/// A local relay on loopback (plain HTTP), as the contract tests' rendezvous.
pub async fn local_relay() -> (Server, RelayUrl) {
    let mut config = ServerConfig::default();
    config.relay = Some(ServerRelayConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))));
    let server = Server::spawn(config).await.expect("local relay");
    let url: RelayUrl = format!("http://{}", server.http_addr().expect("http addr")).parse().expect("relay url");
    (server, url)
}

pub async fn endpoint(relay: &RelayUrl, alpns: &[&[u8]]) -> Endpoint {
    let config = EndpointConfig {
        relays: RelayConfig { relays: vec![relay.to_string()], ..RelayConfig::default() },
        alpns: alpns.iter().map(|a| a.to_vec()).collect(),
        bind: None,
    };
    bind(random_key(), &config).await.expect("endpoint")
}

/// A server endpoint running a [`Router`] whose handlers echo one bidirectional stream, and a client endpoint.
pub struct Pair {
    pub server: Endpoint,
    pub client: Endpoint,
    pub registry: Arc<MemoryRegistry>,
    pub relay_url: RelayUrl,
    _relay: Server,
}

impl std::fmt::Debug for Pair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pair").field("server", &self.server.id()).field("client", &self.client.id()).finish()
    }
}

async fn echo(conn: Connection) {
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        if let Ok(data) = recv.read_to_end(1 << 20).await {
            let _ = send.write_all(&data).await;
            let _ = send.finish();
        }
    }
}

impl Pair {
    pub async fn new(alpns: &[&[u8]]) -> Pair {
        let (relay, relay_url) = local_relay().await;
        let server = endpoint(&relay_url, alpns).await;
        let client = endpoint(&relay_url, &[]).await;
        let registry = Arc::new(MemoryRegistry::default());
        let mut router = Router::new(server.clone(), registry.clone());
        for alpn in alpns {
            router = router.route(alpn, handler(echo));
        }
        tokio::spawn(router.serve());
        Pair { server, client, registry, relay_url, _relay: relay }
    }

    /// The server's address: its relay and its direct addresses.
    pub fn server_addr(&self) -> EndpointAddr {
        let mut addr = self.server.addr();
        addr.addrs.insert(TransportAddr::Relay(self.relay_url.clone()));
        addr
    }
}
