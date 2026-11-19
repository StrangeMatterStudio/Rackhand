//! ALPN routing with registry checks (7.3): the accepting side looks up the caller's endpoint id in its registry for
//! that ALPN; unknown ids are closed with `0x10`, revoked ids with `0x13`. `rackhand/join/1` accepts any id.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use iroh::Endpoint;
use iroh::endpoint::Connection;
use rackhand_proto::alpn;
use rackhand_proto::close::CloseCode;

use crate::close;
use crate::registry::{Admission, Registry};

pub type Handler = Arc<dyn Fn(Connection) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Wraps an async function as a [`Handler`].
pub fn handler<F, Fut>(f: F) -> Handler
where
    F: Fn(Connection) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    Arc::new(move |conn| Box::pin(f(conn)))
}

pub struct Router {
    endpoint: Endpoint,
    registry: Arc<dyn Registry>,
    handlers: HashMap<Vec<u8>, Handler>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router").field("alpns", &self.handlers.keys().collect::<Vec<_>>()).finish()
    }
}

impl Router {
    pub fn new(endpoint: Endpoint, registry: Arc<dyn Registry>) -> Router {
        Router { endpoint, registry, handlers: HashMap::new() }
    }

    pub fn route(mut self, alpn: &[u8], handler: Handler) -> Router {
        self.handlers.insert(alpn.to_vec(), handler);
        self
    }

    /// Serves until the endpoint closes. The endpoint's ALPN list must be the routed ALPNs, so a client offering any
    /// other ALPN fails the handshake.
    pub async fn serve(self) {
        let this = Arc::new(self);
        while let Some(incoming) = this.endpoint.accept().await {
            let this = this.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let id = conn.remote_id();
                let alpn = conn.alpn().to_vec();
                let Some(handler) = this.handlers.get(&alpn).cloned() else {
                    close(&conn, CloseCode::UnsupportedVersion);
                    return;
                };
                if alpn != alpn::JOIN {
                    match this.registry.admission(&alpn, &id) {
                        Admission::Allowed => {}
                        Admission::Unknown => {
                            tracing::info!(peer = %id.fmt_short(), alpn = %String::from_utf8_lossy(&alpn), "unknown peer");
                            close(&conn, CloseCode::UnknownPeer);
                            return;
                        }
                        Admission::Revoked => {
                            close(&conn, CloseCode::Revoked);
                            return;
                        }
                    }
                }
                handler(conn).await;
            });
        }
    }
}
