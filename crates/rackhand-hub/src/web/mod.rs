//! Dashboard (7.7): server-rendered pages over HTTPS. Every request goes through one gate that applies, in order, the
//! first-run redirect, the session, the route's permission (7.7.2) and, for state-changing routes, the CSRF token.

pub mod auth;
pub mod csp;
pub mod csrf;
pub(crate) mod pages;
pub mod perms;
pub mod routes;
pub mod session;
pub mod tls;
pub mod totp;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Method, Request, Response, StatusCode, header};
use axum::routing::{MethodFilter, on};
use rackhand_store::Db;
use rackhand_store::ids::now_ms;

use crate::audit::Audit;
use crate::vault::Vault;
use csrf::Binding;
use perms::allowed;
use routes::{Access, ROUTES, RouteSpec};
use session::SessionUser;

/// Largest form body accepted.
const MAX_FORM: usize = 1 << 20;

pub struct WebConfig {
    /// SHA-256 of the one-time setup code the installer printed (7.7.4).
    pub setup_code_hash: [u8; 32],
    /// The key CSRF tokens and signed form values are made with.
    pub csrf_key: [u8; 32],
    /// `trusted_proxies` from `hub.toml`: networks whose `X-Forwarded-For` is believed (7.7.2).
    pub trusted_proxies: Vec<(IpAddr, u8)>,
}

/// The time source, injectable for tests.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

impl std::fmt::Debug for WebConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WebConfig(redacted)")
    }
}

struct Inner {
    db: Arc<Db>,
    vault: Arc<Vault>,
    audit: Audit,
    recovery_code: String,
    config: WebConfig,
    admin_exists: AtomicBool,
    clock: Clock,
    limits: Mutex<auth::limits::Limits>,
    pending: Mutex<HashMap<String, auth::Pending>>,
    host_keys: Option<Arc<crate::ssh::hostkeys::HostKeys>>,
    registry: Option<Arc<crate::registry::Registry>>,
    passkeys: Option<auth::passkey::Passkeys>,
}

#[derive(Clone)]
pub struct Web(Arc<Inner>);

impl std::fmt::Debug for Web {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Web")
    }
}

/// What a page handler gets from the gate.
pub(crate) struct Ctx {
    pub now_ms: i64,
    pub user: Option<SessionUser>,
    pub binding: Binding,
    pub csrf: String,
    pub form: HashMap<String, String>,
    pub path: String,
    /// The client's source (7.7.2) as the limits count it.
    pub source: String,
    pub cookies: HashMap<String, String>,
}

impl Web {
    pub fn new(db: Arc<Db>, vault: Arc<Vault>, audit: Audit, recovery_code: String, config: WebConfig) -> Web {
        Web(Arc::new(Inner {
            db,
            vault,
            audit,
            recovery_code,
            config,
            admin_exists: AtomicBool::new(false),
            clock: Arc::new(now_ms),
            limits: Mutex::new(auth::limits::Limits::default()),
            pending: Mutex::new(HashMap::new()),
            host_keys: None,
            registry: None,
            passkeys: None,
        }))
    }

    /// The SSH system's host keys, for accepting a changed one; before the router is built.
    pub fn with_host_keys(mut self, keys: Arc<crate::ssh::hostkeys::HostKeys>) -> Web {
        if let Some(inner) = Arc::get_mut(&mut self.0) {
            inner.host_keys = Some(keys);
        }
        self
    }

    /// The Registry, for listing and revoking devices; before the router is built.
    pub fn with_registry(mut self, registry: Arc<crate::registry::Registry>) -> Web {
        if let Some(inner) = Arc::get_mut(&mut self.0) {
            inner.registry = Some(registry);
        }
        self
    }

    #[cfg(test)]
    pub(crate) fn db(&self) -> &Arc<Db> {
        &self.0.db
    }

    /// Replaces the clock; for tests, before the router is built.
    pub fn with_clock(mut self, clock: Clock) -> Web {
        if let Some(inner) = Arc::get_mut(&mut self.0) {
            inner.clock = clock;
        }
        self
    }

    pub fn router(&self) -> Router {
        let mut router = Router::new();
        for spec in ROUTES {
            let web = self.clone();
            let filter = if spec.method == Method::POST { MethodFilter::POST } else { MethodFilter::GET };
            router = router
                .route(spec.path, on(filter, move |req: Request<Body>| async move { web.handle(spec, req).await }));
        }
        router.fallback(|| async { pages::status(StatusCode::NOT_FOUND, "Not found") }).layer(
            axum::middleware::map_response(|mut resp: Response<Body>| async move {
                csp::apply(resp.headers_mut());
                resp
            }),
        )
    }

    fn admin_exists(&self) -> bool {
        if self.0.admin_exists.load(Ordering::Relaxed) {
            return true;
        }
        let exists = self
            .0
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT EXISTS (SELECT 1 FROM users WHERE role = 'admin' AND disabled_at IS NULL)",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap_or(false);
        if exists {
            self.0.admin_exists.store(true, Ordering::Relaxed);
        }
        exists
    }

    async fn handle(&self, spec: &'static RouteSpec, req: Request<Body>) -> Response<Body> {
        let now = (self.0.clock)();
        let admin = self.admin_exists();
        match spec.access {
            Access::FirstRun if admin => return pages::redirect("/sign-in"),
            Access::Perm(_) if !admin => return pages::redirect("/first-run"),
            _ => {}
        }
        let cookies = parse_cookies(req.headers().get(header::COOKIE));
        let peer =
            req.extensions().get::<auth::client_addr::PeerAddr>().map_or(SocketAddr::from(([0, 0, 0, 0], 0)), |p| p.0);
        let source = auth::client_addr::source_key(auth::client_addr::client_ip(
            peer,
            req.headers(),
            &self.0.config.trusted_proxies,
        ));
        let user = cookies.get(session::COOKIE).and_then(|t| session::lookup(&self.0.db, t, now).ok().flatten());
        if let Some(u) = &user {
            // The idle limit counts from the last use; written at most once a minute.
            if now - u.last_seen_at > 60_000
                && let Err(e) = session::touch_hash(&self.0.db, &u.id_hash, now).await
            {
                tracing::warn!(error = %e, "session touch");
            }
        }
        let mut set_cookies = Vec::new();
        let binding = match &user {
            Some(u) => Binding::Session(u.id_hash),
            None => {
                let anon = match cookies.get(session::ANON_COOKIE) {
                    Some(a) => a.clone(),
                    None => {
                        let Ok(a) = session::random_token() else {
                            return pages::status(StatusCode::INTERNAL_SERVER_ERROR, "No randomness");
                        };
                        set_cookies.push(session::cookie(session::ANON_COOKIE, &a, 3600));
                        a
                    }
                };
                Binding::Anonymous(anon)
            }
        };
        if let Access::Perm(p) = spec.access {
            match &user {
                None => return pages::redirect("/sign-in"),
                Some(u) if !allowed(u.role, p) => {
                    return pages::status(StatusCode::FORBIDDEN, "Your role can't do this");
                }
                Some(_) => {}
            }
        }
        let path = req.uri().path().to_string();
        let mut form = HashMap::new();
        if spec.method == Method::POST {
            let Ok(bytes) = axum::body::to_bytes(req.into_body(), MAX_FORM).await else {
                return pages::status(StatusCode::PAYLOAD_TOO_LARGE, "Form too large");
            };
            form = form_urlencoded::parse(&bytes).into_owned().collect();
            let token = form.get("csrf").map(String::as_str).unwrap_or("");
            if !csrf::verify(&self.0.config.csrf_key, &binding, token) {
                return pages::status(StatusCode::FORBIDDEN, "The form expired; reload the page and try again");
            }
        }
        let csrf = csrf::token(&self.0.config.csrf_key, &binding);
        let ctx = Ctx { now_ms: now, user, binding, csrf, form, path, source, cookies };
        let mut resp = pages::render(self, spec.page, &ctx).await;
        for c in set_cookies {
            if let Ok(v) = HeaderValue::from_str(&c) {
                resp.headers_mut().append(header::SET_COOKIE, v);
            }
        }
        resp
    }
}

fn parse_cookies(header: Option<&HeaderValue>) -> HashMap<String, String> {
    header
        .and_then(|h| h.to_str().ok())
        .map(|s| {
            s.split(';')
                .filter_map(|kv| kv.trim().split_once('='))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
