//! Dashboard (7.7): server-rendered pages over HTTPS. Every request goes through one gate that applies, in order, the
//! first-run redirect, the session, the route's permission (7.7.2) and, for state-changing routes, the CSRF token.

pub mod auth;
pub mod csp;
pub mod csrf;
mod forms;
mod icons;
mod metrics;
pub(crate) mod pages;
pub mod perms;
pub mod routes;
pub mod session;
pub mod tls;
pub mod totp;
mod ui;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
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
    /// The key CSRF tokens are made with.
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
    pub(crate) bindings: Option<Arc<crate::registry::guest_binding::GuestBindings>>,
    /// The hub as an install command names it (`rackhand1:...`), from the composition (its endpoint and addresses).
    ticket: Option<Arc<dyn Fn() -> Option<String> + Send + Sync>>,
    /// The release files the hub holds (`install.sh`, ...), for the offline install command.
    release_dir: Option<std::path::PathBuf>,
    registry: Option<Arc<crate::registry::Registry>>,
    /// The API drivers, by name, for the appliance forms' first poll.
    drivers: std::collections::BTreeMap<&'static str, Arc<dyn rackhand_drivers::Driver>>,
    passkeys: Option<auth::passkey::Passkeys>,
    oidc_flows: Mutex<HashMap<String, auth::oidc::Flow>>,
    library: Option<crate::library::items::Library>,
    ingest: Option<crate::ingest::Ingest>,
    /// The threat lists and GeoIP, for the Security page's freshness.
    intel: Option<crate::intel::Intel>,
    /// The assistant, for Resume job and the operators that are connected.
    assist: Option<crate::assist::Assist>,
    notify: Option<crate::notify::Notify>,
    bus: Option<crate::bus::Bus>,
    first_run: pages::FirstRunDrafts,
    held: forms::HeldForms,
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
    /// The query string's parameters (the OIDC callback's `code` and `state`).
    pub query: HashMap<String, String>,
    pub path: String,
    /// The client's source (7.7.2) as the limits count it.
    pub source: String,
    pub cookies: HashMap<String, String>,
    /// The request's `Host`, as the browser reached the dashboard.
    pub host: Option<String>,
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
            bindings: None,
            ticket: None,
            release_dir: None,
            registry: None,
            drivers: std::collections::BTreeMap::new(),
            passkeys: None,
            oidc_flows: Mutex::new(HashMap::new()),
            library: None,
            ingest: None,
            intel: None,
            assist: None,
            notify: None,
            bus: None,
            first_run: pages::FirstRunDrafts::default(),
            held: forms::HeldForms::default(),
        }))
    }

    /// The Bus, for the state changes the dashboard makes (a decided approval); before the router is built.
    pub fn with_bus(mut self, bus: crate::bus::Bus) -> Web {
        if let Some(inner) = Arc::get_mut(&mut self.0) {
            inner.bus = Some(bus);
        }
        self
    }

    /// Ingest, for vitals (the recent window and chunk rows) and what probes last reported; before the router is built.
    pub fn with_ingest(mut self, ingest: crate::ingest::Ingest) -> Web {
        if let Some(inner) = Arc::get_mut(&mut self.0) {
            inner.ingest = Some(ingest);
        }
        self
    }

    /// Assist, for an incident's Resume job and the operators page; before the router is built.
    pub fn with_assist(mut self, assist: crate::assist::Assist) -> Web {
        if let Some(inner) = Arc::get_mut(&mut self.0) {
            inner.assist = Some(assist);
        }
        self
    }

    /// The threat lists and GeoIP, for the Security page; before the router is built.
    pub fn with_intel(mut self, intel: crate::intel::Intel) -> Web {
        if let Some(inner) = Arc::get_mut(&mut self.0) {
            inner.intel = Some(intel);
        }
        self
    }

    /// The notifiers, for Settings: Notifiers and its Send test; before the router is built.
    pub fn with_notify(mut self, notify: crate::notify::Notify) -> Web {
        if let Some(inner) = Arc::get_mut(&mut self.0) {
            inner.notify = Some(notify);
        }
        self
    }

    /// The SSH system's host keys, for accepting a changed one; before the router is built.
    pub fn with_ticket(mut self, ticket: Arc<dyn Fn() -> Option<String> + Send + Sync>) -> Web {
        if let Some(inner) = Arc::get_mut(&mut self.0) {
            inner.ticket = Some(ticket);
        }
        self
    }

    pub fn with_release_dir(mut self, dir: std::path::PathBuf) -> Web {
        if let Some(inner) = Arc::get_mut(&mut self.0) {
            inner.release_dir = Some(dir);
        }
        self
    }

    pub(crate) fn ticket(&self) -> Option<String> {
        self.0.ticket.as_ref().and_then(|t| t())
    }

    pub(crate) fn release_dir(&self) -> Option<&std::path::Path> {
        self.0.release_dir.as_deref()
    }

    /// The API drivers the appliance forms poll with; before the router is built.
    pub fn with_drivers(mut self, drivers: Vec<Arc<dyn rackhand_drivers::Driver>>) -> Web {
        if let Some(inner) = Arc::get_mut(&mut self.0) {
            inner.drivers = drivers.into_iter().map(|d| (d.kind().name(), d)).collect();
        }
        self
    }

    pub fn with_bindings(mut self, bindings: Arc<crate::registry::guest_binding::GuestBindings>) -> Web {
        if let Some(inner) = Arc::get_mut(&mut self.0) {
            inner.bindings = Some(bindings);
        }
        self
    }

    pub fn with_host_keys(mut self, keys: Arc<crate::ssh::hostkeys::HostKeys>) -> Web {
        if let Some(inner) = Arc::get_mut(&mut self.0) {
            inner.host_keys = Some(keys);
        }
        self
    }

    /// The Library whose changes the git mirror follows; before the router is built.
    pub fn with_library(mut self, library: crate::library::items::Library) -> Web {
        if let Some(inner) = Arc::get_mut(&mut self.0) {
            inner.library = Some(library);
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
        let web = self.clone();
        let other = move |req: Request<Body>| async move { web.handle(&routes::NOT_FOUND, req).await };
        router.fallback(other).layer(axum::middleware::map_response(|mut resp: Response<Body>| async move {
            csp::apply(resp.headers_mut());
            resp
        }))
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
        if matches!(spec.page, routes::Page::Metrics) {
            let auth = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
            return metrics::render(self, auth, now);
        }
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
                        set_cookies.push(session::cookie(session::ANON_COOKIE, &a, session::ABSOLUTE_MS / 1000));
                        a
                    }
                };
                Binding::Anonymous(anon)
            }
        };
        let mut refused = false;
        if let Access::Perm(p) = spec.access {
            match &user {
                None => {
                    // signing in leads back to the page that was asked for
                    let asked = req.uri().path_and_query().map_or("/", |p| p.as_str());
                    let mut resp = pages::redirect("/sign-in");
                    if spec.method == Method::GET
                        && a_page(spec, req.headers())
                        && asked != "/"
                        && ui::local(asked) == asked
                    {
                        remember_next(&mut resp, asked);
                    }
                    return resp;
                }
                Some(u) if !allowed(u.role, p) => refused = true,
                Some(_) => {}
            }
        }
        let path = req.uri().path().to_string();
        let host = req.headers().get(axum::http::header::HOST).and_then(|h| h.to_str().ok()).map(str::to_string);
        let query: HashMap<String, String> =
            form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes()).into_owned().collect();
        let mut form = HashMap::new();
        let mut expired = false;
        if spec.method == Method::POST && !refused {
            let Ok(bytes) = axum::body::to_bytes(req.into_body(), MAX_FORM).await else {
                return pages::status(StatusCode::PAYLOAD_TOO_LARGE, "Form too large");
            };
            form = form_urlencoded::parse(&bytes).into_owned().collect();
            let token = form.get("csrf").map(String::as_str).unwrap_or("");
            if !csrf::verify(&self.0.config.csrf_key, &binding, token) {
                expired = true;
            }
        }
        let csrf = csrf::token(&self.0.config.csrf_key, &binding);
        let ctx = Ctx { now_ms: now, user, binding, csrf, form, query, path, source, cookies, host };
        let mut resp = if refused {
            pages::status(StatusCode::FORBIDDEN, "Your role can't do this.")
        } else if expired {
            pages::status(StatusCode::FORBIDDEN, "The form expired. Go back, reload the page and try again.")
        } else {
            pages::render(self, spec.page, &ctx).await
        };
        if let Some(said) = resp.extensions_mut().remove::<pages::Said>() {
            resp = pages::said(self, &ctx, resp.status(), &said);
        }
        for c in set_cookies {
            if let Ok(v) = HeaderValue::from_str(&c) {
                resp.headers_mut().append(header::SET_COOKIE, v);
            }
        }
        resp
    }
}

/// Whether a person is looking at what they asked for: not a fragment, and not something a script fetches.
fn a_page(spec: &RouteSpec, headers: &HeaderMap) -> bool {
    let sent = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    !matches!(spec.page, routes::Page::MachineVitals)
        && sent("hx-request").is_none()
        && sent("sec-fetch-dest").is_none_or(|d| d == "document")
}

/// Remembers where signing in or stepping up returns to, for ten minutes.
pub(crate) fn remember_next(resp: &mut Response<Body>, path: &str) {
    if let Ok(v) = HeaderValue::from_str(&session::cookie(ui::NEXT_COOKIE, ui::local(path), 600)) {
        resp.headers_mut().append(header::SET_COOKIE, v);
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
