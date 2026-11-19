use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use rackhand_store::Db;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use super::client_addr::{PeerAddr, client_ip, source_key};
use super::step_up;
use super::users::create_local;
use crate::audit::Audit;
use crate::policy::approvals::Role;
use crate::vault::Vault;
use crate::vault::master_key::MasterKey;
use crate::web::{Web, WebConfig, session, totp};

const MIN: i64 = 60_000;
const T0: i64 = 1_795_000_000_000;
const PASSWORD: &str = "correct horse battery staple";
const SECRET: &[u8; 20] = b"12345678901234567890";

struct App {
    db: Arc<Db>,
    router: Router,
    clock: Arc<AtomicI64>,
}

impl App {
    fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }
    fn advance(&self, ms: i64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }
    /// A code for the current time step.
    fn code(&self) -> String {
        totp::code(SECRET, self.now() / 1000)
    }
}

async fn app(name: &str) -> App {
    let dir = std::env::temp_dir().join(format!("rackhand-auth-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let vault = Arc::new(Vault::new(MasterKey::from_bytes([5u8; 32]), db.clone()));
    let config = WebConfig {
        setup_code_hash: Sha256::digest(b"unused").into(),
        csrf_key: [8u8; 32],
        trusted_proxies: vec![("10.0.0.1".parse().unwrap(), 32)],
    };
    let clock = Arc::new(AtomicI64::new(T0));
    let c = clock.clone();
    let web = Web::new(db.clone(), vault.clone(), Audit::new(db.writer()), "RECOVERY".into(), config)
        .with_clock(Arc::new(move || c.load(Ordering::SeqCst)));
    create_local(&db, &vault, "admin", Role::Admin, PASSWORD, Some(SECRET), T0).await.unwrap();
    App { db, router: web.router(), clock }
}

/// A browser: its own cookies, at a source address.
struct Browser {
    cookies: Vec<(String, String)>,
    addr: SocketAddr,
    forwarded: Option<String>,
}

impl Browser {
    fn at(ip: &str) -> Browser {
        Browser { cookies: Vec::new(), addr: SocketAddr::new(ip.parse().unwrap(), 50000), forwarded: None }
    }

    fn cookie_header(&self) -> String {
        self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
    }

    fn keep(&mut self, resp: &Response<Body>) {
        for v in resp.headers().get_all(header::SET_COOKIE).iter().filter_map(|v| v.to_str().ok()) {
            let Some((k, rest)) = v.split_once('=') else { continue };
            let value = rest.split(';').next().unwrap_or("").to_string();
            self.cookies.retain(|(n, _)| n != k);
            if !v.contains("Max-Age=0") {
                self.cookies.push((k.to_string(), value));
            }
        }
    }

    async fn send(&mut self, app: &App, mut req: Request<Body>) -> Response<Body> {
        req.extensions_mut().insert(PeerAddr(self.addr));
        if let Some(f) = &self.forwarded {
            req.headers_mut().insert("x-forwarded-for", f.parse().unwrap());
        }
        req.headers_mut().insert(header::COOKIE, self.cookie_header().parse().unwrap());
        let resp = app.router.clone().oneshot(req).await.unwrap();
        self.keep(&resp);
        resp
    }

    async fn page(&mut self, app: &App, path: &str) -> (StatusCode, String) {
        let resp = self.send(app, Request::get(path).body(Body::empty()).unwrap()).await;
        let status = resp.status();
        (status, body(resp).await)
    }

    async fn post(&mut self, app: &App, path: &str, form_page: &str, fields: &[(&str, &str)]) -> Response<Body> {
        let (_, html) = self.page(app, form_page).await;
        let csrf = field(&html, "csrf");
        let mut all = vec![("csrf", csrf.as_str())];
        all.extend_from_slice(fields);
        let body: String = form_urlencoded::Serializer::new(String::new()).extend_pairs(all).finish();
        let req = Request::post(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        self.send(app, req).await
    }

    async fn password(&mut self, app: &App, name: &str, password: &str) -> Response<Body> {
        self.post(app, "/sign-in", "/sign-in", &[("name", name), ("password", password)]).await
    }

    async fn code(&mut self, app: &App, code: &str) -> Response<Body> {
        self.post(app, "/sign-in/code", "/sign-in/code", &[("code", code)]).await
    }

    /// Both steps; true if a session came of it.
    async fn sign_in(&mut self, app: &App, password: &str, code: &str) -> bool {
        let first = self.password(app, "admin", password).await;
        if first.status() != StatusCode::SEE_OTHER {
            return false;
        }
        let second = self.code(app, code).await;
        second.status() == StatusCode::SEE_OTHER && self.has(session::COOKIE)
    }

    fn has(&self, cookie: &str) -> bool {
        self.cookies.iter().any(|(k, _)| k == cookie)
    }
}

async fn body(resp: Response<Body>) -> String {
    String::from_utf8_lossy(&axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap()).into_owned()
}

fn field(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let Some(i) = html.find(&marker) else { return String::new() };
    let start = i + marker.len();
    html[start..start + html[start..].find('"').unwrap()].to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn account_without_second_factor_cannot_sign_in() {
    let app = app("no2fa").await;
    let vault = Arc::new(Vault::new(MasterKey::from_bytes([5u8; 32]), app.db.clone()));
    create_local(&app.db, &vault, "bare", Role::Viewer, PASSWORD, None, T0).await.unwrap();
    let mut b = Browser::at("192.0.2.20");
    let resp = b.password(&app, "bare", PASSWORD).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(body(resp).await.contains("second factor"));
    assert!(!b.has(session::COOKIE));
    let (status, _) = b.page(&app, "/sign-in/code").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "no code step without a passed password step");
}

#[tokio::test(flavor = "multi_thread")]
async fn used_totp_code_refused() {
    let app = app("replay").await;
    let code = app.code();
    let mut first = Browser::at("192.0.2.21");
    assert!(first.sign_in(&app, PASSWORD, &code).await);
    let mut second = Browser::at("192.0.2.22");
    assert!(!second.sign_in(&app, PASSWORD, &code).await, "the same code twice");
    // The same time step is refused even through a different code of that step's window (one step back).
    app.advance(30_000);
    let previous_step = totp::code_at_step(SECRET, totp::step(app.now() / 1000) - 1);
    let mut third = Browser::at("192.0.2.23");
    assert!(!third.sign_in(&app, PASSWORD, &previous_step).await, "the step already used");
    let mut fourth = Browser::at("192.0.2.24");
    assert!(fourth.sign_in(&app, PASSWORD, &app.code()).await, "the next step works");
}

#[tokio::test(flavor = "multi_thread")]
async fn five_wrong_codes_restart_password_step() {
    let app = app("codes").await;
    let mut b = Browser::at("192.0.2.30");
    assert_eq!(b.password(&app, "admin", PASSWORD).await.status(), StatusCode::SEE_OTHER);
    for i in 0..4 {
        let resp = b.code(&app, "000000").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "wrong code {i}");
    }
    let fifth = b.code(&app, "000000").await;
    assert_eq!(fifth.status(), StatusCode::SEE_OTHER, "back to the password step");
    assert_eq!(fifth.headers().get(header::LOCATION).unwrap(), "/sign-in");
    let late = b.code(&app, &app.code()).await;
    assert_ne!(late.status(), StatusCode::SEE_OTHER, "a right code no longer helps");
    assert!(!b.has(session::COOKIE));
    // Those five failures count against the source: the sixth attempt from it within 15 minutes waits.
    let resp = b.password(&app, "admin", PASSWORD).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "the first attempt after 5 failures is allowed");
    let resp = b.password(&app, "admin", "wrong").await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "then 1 a minute");
}

#[tokio::test(flavor = "multi_thread")]
async fn source_backoff_after_5_failures_per_15_min() {
    let app = app("source").await;
    let mut b = Browser::at("2001:db8:1:2::10");
    for _ in 0..5 {
        assert_eq!(b.password(&app, "admin", "wrong").await.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(b.password(&app, "admin", "wrong").await.status(), StatusCode::UNAUTHORIZED, "one attempt now");
    assert_eq!(b.password(&app, "admin", "wrong").await.status(), StatusCode::TOO_MANY_REQUESTS);
    // Another address in the same /64 is the same source.
    let mut neighbour = Browser::at("2001:db8:1:2::99");
    assert_eq!(neighbour.password(&app, "admin", PASSWORD).await.status(), StatusCode::TOO_MANY_REQUESTS);
    app.advance(MIN);
    assert_eq!(neighbour.password(&app, "admin", "wrong").await.status(), StatusCode::UNAUTHORIZED, "a minute later");
    assert_eq!(neighbour.password(&app, "admin", "wrong").await.status(), StatusCode::TOO_MANY_REQUESTS);
    // After 15 minutes without failures the source is free again.
    app.advance(15 * MIN);
    assert_eq!(b.password(&app, "admin", "wrong").await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(b.password(&app, "admin", "wrong").await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(source_key("2001:db8:1:2::10".parse().unwrap()), source_key("2001:db8:1:2:ffff::1".parse().unwrap()));
    assert_ne!(source_key("192.0.2.1".parse().unwrap()), source_key("192.0.2.2".parse().unwrap()));
}

#[tokio::test(flavor = "multi_thread")]
async fn account_never_locked() {
    let app = app("never-locked").await;
    let mut attacker = Browser::at("192.0.2.40");
    for _ in 0..7 {
        let _ = attacker.password(&app, "admin", "wrong").await;
    }
    assert_eq!(attacker.password(&app, "admin", PASSWORD).await.status(), StatusCode::TOO_MANY_REQUESTS);
    let mut owner = Browser::at("198.51.100.7");
    assert!(owner.sign_in(&app, PASSWORD, &app.code()).await, "the right password from another source still works");
}

#[tokio::test(flavor = "multi_thread")]
async fn account_flood_limits_new_browsers_not_known_ones() {
    let app = app("flood").await;
    // The owner's browser has signed in before, so it carries a device cookie.
    let mut owner = Browser::at("198.51.100.50");
    assert!(owner.sign_in(&app, PASSWORD, &app.code()).await);
    assert!(owner.has(super::devices::DEVICE_COOKIE));
    owner.cookies.retain(|(k, _)| k != session::COOKIE);
    app.advance(30_000);
    // 10 failures for the account from 10 addresses.
    for i in 0..10 {
        let mut b = Browser::at(&format!("192.0.2.{}", 100 + i));
        assert_eq!(b.password(&app, "admin", "wrong").await.status(), StatusCode::UNAUTHORIZED, "attempt {i}");
    }
    let mut fresh = Browser::at("203.0.113.5");
    assert_eq!(fresh.password(&app, "admin", "wrong").await.status(), StatusCode::UNAUTHORIZED, "1 a minute in total");
    let mut another = Browser::at("203.0.113.6");
    assert_eq!(another.password(&app, "admin", PASSWORD).await.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(owner.sign_in(&app, PASSWORD, &app.code()).await, "the known browser keeps its own limit");
    app.advance(MIN);
    assert!(another.sign_in(&app, PASSWORD, &app.code()).await, "a minute later a new browser gets its attempt");
}

#[tokio::test(flavor = "multi_thread")]
async fn forwarded_header_ignored_unless_trusted_proxy() {
    let trusted = vec![("10.0.0.1".parse::<IpAddr>().unwrap(), 32)];
    let headers = |xff: &str| {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-for", xff.parse().unwrap());
        h
    };
    let direct: SocketAddr = "192.0.2.9:4000".parse().unwrap();
    assert_eq!(client_ip(direct, &headers("198.51.100.1"), &trusted), direct.ip(), "not from a trusted proxy");
    let proxy: SocketAddr = "10.0.0.1:4000".parse().unwrap();
    assert_eq!(client_ip(proxy, &headers("198.51.100.1"), &trusted), "198.51.100.1".parse::<IpAddr>().unwrap());
    assert_eq!(
        client_ip(proxy, &headers("6.6.6.6, 198.51.100.1"), &trusted),
        "198.51.100.1".parse::<IpAddr>().unwrap(),
        "the address the proxy saw, not what the client claimed"
    );
    // End to end: a client faking the header still hits its own source's backoff.
    let app = app("xff").await;
    let mut liar = Browser::at("192.0.2.60");
    for i in 0..6 {
        liar.forwarded = Some(format!("198.51.100.{i}"));
        let _ = liar.password(&app, "admin", "wrong").await;
    }
    liar.forwarded = Some("198.51.100.200".into());
    assert_eq!(liar.password(&app, "admin", "wrong").await.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test(flavor = "multi_thread")]
async fn step_up_valid_5_minutes() {
    let app = app("step-up").await;
    let mut b = Browser::at("192.0.2.70");
    assert!(b.sign_in(&app, PASSWORD, &app.code()).await);
    app.advance(30_000);
    let resp = b.post(&app, "/step-up", "/step-up", &[("code", &app.code())]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let stepped = app.now();
    assert!(step_up::fresh(Some(stepped), stepped + 5 * MIN - 1_000), "valid at 4:59");
    assert!(!step_up::fresh(Some(stepped), stepped + 5 * MIN + 1_000), "prompts at 5:01");
    assert!(!step_up::fresh(None, stepped));
    let token = b.cookies.iter().find(|(k, _)| k == session::COOKIE).unwrap().1.clone();
    let user = session::lookup(&app.db, &token, stepped + 1_000).unwrap().unwrap();
    assert_eq!(user.step_up_at, Some(stepped), "recorded on the session");
    // A step-up code is single use too.
    let again = b.post(&app, "/step-up", "/step-up", &[("code", &app.code())]).await;
    assert_eq!(again.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn session_absolute_and_idle_expiry() {
    let app = app("expiry").await;
    let user_id: String = app.db.readers().with(|c| c.query_row("SELECT id FROM users", [], |r| r.get(0))).unwrap();
    let token = session::create(&app.db, &user_id, T0).await.unwrap();
    assert!(session::lookup(&app.db, &token, T0 + 2 * 60 * MIN - 1).unwrap().is_some());
    assert!(session::lookup(&app.db, &token, T0 + 2 * 60 * MIN + 1).unwrap().is_none(), "2 hours idle");
    let token = session::create(&app.db, &user_id, T0).await.unwrap();
    // Active every hour: idle never runs out, the absolute limit does.
    for h in 1..12 {
        let at = T0 + h * 60 * MIN;
        assert!(session::lookup(&app.db, &token, at).unwrap().is_some(), "hour {h}");
        session::touch(&app.db, &token, at).await.unwrap();
    }
    assert!(session::lookup(&app.db, &token, T0 + 12 * 60 * MIN - 1).unwrap().is_some());
    assert!(session::lookup(&app.db, &token, T0 + 12 * 60 * MIN + 1).unwrap().is_none(), "12 hours absolute");
    // Requests keep a session alive through the gate.
    let mut b = Browser::at("192.0.2.80");
    assert!(b.sign_in(&app, PASSWORD, &app.code()).await);
    for _ in 0..3 {
        app.advance(90 * MIN);
        let (status, _) = b.page(&app, "/").await;
        assert_eq!(status, StatusCode::OK, "used every 90 minutes");
    }
    app.advance(2 * 60 * MIN + MIN);
    let (status, _) = b.page(&app, "/").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "idle for over 2 hours");
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_ins_and_failures_are_audited() {
    let app = app("audited").await;
    let mut b = Browser::at("192.0.2.90");
    let _ = b.password(&app, "admin", "wrong").await;
    let _ = b.password(&app, "nobody", "wrong").await;
    assert!(b.sign_in(&app, PASSWORD, &app.code()).await);
    let _ = b.post(&app, "/sign-out", "/", &[]).await;
    let rows: Vec<(String, String, String)> = app
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT actor, action, data FROM audit_log ORDER BY seq")?;
            let rows = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect()
        })
        .unwrap();
    let actions: Vec<&str> = rows.iter().map(|(_, a, _)| a.as_str()).collect();
    assert_eq!(actions, ["auth.sign_in_failed", "auth.sign_in_failed", "auth.sign_in", "auth.sign_out"], "{rows:?}");
    assert!(rows[0].2.contains("192.0.2.90") && rows[0].2.contains("password"), "{}", rows[0].2);
    assert_eq!(rows[1].0, "nobody");
    assert_eq!(rows[2].0, "admin");
}
