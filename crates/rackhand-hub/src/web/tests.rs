use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, Response, StatusCode, header};
use rackhand_store::ids::now_ms;
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use super::perms::{ALL_PERMISSIONS, Permission, allowed};
use super::routes::{Access, ROUTES};
use super::{Web, WebConfig, session, totp};
use crate::audit::Audit;
use crate::policy::approvals::Role;
use crate::vault::Vault;
use crate::vault::master_key::{MasterKey, recovery_code};

const SETUP_CODE: &str = "SETUP-7Q2X-9KPL";

struct App {
    db: Arc<Db>,
    router: Router,
    recovery: String,
    path: std::path::PathBuf,
}

impl App {
    fn db_path(&self) -> &std::path::Path {
        &self.path
    }
}

async fn app(name: &str) -> App {
    app_with(name, |web| web).await
}

/// An app whose `Web` is adjusted (for example given the Registry) before the router is built.
async fn app_with(name: &str, adjust: impl FnOnce(Web) -> Web) -> App {
    let dir = std::env::temp_dir().join(format!("rackhand-web-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hub.db");
    let db = Arc::new(Db::open(&path).unwrap());
    let key = MasterKey::from_bytes([3u8; 32]);
    let recovery = recovery_code(&key);
    let vault = Arc::new(Vault::new(key, db.clone()));
    let config = WebConfig {
        setup_code_hash: Sha256::digest(SETUP_CODE.as_bytes()).into(),
        csrf_key: [9u8; 32],
        trusted_proxies: vec![],
    };
    let web = adjust(Web::new(db.clone(), vault, Audit::new(db.writer()), recovery.clone(), config));
    App { db, router: web.router(), recovery, path }
}

async fn send(router: &Router, req: Request<Body>) -> Response<Body> {
    router.clone().oneshot(req).await.unwrap()
}

fn get(path: &str, cookie: &str) -> Request<Body> {
    Request::get(path).header(header::COOKIE, cookie).body(Body::empty()).unwrap()
}

fn post(path: &str, cookie: &str, fields: &[(&str, &str)]) -> Request<Body> {
    let body: String = form_urlencoded::Serializer::new(String::new()).extend_pairs(fields).finish();
    Request::post(path)
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

async fn text(resp: Response<Body>) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn set_cookie(resp: &Response<Body>, name: &str) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{name}=")))
        .map(str::to_string)
}

fn location(resp: &Response<Body>) -> Option<String> {
    resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).map(str::to_string)
}

/// The value of a hidden form field in a page.
fn field(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html.find(&marker).unwrap_or_else(|| panic!("no field {name}")) + marker.len();
    html[start..start + html[start..].find('"').unwrap()].to_string()
}

/// Opens the first-run page: the anonymous cookie, the CSRF token and the TOTP secret with its signature.
async fn open_first_run(app: &App) -> (String, String, String, String) {
    let resp = send(&app.router, get("/first-run", "")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = set_cookie(&resp, "rh_anon").expect("anonymous cookie").split(';').next().unwrap().to_string();
    let html = text(resp).await;
    (cookie, field(&html, "csrf"), field(&html, "totp_secret"), field(&html, "totp_sig"))
}

async fn complete_first_run(app: &App, setup_code: &str) -> Response<Body> {
    let opened = open_first_run(app).await;
    submit_first_run(app, opened, setup_code).await
}

async fn submit_first_run(app: &App, opened: (String, String, String, String), setup_code: &str) -> Response<Body> {
    submit_first_run_at(app, opened, setup_code, now_ms()).await
}

/// The same, with the authenticator code for the hub's clock at `at_ms`.
async fn submit_first_run_at(
    app: &App,
    opened: (String, String, String, String),
    setup_code: &str,
    at_ms: i64,
) -> Response<Body> {
    let (cookie, csrf, secret, sig) = opened;
    let code = totp::code(&totp::decode_base32(&secret).unwrap(), at_ms / 1000);
    let req = post(
        "/first-run",
        &cookie,
        &[
            ("csrf", csrf.as_str()),
            ("setup_code", setup_code),
            ("admin_name", "admin"),
            ("password", "correct horse battery staple"),
            ("totp_secret", secret.as_str()),
            ("totp_sig", sig.as_str()),
            ("totp_code", code.as_str()),
            ("site_name", "home"),
            ("timezone", "Europe/Berlin"),
            ("source_spamhaus", "on"),
            ("source_dbip", "on"),
        ],
    );
    send(&app.router, req).await
}

async fn user_count(db: &Db) -> i64 {
    db.readers().with(|c| c.query_row("SELECT count(*) FROM users", [], |r| r.get(0))).unwrap()
}

/// A signed-in session for a new user with `role`.
async fn session_for(db: &Arc<Db>, role: Role) -> String {
    let id = ulid::Ulid::new().to_string();
    let name = format!("{}-{}", super::perms::role_name(role), id.to_lowercase());
    db.writer()
        .send(WriteCmd::Batch(vec![RowWrite::insert(
            "users",
            Row::from([
                ("id", Value::Text(id.clone())),
                ("name", Value::Text(name)),
                ("role", Value::Text(super::perms::role_name(role).into())),
                ("created_at", Value::Integer(0)),
            ]),
        )]))
        .await
        .unwrap();
    let token = session::create(db, &id, now_ms()).await.unwrap();
    format!("{}={token}", session::COOKIE)
}

/// The CSRF token of a signed-in session, as its pages embed it (the overview's sign-out form, for every role).
async fn csrf_of(app: &App, cookie: &str) -> String {
    let html = text(send(&app.router, get("/", cookie)).await).await;
    field(&html, "csrf")
}

fn sample_path(path: &str) -> String {
    path.replace("{file}", "htmx-2.0.11.min.js").replace("{id}", "m1")
}

#[tokio::test(flavor = "multi_thread")]
async fn first_run_shown_until_admin_exists() {
    let app = app("gate").await;
    for r in ROUTES.iter().filter(|r| r.method == Method::GET && matches!(r.access, Access::Perm(_))) {
        let resp = send(&app.router, get(&sample_path(r.path), "")).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{}", r.path);
        assert_eq!(location(&resp).as_deref(), Some("/first-run"), "{}", r.path);
    }
    for public in ["/healthz", "/static/vendor/htmx-2.0.11.min.js", "/sign-in"] {
        assert_eq!(send(&app.router, get(public, "")).await.status(), StatusCode::OK, "{public}");
    }
    assert_eq!(complete_first_run(&app, SETUP_CODE).await.status(), StatusCode::OK);
    let after = send(&app.router, get("/first-run", "")).await;
    assert_eq!(after.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&after).as_deref(), Some("/sign-in"), "never again after an admin exists");
    let home = send(&app.router, get("/", "")).await;
    assert_eq!(location(&home).as_deref(), Some("/sign-in"), "signed out now, not first run");
}

#[tokio::test(flavor = "multi_thread")]
async fn first_run_setup_code_guessing_limited() {
    // the hub's clock, moved by the test
    let clock = Arc::new(std::sync::atomic::AtomicI64::new(now_ms()));
    let c = clock.clone();
    let app = app_with("first-run-limit", move |web| {
        web.with_clock(Arc::new(move || c.load(std::sync::atomic::Ordering::SeqCst)))
    })
    .await;
    // 5 wrong codes, each refused for being wrong
    for _ in 0..5 {
        let opened = open_first_run(&app).await;
        assert_eq!(submit_first_run(&app, opened, "SETUP-WRONG-0000").await.status(), StatusCode::FORBIDDEN);
    }
    // then one attempt a minute from this source: the next goes ahead, the one after it waits
    let opened = open_first_run(&app).await;
    assert_eq!(submit_first_run(&app, opened, "SETUP-WRONG-0001").await.status(), StatusCode::FORBIDDEN);
    let opened = open_first_run(&app).await;
    let limited = submit_first_run(&app, opened, SETUP_CODE).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS, "even the right code waits");
    assert_eq!(user_count(&app.db).await, 0);
    let later = clock.fetch_add(60_000, std::sync::atomic::Ordering::SeqCst) + 60_000;
    let opened = open_first_run(&app).await;
    let done = submit_first_run_at(&app, opened, SETUP_CODE, later).await;
    assert!(done.status().is_success() || done.status() == StatusCode::SEE_OTHER, "{}", done.status());
    assert_eq!(user_count(&app.db).await, 1, "a minute later it goes through");
}

#[tokio::test(flavor = "multi_thread")]
async fn first_run_shows_recovery_code_once() {
    let app = app("recovery").await;
    let wrong = complete_first_run(&app, "SETUP-WRONG").await;
    assert_eq!(wrong.status(), StatusCode::FORBIDDEN, "the installer's setup code is required");
    assert_eq!(user_count(&app.db).await, 0);
    // Two first runs at once (both forms opened before either is sent) make one admin.
    let (one, two) = (open_first_run(&app).await, open_first_run(&app).await);
    let late = open_first_run(&app).await;
    let (a, b) = tokio::join!(submit_first_run(&app, one, SETUP_CODE), submit_first_run(&app, two, SETUP_CODE));
    let pages = [text(a).await, text(b).await];
    let shown = pages.iter().filter(|p| p.contains(&app.recovery)).count();
    assert_eq!(shown, 1, "the recovery code is shown to the one first run that created the admin");
    assert_eq!(user_count(&app.db).await, 1);
    let reload = send(&app.router, get("/first-run", "")).await;
    assert!(!text(reload).await.contains(&app.recovery), "not on reload");
    // A form opened before the admin existed, sent after: refused, no code.
    let again = submit_first_run(&app, late, SETUP_CODE).await;
    assert_eq!(again.status(), StatusCode::SEE_OTHER);
    assert!(!text(again).await.contains(&app.recovery));
    let roles: Vec<String> = app
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT role || ':' || name FROM users")?;
            let rows = s.query_map([], |r| r.get(0))?;
            rows.collect()
        })
        .unwrap();
    assert_eq!(roles, ["admin:admin"]);
    let creds: i64 = app
        .db
        .readers()
        .with(|c| c.query_row("SELECT count(*) FROM credentials WHERE kind IN ('password', 'totp')", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(creds, 2, "password and TOTP: no admin without a second factor");
}

#[tokio::test(flavor = "multi_thread")]
async fn post_without_csrf_token_is_403() {
    let app = app("csrf").await;
    let (cookie, _, _, _) = open_first_run(&app).await;
    let no_token = send(&app.router, post("/first-run", &cookie, &[("setup_code", SETUP_CODE)])).await;
    assert_eq!(no_token.status(), StatusCode::FORBIDDEN, "first run");
    complete_first_run(&app, SETUP_CODE).await;
    let admin = session_for(&app.db, Role::Admin).await;
    let good = csrf_of(&app, &admin).await;
    // Every state-changing route; first run is checked above (after it, the route only redirects).
    let posts: Vec<_> = ROUTES.iter().filter(|r| r.method == Method::POST && r.access != Access::FirstRun).collect();
    assert!(posts.len() >= 4, "{posts:?}");
    for r in posts {
        let none = send(&app.router, post(r.path, &admin, &[("x", "1")])).await;
        assert_eq!(none.status(), StatusCode::FORBIDDEN, "{} without a token", r.path);
        let wrong = send(&app.router, post(r.path, &admin, &[("csrf", "0000")])).await;
        assert_eq!(wrong.status(), StatusCode::FORBIDDEN, "{} with a wrong token", r.path);
        // Another session's token doesn't work either.
        let other = session_for(&app.db, Role::Admin).await;
        let theirs = csrf_of(&app, &other).await;
        assert_ne!(theirs, good);
        let stolen = send(&app.router, post(r.path, &admin, &[("csrf", theirs.as_str())])).await;
        assert_eq!(stolen.status(), StatusCode::FORBIDDEN, "{} with another session's token", r.path);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn csp_and_cookie_flags_set() {
    let app = app("headers").await;
    let resp = send(&app.router, get("/first-run", "")).await;
    let csp = resp.headers().get(header::CONTENT_SECURITY_POLICY).unwrap().to_str().unwrap().to_string();
    assert!(csp.contains("default-src 'self'") && csp.contains("frame-ancestors 'none'"), "{csp}");
    assert!(!csp.contains("unsafe-inline") && !csp.contains("unsafe-eval"), "{csp}");
    assert_eq!(resp.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
    let anon = set_cookie(&resp, "rh_anon").unwrap();
    for flag in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(anon.contains(flag), "{anon}");
    }
    let session_cookie = session::cookie(session::COOKIE, "value", 3600);
    for flag in ["Secure", "HttpOnly", "SameSite=Strict"] {
        assert!(session_cookie.contains(flag), "{session_cookie}");
    }
    // Every response carries the policy, errors and redirects included.
    let redirect = send(&app.router, get("/", "")).await;
    assert!(redirect.headers().contains_key(header::CONTENT_SECURITY_POLICY));
}

#[tokio::test(flavor = "multi_thread")]
async fn template_output_is_escaped() {
    let app = app("escape").await;
    complete_first_run(&app, SETUP_CODE).await;
    let site: String = app.db.readers().with(|c| c.query_row("SELECT id FROM sites", [], |r| r.get(0))).unwrap();
    app.db
        .writer()
        .send(WriteCmd::Batch(vec![RowWrite::insert(
            "machines",
            Row::from([
                ("id", Value::Text("m1".into())),
                ("site_id", Value::Text(site)),
                ("name", Value::Text("<script>alert(1)</script>".into())),
                ("kind", Value::Text("linux".into())),
            ]),
        )]))
        .await
        .unwrap();
    let viewer = session_for(&app.db, Role::Viewer).await;
    let html = text(send(&app.router, get("/", &viewer)).await).await;
    // The name appears with `<` and `>` as entities (askama writes them as `&#60;` and `&#62;`), never raw.
    assert!(html.contains("&#60;script&#62;alert(1)&#60;/script&#62;"), "{html}");
    assert!(!html.contains("<script>alert(1)"), "{html}");
    assert_eq!(html.matches("<script").count(), 1, "only the page's own htmx script tag: {html}");
}

#[tokio::test(flavor = "multi_thread")]
async fn permission_matrix_enforced_for_each_role() {
    use Permission::*;
    use Role::*;
    // 7.7.2, row by row.
    let matrix: [(Permission, [bool; 3]); 9] = [
        (SeeEverything, [true, true, true]),
        (Respond, [false, true, true]),
        (ApproveNormal, [false, true, true]),
        (ApproveHigh, [false, false, true]),
        (Operate, [false, true, true]),
        (EditLibrary, [false, false, true]),
        (Enroll, [false, false, true]),
        (ConfirmBinding, [false, false, true]),
        (Administer, [false, false, true]),
    ];
    assert_eq!(ALL_PERMISSIONS.len(), matrix.len());
    for (p, want) in matrix {
        for (role, w) in [Viewer, Responder, Admin].into_iter().zip(want) {
            assert_eq!(allowed(role, p), w, "{role:?} {p:?}");
        }
    }
    // Every guarded route enforces its row, for each role.
    let app = app("matrix").await;
    complete_first_run(&app, SETUP_CODE).await;
    for role in [Viewer, Responder, Admin] {
        for r in ROUTES.iter() {
            let Access::Perm(p) = r.access else { continue };
            // A fresh session per route (sign-out ends one).
            let cookie = session_for(&app.db, role).await;
            let resp = if r.method == Method::POST {
                // A valid token, so only the permission decides.
                let csrf = csrf_of(&app, &cookie).await;
                send(&app.router, post(r.path, &cookie, &[("csrf", csrf.as_str())])).await
            } else {
                send(&app.router, get(&sample_path(r.path), &cookie)).await
            };
            if allowed(role, p) {
                assert_ne!(resp.status(), StatusCode::FORBIDDEN, "{role:?} {} {}", r.method, r.path);
            } else {
                assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{role:?} {} {}", r.method, r.path);
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn vendored_assets_match_checksums() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("static/vendor");
    let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
    let mut listed = Vec::new();
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        let (sum, name) = line.split_once("  ").unwrap();
        let bytes = std::fs::read(dir.join(name)).unwrap();
        let got: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, sum, "{name}");
        listed.push(name.to_string());
    }
    for entry in std::fs::read_dir(&dir).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(name == "SHA256SUMS" || listed.contains(&name), "{name} isn't in SHA256SUMS");
    }
    // What the hub serves is exactly those bytes.
    let app = app("assets").await;
    for name in listed.iter().filter(|n| !n.ends_with("LICENSE")) {
        let resp = send(&app.router, get(&format!("/static/vendor/{name}"), "")).await;
        assert_eq!(resp.status(), StatusCode::OK, "{name}");
        let served = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
        assert_eq!(served.as_ref(), std::fs::read(dir.join(name)).unwrap().as_slice(), "{name}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn configuration_changes_are_audited() {
    let app = app("audit").await;
    complete_first_run(&app, SETUP_CODE).await;
    let admin = session_for(&app.db, Role::Admin).await;
    let csrf = csrf_of(&app, &admin).await;
    let resp =
        send(&app.router, post("/settings/sources", &admin, &[("csrf", csrf.as_str()), ("source_spamhaus", "on")]))
            .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let rows: Vec<(String, String, String)> = app
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT actor, action, data FROM audit_log ORDER BY seq")?;
            let rows = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect()
        })
        .unwrap();
    assert!(rows.iter().any(|(_, a, _)| a == "first_run.completed"), "{rows:?}");
    let change = rows.iter().find(|(_, a, _)| a == "settings.sources").expect("audited");
    assert!(change.0.starts_with("admin-"), "the signed-in user is the actor: {}", change.0);
    assert!(change.2.contains("\"dbip\":false") && change.2.contains("\"spamhaus\":true"), "{}", change.2);
    let revs: i64 = app
        .db
        .readers()
        .with(|c| {
            c.query_row("SELECT max(rev) FROM library_revisions WHERE kind = 'config' AND name = 'hub'", [], |r| {
                r.get(0)
            })
        })
        .unwrap();
    assert_eq!(revs, 2, "stored with revisions: first run, then this change");
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_changes_reach_the_mirror() {
    // the composition gives Web the Library; its change channel feeds the git mirror (7.3.13)
    let slot: Arc<std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<crate::library::items::Change>>>> =
        Arc::default();
    let keep = slot.clone();
    let app = app_with("settings-mirror", move |web| {
        let (library, changes) = crate::library::items::Library::new(web.0.db.clone(), web.0.audit.clone());
        *keep.lock().unwrap() = Some(changes);
        web.with_library(library)
    })
    .await;
    let mut changes = slot.lock().unwrap().take().unwrap();
    complete_first_run(&app, SETUP_CODE).await;
    let admin = session_for(&app.db, Role::Admin).await;
    let csrf = csrf_of(&app, &admin).await;
    let resp =
        send(&app.router, post("/settings/sources", &admin, &[("csrf", csrf.as_str()), ("source_dbip", "on")])).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let change = changes.try_recv().expect("a settings change reaches the mirror");
    assert!(change.user.starts_with("admin-") && change.summary.contains("config/hub"), "{change:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_changes_reach_the_mirror() {
    // a policy is a revision of `config/policies.toml`, written outside `Library::save` (7.3.13)
    let slot: Arc<std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<crate::library::items::Change>>>> =
        Arc::default();
    let keep = slot.clone();
    let app = app_with("policy-mirror", move |web| {
        let (library, changes) = crate::library::items::Library::new(web.0.db.clone(), web.0.audit.clone());
        *keep.lock().unwrap() = Some(changes);
        web.with_library(library)
    })
    .await;
    let mut changes = slot.lock().unwrap().take().unwrap();
    complete_first_run(&app, SETUP_CODE).await;
    let admin = session_for(&app.db, Role::Admin).await;
    let csrf = csrf_of(&app, &admin).await;
    let policy = [
        ("csrf", csrf.as_str()),
        ("name", "web-servers"),
        ("patch", "auto"),
        ("snapshot", "required"),
        ("quarantine", "approval"),
        ("peer_requests", "approval"),
    ];
    assert_eq!(send(&app.router, post("/policies", &admin, &policy)).await.status(), StatusCode::SEE_OTHER);
    let change = changes.try_recv().expect("a policy change reaches the mirror");
    assert!(change.user.starts_with("admin-") && change.summary.contains("config/policies"), "{change:?}");
    let csrf = csrf_of(&app, &admin).await;
    let bad = [("csrf", csrf.as_str()), ("name", "Bad Name!"), ("patch", "auto")];
    assert_ne!(send(&app.router, post("/policies", &admin, &bad)).await.status(), StatusCode::SEE_OTHER);
    assert!(changes.try_recv().is_err(), "a refused change sends nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn serves_https_with_generated_certificate() {
    let (cert_pem, key_pem) = super::tls::generate(&["localhost".to_string()]).unwrap();
    let config = super::tls::server_config(&cert_pem, &key_pem).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = app("tls").await;
    tokio::spawn(super::tls::serve(listener, app.router.clone(), config));
    let response = super::tls::test_client_get(addr, "localhost", &cert_pem, "/healthz").await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.to_ascii_lowercase().contains("content-security-policy"), "{response}");
}

#[test]
fn totp_matches_rfc6238_vectors() {
    // RFC 6238 appendix B, SHA-1 secret; the 6-digit code is the last six digits of the 8-digit value.
    let secret = b"12345678901234567890";
    for (t, eight) in
        [(59, "94287082"), (1_111_111_109, "07081804"), (1_234_567_890, "89005924"), (2_000_000_000, "69279037")]
    {
        assert_eq!(totp::code(secret, t), eight[2..], "t = {t}");
    }
    assert_eq!(totp::verify(secret, "287082", 59), Some(1));
    assert_eq!(totp::verify(secret, "287082", 59 + 30), Some(1), "one step of drift");
    assert_eq!(totp::verify(secret, "287082", 59 + 60), None, "two steps is too far");
    assert_eq!(totp::verify(secret, "28708", 59), None);
    let b32 = totp::encode_base32(secret);
    assert_eq!(b32, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert_eq!(totp::decode_base32(&b32).unwrap(), secret);
}

mod settings {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn git_mirror_url_and_deploy_key_in_vault() {
        let app = app("git-mirror").await;
        complete_first_run(&app, SETUP_CODE).await;
        let admin = session_for(&app.db, Role::Admin).await;
        let csrf = csrf_of(&app, &admin).await;
        let url = "ssh://git@git.example.invalid/homelab/rackhand.git";
        let resp =
            send(&app.router, post("/settings/git-mirror", &admin, &[("csrf", csrf.as_str()), ("url", url)])).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let html = text(send(&app.router, get("/settings", &admin)).await).await;
        assert!(html.contains(url), "the URL is shown");
        let line = html.lines().find(|l| l.contains("ssh-ed25519 ")).expect("the deploy key's public half is shown");
        assert!(!html.contains("PRIVATE KEY"), "never the private half");
        // The private half is in the Vault, sealed; the stored settings refer to nothing secret.
        let sealed: i64 = app
            .db
            .readers()
            .with(|c| c.query_row("SELECT count(*) FROM secrets WHERE name = 'git.deploy_key'", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(sealed, 1);
        let config = crate::library::config::current(&app.db, "hub").unwrap().unwrap();
        assert!(config.contains(url) && !config.contains("BEGIN"), "{config}");
        // Saving again keeps the same key.
        let csrf = csrf_of(&app, &admin).await;
        send(&app.router, post("/settings/git-mirror", &admin, &[("csrf", csrf.as_str()), ("url", url)])).await;
        let again = text(send(&app.router, get("/settings", &admin)).await).await;
        assert!(again.contains(line.trim()), "the deploy key is kept");
        let bad = send(
            &app.router,
            post(
                "/settings/git-mirror",
                &admin,
                &[("csrf", csrf_of(&app, &admin).await.as_str()), ("url", "file:///etc")],
            ),
        )
        .await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST, "only ssh:// URLs");
    }

    fn user_row(db: &Db, name: &str) -> Option<(String, String, Option<i64>)> {
        use rusqlite::OptionalExtension;
        db.readers()
            .with(|c| {
                c.query_row("SELECT id, role, disabled_at FROM users WHERE name = ?1", [name], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .optional()
            })
            .unwrap()
    }

    async fn session_of(db: &Arc<Db>, user_id: &str) -> String {
        let token = session::create(db, user_id, now_ms()).await.unwrap();
        format!("{}={token}", session::COOKIE)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn users_and_roles_admin_only() {
        let app = app("users").await;
        complete_first_run(&app, SETUP_CODE).await;
        let admin = session_for(&app.db, Role::Admin).await;
        // An admin creates a local account; its authenticator secret is shown once.
        let csrf = csrf_of(&app, &admin).await;
        let fields = [
            ("csrf", csrf.as_str()),
            ("name", "alice"),
            ("role", "responder"),
            ("auth", "local"),
            ("password", "a long enough secret"),
        ];
        let resp = send(&app.router, post("/settings/users", &admin, &fields)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let shown = text(resp).await;
        assert!(shown.contains("otpauth://totp/"), "{shown}");
        let (id, role, disabled) = user_row(&app.db, "alice").expect("created");
        assert_eq!((role.as_str(), disabled), ("responder", None));
        let page = text(send(&app.router, get("/settings", &admin)).await).await;
        assert!(page.contains("alice"), "listed");
        // Change the role, then disable: alice's session stops working.
        let alice = session_of(&app.db, &id).await;
        assert_eq!(send(&app.router, get("/", &alice)).await.status(), StatusCode::OK);
        let csrf = csrf_of(&app, &admin).await;
        let role_path = format!("/settings/users/{id}/role");
        let resp = send(&app.router, post(&role_path, &admin, &[("csrf", csrf.as_str()), ("role", "viewer")])).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(user_row(&app.db, "alice").unwrap().1, "viewer");
        let csrf = csrf_of(&app, &admin).await;
        let disable_path = format!("/settings/users/{id}/disable");
        let resp = send(&app.router, post(&disable_path, &admin, &[("csrf", csrf.as_str())])).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert!(user_row(&app.db, "alice").unwrap().2.is_some());
        assert_eq!(location(&send(&app.router, get("/", &alice)).await).as_deref(), Some("/sign-in"));
        // A responder can't do any of it.
        let responder = session_for(&app.db, Role::Responder).await;
        let csrf = csrf_of(&app, &responder).await;
        for (path, extra) in
            [("/settings/users".to_string(), ("name", "mallory")), (role_path.clone(), ("role", "admin"))]
        {
            let resp = send(&app.router, post(&path, &responder, &[("csrf", csrf.as_str()), extra])).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
        }
        assert!(user_row(&app.db, "mallory").is_none());
        let audited: i64 = app
            .db
            .readers()
            .with(|c| c.query_row("SELECT count(*) FROM audit_log WHERE action LIKE 'user.%'", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(audited, 3, "created, role changed, disabled");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn last_admin_cannot_be_disabled_or_demoted() {
        let app = app("last-admin").await;
        complete_first_run(&app, SETUP_CODE).await;
        let (id, _, _) = user_row(&app.db, "admin").unwrap();
        let admin = session_of(&app.db, &id).await;
        let csrf = csrf_of(&app, &admin).await;
        let role_path = format!("/settings/users/{id}/role");
        let demote = send(&app.router, post(&role_path, &admin, &[("csrf", csrf.as_str()), ("role", "viewer")])).await;
        assert_eq!(demote.status(), StatusCode::CONFLICT);
        let disable_path = format!("/settings/users/{id}/disable");
        let disable = send(&app.router, post(&disable_path, &admin, &[("csrf", csrf.as_str())])).await;
        assert_eq!(disable.status(), StatusCode::CONFLICT);
        assert_eq!(user_row(&app.db, "admin").unwrap(), (id, "admin".to_string(), None));
    }

    async fn echo(conn: iroh::endpoint::Connection) {
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            if let Ok(data) = recv.read_to_end(64).await {
                let _ = send.write_all(&data).await;
                let _ = send.finish();
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn devices_listed_and_revocable() {
        use rackhand_net::registry::{Admission, Registry as Admit};
        use rackhand_proto::alpn;
        use rackhand_proto::close::CloseCode;

        // The Registry the hub serves device connections with, and the same one the dashboard revokes through.
        let slot: Arc<std::sync::Mutex<Option<Arc<crate::registry::Registry>>>> = Arc::default();
        let app = app_with("devices", {
            let slot = slot.clone();
            move |web| {
                let registry = crate::registry::Registry::load(web.db().clone()).unwrap();
                *slot.lock().unwrap() = Some(registry.clone());
                web.with_registry(registry)
            }
        })
        .await;
        let registry = slot.lock().unwrap().clone().unwrap();
        complete_first_run(&app, SETUP_CODE).await;
        let (user_id, _, _) = user_row(&app.db, "admin").unwrap();
        // A person's device, joined (T35 writes the row and admits it).
        let (_relay, relay_url) = rackhand_net::testing::local_relay().await;
        let server = rackhand_net::testing::endpoint(&relay_url, &[alpn::TUNNEL]).await;
        let device = rackhand_net::testing::endpoint(&relay_url, &[]).await;
        let mut addr = server.addr();
        addr.addrs.insert(iroh::TransportAddr::Relay(relay_url.clone()));
        app.db
            .writer()
            .send(WriteCmd::RegistryChange(rackhand_store::RegistryChange {
                writes: vec![RowWrite::insert(
                    "devices",
                    Row::from([
                        ("id", Value::Text("d1".into())),
                        ("user_id", Value::Text(user_id)),
                        ("name", Value::Text("laptop".into())),
                        ("endpoint_id", Value::Text(device.id().to_string())),
                        ("created_at", Value::Integer(1)),
                    ]),
                )],
                ..Default::default()
            }))
            .await
            .unwrap();
        registry.allow(crate::registry::tokens::TokenKind::Device, device.id());
        let router = rackhand_net::router::Router::new(server.clone(), registry.clone())
            .route(alpn::TUNNEL, rackhand_net::router::handler(echo));
        tokio::spawn(router.serve());
        let conn = device.connect(addr.clone(), alpn::TUNNEL).await.unwrap();
        let (mut tx, mut rx) = conn.open_bi().await.unwrap();
        tx.write_all(b"hi").await.unwrap();
        tx.finish().unwrap();
        assert_eq!(rx.read_to_end(64).await.unwrap(), b"hi", "the device is served");
        conn.close(0u32.into(), b"done");
        // Listed on the settings page, then revoked there.
        let admin = session_for(&app.db, Role::Admin).await;
        let page = text(send(&app.router, get("/settings", &admin)).await).await;
        assert!(page.contains("laptop"), "listed");
        let csrf = csrf_of(&app, &admin).await;
        let resp = send(&app.router, post("/settings/devices/d1/revoke", &admin, &[("csrf", csrf.as_str())])).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        // Its next connection is closed with 0x13, now and after the hub reloads admission from the tables.
        let next = device.connect(addr, alpn::TUNNEL).await.unwrap();
        let reason = tokio::time::timeout(std::time::Duration::from_secs(10), next.closed()).await.unwrap();
        assert_eq!(rackhand_net::close_code(&reason), Some(CloseCode::Revoked));
        let reloaded = crate::registry::Registry::load(app.db.clone()).unwrap();
        assert_eq!(reloaded.admission(alpn::TUNNEL, &device.id()), Admission::Revoked);
        let audited: i64 = app
            .db
            .readers()
            .with(|c| c.query_row("SELECT count(*) FROM audit_log WHERE action = 'device.revoked'", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(audited, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oidc_client_secret_stored_in_vault() {
        let app = app("oidc-settings").await;
        complete_first_run(&app, SETUP_CODE).await;
        let admin = session_for(&app.db, Role::Admin).await;
        let secret = "do-not-mirror-this-client-secret";
        let csrf = csrf_of(&app, &admin).await;
        let fields = [
            ("csrf", csrf.as_str()),
            ("issuer", "https://id.example.test/realms/home"),
            ("client_id", "rackhand-hub"),
            ("client_secret", secret),
            ("redirect_url", "https://hub.example.test/sign-in/oidc/callback"),
        ];
        let resp = send(&app.router, post("/settings/oidc", &admin, &fields)).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        // The settings (mirrored to git) hold only a reference; the value is sealed in the Vault.
        let config = crate::library::config::current(&app.db, "hub").unwrap().unwrap();
        assert!(config.contains("client_secret = \"secret:oidc.client_secret\""), "{config}");
        assert!(!config.contains(secret));
        let sealed: i64 = app
            .db
            .readers()
            .with(|c| c.query_row("SELECT count(*) FROM secrets WHERE name = 'oidc.client_secret'", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(sealed, 1);
        let leaked: i64 = app
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT count(*) FROM audit_log WHERE data LIKE ?1", [format!("%{secret}%")], |r| r.get(0))
            })
            .unwrap();
        assert_eq!(leaked, 0, "not in the audit log");
        let page = text(send(&app.router, get("/settings", &admin)).await).await;
        assert!(page.contains("https://id.example.test/realms/home") && !page.contains(secret));
        // Saving again without a secret keeps the stored one; plain http is refused for a provider off this host.
        let csrf = csrf_of(&app, &admin).await;
        let keep = [
            ("csrf", csrf.as_str()),
            ("issuer", "https://id.example.test/realms/home"),
            ("client_id", "rackhand-hub"),
            ("client_secret", ""),
            ("redirect_url", "https://hub.example.test/sign-in/oidc/callback"),
        ];
        assert_eq!(send(&app.router, post("/settings/oidc", &admin, &keep)).await.status(), StatusCode::SEE_OTHER);
        let sealed: i64 = app
            .db
            .readers()
            .with(|c| c.query_row("SELECT count(*) FROM secrets WHERE name = 'oidc.client_secret'", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(sealed, 1);
        let csrf = csrf_of(&app, &admin).await;
        let plain = [
            ("csrf", csrf.as_str()),
            ("issuer", "http://id.example.test"),
            ("client_id", "rackhand-hub"),
            ("client_secret", secret),
            ("redirect_url", "https://hub.example.test/sign-in/oidc/callback"),
        ];
        assert_eq!(send(&app.router, post("/settings/oidc", &admin, &plain)).await.status(), StatusCode::BAD_REQUEST);
    }
}

mod pages {
    use super::*;
    use crate::library::items::{Kind, Library};
    use crate::policy::approvals::{ApprovalRequest, Approvals, approval_hash};
    use rackhand_runbook::runbook::Risk;

    fn request(risk: Risk) -> ApprovalRequest {
        ApprovalRequest {
            requester: "job:01JASSISTANTJOBAAAAAAAAAAA".into(),
            tool: "run_runbook".into(),
            target: Some("m1".into()),
            args: serde_json::json!({ "name": "restart-web", "params": { "unit": "nginx.service" } }),
            runbook_rev: Some(3),
            risk,
            step_up: risk == Risk::High,
            reason: "nginx keeps failing its health check".into(),
        }
    }

    async fn approval(app: &App, risk: Risk) -> String {
        Approvals::new(app.db.clone()).create(&request(risk), now_ms(), 3_600_000).await.unwrap()
    }

    fn state(app: &App, id: &str) -> String {
        app.db.readers().with(|c| c.query_row("SELECT state FROM approvals WHERE id = ?1", [id], |r| r.get(0))).unwrap()
    }

    async fn decide(app: &App, cookie: &str, id: &str, verb: &str) -> Response<Body> {
        let csrf = csrf_of(app, cookie).await;
        send(&app.router, post(&format!("/approvals/{id}/{verb}"), cookie, &[("csrf", csrf.as_str())])).await
    }

    async fn machine(app: &App) {
        app.db
            .writer()
            .send(WriteCmd::Batch(vec![RowWrite::insert(
                "machines",
                Row::from([
                    ("id", Value::Text("m1".into())),
                    ("site_id", Value::Text(site_id(&app.db))),
                    ("name", Value::Text("web".into())),
                    ("kind", Value::Text("linux".into())),
                ]),
            )]))
            .await
            .unwrap();
    }

    fn site_id(db: &Db) -> String {
        db.readers().with(|c| c.query_row("SELECT id FROM sites LIMIT 1", [], |r| r.get(0))).unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn approval_shows_exact_arguments_and_hash() {
        let app = app("approval-page").await;
        complete_first_run(&app, SETUP_CODE).await;
        let id = approval(&app, Risk::Normal).await;
        let responder = session_for(&app.db, Role::Responder).await;
        let html = text(send(&app.router, get("/approvals", &responder)).await).await;
        let hash: String = approval_hash(&request(Risk::Normal)).iter().map(|b| format!("{b:02x}")).collect();
        for shown in [
            id.as_str(),
            "run_runbook",
            "m1",
            "restart-web",
            "unit",
            "nginx.service",
            "normal",
            "job:01JASSISTANTJOBAAAAAAAAAAA",
            "nginx keeps failing its health check",
            "revision 3",
            hash.as_str(),
        ] {
            assert!(html.contains(shown), "{shown} not on the page");
        }
        assert!(html.contains(&format!("action=\"/approvals/{id}/approve\"")) && html.contains("/reject\""));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dashboard_decision_publishes_approval_decided() {
        let bus = crate::bus::Bus::new();
        let mut events = bus.subscribe("test");
        let b = bus.clone();
        let app = app_with("approval-bus", move |web| web.with_bus(b)).await;
        complete_first_run(&app, SETUP_CODE).await;
        let id = approval(&app, Risk::Normal).await;
        let responder = session_for(&app.db, Role::Responder).await;
        assert_eq!(decide(&app, &responder, &id, "reject").await.status(), StatusCode::SEE_OTHER);
        let want = ulid::Ulid::from_string(&id).unwrap().to_bytes();
        match tokio::time::timeout(std::time::Duration::from_secs(2), events.recv()).await.unwrap() {
            Some(crate::bus::Delivery::Event(crate::bus::BusEvent::ApprovalDecided { id, approved })) => {
                assert_eq!((id, approved), (want, false));
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn high_risk_approve_prompts_step_up() {
        let app = app("approval-high").await;
        complete_first_run(&app, SETUP_CODE).await;
        let id = approval(&app, Risk::High).await;
        let admin = session_for(&app.db, Role::Admin).await;
        let resp = decide(&app, &admin, &id, "approve").await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&resp).as_deref(), Some("/step-up"), "a step-up first");
        assert_eq!(state(&app, &id), "pending");
        let token = admin.split_once('=').unwrap().1;
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        session::set_step_up(&app.db, &hash, now_ms()).await.unwrap();
        let resp = decide(&app, &admin, &id, "approve").await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&resp).as_deref(), Some("/approvals"));
        assert_eq!(state(&app, &id), "approved");
        let audited: i64 = app
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT count(*) FROM audit_log WHERE action = 'approval.approved' AND target = ?1",
                    [&id],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(audited, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn viewer_cannot_approve_responder_cannot_approve_high() {
        let app = app("approval-roles").await;
        complete_first_run(&app, SETUP_CODE).await;
        let normal = approval(&app, Risk::Normal).await;
        let high = approval(&app, Risk::High).await;
        let viewer = session_for(&app.db, Role::Viewer).await;
        assert_eq!(decide(&app, &viewer, &normal, "approve").await.status(), StatusCode::FORBIDDEN);
        let responder = session_for(&app.db, Role::Responder).await;
        assert_eq!(decide(&app, &responder, &high, "approve").await.status(), StatusCode::FORBIDDEN);
        assert_eq!((state(&app, &normal), state(&app, &high)), ("pending".to_string(), "pending".to_string()));
        // A responder may approve normal risk, and the viewer's page shows no buttons.
        assert_eq!(decide(&app, &responder, &normal, "approve").await.status(), StatusCode::SEE_OTHER);
        let page = text(send(&app.router, get("/approvals", &viewer)).await).await;
        assert!(!page.contains("/approve\""), "no approve button for a viewer");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn second_decision_shows_already_decided() {
        let app = app("approval-twice").await;
        complete_first_run(&app, SETUP_CODE).await;
        let id = approval(&app, Risk::Normal).await;
        let first = session_for(&app.db, Role::Admin).await;
        let second = session_for(&app.db, Role::Admin).await;
        assert_eq!(decide(&app, &first, &id, "approve").await.status(), StatusCode::SEE_OTHER);
        let late = decide(&app, &second, &id, "reject").await;
        assert_eq!(late.status(), StatusCode::CONFLICT);
        assert!(text(late).await.contains("already decided"));
        assert_eq!(state(&app, &id), "approved");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn job_page_shows_commands_exit_codes_output() {
        let app = app("job-page").await;
        complete_first_run(&app, SETUP_CODE).await;
        machine(&app).await;
        let mut output = vec![b'a'; 1000];
        output.extend_from_slice(crate::ssh::client::TRUNCATED.as_bytes());
        app.db
            .writer()
            .send(WriteCmd::Batch(vec![
                RowWrite::insert(
                    "jobs",
                    Row::from([
                        ("id", Value::Text("01JOBPAGEAAAAAAAAAAAAAAAAA".into())),
                        ("kind", Value::Text("runbook".into())),
                        ("name", Value::Text("restart-web".into())),
                        ("target", Value::Text("m1".into())),
                        ("requested_by", Value::Text("admin".into())),
                        ("state", Value::Text("failed".into())),
                        ("outcome", Value::Text("exit_code 3".into())),
                        ("started_at", Value::Integer(now_ms())),
                    ]),
                ),
                RowWrite::insert(
                    "job_steps",
                    Row::from([
                        ("job_id", Value::Text("01JOBPAGEAAAAAAAAAAAAAAAAA".into())),
                        ("step_id", Value::Text("restart".into())),
                        ("state", Value::Text("failed".into())),
                        (
                            "command",
                            Value::Text(
                                "sudo /usr/local/lib/rackhand/run /usr/bin/systemctl restart nginx.service".into(),
                            ),
                        ),
                        ("exit_code", Value::Integer(3)),
                        ("stdout", Value::Blob(output)),
                        ("stderr", Value::Blob(b"<script>alert(1)</script>".to_vec())),
                    ]),
                ),
            ]))
            .await
            .unwrap();
        let viewer = session_for(&app.db, Role::Viewer).await;
        let list = text(send(&app.router, get("/jobs", &viewer)).await).await;
        assert!(list.contains("restart-web") && list.contains("/jobs/01JOBPAGEAAAAAAAAAAAAAAAAA"));
        let page = text(send(&app.router, get("/jobs/01JOBPAGEAAAAAAAAAAAAAAAAA", &viewer)).await).await;
        assert!(page.contains("systemctl restart nginx.service"));
        assert!(page.contains("exit code 3"), "{page}");
        assert!(page.contains("[rackhand: output truncated at 1 MiB]"));
        assert!(!page.contains("<script>alert(1)"), "output is escaped");
        assert_eq!(
            send(&app.router, get("/jobs/01JNOSUCHJOBAAAAAAAAAAAAAA", &viewer)).await.status(),
            StatusCode::NOT_FOUND
        );
    }

    const RB1: &str = "name = \"restart-web\"\ndescription = \"Restart the web service\"\nidentity = \"automation\"\nrisk = \"low\"\nautonomy = 1\n[[step]]\nid = \"restart\"\nkind = \"ssh\"\ncmd = [\"sudo\", \"/usr/local/lib/rackhand/run\", \"/usr/bin/systemctl\", \"restart\", \"nginx.service\"]\n";

    #[tokio::test(flavor = "multi_thread")]
    async fn library_diff_and_validation_errors() {
        let app = app("library-page").await;
        complete_first_run(&app, SETUP_CODE).await;
        let admin = session_for(&app.db, Role::Admin).await;
        let save = |content: String| {
            let router = app.router.clone();
            let admin = admin.clone();
            async move {
                let csrf = {
                    let html = text(router.clone().oneshot(get("/library", &admin)).await.unwrap()).await;
                    field(&html, "csrf")
                };
                router
                    .oneshot(post(
                        "/library/runbook/restart-web",
                        &admin,
                        &[("csrf", csrf.as_str()), ("content", content.as_str())],
                    ))
                    .await
                    .unwrap()
            }
        };
        assert_eq!(save(RB1.to_string()).await.status(), StatusCode::SEE_OTHER);
        assert_eq!(save(RB1.replace("nginx.service", "apache2.service")).await.status(), StatusCode::SEE_OTHER);
        let diff = text(send(&app.router, get("/library/runbook/restart-web?diff=1", &admin)).await).await;
        assert!(diff.contains("revision 1") && diff.contains("revision 2"), "{diff}");
        assert!(diff.contains("class=\"del\"") && diff.contains("nginx.service"));
        assert!(diff.contains("class=\"add\"") && diff.contains("apache2.service"));
        // A runbook that doesn't validate isn't stored; the error is shown with the content kept.
        let bad = save(RB1.replace("risk = \"low\"\n", "")).await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        let shown = text(bad).await;
        assert!(shown.contains("risk"), "{shown}");
        assert!(shown.contains("Restart the web service"), "the content is kept for fixing");
        let (rev, _) = Library::current_in(&app.db, Kind::Runbook, "restart-web").unwrap().unwrap();
        assert_eq!(rev, 2);
        // A draft from an assistant is listed and applied by an admin.
        let (library, _) = Library::new(app.db.clone(), Audit::new(app.db.writer()));
        let draft = library
            .propose(
                Kind::Runbook,
                "restart-web",
                &RB1.replace("nginx.service", "caddy.service"),
                "job:01JDRAFT",
                "caddy",
                now_ms(),
            )
            .await
            .unwrap();
        let page = text(send(&app.router, get("/library", &admin)).await).await;
        assert!(page.contains(&draft) && page.contains("job:01JDRAFT"));
        let csrf = csrf_of(&app, &admin).await;
        let resp =
            send(&app.router, post(&format!("/library/drafts/{draft}/apply"), &admin, &[("csrf", csrf.as_str())]))
                .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert!(
            Library::current_in(&app.db, Kind::Runbook, "restart-web").unwrap().unwrap().1.contains("caddy.service")
        );
        // A responder can read but not edit.
        let responder = session_for(&app.db, Role::Responder).await;
        let csrf = csrf_of(&app, &responder).await;
        let resp = send(
            &app.router,
            post("/library/runbook/restart-web", &responder, &[("csrf", csrf.as_str()), ("content", RB1)]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn nothing_waiting_empty_state() {
        let app = app("approvals-empty").await;
        complete_first_run(&app, SETUP_CODE).await;
        let viewer = session_for(&app.db, Role::Viewer).await;
        let page = text(send(&app.router, get("/approvals", &viewer)).await).await;
        assert!(page.contains("Nothing waiting"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn policy_and_window_editing_admin_only_revisioned() {
        let app = app("policies").await;
        complete_first_run(&app, SETUP_CODE).await;
        machine(&app).await;
        let admin = session_for(&app.db, Role::Admin).await;
        let csrf = csrf_of(&app, &admin).await;
        let policy = [
            ("csrf", csrf.as_str()),
            ("name", "web-servers"),
            ("patch", "auto"),
            ("auto_reboot", "on"),
            ("snapshot", "required"),
            ("quarantine", "approval"),
            ("peer_requests", "approval"),
        ];
        assert_eq!(send(&app.router, post("/policies", &admin, &policy)).await.status(), StatusCode::SEE_OTHER);
        let (patch, reboot): (String, i64) = app
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT patch, auto_reboot FROM policies WHERE name = 'web-servers'", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
            })
            .unwrap();
        assert_eq!((patch.as_str(), reboot), ("auto", 1));
        let csrf = csrf_of(&app, &admin).await;
        let window = [
            ("csrf", csrf.as_str()),
            ("machine", "m1"),
            ("rrule", "weekly sun 03:00 120m"),
            ("timezone", "Europe/Berlin"),
        ];
        assert_eq!(send(&app.router, post("/windows", &admin, &window)).await.status(), StatusCode::SEE_OTHER);
        let windows: i64 = app
            .db
            .readers()
            .with(|c| c.query_row("SELECT count(*) FROM windows WHERE machine_id = 'm1'", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(windows, 1);
        // Both are a revision of `config/policies.toml`, which the git mirror carries.
        let config = crate::library::config::current(&app.db, "policies").unwrap().unwrap();
        assert!(config.contains("web-servers") && config.contains("weekly sun 03:00 120m"), "{config}");
        let files = crate::library::mirror::render(&app.db).unwrap();
        assert!(files.get("config/policies.toml").is_some_and(|f| f.contains("web-servers")));
        let revs: i64 = app
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT count(*) FROM library_revisions WHERE kind = 'config' AND name = 'policies'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(revs, 2, "one revision per change");
        let patching = text(send(&app.router, get("/patching", &admin)).await).await;
        assert!(patching.contains("web-servers") && patching.contains("weekly sun 03:00 120m"));
        // A bad rule is refused; a responder can't edit either.
        let csrf = csrf_of(&app, &admin).await;
        let bad =
            [("csrf", csrf.as_str()), ("machine", "m1"), ("rrule", "every sunday"), ("timezone", "Europe/Berlin")];
        assert_eq!(send(&app.router, post("/windows", &admin, &bad)).await.status(), StatusCode::BAD_REQUEST);
        let responder = session_for(&app.db, Role::Responder).await;
        let csrf = csrf_of(&app, &responder).await;
        let mut theirs = policy.to_vec();
        theirs[0] = ("csrf", csrf.as_str());
        assert_eq!(send(&app.router, post("/policies", &responder, &theirs)).await.status(), StatusCode::FORBIDDEN);
    }

    #[derive(Debug)]
    struct Roomy;

    impl crate::ingest::DiskSpace for Roomy {
        fn free_fraction(&self) -> f64 {
            0.5
        }
    }

    /// An app whose `Web` reads vitals and facts from an `Ingest` on its own database.
    async fn monitored(name: &str) -> (App, crate::ingest::Ingest) {
        let slot: Arc<std::sync::Mutex<Option<crate::ingest::Ingest>>> = Arc::default();
        let keep = slot.clone();
        let app = app_with(name, move |web| {
            let ingest = crate::ingest::Ingest::new(web.0.db.clone(), crate::bus::Bus::new(), Arc::new(Roomy));
            *keep.lock().unwrap() = Some(ingest.clone());
            web.with_ingest(ingest)
        })
        .await;
        let ingest = slot.lock().unwrap().take().unwrap();
        (app, ingest)
    }

    async fn monitor_machine(app: &App, id: &str, access: &str) {
        app.db
            .writer()
            .send(WriteCmd::Batch(vec![RowWrite::insert(
                "machines",
                Row::from([
                    ("id", Value::Text(id.into())),
                    ("site_id", Value::Text(site_id(&app.db))),
                    ("name", Value::Text("web".into())),
                    ("kind", Value::Text("linux".into())),
                    ("os", Value::Text("Debian 12".into())),
                    ("access", Value::Text(access.into())),
                    ("state", Value::Text("enrolled".into())),
                ]),
            )]))
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn overview_empty_state_offers_add_machine() {
        let (app, _ingest) = monitored("overview-empty").await;
        complete_first_run(&app, SETUP_CODE).await;
        let viewer = session_for(&app.db, Role::Viewer).await;
        let html = text(send(&app.router, get("/", &viewer)).await).await;
        assert!(html.contains("No machines yet"), "{html}");
        assert!(html.contains("href=\"/add\""));
        assert!(html.contains("No open incidents"), "the incident summary has an empty state too");
    }

    const M: &str = "01JD0000000000000000000001";

    #[tokio::test(flavor = "multi_thread")]
    async fn machine_page_shows_capture_method_and_access_level() {
        let (app, ingest) = monitored("machine-page").await;
        complete_first_run(&app, SETUP_CODE).await;
        monitor_machine(&app, M, "monitor").await;
        ingest.set_capabilities(M, &[rackhand_proto::probe::Capability::Ebpf as i32]);
        let viewer = session_for(&app.db, Role::Viewer).await;
        let resp = send(&app.router, get(&format!("/machines/{M}"), &viewer)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let html = text(resp).await;
        assert!(html.contains("Capture: eBPF"), "{html}");
        assert!(html.contains("Access: monitor"));
        assert!(html.contains("Debian 12"));
        assert!(html.contains(&format!("hx-get=\"/machines/{M}/vitals\"")), "the chart refreshes with htmx");
        // the htmx partial draws a line for each metric with data
        for i in 0..5u64 {
            let at = now_ms() - (5 - i as i64) * 15_000;
            let r = rackhand_proto::probe::Report {
                epoch: 1,
                seq: i + 1,
                sampled_at_ms: at,
                vitals: vec![rackhand_proto::probe::Sample { metric: 1, labels_id: 0, value: i as f64 }],
                ..Default::default()
            };
            ingest.hello(M, 1, &[rackhand_proto::common::LabelEntry::default()]).await.unwrap();
            ingest.receive(M, crate::ingest::Stream::Live, vec![r], 100, at).await.unwrap();
        }
        let partial = text(send(&app.router, get(&format!("/machines/{M}/vitals"), &viewer)).await).await;
        assert!(partial.contains("cpu.busy_pct") && partial.contains("<polyline"), "{partial}");
        let missing = send(&app.router, get("/machines/01JD00000000000000000000ZZ", &viewer)).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn silent_machine_shows_since() {
        let (app, _ingest) = monitored("silent-page").await;
        complete_first_run(&app, SETUP_CODE).await;
        monitor_machine(&app, M, "managed").await;
        let opened = 1_795_068_000_000i64;
        let incident = Row::from([
            ("id", Value::Text("01JD00000000000000000000I1".into())),
            ("machine_id", Value::Text(M.into())),
            ("rule_id", Value::Text("machine.silent".into())),
            ("dedupe_key", Value::Text(format!("{M}:machine.silent:{{}}"))),
            ("kind", Value::Text("machine.silent".into())),
            ("severity", Value::Text("warning".into())),
            ("state", Value::Text("open".into())),
            ("title", Value::Text("No report from the machine".into())),
            ("opened_at", Value::Integer(opened)),
        ]);
        app.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("incidents", incident)])).await.unwrap();
        let viewer = session_for(&app.db, Role::Viewer).await;
        let html = text(send(&app.router, get(&format!("/machines/{M}"), &viewer)).await).await;
        assert!(html.contains("Probe silent since 2026-11-19T06:00:00Z"), "{html}");
        let overview = text(send(&app.router, get("/", &viewer)).await).await;
        assert!(overview.contains("silent"), "the overview shows it too");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn audit_page_shows_broken_chain_banner() {
        let (app, _ingest) = monitored("audit-page").await;
        complete_first_run(&app, SETUP_CODE).await;
        let admin = session_for(&app.db, Role::Admin).await;
        let html = text(send(&app.router, get("/audit", &admin)).await).await;
        assert!(html.contains("The chain verifies"), "{html}");
        assert!(!html.contains("class=\"banner critical\""));
        let conn = rusqlite::Connection::open(app.db_path()).unwrap();
        conn.execute(
            "UPDATE audit_log SET data = '{\"changed\":true}' WHERE seq = (SELECT min(seq) FROM audit_log)",
            [],
        )
        .unwrap();
        let html = text(send(&app.router, get("/audit", &admin)).await).await;
        assert!(html.contains("class=\"banner critical\""), "{html}");
        assert!(html.contains("changed"), "names the broken row");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn notifier_send_test_sends_one_message() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let hook = axum::Router::new().route(
            "/hook",
            axum::routing::post(move |body: String| {
                let counter = counter.clone();
                async move {
                    assert!(body.contains("Test message from Rackhand"), "{body}");
                    counter.fetch_add(1, Ordering::Relaxed);
                    axum::http::StatusCode::NO_CONTENT
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, hook).await.unwrap() });
        let app = app_with("notifier-test", move |web| {
            let ingest = crate::ingest::Ingest::new(web.0.db.clone(), crate::bus::Bus::new(), Arc::new(Roomy));
            let discord: Arc<dyn crate::notify::Transport> =
                Arc::new(crate::notify::discord::Discord::new("discord", &url));
            let notify = crate::notify::Notify::new(web.0.db.clone(), ingest.clone(), vec![discord]);
            web.with_ingest(ingest).with_notify(notify)
        })
        .await;
        complete_first_run(&app, SETUP_CODE).await;
        let admin = session_for(&app.db, Role::Admin).await;
        let html = text(send(&app.router, get("/settings/notifiers", &admin)).await).await;
        assert!(html.contains("discord") && html.contains("Send test"), "{html}");
        let csrf = csrf_of(&app, &admin).await;
        let resp = send(&app.router, post("/settings/notifiers/test", &admin, &[("csrf", csrf.as_str())])).await;
        assert!(resp.status().is_success() || resp.status() == StatusCode::SEE_OTHER, "{}", resp.status());
        assert_eq!(hits.load(Ordering::Relaxed), 1, "one message");
    }

    fn count(app: &App, sql: &str, arg: &str) -> i64 {
        app.db.readers().with(|c| c.query_row(sql, [arg], |r| r.get(0))).unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn notifier_added_from_settings_keeps_the_url_in_the_vault() {
        type Changes = tokio::sync::mpsc::UnboundedReceiver<crate::library::items::Change>;
        let slot: Arc<std::sync::Mutex<Option<Changes>>> = Arc::default();
        let keep = slot.clone();
        let app = app_with("notifier-add", move |web| {
            let (library, changes) = crate::library::items::Library::new(web.0.db.clone(), web.0.audit.clone());
            *keep.lock().unwrap() = Some(changes);
            web.with_library(library)
        })
        .await;
        let mut changes = slot.lock().unwrap().take().unwrap();
        complete_first_run(&app, SETUP_CODE).await;
        let admin = session_for(&app.db, Role::Admin).await;
        let url = "https://discord.example.test/api/webhooks/1/do-not-mirror-this-token";
        let csrf = csrf_of(&app, &admin).await;
        let discord = [("csrf", csrf.as_str()), ("kind", "discord"), ("name", "ops"), ("webhook", url)];
        assert_eq!(
            send(&app.router, post("/settings/notifiers", &admin, &discord)).await.status(),
            StatusCode::SEE_OTHER
        );
        let password = "do-not-mirror-this-password";
        let csrf = csrf_of(&app, &admin).await;
        let smtp = [
            ("csrf", csrf.as_str()),
            ("kind", "smtp"),
            ("name", "mail"),
            ("host", "smtp.example.test"),
            ("port", "587"),
            ("security", "starttls"),
            ("username", "hub@example.test"),
            ("password", password),
            ("from", "hub@example.test"),
            ("to", "ops@example.test, owner@example.test"),
        ];
        assert_eq!(send(&app.router, post("/settings/notifiers", &admin, &smtp)).await.status(), StatusCode::SEE_OTHER);

        // The file (mirrored to git) holds only references; the values are sealed in the Vault.
        let text_now = crate::library::config::current(&app.db, "notifiers").unwrap().expect("config/notifiers saved");
        let file = crate::notify::config::parse(&text_now).unwrap();
        assert_eq!(file.discord.len(), 1);
        assert_eq!(file.discord[0].webhook, "secret:notifier.ops.webhook");
        assert_eq!(file.smtp.len(), 1);
        assert_eq!(file.smtp[0].password.as_deref(), Some("secret:notifier.mail.password"));
        assert_eq!(file.smtp[0].to, vec!["ops@example.test".to_string(), "owner@example.test".to_string()]);
        assert!(!text_now.contains(url) && !text_now.contains(password), "{text_now}");
        let vault = Vault::new(MasterKey::from_bytes([3u8; 32]), app.db.clone());
        let secret = |name: &str| vault.get(name).ok().map(|s| String::from_utf8_lossy(s.expose()).into_owned());
        assert_eq!(secret("notifier.ops.webhook").as_deref(), Some(url));
        assert_eq!(secret("notifier.mail.password").as_deref(), Some(password));
        assert_eq!(crate::notify::config::build(&file, &secret, None).unwrap().len(), 2, "the hub can build both");
        for leaked in [url, password] {
            let pattern = format!("%{leaked}%");
            assert_eq!(count(&app, "SELECT count(*) FROM audit_log WHERE data LIKE ?1", &pattern), 0);
        }
        assert_eq!(count(&app, "SELECT count(*) FROM audit_log WHERE action = ?1", "settings.notifier"), 2);
        let change = changes.try_recv().expect("the change reaches the mirror");
        assert!(change.summary.contains("config/notifiers"), "{change:?}");

        // The page lists the saved notifiers and says they apply when the hub restarts.
        let page = text(send(&app.router, get("/settings/notifiers", &admin)).await).await;
        assert!(page.contains("ops") && page.contains("mail") && page.contains("restart"), "{page}");
        assert!(!page.contains(url) && !page.contains(password));

        // Saving a name again replaces it; an empty secret keeps the stored one.
        let csrf = csrf_of(&app, &admin).await;
        let again = [("csrf", csrf.as_str()), ("kind", "discord"), ("name", "ops"), ("webhook", "")];
        assert_eq!(
            send(&app.router, post("/settings/notifiers", &admin, &again)).await.status(),
            StatusCode::SEE_OTHER
        );
        let file =
            crate::notify::config::parse(&crate::library::config::current(&app.db, "notifiers").unwrap().unwrap())
                .unwrap();
        assert_eq!(file.discord.len(), 1, "replaced, not added");
        assert_eq!(secret("notifier.ops.webhook").as_deref(), Some(url));

        // Refused: a plain http webhook off this host (D113), a bad name, an unknown security, no recipients,
        // a new notifier without its secret, and a viewer.
        let bad: [&[(&str, &str)]; 5] = [
            &[("kind", "discord"), ("name", "plain"), ("webhook", "http://discord.example.test/hook")],
            &[("kind", "discord"), ("name", "Ops!"), ("webhook", url)],
            &[
                ("kind", "smtp"),
                ("name", "m2"),
                ("host", "h.example.test"),
                ("port", "25"),
                ("security", "none"),
                ("from", "a@example.test"),
                ("to", "b@example.test"),
            ],
            &[
                ("kind", "smtp"),
                ("name", "m3"),
                ("host", "h.example.test"),
                ("port", "465"),
                ("security", "tls"),
                ("from", "a@example.test"),
                ("to", " "),
            ],
            &[("kind", "discord"), ("name", "new"), ("webhook", "")],
        ];
        for fields in bad {
            let csrf = csrf_of(&app, &admin).await;
            let mut all = vec![("csrf", csrf.as_str())];
            all.extend_from_slice(fields);
            let resp = send(&app.router, post("/settings/notifiers", &admin, &all)).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{fields:?}");
        }
        let viewer = session_for(&app.db, Role::Viewer).await;
        let csrf = csrf_of(&app, &viewer).await;
        let resp =
            send(&app.router, post("/settings/notifiers", &viewer, &[("csrf", csrf.as_str()), ("kind", "discord")]))
                .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let file =
            crate::notify::config::parse(&crate::library::config::current(&app.db, "notifiers").unwrap().unwrap())
                .unwrap();
        assert_eq!((file.discord.len(), file.smtp.len()), (1, 1), "nothing refused was saved");
    }
}

mod metrics {
    use super::*;

    #[derive(Debug)]
    struct Roomy;

    impl crate::ingest::DiskSpace for Roomy {
        fn free_fraction(&self) -> f64 {
            0.5
        }
    }

    const TOKEN: &str = "metrics-token-for-tests";

    /// What the app's builder hands back to the test.
    type Slot = Arc<std::sync::Mutex<Option<(crate::ingest::Ingest, Arc<Vault>)>>>;

    /// 3 machines with 10 series each (cpu, memory, load and a disk), reported a moment ago.
    async fn app_with_series(name: &str) -> App {
        let slot: Slot = Arc::default();
        let keep = slot.clone();
        let app = app_with(name, move |web| {
            let ingest = crate::ingest::Ingest::new(web.0.db.clone(), crate::bus::Bus::new(), Arc::new(Roomy));
            *keep.lock().unwrap() = Some((ingest.clone(), web.0.vault.clone()));
            web.with_ingest(ingest)
        })
        .await;
        let (ingest, vault) = slot.lock().unwrap().take().unwrap();
        vault.put("metrics_token", &crate::vault::Secret::from(TOKEN)).await.unwrap();
        complete_first_run(&app, SETUP_CODE).await;
        let site: String =
            app.db.readers().with(|c| c.query_row("SELECT id FROM sites LIMIT 1", [], |r| r.get(0))).unwrap();
        let now = now_ms();
        for (i, machine) in ["01JD0000000000000000000001", "01JD0000000000000000000002", "01JD0000000000000000000003"]
            .iter()
            .enumerate()
        {
            let row = Row::from([
                ("id", Value::Text((*machine).into())),
                ("site_id", Value::Text(site.clone())),
                ("name", Value::Text(format!("m{i}"))),
                ("kind", Value::Text("linux".into())),
                ("state", Value::Text("enrolled".into())),
            ]);
            app.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("machines", row)])).await.unwrap();
            let table = vec![
                rackhand_proto::common::LabelEntry::default(),
                rackhand_proto::common::LabelEntry { id: 1, labels: [("mount".to_string(), "/".to_string())].into() },
            ];
            ingest.hello(machine, 1, &table).await.unwrap();
            // 8 unlabelled metrics and 2 disk metrics labelled by mount
            let mut vitals: Vec<rackhand_proto::probe::Sample> = [1u32, 2, 3, 5, 6, 7, 10, 12]
                .iter()
                .map(|m| rackhand_proto::probe::Sample { metric: *m, labels_id: 0, value: 1.5 })
                .collect();
            vitals.push(rackhand_proto::probe::Sample { metric: 18, labels_id: 1, value: 40.0 });
            vitals.push(rackhand_proto::probe::Sample { metric: 16, labels_id: 1, value: 4096.0 });
            let r =
                rackhand_proto::probe::Report { epoch: 1, seq: 1, sampled_at_ms: now, vitals, ..Default::default() };
            ingest.receive(machine, crate::ingest::Stream::Live, vec![r], 100, now).await.unwrap();
        }
        app
    }

    fn bearer(token: &str) -> Request<Body> {
        Request::builder()
            .uri("/metrics")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn without_token_401() {
        let app = app_with_series("metrics-401").await;
        let none = send(&app.router, Request::builder().uri("/metrics").body(Body::empty()).unwrap()).await;
        assert_eq!(none.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(send(&app.router, bearer("wrong")).await.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(send(&app.router, bearer(TOKEN)).await.status(), StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn with_token_every_series_latest_value() {
        let app = app_with_series("metrics-series").await;
        let body = text(send(&app.router, bearer(TOKEN)).await).await;
        let series: Vec<&str> =
            body.lines().filter(|l| !l.starts_with('#') && !l.starts_with("rackhand_hub_")).collect();
        assert_eq!(series.len(), 30, "{body}");
        assert!(series.iter().all(|l| l.contains("site=\"") && l.contains("machine=\"m")), "{body}");
        assert!(body.contains("rackhand_disk_used_pct{site=\"home\",machine=\"m0\",mount=\"/\"} 40"), "{body}");
        assert!(body.contains("rackhand_cpu_busy_pct{site=\"home\",machine=\"m2\"} 1.5"), "{body}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hub_internals_present() {
        let app = app_with_series("metrics-internals").await;
        let body = text(send(&app.router, bearer(TOKEN)).await).await;
        for name in [
            "rackhand_hub_ingest_reports_total",
            "rackhand_hub_ingest_lag_seconds",
            "rackhand_hub_staging_rows",
            "rackhand_hub_jobs_running",
            "rackhand_hub_db_size_bytes",
            "rackhand_hub_notifier_failures_total",
            "rackhand_hub_peer_up",
            "rackhand_hub_operator_up",
        ] {
            assert!(body.contains(&format!("# TYPE {name} ")), "{name} missing:\n{body}");
        }
        assert!(body.contains("rackhand_hub_ingest_reports_total 3\n"), "{body}");
        assert!(body.contains("rackhand_hub_staging_rows 3\n"), "{body}");
    }

    /// The Prometheus text format (0.0.4), strictly: TYPE before its samples and once per name, then
    /// `name{label="value",...} number` lines.
    fn parse(body: &str) -> Result<usize, String> {
        let name_re = regex::Regex::new(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$").unwrap();
        let sample_re = regex::Regex::new(
            r#"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([a-zA-Z_][a-zA-Z0-9_]*="(\\.|[^"\\\n])*")(,[a-zA-Z_][a-zA-Z0-9_]*="(\\.|[^"\\\n])*")*\})? (-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?|NaN|\+Inf|-Inf)$"#,
        )
        .unwrap();
        let mut typed = std::collections::HashSet::new();
        let mut samples = 0;
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let mut parts = rest.split(' ');
                let (Some(name), Some(kind)) = (parts.next(), parts.next()) else { return Err(line.into()) };
                if !name_re.is_match(name) || !["gauge", "counter"].contains(&kind) || !typed.insert(name.to_string()) {
                    return Err(format!("bad TYPE: {line}"));
                }
            } else if line.starts_with("# HELP ") || line.is_empty() {
            } else if let Some(c) = sample_re.captures(line) {
                if !typed.contains(&c[1]) {
                    return Err(format!("sample before its TYPE: {line}"));
                }
                samples += 1;
            } else {
                return Err(format!("not a sample: {line}"));
            }
        }
        Ok(samples)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn output_parses_as_prometheus_text() {
        let app = app_with_series("metrics-parse").await;
        let body = text(send(&app.router, bearer(TOKEN)).await).await;
        let n = parse(&body).unwrap_or_else(|e| panic!("{e}\n{body}"));
        assert!(n >= 36, "{n} samples: 30 series and the hub's own");
        assert!(
            parse("cpu{a=\"b\"} 1").is_err() && parse("# TYPE x gauge\nx{a=\"b} 1").is_err(),
            "the checker rejects bad text"
        );
    }
}
