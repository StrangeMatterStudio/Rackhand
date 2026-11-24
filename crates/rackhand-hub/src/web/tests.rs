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

/// Opens the first-run page: the anonymous cookie and the CSRF token.
async fn open_first_run(app: &App) -> (String, String) {
    let resp = send(&app.router, get("/first-run", "")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = set_cookie(&resp, "rh_anon").expect("anonymous cookie").split(';').next().unwrap().to_string();
    let html = text(resp).await;
    (cookie, field(&html, "csrf"))
}

async fn complete_first_run(app: &App, setup_code: &str) -> Response<Body> {
    let opened = open_first_run(app).await;
    submit_first_run(app, opened, setup_code).await
}

async fn submit_first_run(app: &App, opened: (String, String), setup_code: &str) -> Response<Body> {
    submit_first_run_at(app, opened, setup_code, now_ms()).await
}

/// The first step: the details.
async fn submit_details(app: &App, opened: &(String, String), setup_code: &str) -> Response<Body> {
    let (cookie, csrf) = opened;
    let req = post(
        "/first-run",
        cookie,
        &[
            ("csrf", csrf.as_str()),
            ("setup_code", setup_code),
            ("admin_name", "admin"),
            ("password", "correct horse battery staple"),
            ("password_again", "correct horse battery staple"),
            ("site_name", "home"),
            ("timezone", "Europe/Berlin"),
            ("source_spamhaus", "on"),
            ("source_dbip", "on"),
        ],
    );
    send(&app.router, req).await
}

/// The second step: the authenticator code for the hub's clock at `at_ms`.
async fn submit_second_factor(app: &App, opened: &(String, String), secret: &str, at_ms: i64) -> Response<Body> {
    let code = totp::code(&totp::decode_base32(secret).unwrap(), at_ms / 1000);
    let fields = [("csrf", opened.1.as_str()), ("totp_code", code.as_str())];
    send(&app.router, post("/first-run/second-factor", &opened.0, &fields)).await
}

/// The key the second step shows.
async fn second_factor_key(app: &App, opened: &(String, String)) -> String {
    field(&text(send(&app.router, get("/first-run/second-factor", &opened.0)).await).await, "totp_secret")
}

/// Both steps, at `at_ms` by the hub's clock; the first step's answer when it isn't accepted.
async fn submit_first_run_at(app: &App, opened: (String, String), setup_code: &str, at_ms: i64) -> Response<Body> {
    let details = submit_details(app, &opened, setup_code).await;
    if location(&details).as_deref() != Some("/first-run/second-factor") {
        return details;
    }
    let secret = second_factor_key(app, &opened).await;
    submit_second_factor(app, &opened, &secret, at_ms).await
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
    // Two first runs at once (both second steps reached before either is sent) make one admin.
    let (one, two) = (open_first_run(&app).await, open_first_run(&app).await);
    let late = open_first_run(&app).await;
    let late_second = open_first_run(&app).await;
    for opened in [&one, &two, &late_second] {
        assert_eq!(submit_details(&app, opened, SETUP_CODE).await.status(), StatusCode::SEE_OTHER);
    }
    let (key_one, key_two) = (second_factor_key(&app, &one).await, second_factor_key(&app, &two).await);
    assert_ne!(key_one, key_two, "a key of its own each");
    let late_key = second_factor_key(&app, &late_second).await;
    let (a, b) = tokio::join!(
        submit_second_factor(&app, &one, &key_one, now_ms()),
        submit_second_factor(&app, &two, &key_two, now_ms())
    );
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
    let again = submit_second_factor(&app, &late_second, &late_key, now_ms()).await;
    assert_eq!(again.status(), StatusCode::SEE_OTHER, "nor a second step reached before and sent after");
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
    let (cookie, _) = open_first_run(&app).await;
    let no_token = send(&app.router, post("/first-run", &cookie, &[("setup_code", SETUP_CODE)])).await;
    assert_eq!(no_token.status(), StatusCode::FORBIDDEN, "first run");
    let no_token = send(&app.router, post("/first-run/second-factor", &cookie, &[("totp_code", "000000")])).await;
    assert_eq!(no_token.status(), StatusCode::FORBIDDEN, "its second step");
    assert!(!text(no_token).await.contains("totp_secret"));
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
    assert_eq!(
        html.matches("<script").count(),
        html.matches("<script src=\"/static/").count(),
        "only the page's own script tags: {html}"
    );
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

#[path = "first_run_tests.rs"]
mod first_run;

#[path = "forms_tests.rs"]
mod forms;

#[path = "shell_tests.rs"]
mod shell;

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
            ("password_again", "a long enough secret"),
        ];
        let resp = send(&app.router, post("/settings/users", &admin, &fields)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let shown = text(resp).await;
        assert!(shown.contains("otpauth://totp/"), "{shown}");
        let (id, role, disabled) = user_row(&app.db, "alice").expect("created");
        assert_eq!((role.as_str(), disabled), ("responder", None));
        let page = text(send(&app.router, get("/users", &admin)).await).await;
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
        // Listed on the users page, then revoked there.
        let admin = session_for(&app.db, Role::Admin).await;
        let page = text(send(&app.router, get("/users", &admin)).await).await;
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
    mod peers {
        include!("peer_pages_tests.rs");
    }
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
        assert!(html.contains(&format!("action=\"/approvals/{id}/approve\"")));
        // rejecting asks first
        let asked = text(send(&app.router, get(&format!("/approvals?confirm=reject:{id}"), &responder)).await).await;
        assert!(html.contains("confirm=reject") && asked.contains(&format!("action=\"/approvals/{id}/reject\"")));
    }

    /// Owner review (B4): an `exec` approval shows the line that runs on the machine, with the timeout that stops it.
    #[tokio::test(flavor = "multi_thread")]
    async fn exec_approval_shows_the_line_that_runs() {
        let app = app("approval-exec").await;
        complete_first_run(&app, SETUP_CODE).await;
        let exec = ApprovalRequest {
            tool: "exec".into(),
            args: serde_json::json!({ "command": "journalctl -u nginx | tail" }),
            runbook_rev: None,
            ..request(Risk::Normal)
        };
        Approvals::new(app.db.clone()).create(&exec, now_ms(), 3_600_000).await.unwrap();
        let responder = session_for(&app.db, Role::Responder).await;
        let html = text(send(&app.router, get("/approvals", &responder)).await).await;
        let html = shell::plain(&html);
        assert!(html.contains("Runs as"), "{html}");
        assert!(html.contains("timeout -k 5 600 sh -c 'journalctl -u nginx | tail'"), "{html}");
        approval(&app, Risk::Normal).await;
        let html = text(send(&app.router, get("/approvals", &responder)).await).await;
        assert_eq!(html.matches("Runs as").count(), 1, "only an exec has a line");
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
        assert!(shell::plain(&page).contains("systemctl restart nginx.service"));
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

    /// The configuration files (7.3.13: `config/checks.toml` and the others) are edited on the Library page too, with
    /// the same validation; the page lists them; only an admin edits them.
    #[tokio::test(flavor = "multi_thread")]
    async fn library_edits_configuration_files() {
        let app = app("library-config").await;
        complete_first_run(&app, SETUP_CODE).await;
        let admin = session_for(&app.db, Role::Admin).await;
        let page = text(send(&app.router, get("/library/config/checks", &admin)).await).await;
        assert!(page.contains("action=\"/library/config/checks\""), "an editor for a file not written yet: {page}");
        let checks = "[[check]]\nname = \"web\"\nkind = \"tcp\"\ntarget = \"192.0.2.20:22\"\n";
        let csrf = csrf_of(&app, &admin).await;
        let fields = [("csrf", csrf.as_str()), ("content", checks)];
        let resp = send(&app.router, post("/library/config/checks", &admin, &fields)).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(Library::current_in(&app.db, Kind::Config, "checks").unwrap().unwrap().1, checks);
        // validated as the file it is
        let csrf = csrf_of(&app, &admin).await;
        let bad = "[[check]]\nname = \"web\"\nkind = \"gopher\"\ntarget = \"x\"\n";
        let resp =
            send(&app.router, post("/library/config/checks", &admin, &[("csrf", csrf.as_str()), ("content", bad)]))
                .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(text(resp).await.contains("gopher"), "the reason");
        let listed = text(send(&app.router, get("/library", &admin)).await).await;
        assert!(listed.contains("/library/config/checks"), "listed: {listed}");
        // a responder reads it but doesn't edit it
        let responder = session_for(&app.db, Role::Responder).await;
        let csrf = csrf_of(&app, &responder).await;
        let resp = send(
            &app.router,
            post("/library/config/checks", &responder, &[("csrf", csrf.as_str()), ("content", checks)]),
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
    pub(super) struct Roomy;

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
    async fn patching_shows_pending_updates_per_machine() {
        let (app, ingest) = monitored("patching-pending").await;
        complete_first_run(&app, SETUP_CODE).await;
        let site = site_id(&app.db);
        let policy = |id: &str, patch: &str| {
            let row = Row::from([
                ("id", Value::Text(id.into())),
                ("name", Value::Text(format!("{id}-policy"))),
                ("patch", Value::Text(patch.into())),
            ]);
            RowWrite::insert("policies", row)
        };
        let machine = |id: &str, name: &str, policy: Option<&str>, state: &str| {
            let mut row = Row::from([
                ("id", Value::Text(id.into())),
                ("site_id", Value::Text(site.clone())),
                ("name", Value::Text(name.into())),
                ("kind", Value::Text("linux".into())),
                ("state", Value::Text(state.into())),
            ]);
            if let Some(p) = policy {
                row.insert("policy_id", Value::Text(p.into()));
            }
            RowWrite::insert("machines", row)
        };
        let ids: Vec<String> = (1..=5).map(|i| format!("01JD000000000000000000000{i}")).collect();
        app.db
            .writer()
            .send(WriteCmd::Batch(vec![
                policy("auto", "auto"),
                policy("held", "hold"),
                machine(&ids[0], "web<1>", Some("auto"), "enrolled"),
                machine(&ids[1], "db", Some("held"), "enrolled"),
                machine(&ids[2], "quiet", None, "enrolled"),
                machine(&ids[3], "current", Some("auto"), "enrolled"),
                machine(&ids[4], "gone", Some("auto"), "revoked"),
            ]))
            .await
            .unwrap();
        for (id, pending, security, reboot) in [(&ids[0], 7, 2, true), (&ids[1], 4, 1, false), (&ids[3], 0, 0, false)] {
            ingest.hello(id, 1, &[rackhand_proto::common::LabelEntry::default()]).await.unwrap();
            let updates = rackhand_proto::probe::UpdateSummary {
                pending,
                security,
                reboot_required: reboot,
                packages: vec!["openssl".into()],
            };
            let now = now_ms();
            let r = rackhand_proto::probe::Report {
                epoch: 1,
                seq: 1,
                sampled_at_ms: now,
                updates: Some(updates),
                ..Default::default()
            };
            ingest.receive(id, crate::ingest::Stream::Live, vec![r], 100, now).await.unwrap();
        }
        let viewer = session_for(&app.db, Role::Viewer).await;
        let html = text(send(&app.router, get("/patching", &viewer)).await).await;
        let row = |id: &str| {
            let from = html.find(&format!("/machines/{id}")).unwrap_or_else(|| panic!("no row for {id}: {html}"));
            html[from..].split("</tr>").next().unwrap().to_string()
        };
        let web = row(&ids[0]);
        assert!(web.contains("web&#60;1&#62;") && web.contains("auto-policy"), "{web}");
        assert_eq!(shell::cells(&web)[..3], ["7", "2", "yes"], "{web}");
        let db = row(&ids[1]);
        assert_eq!(shell::cells(&db)[..3], ["4", "1", "no"], "held updates are still shown (E10): {db}");
        assert!(db.contains("hold") && !web.contains("hold"), "the hold: {db}");
        assert!(row(&ids[2]).contains("not reported yet") && row(&ids[2]).contains("no policy"), "{}", row(&ids[2]));
        assert_eq!(shell::cells(&row(&ids[3]))[..3], ["0", "0", "no"]);
        assert!(!html.contains("gone"), "a revoked machine isn't patched");
    }

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
        assert!(shell::plain(&html).contains("Capture: eBPF"), "{html}");
        assert!(shell::plain(&html).contains("Access: monitor"));
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
    async fn machine_page_shows_updates() {
        let (app, ingest) = monitored("machine-updates").await;
        complete_first_run(&app, SETUP_CODE).await;
        monitor_machine(&app, M, "managed").await;
        let viewer = session_for(&app.db, Role::Viewer).await;
        ingest.hello(M, 1, &[rackhand_proto::common::LabelEntry::default()]).await.unwrap();
        let at = now_ms();
        let plain = rackhand_proto::probe::Report { epoch: 1, seq: 1, sampled_at_ms: at, ..Default::default() };
        ingest.receive(M, crate::ingest::Stream::Live, vec![plain], 100, at).await.unwrap();
        let html = text(send(&app.router, get(&format!("/machines/{M}"), &viewer)).await).await;
        assert!(html.contains("Updates not reported yet"), "{html}");
        let r = rackhand_proto::probe::Report {
            epoch: 1,
            seq: 2,
            sampled_at_ms: at + 15_000,
            updates: Some(rackhand_proto::probe::UpdateSummary {
                pending: 3,
                security: 1,
                reboot_required: true,
                packages: vec!["openssl".into()],
            }),
            ..Default::default()
        };
        ingest.receive(M, crate::ingest::Stream::Live, vec![r], 100, at + 15_000).await.unwrap();
        let html = text(send(&app.router, get(&format!("/machines/{M}"), &viewer)).await).await;
        assert!(html.contains("3 pending, 1 security"), "{html}");
        assert!(html.contains("Reboot required") && html.contains("openssl"), "{html}");
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
        assert!(shell::plain(&html).contains("Probe silent since Thursday, November 19, 06:00 UTC"), "{html}");
        assert!(html.contains("datetime=\"2026-11-19T06:00:00Z\""), "{html}");
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

    /// 7.7.1, 7.8.2, D77 (plan T73): the Security page and what the Machine page shows of connections and quarantine.
    mod security {
        use super::*;

        const SEC: &str = "01JD0000000000000000000001";

        fn intel_app(name: &str, intel: crate::intel::Intel) -> impl std::future::Future<Output = App> {
            app_with(name, move |web| web.with_intel(intel))
        }

        async fn insert(app: &App, table: &'static str, row: Row) {
            app.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert(table, row)])).await.unwrap();
        }

        async fn guest(app: &App, id: &str, name: &str, set: &[(&'static str, Value)]) {
            let mut row = Row::from([
                ("id", Value::Text(id.into())),
                ("site_id", Value::Text(site_id(&app.db))),
                ("name", Value::Text(name.into())),
                ("kind", Value::Text("linux".into())),
                ("state", Value::Text("enrolled".into())),
            ]);
            row.extend(set.iter().cloned());
            insert(app, "machines", row).await;
        }

        async fn page(app: &App, path: &str, cookie: &str) -> String {
            shell::plain(&text(send(&app.router, get(path, cookie)).await).await)
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn security_lists_not_downloaded_empty_state() {
            let intel = crate::intel::Intel::default();
            let app = intel_app("sec-lists", intel.clone()).await;
            complete_first_run(&app, SETUP_CODE).await;
            let viewer = session_for(&app.db, Role::Viewer).await;
            let html = page(&app, "/security", &viewer).await;
            assert!(html.contains("Lists not downloaded yet"), "{html}");
            assert!(html.contains("No security events yet"), "the feed's own empty state: {html}");
            // once a list is in, each source says what it holds and when it last worked
            let now = now_ms();
            let feodo = crate::intel::sources(now).into_iter().find(|s| s.id == "feodo").unwrap();
            intel.load(&feodo, b"203.0.113.9\n198.51.100.7\n", now).unwrap();
            let html = page(&app, "/security", &viewer).await;
            assert!(!html.contains("Lists not downloaded yet"), "{html}");
            assert!(html.contains("abuse.ch Feodo Tracker") && html.contains("2 entries"), "{html}");
            // what the feed shows, and what each machine has learned
            guest(&app, SEC, "web", &[]).await;
            let event = |id: &str, kind: &str, severity: &str, at: i64| {
                Row::from([
                    ("id", Value::Text(id.into())),
                    ("machine_id", Value::Text(SEC.into())),
                    ("at_ms", Value::Integer(at)),
                    ("kind", Value::Text(kind.into())),
                    ("severity", Value::Text(severity.into())),
                    ("subject", Value::Text("203.0.113.9".into())),
                    ("data", Value::Text("{}".into())),
                ])
            };
            insert(&app, "events", event("e1", "conn.known_bad", "critical", now - 60_000)).await;
            insert(&app, "events", event("e2", "service.not_active", "warning", now - 30_000)).await;
            let baseline = |first: i64| {
                Row::from([
                    ("machine_id", Value::Text(SEC.into())),
                    ("exe", Value::Text("/usr/bin/curl".into())),
                    ("dest_asn", Value::Integer(15169)),
                    ("dest_country", Value::Text("US".into())),
                    ("dest_port", Value::Integer(443)),
                    ("proto", Value::Text("tcp".into())),
                    ("first_seen_ms", Value::Integer(first)),
                    ("last_seen_ms", Value::Integer(now)),
                ])
            };
            insert(&app, "conn_baseline", baseline(now - 2 * 86_400_000)).await;
            let html = page(&app, "/security", &viewer).await;
            assert!(
                html.contains("conn.known_bad") && html.contains("203.0.113.9") && html.contains("Critical"),
                "{html}"
            );
            assert!(!html.contains("service.not_active"), "only security events are in the feed: {html}");
            assert!(html.contains("Learning, 5 days left"), "{html}");
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn machine_connections_grouped_by_container_with_verdicts() {
            let app = app("sec-conns").await;
            complete_first_run(&app, SETUP_CODE).await;
            guest(&app, SEC, "web", &[]).await;
            let at = now_ms() - 600_000;
            let conn = |container: &str, exe: &str, ip: &str, port: i64, verdict: &str, count: i64| {
                Row::from([
                    ("machine_id", Value::Text(SEC.into())),
                    ("bucket_ms", Value::Integer(at)),
                    ("container", Value::Text(container.into())),
                    ("exe", Value::Text(exe.into())),
                    ("dest_ip", Value::Text(ip.into())),
                    ("dest_port", Value::Integer(port)),
                    ("proto", Value::Text("tcp".into())),
                    ("dest_country", Value::Text("US".into())),
                    ("verdict", Value::Text(verdict.into())),
                    ("count", Value::Integer(count)),
                ])
            };
            insert(&app, "conn_records", conn("shop-web-1", "/usr/bin/curl", "203.0.113.9", 443, "known_bad", 3)).await;
            insert(&app, "conn_records", conn("shop-db-1", "/usr/sbin/postgres", "192.0.2.5", 5432, "known", 8)).await;
            insert(&app, "conn_records", conn("", "/usr/bin/apt", "198.51.100.20", 80, "new", 1)).await;
            let viewer = session_for(&app.db, Role::Viewer).await;
            let html = page(&app, &format!("/machines/{SEC}"), &viewer).await;
            let at_of = |needle: &str| html.find(needle).unwrap_or_else(|| panic!("no {needle}: {html}"));
            // one heading per container, the host's own first, and under each what it connected to with the verdict
            let (host, db, web) = (at_of("On the machine itself"), at_of("shop-db-1"), at_of("shop-web-1"));
            assert!(host < db && db < web, "{html}");
            let web_part = &html[web..];
            assert!(web_part.contains("203.0.113.9:443") && web_part.contains("curl"), "{html}");
            assert!(html[at_of("203.0.113.9:443")..].starts_with("203.0.113.9:443"), "{html}");
            for verdict in ["Known bad", "Known", "New"] {
                assert!(html.contains(verdict), "{verdict}: {html}");
            }
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn quarantine_kind_enforced_or_advisory_shown() {
            let app = app("sec-kind").await;
            complete_first_run(&app, SETUP_CODE).await;
            let viewer = session_for(&app.db, Role::Viewer).await;
            // two quarantined machines: one isolated by its hypervisor's firewall, one by a table in the machine
            let record = |job: &str, machine: &str, method: &str, enforced: bool| {
                let out = serde_json::json!({ "method": method, "enforced": enforced }).to_string() + "\n";
                (
                    Row::from([
                        ("id", Value::Text(job.into())),
                        ("kind", Value::Text("runbook".into())),
                        ("name", Value::Text("quarantine".into())),
                        ("target", Value::Text(machine.into())),
                        ("requested_by", Value::Text("user:admin".into())),
                        ("state", Value::Text("succeeded".into())),
                        ("started_at", Value::Integer(now_ms())),
                    ]),
                    Row::from([
                        ("job_id", Value::Text(job.into())),
                        ("step_id", Value::Text("isolate".into())),
                        ("state", Value::Text("succeeded".into())),
                        ("stdout", Value::Blob(out.into_bytes())),
                    ]),
                )
            };
            for (id, name, method, enforced) in [
                ("01JD00000000000000000000A1", "guest", "proxmox", true),
                ("01JD00000000000000000000A2", "plain", "in_guest", false),
            ] {
                guest(&app, id, name, &[("quarantine", Value::Text("active".into()))]).await;
                let (job, step) = record(&format!("01JOB{name}"), id, method, enforced);
                insert(&app, "jobs", job).await;
                insert(&app, "job_steps", step).await;
            }
            let enforced = page(&app, "/machines/01JD00000000000000000000A1", &viewer).await;
            assert!(
                enforced.contains("Quarantine") && enforced.contains("Enforced by the hypervisor's firewall"),
                "{enforced}"
            );
            assert!(!enforced.contains("Advisory"), "{enforced}");
            let advisory = page(&app, "/machines/01JD00000000000000000000A2", &viewer).await;
            assert!(
                advisory.contains("Advisory") && advisory.contains("root on the machine can undo it"),
                "{advisory}"
            );
            assert!(!advisory.contains("Enforced by"), "{advisory}");
            // a machine that isn't quarantined says nothing of it
            guest(&app, SEC, "free", &[]).await;
            let free = page(&app, &format!("/machines/{SEC}"), &viewer).await;
            assert!(!free.contains("Advisory") && !free.contains("Enforced by"), "{free}");
        }

        async fn save(app: &App, cookie: &str, fields: &[(&str, &str)]) -> Response<Body> {
            let csrf = csrf_of(app, cookie).await;
            let mut all = vec![("csrf", csrf.as_str())];
            all.extend_from_slice(fields);
            send(&app.router, post("/security/rules", cookie, &all)).await
        }

        fn rules(app: &App) -> Vec<(String, bool, Option<String>)> {
            crate::policy::quarantine::rules(&app.db)
                .unwrap()
                .into_iter()
                .map(|r| (r.name, r.enabled, r.enabled_by))
                .collect()
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn quarantine_rule_edit_admin_only_with_step_up() {
            let app = app("sec-rule").await;
            complete_first_run(&app, SETUP_CODE).await;
            let fields = |enabled: bool| {
                let mut f = vec![
                    ("name", "dmz known bad"),
                    ("severity", "critical"),
                    ("kinds", "conn.known_bad"),
                    ("tags", "dmz"),
                    ("roles", ""),
                ];
                if enabled {
                    f.push(("enabled", "on"));
                }
                f
            };
            // only an admin edits
            for role in [Role::Viewer, Role::Responder] {
                let cookie = session_for(&app.db, role).await;
                assert_eq!(save(&app, &cookie, &fields(false)).await.status(), StatusCode::FORBIDDEN, "{role:?}");
            }
            assert!(rules(&app).is_empty());
            let admin = session_for(&app.db, Role::Admin).await;
            // a rule that stays off needs nothing more
            assert_eq!(save(&app, &admin, &fields(false)).await.status(), StatusCode::SEE_OTHER);
            assert_eq!(rules(&app), [("dmz known bad".to_string(), false, None)]);
            // turning it on needs a fresh step-up first, and nothing changes until it has one
            let resp = save(&app, &admin, &fields(true)).await;
            assert_eq!((resp.status(), location(&resp).as_deref()), (StatusCode::SEE_OTHER, Some("/step-up")));
            assert!(!rules(&app)[0].1);
            let token = admin.split_once('=').unwrap().1;
            let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
            session::set_step_up(&app.db, &hash, now_ms()).await.unwrap();
            let resp = save(&app, &admin, &fields(true)).await;
            assert_eq!((resp.status(), location(&resp).as_deref()), (StatusCode::SEE_OTHER, Some("/security")));
            let stored = rules(&app);
            assert!(stored[0].1 && stored[0].2.as_deref().is_some_and(|by| by.starts_with("admin-")), "{stored:?}");
            let audited: i64 = app
                .db
                .readers()
                .with(|c| {
                    c.query_row("SELECT count(*) FROM audit_log WHERE action = 'quarantine.rule_saved'", [], |r| {
                        r.get(0)
                    })
                })
                .unwrap();
            assert_eq!(audited, 2, "each save is recorded");
            // the page shows the rule, who turned it on, and the edit button to an admin only
            let html = page(&app, "/security", &admin).await;
            assert!(
                html.contains("dmz known bad") && html.contains("conn.known_bad") && html.contains("dmz"),
                "{html}"
            );
            let viewer = session_for(&app.db, Role::Viewer).await;
            let seen = text(send(&app.router, get("/security", &viewer)).await).await;
            assert!(seen.contains("dmz known bad") && !seen.contains("/security?edit="), "{seen}");
            assert!(text(send(&app.router, get("/security", &admin)).await).await.contains("/security?edit="));
        }
    }

    /// 7.7.1, 7.7.2, 10, E21 (plan T79): the assistant's pages.
    mod assistant {
        use super::*;
        use crate::actions::Actions;
        use crate::actions::runner::{BoxFuture, StepCtx, StepResult, StepRunner};
        use crate::assist::Assist;
        use crate::audit::Audit;
        use crate::bus::Bus;
        use rackhand_runbook::runbook::Step;

        const INC: &str = "01JINC00000000000000000001";
        const JOB: &str = "01JJOB00000000000000000001";
        const MACH: &str = "01JD0000000000000000000001";

        #[derive(Debug)]
        struct Nobody;

        impl StepRunner for Nobody {
            fn run<'a>(&'a self, _c: &'a StepCtx, _s: &'a Step, _a: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
                Box::pin(async { StepResult::failed("unused") })
            }
        }

        const TICKET: &str =
            "rackhand1:0000000000000000000000000000000000000000000000000000000000000001@192.0.2.10:7443";

        async fn assistant_app(name: &str) -> App {
            let app = app_with(name, |web| {
                let db = web.db().clone();
                let audit = Audit::new(db.writer());
                let actions = Actions::new(db.clone(), audit.clone(), Bus::new(), Arc::new(Nobody));
                let registry = crate::registry::Registry::load(db.clone()).unwrap();
                web.with_assist(Assist::new(db, audit, actions))
                    .with_registry(registry)
                    .with_ticket(Arc::new(|| Some(TICKET.to_string())))
            })
            .await;
            complete_first_run(&app, SETUP_CODE).await;
            app
        }

        async fn insert(app: &App, table: &'static str, row: Row) {
            app.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert(table, row)])).await.unwrap();
        }

        /// A machine, an incident on it, and an assistant job for the incident that ended as `outcome`.
        async fn incident_with_job(app: &App, outcome: &str) {
            let machine = Row::from([
                ("id", Value::Text(MACH.into())),
                ("site_id", Value::Text(site_id(&app.db))),
                ("name", Value::Text("web".into())),
                ("kind", Value::Text("linux".into())),
                ("state", Value::Text("enrolled".into())),
            ]);
            insert(app, "machines", machine).await;
            let incident = Row::from([
                ("id", Value::Text(INC.into())),
                ("machine_id", Value::Text(MACH.into())),
                ("dedupe_key", Value::Text("k".into())),
                ("kind", Value::Text("service.not_active".into())),
                ("severity", Value::Text("warning".into())),
                ("state", Value::Text("human".into())),
                ("title", Value::Text("nginx is down".into())),
                ("opened_at", Value::Integer(now_ms())),
            ]);
            insert(app, "incidents", incident).await;
            let job = Row::from([
                ("id", Value::Text(JOB.into())),
                ("kind", Value::Text("assistant".into())),
                ("name", Value::Text("service-down".into())),
                ("requested_by", Value::Text("incidents".into())),
                ("incident_id", Value::Text(INC.into())),
                ("state", Value::Text("failed".into())),
                ("outcome", Value::Text(outcome.into())),
                ("started_at", Value::Integer(now_ms() - 600_000)),
            ]);
            insert(app, "jobs", job).await;
        }

        async fn transcript(app: &App, seq: i64, kind: &str, text: &str) {
            let row = Row::from([
                ("job_id", Value::Text(JOB.into())),
                ("seq", Value::Integer(seq)),
                ("at_ms", Value::Integer(now_ms())),
                ("kind", Value::Text(kind.into())),
                ("text", Value::Text(text.into())),
            ]);
            app.db.writer().send(WriteCmd::AppendTranscript(row)).await.unwrap();
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn transcript_rendered_escaped() {
            let app = assistant_app("as-transcript").await;
            incident_with_job(&app, "needs_human").await;
            transcript(&app, 1, "tool_result", "<script>alert('pwned')</script> & \"quotes\"").await;
            transcript(&app, 2, "message", "looking at the journal").await;
            let viewer = session_for(&app.db, Role::Viewer).await;
            let html = text(send(&app.router, get(&format!("/incidents/{INC}"), &viewer)).await).await;
            assert!(html.contains("Assistant: service-down") && html.contains("looking at the journal"), "{html}");
            assert!(!html.contains("<script>alert"), "tool output is escaped, never markup: {html}");
            assert!(html.contains("&#60;script&#62;alert"), "{html}");
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn resume_job_shown_after_late_approval() {
            let app = assistant_app("as-resume").await;
            incident_with_job(&app, "needs_human").await;
            let responder = session_for(&app.db, Role::Responder).await;
            let button = |html: &str| html.contains("Resume job") && html.contains(&format!("/incidents/{INC}/resume"));
            // the job ended needs_human but nothing is waiting to be used: nothing to resume
            let before = text(send(&app.router, get(&format!("/incidents/{INC}"), &responder)).await).await;
            assert!(!button(&before), "{before}");
            // an approval its call asked for is decided after the deadline, and still valid
            let request = crate::policy::approvals::ApprovalRequest {
                requester: format!("job:{JOB}"),
                tool: "run_runbook".into(),
                target: Some(MACH.into()),
                args: serde_json::json!({ "name": "service-restart", "params": {} }),
                runbook_rev: Some(1),
                risk: rackhand_runbook::runbook::Risk::Low,
                step_up: false,
                reason: "restart nginx".into(),
            };
            let id = crate::policy::approvals::Approvals::new(app.db.clone())
                .create(&request, now_ms(), 3_600_000)
                .await
                .unwrap();
            let after = text(send(&app.router, get(&format!("/incidents/{INC}"), &responder)).await).await;
            assert!(button(&after), "{after}");
            // a viewer sees the job but can't resume it; a job that resolved has no button
            let viewer = session_for(&app.db, Role::Viewer).await;
            assert!(!button(&text(send(&app.router, get(&format!("/incidents/{INC}"), &viewer)).await).await));
            let _ = id;
            let app2 = assistant_app("as-resume-resolved").await;
            incident_with_job(&app2, "resolved").await;
            let responder = session_for(&app2.db, Role::Responder).await;
            assert!(!button(&text(send(&app2.router, get(&format!("/incidents/{INC}"), &responder)).await).await));
        }

        fn user_of(app: &App, role: &str) -> String {
            app.db
                .readers()
                .with(|c| {
                    c.query_row("SELECT id FROM users WHERE role = ?1 ORDER BY rowid DESC LIMIT 1", [role], |r| {
                        r.get(0)
                    })
                })
                .unwrap()
        }

        async fn device(app: &App, user: &str, name: &str) -> String {
            let id = ulid::Ulid::new().to_string();
            let row = Row::from([
                ("id", Value::Text(id.clone())),
                ("user_id", Value::Text(user.into())),
                ("name", Value::Text(name.into())),
                ("endpoint_id", Value::Text(format!("{:0>64}", id.to_lowercase()))),
                ("created_at", Value::Integer(0)),
            ]);
            insert(app, "devices", row).await;
            id
        }

        async fn make_key(app: &App, cookie: &str, device: &str, scope: &str, days: &str) -> (StatusCode, String) {
            let csrf = csrf_of(app, cookie).await;
            let resp = send(
                &app.router,
                post(
                    "/account/keys",
                    cookie,
                    &[("csrf", csrf.as_str()), ("device", device), ("scope", scope), ("days", days)],
                ),
            )
            .await;
            (resp.status(), text(resp).await)
        }

        fn key_count(app: &App) -> i64 {
            app.db.readers().with(|c| c.query_row("SELECT count(*) FROM mcp_keys", [], |r| r.get(0))).unwrap()
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn mcp_key_scope_capped_by_role_and_expiry_max_1_year() {
            let app = assistant_app("as-keys").await;
            let viewer = session_for(&app.db, Role::Viewer).await;
            let dev = device(&app, &user_of(&app, "viewer"), "laptop").await;
            // a viewer's key can read only, and a longer-than-a-year key is refused
            let (code, page) = make_key(&app, &viewer, &dev, "read_request", "90").await;
            assert_eq!(code, StatusCode::BAD_REQUEST, "{page}");
            assert!(page.contains("A viewer&#39;s keys can read only") || page.contains("read only"), "{page}");
            assert_eq!(key_count(&app), 0);
            for days in ["366", "0", "-5", "x", ""] {
                assert_eq!(make_key(&app, &viewer, &dev, "read", days).await.0, StatusCode::BAD_REQUEST, "{days:?}");
            }
            assert_eq!(key_count(&app), 0);
            let page = shell::plain(&text(send(&app.router, get("/account/keys", &viewer)).await).await);
            assert!(!page.contains("Read and ask for changes"), "the option isn't offered: {page}");
            // a read key for 90 days: the token is shown once
            let (code, page) = make_key(&app, &viewer, &dev, "read", "90").await;
            assert_eq!(code, StatusCode::OK, "{page}");
            assert!(page.contains("Your new key") && page.contains("rk_"), "{page}");
            assert_eq!(key_count(&app), 1);
            let (expires, scope): (i64, String) = app
                .db
                .readers()
                .with(|c| c.query_row("SELECT expires_at, scope FROM mcp_keys", [], |r| Ok((r.get(0)?, r.get(1)?))))
                .unwrap();
            assert_eq!(scope, "read");
            assert!((expires - now_ms() - 90 * 86_400_000).abs() < 60_000);
            let again = text(send(&app.router, get("/account/keys", &viewer)).await).await;
            assert!(!again.contains("<code>rk_") && again.contains("Active"), "the token isn't shown again: {again}");
            // a responder may ask for changes, up to 365 days
            let responder = session_for(&app.db, Role::Responder).await;
            let dev2 = device(&app, &user_of(&app, "responder"), "phone").await;
            assert_eq!(make_key(&app, &responder, &dev2, "read_request", "365").await.0, StatusCode::OK);
            assert_eq!(key_count(&app), 2);
            // someone else's device isn't yours to make a key for
            let (code, _) = make_key(&app, &responder, &dev, "read", "30").await;
            assert_eq!(code, StatusCode::BAD_REQUEST);
            assert_eq!(key_count(&app), 2);
            // revoking is your own key only
            let id: String = app
                .db
                .readers()
                .with(|c| c.query_row("SELECT id FROM mcp_keys WHERE scope = 'read'", [], |r| r.get(0)))
                .unwrap();
            let csrf = csrf_of(&app, &responder).await;
            let resp =
                send(&app.router, post(&format!("/account/keys/{id}/revoke"), &responder, &[("csrf", csrf.as_str())]))
                    .await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "another user's key");
            let csrf = csrf_of(&app, &viewer).await;
            let resp =
                send(&app.router, post(&format!("/account/keys/{id}/revoke"), &viewer, &[("csrf", csrf.as_str())]))
                    .await;
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let revoked: Option<i64> = app
                .db
                .readers()
                .with(|c| c.query_row("SELECT revoked_at FROM mcp_keys WHERE id = ?1", [&id], |r| r.get(0)))
                .unwrap();
            assert!(revoked.is_some());
        }

        async fn set_cap(app: &App, admin: &str, value: &str) -> Response<Body> {
            let csrf = csrf_of(app, admin).await;
            send(&app.router, post("/settings/assistant/cap", admin, &[("csrf", csrf.as_str()), ("daily_cap", value)]))
                .await
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn operator_setup_states_provider_data_use() {
            let app = assistant_app("as-setup").await;
            let operator = Row::from([
                ("id", Value::Text("op1".into())),
                ("name", Value::Text("lab-operator".into())),
                ("endpoint_id", Value::Text("ab".repeat(32))),
                ("runners", Value::Text("[{\"name\":\"claude-code\",\"version\":\"2.1.328\"}]".into())),
            ]);
            insert(&app, "operators", operator).await;
            let admin = session_for(&app.db, Role::Admin).await;
            let page = shell::plain(&text(send(&app.router, get("/settings/assistant", &admin)).await).await);
            assert!(page.contains("sends the brief and every tool result") && page.contains("AI provider"), "{page}");
            assert!(page.contains("lab-operator") && page.contains("claude-code 2.1.328"), "{page}");
            // an invite gives the command to run on the operator host
            let csrf = csrf_of(&app, &admin).await;
            let resp = send(&app.router, post("/settings/assistant/invite", &admin, &[("csrf", csrf.as_str())])).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let html = text(resp).await.replace("&#x2F;", "/");
            assert!(html.contains(&format!("rackhand operator join --ticket {TICKET} --invite ")), "{html}");
            let tokens: i64 =
                app.db.readers().with(|c| c.query_row("SELECT count(*) FROM join_tokens", [], |r| r.get(0))).unwrap();
            assert_eq!(tokens, 1);
            // the daily cap is a number from 1 to 1000, saved and audited
            assert_eq!(set_cap(&app, &admin, "0").await.status(), StatusCode::BAD_REQUEST);
            assert_eq!(set_cap(&app, &admin, "5000").await.status(), StatusCode::BAD_REQUEST);
            assert_eq!(set_cap(&app, &admin, "5").await.status(), StatusCode::SEE_OTHER);
            assert_eq!(crate::library::config::hub(&app.db).unwrap().assistant.daily_cap, 5);
            let page = text(send(&app.router, get("/settings/assistant", &admin)).await).await;
            assert!(page.contains("name=\"daily_cap\" type=\"number\" min=\"1\" max=\"1000\" value=\"5\""), "{page}");
            // only an admin sees or changes any of it
            let responder = session_for(&app.db, Role::Responder).await;
            assert_eq!(send(&app.router, get("/settings/assistant", &responder)).await.status(), StatusCode::FORBIDDEN);
        }
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

mod binding {
    use super::*;
    use crate::registry::guest_binding::{GuestBindings, GuestMacs};

    const HOST: &str = "01JD0000000000000000000H01";
    const GUEST: &str = "01JD0000000000000000000G01";

    #[derive(Debug)]
    struct Roomy;

    impl crate::ingest::DiskSpace for Roomy {
        fn free_fraction(&self) -> f64 {
            0.5
        }
    }

    fn guests() -> Vec<GuestMacs> {
        let g = |vmid: u64, kind: &str, mac: &str| GuestMacs {
            host: HOST.into(),
            node: "pve8".into(),
            vmid,
            kind: kind.into(),
            macs: vec![mac.into()],
        };
        vec![g(100, "lxc", "BC:24:11:82:F7:1A"), g(200, "qemu", "BC:24:11:00:00:C8")]
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn confirm_after_mismatch_needs_admin_step_up() {
        type Slot = Arc<std::sync::Mutex<Option<Arc<GuestBindings>>>>;
        let slot: Slot = Arc::default();
        let keep = slot.clone();
        let app = app_with("binding-confirm", move |web| {
            let ingest = crate::ingest::Ingest::new(web.0.db.clone(), crate::bus::Bus::new(), Arc::new(Roomy));
            let bindings = Arc::new(GuestBindings::new(web.0.db.clone(), ingest));
            *keep.lock().unwrap() = Some(bindings.clone());
            web.with_bindings(bindings)
        })
        .await;
        let bindings = slot.lock().unwrap().take().unwrap();
        complete_first_run(&app, SETUP_CODE).await;
        let site: String =
            app.db.readers().with(|c| c.query_row("SELECT id FROM sites LIMIT 1", [], |r| r.get(0))).unwrap();
        let machine = |id: &str, name: &str, kind: &str| {
            RowWrite::insert(
                "machines",
                Row::from([
                    ("id", Value::Text(id.into())),
                    ("site_id", Value::Text(site.clone())),
                    ("name", Value::Text(name.into())),
                    ("kind", Value::Text(kind.into())),
                    ("state", Value::Text("enrolled".into())),
                ]),
            )
        };
        app.db
            .writer()
            .send(WriteCmd::Batch(vec![machine(HOST, "pve", "hypervisor"), machine(GUEST, "ct-test", "linux")]))
            .await
            .unwrap();
        bindings.observe(GUEST, &["BC:24:11:82:F7:1A".into()], &guests(), now_ms()).await.unwrap();
        let first = guests()[0].reference();
        bindings.confirm(GUEST, &first, "admin", now_ms()).await.unwrap();
        bindings.observe(GUEST, &["BC:24:11:00:00:C8".into()], &guests(), now_ms()).await.unwrap();
        let other = guests()[1].reference();
        // the machine page says so, and offers both
        let admin = session_for(&app.db, Role::Admin).await;
        let page = text(send(&app.router, get(&format!("/machines/{GUEST}"), &admin)).await).await;
        assert!(shell::plain(&page).contains("Guest binding: mismatch"), "{page}");
        assert!(page.contains("vmid 100") && page.contains("vmid 200"), "{page}");
        let path = format!("/machines/{GUEST}/binding/confirm");
        let state = |app: &App| -> String {
            app.db
                .readers()
                .with(|c| c.query_row("SELECT proxmox_ref_state FROM machines WHERE id = ?1", [GUEST], |r| r.get(0)))
                .unwrap()
        };
        // a responder can't
        let responder = session_for(&app.db, Role::Responder).await;
        let csrf = csrf_of(&app, &responder).await;
        let resp =
            send(&app.router, post(&path, &responder, &[("csrf", csrf.as_str()), ("guest", other.as_str())])).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // an admin is sent to step up first
        let csrf = csrf_of(&app, &admin).await;
        let resp = send(&app.router, post(&path, &admin, &[("csrf", csrf.as_str()), ("guest", other.as_str())])).await;
        assert_eq!((resp.status(), location(&resp).as_deref()), (StatusCode::SEE_OTHER, Some("/step-up")));
        assert_eq!(state(&app), "mismatch");
        let token = admin.split_once('=').unwrap().1;
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        session::set_step_up(&app.db, &hash, now_ms()).await.unwrap();
        let csrf = csrf_of(&app, &admin).await;
        let resp = send(&app.router, post(&path, &admin, &[("csrf", csrf.as_str()), ("guest", other.as_str())])).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(state(&app), "confirmed");
        let audited: i64 = app
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT count(*) FROM audit_log WHERE action = 'machine.binding_confirmed'", [], |r| {
                    r.get(0)
                })
            })
            .unwrap();
        assert_eq!(audited, 1);
        // a guest it neither is nor looks like can't be confirmed
        let csrf = csrf_of(&app, &admin).await;
        let stranger = serde_json::json!({ "cluster": HOST, "node": "pve8", "vmid": 300, "type": "qemu" }).to_string();
        let resp =
            send(&app.router, post(&path, &admin, &[("csrf", csrf.as_str()), ("guest", stranger.as_str())])).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }
}

mod add {
    use super::*;

    const TICKET: &str = "rackhand1:0000000000000000000000000000000000000000000000000000000000000001@192.0.2.10:7443";
    const SCRIPT: &[u8] = b"#!/bin/sh\necho the installer\n";

    async fn add_app(name: &str) -> App {
        let release = std::env::temp_dir().join(format!("rackhand-web-release-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&release).unwrap();
        std::fs::write(release.join("install.sh"), SCRIPT).unwrap();
        let app = app_with(name, move |web| {
            let registry = crate::registry::Registry::load(web.db().clone()).unwrap();
            web.with_registry(registry).with_ticket(Arc::new(|| Some(TICKET.to_string()))).with_release_dir(release)
        })
        .await;
        complete_first_run(&app, SETUP_CODE).await;
        app
    }

    fn unescape(html: &str) -> String {
        html.replace("&#x2F;", "/")
            .replace("&#x27;", "'")
            .replace("&#38;", "&")
            .replace("&amp;", "&")
            .replace("&#39;", "'")
            .replace("&quot;", "\"")
    }

    fn command_token(page: &str) -> String {
        let at = page.find("--token ").expect("a --token") + 8;
        page[at..].chars().take_while(|c| c.is_ascii_alphanumeric()).collect()
    }

    async fn add(app: &App, admin: &str, fields: &[(&str, &str)]) -> (StatusCode, String) {
        let csrf = csrf_of(app, admin).await;
        let mut all = vec![("csrf", csrf.as_str())];
        all.extend_from_slice(fields);
        let resp = send(&app.router, post("/add/machine", admin, &all)).await;
        let code = resp.status();
        (code, unescape(&text(resp).await))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn machine_command_per_os_mode_and_level() {
        let app = add_app("add-machine").await;
        let admin = session_for(&app.db, Role::Admin).await;
        let page = unescape(&text(send(&app.router, get("/add", &admin)).await).await);
        assert!(
            page.contains("Add a machine") && page.contains("-- --hub"),
            "the machine form and the site bootstrap: {page}"
        );
        let linux = [("os", "linux"), ("name", "web2"), ("access", "monitor"), ("mode", "remote")];
        let (code, html) = add(&app, &admin, &linux).await;
        assert_eq!(code, StatusCode::OK, "{html}");
        assert!(html.contains(&format!("--ticket {TICKET}")), "{html}");
        assert!(html.contains("--monitor") && html.contains("--remote"), "{html}");
        assert!(html.contains("install.sh | sudo sh -s --"), "{html}");
        let token = command_token(&html);
        assert_eq!(token.len(), 26, "the one-time token: {token}");
        // the offline variant: the hub's own install.sh, checked against its SHA-256
        let sha: String = Sha256::digest(SCRIPT).iter().map(|b| format!("{b:02x}")).collect();
        assert!(html.contains(&format!("echo '{sha}  /tmp/rackhand-install.sh' | sha256sum -c -")), "{html}");
        assert!(html.contains(":8443/install.sh"), "{html}");
        // the token: a machine's, 60 minutes, bound to the level chosen
        let (kind, bound, life): (String, String, i64) = app
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT kind, bound, expires_at FROM join_tokens ORDER BY rowid DESC LIMIT 1", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
            })
            .unwrap();
        assert_eq!(kind, "machine");
        assert!(bound.contains("monitor"), "bound to monitor: {bound}");
        assert!((life - now_ms() - 3_600_000).abs() < 60_000, "60 minutes");
        let pending: (String, String, String) = app
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT kind, access, mode FROM machines WHERE name = 'web2'", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
            })
            .unwrap();
        assert_eq!(pending, ("linux".into(), "monitor".into(), "remote".into()));
        // Alpine has no sudo and maybe no curl; Windows is PowerShell; managed and local are the defaults
        let (_, alpine) =
            add(&app, &admin, &[("os", "alpine"), ("name", "nas-alpine"), ("access", "managed"), ("mode", "local")])
                .await;
        assert!(
            alpine.contains("wget -qO-") && !alpine.contains("--monitor") && !alpine.contains("--remote"),
            "{alpine}"
        );
        // its offline variant with BusyBox's wget too, as root
        assert!(
            alpine.contains(&format!(
                "wget -q --no-check-certificate -O /tmp/rackhand-install.sh https://192.0.2.10:8443/install.sh && echo '{sha}  /tmp/rackhand-install.sh' | sha256sum -c - && sh /tmp/rackhand-install.sh"
            )),
            "{alpine}"
        );
        assert!(!alpine.contains("curl"), "a stock Alpine machine has no curl: {alpine}");
        let (_, windows) =
            add(&app, &admin, &[("os", "windows"), ("name", "desk1"), ("access", "managed"), ("mode", "local")]).await;
        assert!(windows.contains("install.ps1") && windows.contains("-Ticket"), "{windows}");
        // a name in use, or an unknown OS, is refused
        let (code, _) =
            add(&app, &admin, &[("os", "linux"), ("name", "web2"), ("access", "managed"), ("mode", "local")]).await;
        assert_eq!(code, StatusCode::CONFLICT);
        let (code, _) =
            add(&app, &admin, &[("os", "beos"), ("name", "x"), ("access", "managed"), ("mode", "local")]).await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }

    /// The offline variant's files (7.3.12): the hub serves `install.sh` and the release files it holds, to anyone (the
    /// script is checked against the SHA-256 in the command, the binaries by their signatures), and nothing else.
    #[tokio::test(flavor = "multi_thread")]
    async fn hub_serves_its_release_files() {
        let app = add_app("add-release").await;
        let release = std::env::temp_dir().join(format!("rackhand-web-release-add-release-{}", std::process::id()));
        std::fs::write(release.join("rackhand-probe-x86_64-unknown-linux-musl"), b"\x7fELF probe").unwrap();
        let fetch = |path: &str| Request::get(path).body(Body::empty()).unwrap();
        let resp = send(&app.router, fetch("/install.sh")).await;
        assert_eq!(resp.status(), StatusCode::OK, "no session needed");
        assert_eq!(axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap().as_ref(), SCRIPT);
        let resp = send(&app.router, fetch("/release/rackhand-probe-x86_64-unknown-linux-musl")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap().as_ref(), b"\x7fELF probe");
        for missing in ["/release/rackhand-cli", "/release/..%2Fhub.db", "/release/.hidden", "/release/a%2Fb"] {
            assert_eq!(send(&app.router, fetch(missing)).await.status(), StatusCode::NOT_FOUND, "{missing}");
        }
        // the offline command fetches the release files from the hub too
        let admin = session_for(&app.db, Role::Admin).await;
        let (_, html) =
            add(&app, &admin, &[("os", "linux"), ("name", "web3"), ("access", "managed"), ("mode", "local")]).await;
        assert!(html.contains(":8443/release --self-signed"), "{html}");
        // a hub that holds no release files serves none
        let bare = super::app("add-release-none").await;
        assert_eq!(send(&bare.router, fetch("/install.sh")).await.status(), StatusCode::NOT_FOUND);
    }

    /// The machines added in the last day, as the Add page lists them (7.3.12, AC35): enrolled and healthy once the
    /// hub's SSH test passed, or the failure with its account; a monitor machine once it reports.
    #[tokio::test(flavor = "multi_thread")]
    async fn lists_recently_added_machines_with_ssh_test_result() {
        let app = add_app("add-recent").await;
        let admin = session_for(&app.db, Role::Admin).await;
        let site: String =
            app.db.readers().with(|c| c.query_row("SELECT id FROM sites LIMIT 1", [], |r| r.get(0))).unwrap();
        let now = rackhand_store::ids::now_ms();
        let day = 86_400_000;
        let mut writes = Vec::new();
        // D84: a managed machine is pending until its SSH test passes, and listed while it is.
        for (id, access, state, enrolled_at) in [
            ("web1", "managed", "enrolled", now - 60_000),
            ("web2", "managed", "pending", now - 120_000),
            ("web3", "managed", "pending", now - 1_000),
            ("mon1", "monitor", "enrolled", now - 5_000),
            ("old1", "managed", "enrolled", now - 2 * day),
        ] {
            writes.push(RowWrite::insert(
                "machines",
                Row::from([
                    ("id", Value::Text(id.into())),
                    ("site_id", Value::Text(site.clone())),
                    ("name", Value::Text(id.into())),
                    ("kind", Value::Text("linux".into())),
                    ("access", Value::Text(access.into())),
                    ("state", Value::Text(state.into())),
                    ("enrolled_at", Value::Integer(enrolled_at)),
                ]),
            ));
        }
        for (n, (machine, kind, at, data)) in [
            ("web1", "machine.ssh_test_passed", now - 50_000, "{}"),
            ("web2", "machine.ssh_test_passed", now - 110_000, "{}"),
            (
                "web2",
                "machine.ssh_test_failed",
                now - 100_000,
                r#"{"account":"rackhand-ai","reason":"`sudo -n true`: exit 1"}"#,
            ),
            ("old1", "machine.ssh_test_passed", now - day, "{}"),
        ]
        .into_iter()
        .enumerate()
        {
            writes.push(RowWrite::insert(
                "events",
                Row::from([
                    ("id", Value::Text(format!("e{n}"))),
                    ("machine_id", Value::Text(machine.into())),
                    ("at_ms", Value::Integer(at)),
                    ("kind", Value::Text(kind.into())),
                    ("severity", Value::Text("info".into())),
                    ("data", Value::Text(data.into())),
                ]),
            ));
        }
        app.db.writer().send(WriteCmd::Batch(writes)).await.unwrap();

        let page = unescape(&text(send(&app.router, get("/add", &admin)).await).await);
        let at = page.find("Recently added").unwrap_or_else(|| panic!("a recently added list: {page}"));
        let list = &page[at..page[at..].find("</table>").map_or(page.len(), |e| at + e)];
        let row = |name: &str| {
            list.split("<tr")
                .find(|r| shell::cells(r).first().is_some_and(|c| c == name))
                .unwrap_or_else(|| panic!("{name} listed: {list}"))
                .to_string()
        };
        assert!(row("web1").contains("Enrolled and healthy"), "{}", row("web1"));
        let failed = row("web2");
        assert!(
            failed.contains("Pending: SSH test failed as rackhand-ai") && failed.contains("exit 1"),
            "the latest test: {failed}"
        );
        assert!(row("web3").contains("Pending: waiting for the hub's SSH test"), "{}", row("web3"));
        assert!(row("mon1").contains("Waiting for its first report"), "{}", row("mon1"));
        assert!(!list.contains("old1"), "only the last day: {list}");
        assert!(list.find("web3").unwrap() < list.find("web1").unwrap(), "newest first: {list}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn device_operator_peer_invites_expire_in_24h() {
        let app = add_app("add-invites").await;
        let admin = session_for(&app.db, Role::Admin).await;
        let user: String =
            app.db.readers().with(|c| c.query_row("SELECT id FROM users LIMIT 1", [], |r| r.get(0))).unwrap();
        for (kind, hint) in
            [("operator", "rackhand operator join"), ("peer", "Peers"), ("device", "rackhand-cli login")]
        {
            let csrf = csrf_of(&app, &admin).await;
            let fields = [("csrf", csrf.as_str()), ("kind", kind), ("user", user.as_str())];
            let resp = send(&app.router, post("/add/invite", &admin, &fields)).await;
            assert_eq!(resp.status(), StatusCode::OK, "{kind}");
            let page = unescape(&text(resp).await);
            let marker = format!("{TICKET}#");
            assert!(page.contains(hint) && page.contains(&marker), "{kind}: {page}");
            let (k, expires): (String, i64) = app
                .db
                .readers()
                .with(|c| {
                    c.query_row("SELECT kind, expires_at FROM join_tokens ORDER BY rowid DESC LIMIT 1", [], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                })
                .unwrap();
            assert_eq!(k, kind);
            assert!((expires - now_ms() - 86_400_000).abs() < 60_000, "{kind}: 24 hours");
            // single use and bound to its kind
            let at = page.find(&marker).unwrap() + marker.len();
            let secret: String = page[at..].chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
            let token = crate::registry::tokens::Token::parse(&secret);
            let consume = |kind: &str| rackhand_store::RegistryChange {
                consume: Some(rackhand_store::ConsumeToken {
                    hash: crate::registry::tokens::hash(&token).to_vec(),
                    kind: kind.into(),
                    now_ms: now_ms(),
                }),
                writes: vec![],
                updates: vec![],
            };
            let other = if kind == "peer" { "operator" } else { "peer" };
            assert!(
                app.db.writer().send(WriteCmd::RegistryChange(consume(other))).await.is_err(),
                "{kind}: kind-bound"
            );
            app.db.writer().send(WriteCmd::RegistryChange(consume(kind))).await.unwrap();
            assert!(app.db.writer().send(WriteCmd::RegistryChange(consume(kind))).await.is_err(), "{kind}: single use");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn admin_only() {
        let app = add_app("add-admin").await;
        let responder = session_for(&app.db, Role::Responder).await;
        assert_eq!(send(&app.router, get("/add", &responder)).await.status(), StatusCode::FORBIDDEN);
        let csrf = csrf_of(&app, &responder).await;
        let machine = [("csrf", csrf.as_str()), ("os", "linux"), ("name", "x")];
        assert_eq!(send(&app.router, post("/add/machine", &responder, &machine)).await.status(), StatusCode::FORBIDDEN);
        let invite = [("csrf", csrf.as_str()), ("kind", "peer")];
        assert_eq!(send(&app.router, post("/add/invite", &responder, &invite)).await.status(), StatusCode::FORBIDDEN);
    }
}

/// 7.3.12, D89, AC59: the dashboard issues a one-time command that changes a machine's access level; it changes nothing
/// itself, and the command works only on the machine it names.
mod level {
    use super::*;

    const TICKET: &str = "rackhand1:0000000000000000000000000000000000000000000000000000000000000001@192.0.2.10:7443";
    const ID: &str = "01JD0000000000000000000009";

    async fn level_app(name: &str, access: &str) -> App {
        let app = app_with(name, move |web| {
            let registry = crate::registry::Registry::load(web.db().clone()).unwrap();
            web.with_registry(registry).with_ticket(Arc::new(|| Some(TICKET.to_string())))
        })
        .await;
        complete_first_run(&app, SETUP_CODE).await;
        let site: String =
            app.db.readers().with(|c| c.query_row("SELECT id FROM sites LIMIT 1", [], |r| r.get(0))).unwrap();
        let row = Row::from([
            ("id", Value::Text(ID.into())),
            ("site_id", Value::Text(site)),
            ("name", Value::Text("web1".into())),
            ("kind", Value::Text("linux".into())),
            ("access", Value::Text(access.into())),
            ("state", Value::Text("enrolled".into())),
        ]);
        app.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("machines", row)])).await.unwrap();
        app
    }

    fn access(app: &App) -> String {
        app.db.readers().with(|c| c.query_row("SELECT access FROM machines WHERE id = ?1", [ID], |r| r.get(0))).unwrap()
    }

    fn tokens(app: &App) -> i64 {
        app.db.readers().with(|c| c.query_row("SELECT count(*) FROM join_tokens", [], |r| r.get(0))).unwrap()
    }

    async fn ask(app: &App, cookie: &str, to: &str) -> (StatusCode, String) {
        let csrf = csrf_of(app, cookie).await;
        let path = format!("/machines/{ID}/level");
        let resp = send(&app.router, post(&path, cookie, &[("csrf", csrf.as_str()), ("access", to)])).await;
        let code = resp.status();
        (code, text(resp).await.replace("&#x2F;", "/").replace("&#38;", "&").replace("&#x27;", "'"))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn level_command_binds_a_token_to_the_machine_and_changes_nothing() {
        let app = level_app("level-command", "managed").await;
        let admin = session_for(&app.db, Role::Admin).await;
        let before = tokens(&app);
        let (code, page) = ask(&app, &admin, "monitor").await;
        assert_eq!(code, StatusCode::OK, "{page}");
        assert!(page.contains(&format!("--ticket {TICKET}")) && page.contains("--monitor"), "{page}");
        assert!(page.contains("--token "), "{page}");
        assert_eq!(access(&app), "managed", "the dashboard changes no level");
        assert_eq!(tokens(&app), before + 1);
        let (bound, life): (String, i64) = app
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT bound, expires_at FROM join_tokens ORDER BY rowid DESC LIMIT 1", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
            })
            .unwrap();
        let bound: serde_json::Value = serde_json::from_str(&bound).unwrap();
        assert_eq!(
            (bound["access"].as_str(), bound["machine_id"].as_str(), bound["level_change"].as_bool()),
            (Some("monitor"), Some(ID), Some(true)),
            "bound to this machine and the new level"
        );
        assert!((life - now_ms() - 3_600_000).abs() < 60_000, "60 minutes");
        let audit: i64 = app
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT count(*) FROM audit_log WHERE action = 'machine.level_change_issued'", [], |r| {
                    r.get(0)
                })
            })
            .unwrap();
        assert_eq!(audit, 1, "recorded");
        // the other direction: no `--monitor`
        let app = level_app("level-command-up", "monitor").await;
        let admin = session_for(&app.db, Role::Admin).await;
        let (_, page) = ask(&app, &admin, "managed").await;
        assert!(page.contains("--token ") && !page.contains("--monitor"), "{page}");
        assert_eq!(access(&app), "monitor");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn only_an_admin_asks_and_only_for_a_change() {
        let app = level_app("level-refused", "managed").await;
        let responder = session_for(&app.db, Role::Responder).await;
        let before = tokens(&app);
        assert_eq!(ask(&app, &responder, "monitor").await.0, StatusCode::FORBIDDEN);
        let admin = session_for(&app.db, Role::Admin).await;
        let (code, page) = ask(&app, &admin, "managed").await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{page}");
        assert!(page.contains("already managed"), "{page}");
        let (code, _) = ask(&app, &admin, "root").await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert_eq!(tokens(&app), before, "no token for any of them");
        // the machine page offers the change to an admin, and not to a responder
        let page = shell::plain(&text(send(&app.router, get(&format!("/machines/{ID}"), &admin)).await).await);
        assert!(page.contains("Change to monitor"), "{page}");
        let page = shell::plain(&text(send(&app.router, get(&format!("/machines/{ID}"), &responder)).await).await);
        assert!(!page.contains("Change to monitor"), "{page}");
    }
}

/// 7.7.1, D65: the Settings page turns each outside source and air-gapped mode on and off; each change is audited, and what
/// the form doesn't show (the sources that are off unless enabled) is kept.
mod intel {
    use super::*;

    fn sources(app: &App) -> crate::library::config::Sources {
        crate::library::config::hub(&app.db).unwrap().sources
    }

    async fn set(app: &App, admin: &str, fields: &[(&str, &str)]) {
        let csrf = csrf_of(app, admin).await;
        let mut all = vec![("csrf", csrf.as_str())];
        all.extend_from_slice(fields);
        let resp = send(&app.router, post("/settings/sources", admin, &all)).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn settings_toggle_each_source_and_air_gapped_mode() {
        let app = app("intel-settings").await;
        complete_first_run(&app, SETUP_CODE).await;
        let admin = session_for(&app.db, Role::Admin).await;
        let page = shell::plain(&text(send(&app.router, get("/settings", &admin)).await).await);
        for what in ["abuse.ch Feodo Tracker", "Spamhaus DROP", "DB-IP Lite", "Air-gapped"] {
            assert!(page.contains(what), "{what}: {page}");
        }
        set(&app, &admin, &[("source_feodo", "on"), ("source_dbip", "on")]).await;
        let s = sources(&app);
        assert_eq!((s.feodo, s.spamhaus, s.dbip, s.airgapped), (true, false, true, false));
        set(&app, &admin, &[("source_spamhaus", "on"), ("source_airgapped", "on")]).await;
        let s = sources(&app);
        assert_eq!((s.feodo, s.spamhaus, s.dbip, s.airgapped), (false, true, false, true));
        assert!(!s.maxmind && !s.reputation && !s.relay_lists && !s.n0_relays, "the optional ones stay off");
        let page = text(send(&app.router, get("/settings", &admin)).await).await;
        assert!(page.contains("name=\"source_airgapped\" checked"), "the page shows the mode it is in");
        set(&app, &admin, &[]).await;
        assert!(!sources(&app).airgapped, "and turns it off again");
        // each change is audited with what it set
        let changes: Vec<String> = app
            .db
            .readers()
            .with(|c| {
                let mut st = c.prepare("SELECT data FROM audit_log WHERE action = 'settings.sources' ORDER BY seq")?;
                st.query_map([], |r| r.get(0))?.collect()
            })
            .unwrap();
        assert_eq!(changes.len(), 3, "{changes:?}");
        assert!(changes[1].contains("\"airgapped\":true") && changes[2].contains("\"airgapped\":false"), "{changes:?}");
    }
}

mod agentless {
    use super::*;
    use rackhand_drivers::{Driver, Proxmox, Redfish, Snmp, TrueNas};

    const KEY: &str = "1-invented-api-key";
    const PVE_TOKEN: &str = "rackhand@pve!hub=00000000-1111-2222-3333-444444444444";

    fn drivers() -> Vec<Arc<dyn Driver>> {
        vec![Arc::new(Proxmox::new()), Arc::new(TrueNas::new()), Arc::new(Redfish::new()), Arc::new(Snmp::new())]
    }

    async fn agentless_app(name: &str) -> App {
        let app = app_with(name, |web| {
            let registry = crate::registry::Registry::load(web.db().clone()).unwrap();
            web.with_registry(registry).with_drivers(drivers())
        })
        .await;
        complete_first_run(&app, SETUP_CODE).await;
        app
    }

    fn vault(app: &App) -> Vault {
        Vault::new(MasterKey::from_bytes([3u8; 32]), app.db.clone())
    }

    fn unescape(html: &str) -> String {
        html.replace("&#x2F;", "/")
            .replace("&#x27;", "'")
            .replace("&amp;", "&")
            .replace("&#39;", "'")
            .replace("&quot;", "\"")
    }

    /// The value of the hidden field `name` on a page.
    fn hidden(page: &str, name: &str) -> String {
        let at = page.find(&format!("name=\"{name}\" value=\"")).unwrap_or_else(|| panic!("a `{name}` field: {page}"));
        let rest = &page[at + name.len() + 15..];
        rest[..rest.find('"').unwrap()].to_string()
    }

    async fn submit(app: &App, admin: &str, path: &str, fields: &[(&str, &str)]) -> (StatusCode, String) {
        let csrf = csrf_of(app, admin).await;
        let mut all = vec![("csrf", csrf.as_str())];
        all.extend_from_slice(fields);
        let resp = send(&app.router, post(path, admin, &all)).await;
        let code = resp.status();
        (code, unescape(&text(resp).await))
    }

    /// Every text and blob value in the database, for looking for a credential where none may be.
    fn every_value(db: &Db) -> Vec<String> {
        db.readers()
            .with(|c| {
                let tables: Vec<String> = {
                    let mut s = c.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?;
                    s.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?
                };
                let mut out = Vec::new();
                for t in tables {
                    let mut s = c.prepare(&format!("SELECT * FROM \"{t}\""))?;
                    let n = s.column_count();
                    let mut rows = s.query([])?;
                    while let Some(r) = rows.next()? {
                        for i in 0..n {
                            match r.get_ref(i)? {
                                rusqlite::types::ValueRef::Text(b) | rusqlite::types::ValueRef::Blob(b) => {
                                    out.push(format!("{t}: {}", String::from_utf8_lossy(b)));
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Ok(out)
            })
            .unwrap()
    }

    fn machine_row(db: &Db, name: &str) -> (String, String, String, Option<String>, Option<String>, String) {
        db.readers()
            .with(|c| {
                c.query_row(
                    "SELECT id, kind, state, driver, driver_settings, address FROM machines WHERE name = ?1",
                    [name],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
                )
            })
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn form_stores_credentials_in_vault_only() {
        let app = agentless_app("agentless-vault").await;
        let admin = session_for(&app.db, Role::Admin).await;
        let sim = rackhand_drivers::truenas::sim::Sim::start(rackhand_drivers::truenas::sim::Api::WebSocket).await;
        let page = unescape(&text(send(&app.router, get("/add?add=truenas", &admin)).await).await);
        assert!(page.contains("/add/appliance") && page.contains("truenas"), "the appliance forms: {page}");
        // first the address: the hub shows the certificate it was given, before any credential is asked for
        let fields = [("driver", "truenas"), ("name", "nas1"), ("address", sim.url.as_str())];
        let (code, shown) = submit(&app, &admin, "/add/appliance", &fields).await;
        assert_eq!(code, StatusCode::OK, "{shown}");
        assert!(shown.contains(&sim.fingerprint), "the fingerprint to accept: {shown}");
        assert!(sim.calls().is_empty(), "nothing sent to an unaccepted certificate: {:?}", sim.calls());
        let token = hidden(&shown, "token");
        // a wrong key fails the first poll: refused, and the form can be sent again
        let wrong =
            [("token", token.as_str()), ("fingerprint", sim.fingerprint.as_str()), ("api_key", "1-not-the-key")];
        let (code, _) = submit(&app, &admin, "/add/appliance/accept", &wrong).await;
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);
        // a fingerprint that isn't the appliance's: the poll is pinned to what the admin accepted
        let other = "AA:".repeat(31) + "AA";
        let pinned = [("token", token.as_str()), ("fingerprint", other.as_str()), ("api_key", KEY)];
        let (code, _) = submit(&app, &admin, "/add/appliance/accept", &pinned).await;
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);
        let right = [("token", token.as_str()), ("fingerprint", sim.fingerprint.as_str()), ("api_key", KEY)];
        let (code, done) = submit(&app, &admin, "/add/appliance/accept", &right).await;
        assert_eq!(code, StatusCode::OK, "{done}");
        let (id, kind, state, driver, settings, _) = machine_row(&app.db, "nas1");
        assert_eq!((kind.as_str(), state.as_str(), driver.as_deref()), ("appliance", "enrolled", Some("truenas")));
        let settings: serde_json::Value = serde_json::from_str(&settings.unwrap()).unwrap();
        assert_eq!(settings["api_key"], format!("secret:driver.{id}"), "a reference: {settings}");
        assert_eq!(settings["fingerprint"], sim.fingerprint.as_str(), "the accepted certificate: {settings}");
        let held: serde_json::Value =
            serde_json::from_slice(vault(&app).get(&format!("driver.{id}")).unwrap().expose()).unwrap();
        assert_eq!(held["api_key"], KEY);
        assert_eq!(held["fingerprint"], sim.fingerprint.as_str());
        let leaks: Vec<String> = every_value(&app.db).into_iter().filter(|v| v.contains(KEY)).collect();
        assert!(leaks.is_empty(), "the key only in the Vault: {leaks:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn form_join_completes_and_used_invite_refused() {
        let app = agentless_app("agentless-once").await;
        let admin = session_for(&app.db, Role::Admin).await;
        let sim = rackhand_drivers::truenas::sim::Sim::start(rackhand_drivers::truenas::sim::Api::WebSocket).await;
        let fields = [("driver", "truenas"), ("name", "nas1"), ("address", sim.url.as_str())];
        let (_, shown) = submit(&app, &admin, "/add/appliance", &fields).await;
        let token = hidden(&shown, "token");
        let right = [("token", token.as_str()), ("fingerprint", sim.fingerprint.as_str()), ("api_key", KEY)];
        let (code, done) = submit(&app, &admin, "/add/appliance/accept", &right).await;
        assert_eq!(code, StatusCode::OK, "{done}");
        assert!(done.contains("nas1"), "{done}");
        let (id, ..) = machine_row(&app.db, "nas1");
        // sent again, even with other credentials: refused with its reason, and nothing changes
        let again = [("token", token.as_str()), ("fingerprint", sim.fingerprint.as_str()), ("api_key", "1-other")];
        let (code, refused) = submit(&app, &admin, "/add/appliance/accept", &again).await;
        assert_eq!(code, StatusCode::CONFLICT);
        assert!(refused.contains("already been used"), "{refused}");
        let held: serde_json::Value =
            serde_json::from_slice(vault(&app).get(&format!("driver.{id}")).unwrap().expose()).unwrap();
        assert_eq!(held["api_key"], KEY, "the stored credential is untouched");
        // an expired form
        let (_, shown) = submit(
            &app,
            &admin,
            "/add/appliance",
            &[("driver", "truenas"), ("name", "nas2"), ("address", sim.url.as_str())],
        )
        .await;
        let late = hidden(&shown, "token");
        let expire = rackhand_store::RowUpdate {
            table: "join_tokens",
            key: (
                "hash",
                Value::Blob(crate::registry::tokens::hash(&crate::registry::tokens::Token::parse(&late)).to_vec()),
            ),
            set: Row::from([("expires_at", Value::Integer(1))]),
        };
        let change = rackhand_store::RegistryChange { consume: None, writes: vec![], updates: vec![expire] };
        app.db.writer().send(WriteCmd::RegistryChange(change)).await.unwrap();
        let fields = [("token", late.as_str()), ("fingerprint", sim.fingerprint.as_str()), ("api_key", KEY)];
        let (code, refused) = submit(&app, &admin, "/add/appliance/accept", &fields).await;
        assert_eq!(code, StatusCode::GONE);
        assert!(refused.contains("expired"), "{refused}");
        // a probe machine's install token isn't an appliance form's, nor the other way round
        let registry = crate::registry::Registry::load(app.db.clone()).unwrap();
        let add = crate::registry::machines::AddMachine {
            site_id: app.db.readers().with(|c| c.query_row("SELECT id FROM sites LIMIT 1", [], |r| r.get(0))).unwrap(),
            name: "web9".into(),
            kind: "linux".into(),
            access: rackhand_proto::common::Access::Managed,
            mode: rackhand_proto::common::ProbeMode::Local,
            roles: vec![],
        };
        let (_, machine_token) = registry.add_machine(&add, "admin", now_ms()).await.unwrap();
        let fields = [("token", machine_token.as_str()), ("fingerprint", sim.fingerprint.as_str()), ("api_key", KEY)];
        let (code, refused) = submit(&app, &admin, "/add/appliance/accept", &fields).await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert!(refused.contains("another kind"), "{refused}");
        let (_, shown) = submit(
            &app,
            &admin,
            "/add/appliance",
            &[("driver", "truenas"), ("name", "nas3"), ("address", sim.url.as_str())],
        )
        .await;
        let form_token = crate::registry::tokens::Token::parse(&hidden(&shown, "token"));
        let as_probe = rackhand_store::RegistryChange {
            consume: Some(rackhand_store::ConsumeToken {
                hash: crate::registry::tokens::hash(&form_token).to_vec(),
                kind: "machine".into(),
                now_ms: now_ms(),
            }),
            writes: vec![],
            updates: vec![],
        };
        assert!(app.db.writer().send(WriteCmd::RegistryChange(as_probe)).await.is_err(), "a probe can't join with it");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn proxmox_token_attaches_to_its_enrolled_host() {
        let app = agentless_app("agentless-pve").await;
        let admin = session_for(&app.db, Role::Admin).await;
        let sim = rackhand_drivers::proxmox::sim::Sim::start("pve8").await;
        // the Proxmox host already runs a probe
        let site: String =
            app.db.readers().with(|c| c.query_row("SELECT id FROM sites LIMIT 1", [], |r| r.get(0))).unwrap();
        let host = "01JD00000000000000000000PV";
        let row = Row::from([
            ("id", Value::Text(host.into())),
            ("site_id", Value::Text(site)),
            ("name", Value::Text("pve".into())),
            ("kind", Value::Text("linux".into())),
            ("state", Value::Text("enrolled".into())),
            ("probe_endpoint_id", Value::Text("e".repeat(64))),
        ]);
        app.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("machines", row)])).await.unwrap();
        let fields = [("driver", "proxmox"), ("machine", host), ("address", sim.url.as_str())];
        let (code, shown) = submit(&app, &admin, "/add/appliance", &fields).await;
        assert_eq!(code, StatusCode::OK, "{shown}");
        let token = hidden(&shown, "token");
        let fields = [("token", token.as_str()), ("fingerprint", sim.fingerprint.as_str()), ("token_value", PVE_TOKEN)];
        let (code, done) = submit(&app, &admin, "/add/appliance/accept", &fields).await;
        assert_eq!(code, StatusCode::OK, "{done}");
        let count: i64 =
            app.db.readers().with(|c| c.query_row("SELECT count(*) FROM machines", [], |r| r.get(0))).unwrap();
        assert_eq!(count, 1, "no second row for the same host");
        let (id, kind, state, driver, _, address) = machine_row(&app.db, "pve");
        assert_eq!((id.as_str(), kind.as_str(), state.as_str()), (host, "linux", "enrolled"));
        assert_eq!(driver.as_deref(), Some("proxmox"));
        assert_eq!(address, sim.url);
        // what the snapshot step reads (`driver.<host>`: token and fingerprint)
        let held: serde_json::Value =
            serde_json::from_slice(vault(&app).get(&format!("driver.{host}")).unwrap().expose()).unwrap();
        assert_eq!(
            (held["token"].as_str(), held["fingerprint"].as_str()),
            (Some(PVE_TOKEN), Some(sim.fingerprint.as_str()))
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snmp_form_has_no_certificate_and_keeps_its_community_secret() {
        let app = agentless_app("agentless-snmp").await;
        let admin = session_for(&app.db, Role::Admin).await;
        let sim = rackhand_drivers::snmp::sim::Sim::start().await;
        let fields = [("driver", "snmp"), ("name", "switch1"), ("address", sim.addr.as_str())];
        let (code, shown) = submit(&app, &admin, "/add/appliance", &fields).await;
        assert_eq!(code, StatusCode::OK, "{shown}");
        assert!(!shown.contains("fingerprint\" value"), "no certificate to accept: {shown}");
        let token = hidden(&shown, "token");
        let community = "public-lab";
        let fields = [("token", token.as_str()), ("version", "2c"), ("community", community)];
        let (code, done) = submit(&app, &admin, "/add/appliance/accept", &fields).await;
        assert_eq!(code, StatusCode::OK, "{done}");
        let (id, _, state, _, settings, _) = machine_row(&app.db, "switch1");
        assert_eq!(state, "enrolled");
        assert!(settings.unwrap().contains(&format!("secret:driver.{id}")));
        let leaks: Vec<String> = every_value(&app.db).into_iter().filter(|v| v.contains(community)).collect();
        assert!(leaks.is_empty(), "the community only in the Vault: {leaks:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn appliance_forms_admin_only() {
        let app = agentless_app("agentless-admin").await;
        let responder = session_for(&app.db, Role::Responder).await;
        let csrf = csrf_of(&app, &responder).await;
        let fields = [("csrf", csrf.as_str()), ("driver", "snmp"), ("name", "x"), ("address", "192.0.2.1")];
        assert_eq!(
            send(&app.router, post("/add/appliance", &responder, &fields)).await.status(),
            StatusCode::FORBIDDEN
        );
        let fields = [("csrf", csrf.as_str()), ("token", "X")];
        assert_eq!(
            send(&app.router, post("/add/appliance/accept", &responder, &fields)).await.status(),
            StatusCode::FORBIDDEN
        );
    }
}

/// 7.5.5, 7.7.1 (plan T81): the dead-man URL is an admin's setting, saved and audited without the URL itself.
mod deadman {
    use super::*;

    async fn set(app: &App, cookie: &str, url: &str) -> Response<Body> {
        let csrf = csrf_of(app, cookie).await;
        send(&app.router, post("/settings/deadman", cookie, &[("csrf", csrf.as_str()), ("url", url)])).await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn url_set_in_settings_admin_only() {
        let app = app("deadman-url").await;
        complete_first_run(&app, SETUP_CODE).await;
        let responder = session_for(&app.db, Role::Responder).await;
        assert_eq!(set(&app, &responder, "https://hc.example/ping/secret-key").await.status(), StatusCode::FORBIDDEN);
        assert!(crate::library::config::hub(&app.db).unwrap().deadman_url.is_none());
        let admin = session_for(&app.db, Role::Admin).await;
        // only an https address without spaces
        for bad in ["http://hc.example/ping", "ftp://x", "https://a b", "not a url"] {
            assert_eq!(set(&app, &admin, bad).await.status(), StatusCode::BAD_REQUEST, "{bad:?}");
        }
        assert_eq!(set(&app, &admin, "https://hc.example/ping/secret-key").await.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            crate::library::config::hub(&app.db).unwrap().deadman_url.as_deref(),
            Some("https://hc.example/ping/secret-key")
        );
        let page = text(send(&app.router, get("/settings", &admin)).await).await;
        assert!(page.contains("value=\"https:&#x2F;&#x2F;hc.example") || page.contains("hc.example"), "{page}");
        // audited, with no trace of the key in the log
        let logged: Vec<String> = app
            .db
            .readers()
            .with(|c| {
                let mut s = c.prepare("SELECT data FROM audit_log WHERE action = 'settings.deadman'")?;
                s.query_map([], |r| r.get(0))?.collect()
            })
            .unwrap();
        assert_eq!(logged.len(), 1, "{logged:?}");
        assert!(logged[0].contains("\"set\":true") && !logged[0].contains("secret-key"), "{logged:?}");
        // empty turns it off
        assert_eq!(set(&app, &admin, "").await.status(), StatusCode::SEE_OTHER);
        assert!(crate::library::config::hub(&app.db).unwrap().deadman_url.is_none());
    }
}
