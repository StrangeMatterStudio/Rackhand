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
}

async fn app(name: &str) -> App {
    let dir = std::env::temp_dir().join(format!("rackhand-web-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let key = MasterKey::from_bytes([3u8; 32]);
    let recovery = recovery_code(&key);
    let vault = Arc::new(Vault::new(key, db.clone()));
    let config = WebConfig {
        setup_code_hash: Sha256::digest(SETUP_CODE.as_bytes()).into(),
        csrf_key: [9u8; 32],
        trusted_proxies: vec![],
    };
    let web = Web::new(db.clone(), vault, Audit::new(db.writer()), recovery.clone(), config);
    App { db, router: web.router(), recovery }
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
    let (cookie, csrf, secret, sig) = opened;
    let code = totp::code(&totp::decode_base32(&secret).unwrap(), now_ms() / 1000);
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
}
