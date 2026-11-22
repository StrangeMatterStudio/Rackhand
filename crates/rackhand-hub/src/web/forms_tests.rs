//! Every form of the dashboard (docs/designs/0002-dashboard-ui): what's wrong is shown on the form itself, all of it at
//! once and beside its field, with what was typed kept and secrets never sent back.

use super::first_run::{control, error_of, no_inline, scan, selected};
use super::*;

async fn admin_app(name: &str) -> (App, String) {
    let app = app_with(name, |web| {
        let registry = crate::registry::Registry::load(web.db().clone()).unwrap();
        let drivers: Vec<Arc<dyn rackhand_drivers::Driver>> =
            vec![Arc::new(rackhand_drivers::TrueNas::new()), Arc::new(rackhand_drivers::Snmp::new())];
        let ticket = "rackhand1:0000000000000000000000000000000000000000000000000000000000000001@192.0.2.10:7443";
        web.with_registry(registry).with_drivers(drivers).with_ticket(Arc::new(move || Some(ticket.to_string())))
    })
    .await;
    complete_first_run(&app, SETUP_CODE).await;
    let admin = session_for(&app.db, Role::Admin).await;
    (app, admin)
}

/// Sends a form: the status and the page (or where it leads).
async fn submit(app: &App, cookie: &str, path: &str, fields: &[(&str, &str)]) -> (StatusCode, String) {
    let csrf = csrf_of(app, cookie).await;
    let mut all = vec![("csrf", csrf.as_str())];
    all.extend_from_slice(fields);
    let resp = send(&app.router, post(path, cookie, &all)).await;
    let code = resp.status();
    if code == StatusCode::SEE_OTHER {
        return (code, location(&resp).unwrap_or_default());
    }
    (code, text(resp).await)
}

fn wrong(html: &str, form: &str, names: &[&str]) {
    for name in names {
        assert_ne!(error_of(html, form, name), "", "{form}-{name}: {html}");
        assert!(html.contains(&format!("href=\"#{form}-{name}\"")), "{form}-{name} in the summary");
        assert!(control(html, form, name).contains("aria-invalid=\"true\""), "{form}-{name}");
    }
}

fn right(html: &str, form: &str, names: &[&str]) {
    for name in names {
        assert_eq!(error_of(html, form, name), "", "{form}-{name}");
    }
}

fn kept(html: &str, form: &str, name: &str, value: &str) {
    let tag = control(html, form, name);
    assert!(tag.contains(&format!("value=\"{value}\"")), "{form}-{name} keeps {value}: {tag}");
}

fn held(html: &str) -> String {
    field(html, "held")
}

#[tokio::test(flavor = "multi_thread")]
async fn no_form_relies_on_the_browsers_one_at_a_time_bubbles() {
    let (app, admin) = admin_app("forms-bubbles").await;
    for path in ["/add", "/settings", "/settings/notifiers", "/patching", "/account", "/step-up"] {
        let html = text(send(&app.router, get(path, &admin)).await).await;
        no_inline(&html);
        let mut rules = 0;
        for (i, _) in html.match_indices("<form") {
            let form = &html[i..i + html[i..].find("</form>").unwrap()];
            let open = &form[..form.find('>').unwrap()];
            if form.contains(" required") || form.contains(" pattern=") || form.contains("type=\"password\"") {
                rules += 1;
                assert!(open.contains("novalidate") && open.contains("data-check"), "{path}: {open}");
                assert!(html.contains("src=\"/static/forms.js\""), "{path}");
            }
            // an unescaped `-` in a class is an error to browsers, which then check nothing
            for (p, _) in form.match_indices(" pattern=\"") {
                let pattern = &form[p + 10..p + 10 + form[p + 10..].find('"').unwrap()];
                assert!(!pattern.replace("\\-", "").contains("-]"), "{path}: {pattern}");
            }
        }
        assert!(rules > 0 || path == "/account", "{path} has a form with rules");
    }
    let (_, html) = submit(&app, &admin, "/sign-in", &[]).await;
    assert!(html.contains("novalidate"), "{html}");
}

#[tokio::test(flavor = "multi_thread")]
async fn add_machine_shows_every_problem_on_its_form() {
    let (app, admin) = admin_app("forms-machine").await;
    let bad = [("name", "web 1"), ("os", "beos"), ("access", "monitor"), ("mode", "remote")];
    let (code, html) = submit(&app, &admin, "/add/machine", &bad).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    wrong(&html, "add-machine", &["name", "os"]);
    right(&html, "add-machine", &["access", "mode"]);
    kept(&html, "add-machine", "name", "web 1");
    assert_eq!(selected(&html, "add-machine", "access").as_deref(), Some("monitor"));
    assert_eq!(selected(&html, "add-machine", "mode").as_deref(), Some("remote"));
    assert!(html.contains("Add an appliance"), "on the Add page itself");
    let good = [("name", "web1"), ("os", "linux"), ("access", "managed"), ("mode", "local")];
    assert_eq!(submit(&app, &admin, "/add/machine", &good).await.0, StatusCode::OK);
    let (code, html) = submit(&app, &admin, "/add/machine", &good).await;
    assert_eq!(code, StatusCode::CONFLICT);
    assert!(error_of(&html, "add-machine", "name").contains("already here"), "{html}");
    kept(&html, "add-machine", "name", "web1");
}

#[tokio::test(flavor = "multi_thread")]
async fn add_appliance_shows_every_problem_on_the_form_of_its_driver() {
    let (app, admin) = admin_app("forms-appliance").await;
    let bad = [("driver", "truenas"), ("name", "nas 1"), ("address", "ftp://nas")];
    let (code, html) = submit(&app, &admin, "/add/appliance", &bad).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    wrong(&html, "add-truenas", &["name", "address"]);
    kept(&html, "add-truenas", "address", "ftp://nas");
    right(&html, "add-snmp", &["name", "address"]);
    // an appliance that can't be reached: on its address
    let gone = [("driver", "truenas"), ("name", "nas1"), ("address", "https://127.0.0.1:9")];
    let (code, html) = submit(&app, &admin, "/add/appliance", &gone).await;
    assert_eq!(code, StatusCode::BAD_GATEWAY);
    assert!(error_of(&html, "add-truenas", "address").contains("reach"), "{html}");
    kept(&html, "add-truenas", "name", "nas1");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_first_poll_keeps_the_credentials_form() {
    let (app, admin) = admin_app("forms-poll").await;
    let sim = rackhand_drivers::snmp::sim::Sim::start().await;
    let start = [("driver", "snmp"), ("name", "switch1"), ("address", sim.addr.as_str())];
    let (code, html) = submit(&app, &admin, "/add/appliance", &start).await;
    assert_eq!(code, StatusCode::OK);
    let token = field(&html, "token");
    // v3 needs its own three, v2c its community: said together, not by a failed poll
    let (code, html) =
        submit(&app, &admin, "/add/appliance/accept", &[("token", token.as_str()), ("version", "3")]).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    wrong(&html, "accept", &["user", "auth_password", "priv_password"]);
    right(&html, "accept", &["community"]);
    let v3 = [
        ("token", token.as_str()),
        ("version", "3"),
        ("user", "monitor"),
        ("auth_password", "not-the-auth-password"),
        ("priv_password", "not-the-priv-password"),
    ];
    let (code, html) = submit(&app, &admin, "/add/appliance/accept", &v3).await;
    assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(html.contains("first poll failed"), "{html}");
    assert_eq!(field(&html, "token"), token, "the same form");
    kept(&html, "accept", "user", "monitor");
    assert_eq!(selected(&html, "accept", "version").as_deref(), Some("3"));
    assert!(!html.contains("not-the-auth-password") && !html.contains("not-the-priv-password"));
    // what was typed is held: only what was wrong has to be typed again
    let wrong_hold = held(&html);
    let again = [
        ("token", token.as_str()),
        ("held", wrong_hold.as_str()),
        ("version", "3"),
        ("user", "monitor"),
        ("auth_password", ""),
        ("priv_password", ""),
    ];
    let (code, html) = submit(&app, &admin, "/add/appliance/accept", &again).await;
    assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY, "polled with the held passwords, not refused as missing");
    // in another session the hold is nothing
    let other = session_for(&app.db, Role::Admin).await;
    let theirs = held(&html);
    let again = [
        ("token", token.as_str()),
        ("held", theirs.as_str()),
        ("version", "3"),
        ("user", "monitor"),
        ("auth_password", ""),
        ("priv_password", ""),
    ];
    let (code, html) = submit(&app, &other, "/add/appliance/accept", &again).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    wrong(&html, "accept", &["auth_password", "priv_password"]);
    // and the form still works
    let v2c = [("token", token.as_str()), ("version", "2c"), ("community", "public-lab")];
    assert_eq!(submit(&app, &admin, "/add/appliance/accept", &v2c).await.0, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn add_user_shows_every_problem_and_the_new_key_has_a_qr_code() {
    let (app, admin) = admin_app("forms-user").await;
    let bad = [("name", "al ice"), ("role", "owner"), ("auth", "local"), ("password", "tooshort")];
    let (code, html) = submit(&app, &admin, "/settings/users", &bad).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    wrong(&html, "user", &["name", "role", "password"]);
    right(&html, "user", &["auth", "subject"]);
    kept(&html, "user", "name", "al ice");
    assert!(!html.contains("tooshort"));
    let (code, html) =
        submit(&app, &admin, "/settings/users", &[("name", "bob"), ("role", "viewer"), ("auth", "oidc")]).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    wrong(&html, "user", &["subject"]);
    right(&html, "user", &["password"]);
    // the password is held while the name is put right
    let typed = "a long enough secret";
    let bad = [("name", "al ice"), ("role", "viewer"), ("auth", "local"), ("password", typed)];
    let (_, html) = submit(&app, &admin, "/settings/users", &bad).await;
    assert!(!html.contains(typed));
    let token = held(&html);
    let good = [("held", token.as_str()), ("name", "alice"), ("role", "viewer"), ("auth", "local"), ("password", "")];
    let (code, html) = submit(&app, &admin, "/settings/users", &good).await;
    assert_eq!(code, StatusCode::OK, "{html}");
    no_inline(&html);
    let key = field(&html, "totp_secret");
    assert_eq!(scan(&html), totp::uri("Rackhand", "alice", &totp::decode_base32(&key).unwrap()));
    assert!(html.contains("data-copy=\"totp-key\""));
    let account = crate::web::auth::users::find(&app.db, "alice").unwrap().unwrap();
    assert!(crate::web::auth::password::verify(account.password_hash.as_deref().unwrap(), typed));
    // the name is taken now
    let again = [("name", "alice"), ("role", "viewer"), ("auth", "local"), ("password", typed)];
    let (code, html) = submit(&app, &admin, "/settings/users", &again).await;
    assert_eq!(code, StatusCode::CONFLICT);
    assert!(error_of(&html, "user", "name").contains("taken"), "{html}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_last_admin_is_explained_on_the_settings_page() {
    let app = app("forms-last-admin").await;
    complete_first_run(&app, SETUP_CODE).await;
    let id: String = app.db.readers().with(|c| c.query_row("SELECT id FROM users", [], |r| r.get(0))).unwrap();
    let cookie = format!("{}={}", session::COOKIE, session::create(&app.db, &id, now_ms()).await.unwrap());
    let (code, html) = submit(&app, &cookie, &format!("/settings/users/{id}/disable"), &[]).await;
    assert_eq!(code, StatusCode::CONFLICT);
    assert!(html.contains("at least one enabled admin") && html.contains("Outside sources"), "{html}");
    // each user's own role is the one shown
    let html = text(send(&app.router, get("/settings", &cookie)).await).await;
    assert!(html.contains("<option value=\"admin\" selected>"), "{html}");
}

#[tokio::test(flavor = "multi_thread")]
async fn notifiers_show_every_problem_on_the_form_that_was_sent() {
    let (app, admin) = admin_app("forms-notifiers").await;
    let bad = [
        ("kind", "smtp"),
        ("name", "Ops Mail"),
        ("host", "bad host"),
        ("port", "99999"),
        ("security", "none"),
        ("username", "hub@example.test"),
        ("password", "do-not-echo-this"),
        ("from", "nobody"),
        ("to", " "),
    ];
    let (code, html) = submit(&app, &admin, "/settings/notifiers", &bad).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    wrong(&html, "smtp", &["name", "host", "port", "security", "from", "to"]);
    right(&html, "discord", &["name", "webhook"]);
    kept(&html, "smtp", "host", "bad host");
    kept(&html, "smtp", "port", "99999");
    kept(&html, "smtp", "username", "hub@example.test");
    assert!(!html.contains("do-not-echo-this"));
    let token = held(&html);
    let good = [
        ("kind", "smtp"),
        ("held", token.as_str()),
        ("name", "mail"),
        ("host", "smtp.example.test"),
        ("port", "587"),
        ("security", "starttls"),
        ("username", "hub@example.test"),
        ("password", ""),
        ("from", "hub@example.test"),
        ("to", "ops@example.test"),
    ];
    assert_eq!(submit(&app, &admin, "/settings/notifiers", &good).await.0, StatusCode::SEE_OTHER);
    let vault = Vault::new(MasterKey::from_bytes([3u8; 32]), app.db.clone());
    assert_eq!(vault.get("notifier.mail.password").unwrap().expose(), b"do-not-echo-this");
    let bad = [("kind", "discord"), ("name", "Ops!"), ("webhook", "http://discord.example.test/do-not-echo")];
    let (code, html) = submit(&app, &admin, "/settings/notifiers", &bad).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    wrong(&html, "discord", &["name", "webhook"]);
    right(&html, "smtp", &["name", "host"]);
    assert!(!html.contains("do-not-echo"));
    let (code, html) = submit(&app, &admin, "/settings/notifiers", &[("kind", "discord"), ("name", "new")]).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    wrong(&html, "discord", &["webhook"]);
    kept(&html, "discord", "name", "new");
}

#[tokio::test(flavor = "multi_thread")]
async fn policies_and_windows_show_every_problem() {
    let (app, admin) = admin_app("forms-patching").await;
    let (code, html) = submit(
        &app,
        &admin,
        "/policies",
        &[
            ("name", ""),
            ("patch", "sometimes"),
            ("auto_reboot", "on"),
            ("snapshot", "maybe"),
            ("quarantine", "never"),
            ("peer_requests", "auto"),
        ],
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    wrong(&html, "policy", &["name", "patch", "snapshot"]);
    right(&html, "policy", &["quarantine", "peer_requests"]);
    assert!(control(&html, "policy", "auto_reboot").contains(" checked"));
    assert_eq!(selected(&html, "policy", "quarantine").as_deref(), Some("never"));
    let bad = [("machine", ""), ("tag", ""), ("rrule", "every sunday"), ("timezone", "Mars-Olympus")];
    let (code, html) = submit(&app, &admin, "/windows", &bad).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    wrong(&html, "window", &["machine", "rrule", "timezone"]);
    kept(&html, "window", "rrule", "every sunday");
    assert!(error_of(&html, "window", "rrule").contains("weekly"), "{html}");
    let both = [("machine", "nobody"), ("tag", "lab"), ("rrule", "daily 03:00 60m"), ("timezone", "UTC")];
    let (code, html) = submit(&app, &admin, "/windows", &both).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    wrong(&html, "window", &["machine"]);
    kept(&html, "window", "tag", "lab");
    assert_eq!(selected(&html, "window", "timezone").as_deref(), Some("UTC"));
    let good = [("machine", ""), ("tag", "lab"), ("rrule", "daily 03:00 60m"), ("timezone", "Europe/Berlin")];
    assert_eq!(submit(&app, &admin, "/windows", &good).await.0, StatusCode::SEE_OTHER);
    // the form picks the machine and the timezone, rather than asking for an id
    let html = text(send(&app.router, get("/patching", &admin)).await).await;
    assert!(control(&html, "window", "machine").starts_with("<select"));
    assert!(control(&html, "window", "timezone").contains("data-browser-timezone"));
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_show_every_problem_on_the_form_that_was_sent() {
    let (app, admin) = admin_app("forms-settings").await;
    let (code, html) = submit(&app, &admin, "/settings/git-mirror", &[("url", "file:///etc")]).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    wrong(&html, "mirror", &["url"]);
    kept(&html, "mirror", "url", "file:///etc");
    let bad = [
        ("issuer", "http://id.example.test"),
        ("client_id", ""),
        ("client_secret", "do-not-echo-this"),
        ("redirect_url", "https://hub.example.test/elsewhere"),
    ];
    let (code, html) = submit(&app, &admin, "/settings/oidc", &bad).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    wrong(&html, "oidc", &["issuer", "client_id", "redirect_url"]);
    right(&html, "oidc", &["client_secret"]);
    kept(&html, "oidc", "issuer", "http://id.example.test");
    assert!(!html.contains("do-not-echo-this"));
    let token = held(&html);
    let good = [
        ("held", token.as_str()),
        ("issuer", "https://id.example.test"),
        ("client_id", "hub"),
        ("client_secret", ""),
        ("redirect_url", "https://hub.example.test/sign-in/oidc/callback"),
    ];
    assert_eq!(submit(&app, &admin, "/settings/oidc", &good).await.0, StatusCode::SEE_OTHER);
    // with nothing held and nothing stored, the secret is asked for
    let (other, admin) = admin_app("forms-settings-2").await;
    let missing: Vec<(&str, &str)> = good.iter().copied().filter(|(k, _)| *k != "held").collect();
    let (code, html) = submit(&other, &admin, "/settings/oidc", &missing).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    wrong(&html, "oidc", &["client_secret"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_draft_that_cannot_be_applied_is_explained_in_the_library() {
    let (app, admin) = admin_app("forms-draft").await;
    let (code, html) = submit(&app, &admin, "/library/drafts/01JNOSUCHDRAFT/apply", &[]).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert!(html.contains("no pending draft") && html.contains("<h2>Drafts</h2>"), "on the Library page: {html}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_decision_is_explained_on_the_approvals_page() {
    let (app, admin) = admin_app("forms-approval").await;
    let (code, html) = submit(&app, &admin, "/approvals/01JNOSUCHAPPROVAL/approve", &[]).await;
    assert_eq!(code, StatusCode::NOT_FOUND);
    assert!(html.contains("No such approval") && html.contains("<h1>Approvals</h1>"), "{html}");
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_in_keeps_the_name_and_says_what_to_do() {
    let (app, _) = admin_app("forms-sign-in").await;
    let resp = send(&app.router, get("/sign-in", "")).await;
    let cookie = set_cookie(&resp, "rh_anon").unwrap().split(';').next().unwrap().to_string();
    let csrf = field(&text(resp).await, "csrf");
    let attempt = async |name: &str, password: &str| {
        let fields = [("csrf", csrf.as_str()), ("name", name), ("password", password)];
        let resp = send(&app.router, post("/sign-in", &cookie, &fields)).await;
        (resp.status(), text(resp).await)
    };
    let (code, html) = attempt("", "").await;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
    wrong(&html, "sign-in", &["name", "password"]);
    let (code, html) = attempt("admin", "wrong").await;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
    kept(&html, "sign-in", "name", "admin");
    assert!(html.contains("Wrong name or password"), "still not saying which: {html}");
    assert!(!html.contains("value=\"wrong\""));
    for _ in 0..8 {
        let _ = attempt("admin", "wrong").await;
    }
    let (code, html) = attempt("admin", "wrong").await;
    assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);
    assert!(html.contains("minute"), "{html}");
    kept(&html, "sign-in", "name", "admin");
}

/// A failed test message is said on the page, which stays (it used to refresh away at once).
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_test_message_stays_on_the_notifiers_page() {
    let app = app_with("forms-test-message", |web| {
        let ingest = crate::ingest::Ingest::new(web.db().clone(), crate::bus::Bus::new(), Arc::new(pages::Roomy));
        let nowhere: Arc<dyn crate::notify::Transport> =
            Arc::new(crate::notify::discord::Discord::new("ops", "http://127.0.0.1:9/hook"));
        let notify = crate::notify::Notify::new(web.db().clone(), ingest.clone(), vec![nowhere]);
        web.with_ingest(ingest).with_notify(notify)
    })
    .await;
    complete_first_run(&app, SETUP_CODE).await;
    let admin = session_for(&app.db, Role::Admin).await;
    let (code, html) = submit(&app, &admin, "/settings/notifiers/test", &[]).await;
    assert_eq!(code, StatusCode::BAD_GATEWAY);
    assert!(html.contains("The test failed") && html.contains("<h1>Notifiers</h1>"), "{html}");
    assert!(!html.contains("http-equiv"), "it doesn't move on by itself: {html}");
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_codes_keep_the_step_and_the_last_one_says_why_it_ends() {
    let (app, _) = admin_app("forms-codes").await;
    let resp = send(&app.router, get("/sign-in", "")).await;
    let anon = set_cookie(&resp, "rh_anon").unwrap().split(';').next().unwrap().to_string();
    let csrf = field(&text(resp).await, "csrf");
    let fields = [("csrf", csrf.as_str()), ("name", "admin"), ("password", "correct horse battery staple")];
    let resp = send(&app.router, post("/sign-in", &anon, &fields)).await;
    assert_eq!(location(&resp).as_deref(), Some("/sign-in/code"));
    let pending = set_cookie(&resp, "rh_pending").unwrap().split(';').next().unwrap().to_string();
    let cookies = format!("{anon}; {pending}");
    for wrong_code in ["12", "abcdef", "000000", "000000"] {
        let fields = [("csrf", csrf.as_str()), ("code", wrong_code)];
        let resp = send(&app.router, post("/sign-in/code", &cookies, &fields)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{wrong_code}");
        let html = text(resp).await;
        wrong(&html, "code", &["code"]);
        kept(&html, "code", "code", "");
    }
    let fields = [("csrf", csrf.as_str()), ("code", "000000")];
    let last = send(&app.router, post("/sign-in/code", &cookies, &fields)).await;
    assert_eq!(location(&last).as_deref(), Some("/sign-in"));
    let html = text(send(&app.router, get("/sign-in", &cookies)).await).await;
    assert!(html.contains("Too many wrong codes"), "{html}");
    let resp = send(&app.router, get("/sign-in/code", &cookies)).await;
    assert_eq!(location(&resp).as_deref(), Some("/sign-in"), "the code step is over");
}

/// Held secrets are for half an hour, and for one try.
#[tokio::test(flavor = "multi_thread")]
async fn held_secrets_expire_and_work_once() {
    let clock = Arc::new(std::sync::atomic::AtomicI64::new(now_ms()));
    let c = clock.clone();
    let app = app_with("forms-held", move |web| {
        web.with_clock(Arc::new(move || c.load(std::sync::atomic::Ordering::SeqCst)))
    })
    .await;
    complete_first_run(&app, SETUP_CODE).await;
    let admin = session_for(&app.db, Role::Admin).await;
    let bad = [("name", "al ice"), ("role", "viewer"), ("auth", "local"), ("password", "a long enough secret")];
    let again = |token: String| {
        let (app, admin) = (&app, &admin);
        async move {
            let fields = [("held", token.as_str()), ("name", "al ice"), ("role", "viewer"), ("auth", "local")];
            submit(app, admin, "/settings/users", &fields).await.1
        }
    };
    let token = held(&submit(&app, &admin, "/settings/users", &bad).await.1);
    right(&again(token.clone()).await, "user", &["password"]);
    wrong(&again(token).await, "user", &["password"]);
    let token = held(&submit(&app, &admin, "/settings/users", &bad).await.1);
    clock.fetch_add(31 * 60_000, std::sync::atomic::Ordering::SeqCst);
    wrong(&again(token).await, "user", &["password"]);
}

/// The rules the pages show and check are the ones the systems behind them have.
#[tokio::test(flavor = "multi_thread")]
async fn the_rules_shown_are_the_rules_kept() {
    let app = app("forms-rules").await;
    let resp = send(&app.router, get("/first-run", "")).await;
    let cookie = set_cookie(&resp, "rh_anon").unwrap().split(';').next().unwrap().to_string();
    let csrf = field(&text(resp).await, "csrf");
    let long = "a".repeat(33);
    for name in ["home", "a-1", "-", long.as_str(), "Home", "a b", "a.b", "a_b", "caf\u{e9}", "a\nb"] {
        let fields = [("csrf", csrf.as_str()), ("setup_code", SETUP_CODE), ("site_name", name)];
        let html = text(send(&app.router, post("/first-run", &cookie, &fields)).await).await;
        let fits = error_of(&html, "first-run", "site_name").is_empty();
        assert_eq!(fits, crate::registry::peers::valid_site_name(name), "{name:?}");
    }
}
