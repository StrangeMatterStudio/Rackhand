//! First run in two steps (docs/designs/0002-dashboard-ui): the details, every problem shown at once beside its field
//! with what was typed kept; then the authenticator, with a QR code, the key and its own retries.

use super::*;

const PASSWORD: &str = "correct horse battery staple";
const SECOND: &str = "/first-run/second-factor";

/// The text under a field: what's wrong with it, empty when nothing is.
pub(super) fn error_of(html: &str, form: &str, name: &str) -> String {
    let marker = format!("id=\"{form}-{name}-error\"");
    let at = html.find(&marker).unwrap_or_else(|| panic!("no error element for {form}-{name}: {html}"));
    let open = at + html[at..].find('>').unwrap() + 1;
    html[open..open + html[open..].find("</p>").unwrap()].trim().to_string()
}

/// The opening tag of the control named `name` in the form with id `form`.
pub(super) fn control(html: &str, form: &str, name: &str) -> String {
    let marker = format!("id=\"{form}-{name}\"");
    let at = html.find(&marker).unwrap_or_else(|| panic!("no control {form}-{name}: {html}"));
    let open = html[..at].rfind('<').unwrap();
    html[open..open + html[open..].find('>').unwrap() + 1].to_string()
}

/// The option chosen in a select, if one is.
pub(super) fn selected(html: &str, form: &str, name: &str) -> Option<String> {
    let at = html.find(&format!("id=\"{form}-{name}\""))?;
    let select = &html[at..at + html[at..].find("</select>")?];
    let on = select.find(" selected")?;
    let open = select[..on].rfind("value=\"")? + 7;
    Some(select[open..open + select[open..].find('"')?].to_string())
}

/// Whether a checkbox is ticked.
fn ticked(html: &str, form: &str, name: &str) -> bool {
    control(html, form, name).contains(" checked")
}

async fn page(app: &App, path: &str, cookie: &str) -> (StatusCode, String) {
    let resp = send(&app.router, get(path, cookie)).await;
    let code = resp.status();
    (code, text(resp).await)
}

/// Sends the first step: the status, and the page shown or where it leads.
async fn step_one(app: &App, opened: &(String, String), fields: &[(&str, &str)]) -> (StatusCode, String) {
    let mut all = vec![("csrf", opened.1.as_str())];
    all.extend_from_slice(fields);
    let resp = send(&app.router, post("/first-run", &opened.0, &all)).await;
    let code = resp.status();
    if code == StatusCode::SEE_OTHER {
        return (code, location(&resp).unwrap_or_default());
    }
    (code, text(resp).await)
}

/// Details with nothing wrong, but for what the test changes.
fn with(change: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    let mut fields = vec![
        ("setup_code", SETUP_CODE),
        ("admin_name", "alex"),
        ("password", PASSWORD),
        ("site_name", "cabin"),
        ("timezone", "Europe/Berlin"),
        ("source_dbip", "on"),
    ];
    for (k, v) in change {
        fields.retain(|(name, _)| name != k);
        fields.push((k, v));
    }
    fields
}

async fn second(app: &App, opened: &(String, String), code: &str) -> Response<Body> {
    send(&app.router, post(SECOND, &opened.0, &[("csrf", opened.1.as_str()), ("totp_code", code)])).await
}

fn code_for(secret_b32: &str) -> String {
    totp::code(&totp::decode_base32(secret_b32).unwrap(), now_ms() / 1000)
}

/// Reads the page's QR code back, as an authenticator app would.
pub(super) fn scan(html: &str) -> String {
    let svg = &html[html.find("<svg").expect("an inline SVG")..];
    let svg = &svg[..svg.find("</svg>").unwrap()];
    let view = &svg[svg.find("viewBox=\"0 0 ").unwrap() + 13..];
    let size: usize = view[..view.find(' ').unwrap()].parse().unwrap();
    let path = &svg[svg.rfind(" d=\"").unwrap() + 4..];
    let path = &path[..path.find('"').unwrap()];
    let mut dark = std::collections::HashSet::new();
    for part in path.split('M').filter(|p| !p.trim().is_empty()) {
        let (x, rest) = part.trim().split_once(' ').unwrap();
        let y = rest.split('h').next().unwrap();
        dark.insert((x.parse::<usize>().unwrap(), y.parse::<usize>().unwrap()));
    }
    const SCALE: usize = 4;
    let px = size * SCALE;
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(px, px, |x, y| {
        if dark.contains(&(x / SCALE, y / SCALE)) { 0 } else { 255 }
    });
    let grids = img.detect_grids();
    assert_eq!(grids.len(), 1, "one QR code");
    grids[0].decode().unwrap().1
}

/// What the content security policy would refuse isn't there.
pub(super) fn no_inline(html: &str) {
    for (i, _) in html.match_indices("<script") {
        let tag = &html[i..i + html[i..].find('>').unwrap()];
        assert!(tag.contains("src=\"/static/"), "only scripts from /static: {tag}");
    }
    assert!(!html.contains(" style=") && !html.contains("<style"), "no inline style: {html}");
    assert!(!html.contains(" onclick=") && !html.contains("javascript:"), "no inline handlers");
}

#[tokio::test(flavor = "multi_thread")]
async fn every_field_says_what_it_needs_before_anything_goes_wrong() {
    let app = app("fr-hints").await;
    let (code, html) = page(&app, "/first-run", "").await;
    assert_eq!(code, StatusCode::OK);
    no_inline(&html);
    for (name, says) in [
        ("setup_code", "SETUP-"),
        ("admin_name", "1 to 64"),
        ("password", "12 characters"),
        ("site_name", "1 to 32"),
        ("timezone", "timezone"),
    ] {
        let id = format!("first-run-{name}");
        let tag = control(&html, "first-run", name);
        assert!(tag.contains(&format!("aria-describedby=\"{id}-hint {id}-error\"")), "{tag}");
        assert!(!tag.contains("aria-invalid"), "{tag}");
        let hint = &html[html.find(&format!("id=\"{id}-hint\"")).expect("a hint")..];
        let hint = &hint[..hint.find("</p>").unwrap()];
        assert!(hint.contains(says), "{name}: {hint}");
        assert_eq!(error_of(&html, "first-run", name), "", "{name}");
    }
    // the rules the page's script checks as it is filled in, without the browser's one-at-a-time bubbles
    let at = html.find("action=\"/first-run\"").unwrap();
    let form = &html[html[..at].rfind("<form").unwrap()..];
    let form = &form[..form.find('>').unwrap()];
    assert!(form.contains("novalidate") && form.contains("data-check"), "{form}");
    assert!(html.contains("src=\"/static/forms.js\""));
    // (an unescaped `-` in a class is an error to browsers, which then check nothing)
    assert!(control(&html, "first-run", "admin_name").contains("pattern=\"[a-z0-9._\\-]{1,64}\""), "{html}");
    assert!(control(&html, "first-run", "site_name").contains("pattern=\"[a-z0-9\\-]{1,32}\""));
    assert!(control(&html, "first-run", "password").contains("minlength=\"12\""));
    // the second factor isn't asked for yet
    assert!(!html.contains("totp_code") && !html.contains("totp_secret"), "{html}");
    let script = send(&app.router, get("/static/forms.js", "")).await;
    assert_eq!(script.status(), StatusCode::OK, "the script is served before anyone has signed in");
}

#[tokio::test(flavor = "multi_thread")]
async fn all_problems_are_shown_together_beside_their_fields_with_the_input_kept() {
    let app = app("fr-all").await;
    let opened = open_first_run(&app).await;
    let bad = [
        ("setup_code", SETUP_CODE),
        ("admin_name", "Alex Smith"),
        ("password", "short"),
        ("site_name", "My Cabin"),
        ("timezone", "Mars-Olympus"),
        ("source_spamhaus", "on"),
    ];
    let (code, html) = step_one(&app, &opened, &bad).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    for (name, says) in [("admin_name", "a-z"), ("password", "12"), ("site_name", "a-z"), ("timezone", "Mars-Olympus")]
    {
        let shown = error_of(&html, "first-run", name);
        assert!(shown.contains(says), "{name}: {shown}");
        assert!(control(&html, "first-run", name).contains("aria-invalid=\"true\""), "{name}");
        // one summary that names them all, linked to their fields
        assert!(html.contains(&format!("href=\"#first-run-{name}\"")), "{name} in the summary");
    }
    assert!(control(&html, "first-run", "admin_name").contains("value=\"Alex Smith\""), "kept");
    assert!(control(&html, "first-run", "site_name").contains("value=\"My Cabin\""), "kept");
    assert!(ticked(&html, "first-run", "source_spamhaus"), "a ticked box stays ticked");
    assert!(!ticked(&html, "first-run", "source_feodo"), "an unticked one stays unticked");
    assert!(!html.contains("value=\"short\""), "a password is never sent back");
    // an empty form: every field says it is needed
    let opened = open_first_run(&app).await;
    let (code, html) = step_one(&app, &opened, &[]).await;
    assert_ne!(code, StatusCode::SEE_OTHER);
    for name in ["setup_code", "admin_name", "password", "site_name", "timezone"] {
        assert_ne!(error_of(&html, "first-run", name), "", "{name}");
    }
    assert_eq!(user_count(&app.db).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_setup_code_keeps_the_form_and_names_every_other_problem() {
    let app = app("fr-setup").await;
    let opened = open_first_run(&app).await;
    let (code, html) =
        step_one(&app, &opened, &with(&[("setup_code", "SETUP-WRONG-0000"), ("site_name", "My Cabin")])).await;
    assert_eq!(code, StatusCode::FORBIDDEN);
    assert!(error_of(&html, "first-run", "setup_code").contains("installer"), "{html}");
    assert_ne!(error_of(&html, "first-run", "site_name"), "", "the other problems too");
    assert_eq!(error_of(&html, "first-run", "admin_name"), "", "nothing wrong with the name");
    assert!(control(&html, "first-run", "setup_code").contains("value=\"SETUP-WRONG-0000\""), "kept, to correct");
    assert!(control(&html, "first-run", "admin_name").contains("value=\"alex\""));
    assert_eq!(selected(&html, "first-run", "timezone").as_deref(), Some("Europe/Berlin"));
    assert!(!html.contains(PASSWORD), "the password isn't sent back");
    // corrected: the password typed the first time is kept by the hub and needn't be typed again
    let (code, to) = step_one(&app, &opened, &with(&[("password", "")])).await;
    assert_eq!((code, to.as_str()), (StatusCode::SEE_OTHER, SECOND));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_attempt_over_the_limit_keeps_the_form() {
    let app = app("fr-limited").await;
    for _ in 0..6 {
        let opened = open_first_run(&app).await;
        let (code, _) = step_one(&app, &opened, &with(&[("setup_code", "SETUP-WRONG-0000")])).await;
        assert_eq!(code, StatusCode::FORBIDDEN);
    }
    let opened = open_first_run(&app).await;
    let (code, html) = step_one(&app, &opened, &with(&[])).await;
    assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);
    assert!(html.contains("minute"), "{html}");
    assert!(control(&html, "first-run", "admin_name").contains("value=\"alex\""), "kept");
    assert_eq!(selected(&html, "first-run", "timezone").as_deref(), Some("Europe/Berlin"));
    assert!(!html.contains(PASSWORD));
    assert_eq!(user_count(&app.db).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_setup_code_is_not_asked_for_again() {
    let app = app("fr-accepted").await;
    let opened = open_first_run(&app).await;
    let (code, html) = step_one(&app, &opened, &with(&[("site_name", "My Cabin")])).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert!(html.contains("Setup code accepted"), "{html}");
    // now the source goes over the limit in another browser; the accepted one isn't guessing any more
    for _ in 0..7 {
        let other = open_first_run(&app).await;
        let _ = step_one(&app, &other, &with(&[("setup_code", "SETUP-WRONG-0000")])).await;
    }
    let fixed = [("admin_name", "alex"), ("password", ""), ("site_name", "cabin"), ("timezone", "Europe/Berlin")];
    let (code, to) = step_one(&app, &opened, &fixed).await;
    assert_eq!((code, to.as_str()), (StatusCode::SEE_OTHER, SECOND));
    // another browser hasn't been accepted by that
    let other = open_first_run(&app).await;
    let (code, _) = step_one(&app, &other, &fixed).await;
    assert_ne!(code, StatusCode::SEE_OTHER, "no code, no password");
}

#[tokio::test(flavor = "multi_thread")]
async fn timezones_are_picked_from_the_known_list() {
    let app = app("fr-tz").await;
    let (_, html) = page(&app, "/first-run", "").await;
    let select = control(&html, "first-run", "timezone");
    assert!(select.starts_with("<select") && select.contains("data-browser-timezone"), "{select}");
    for zone in ["UTC", "Europe/Berlin", "America/New_York", "Asia/Kolkata", "Pacific/Auckland"] {
        assert!(html.contains(&format!("<option value=\"{zone}\"")), "{zone}");
        assert!(jiff::tz::TimeZone::get(zone).is_ok());
    }
    assert!(html.matches("<option value=\"").count() > 300, "the whole list");
    assert_eq!(selected(&html, "first-run", "timezone"), None, "none is chosen for someone without the script");
    let opened = open_first_run(&app).await;
    let (code, html) = step_one(&app, &opened, &with(&[("timezone", "")])).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert_ne!(error_of(&html, "first-run", "timezone"), "", "not silently UTC");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_second_factor_is_its_own_last_step_with_a_qr_code_and_the_key() {
    let app = app("fr-second").await;
    let opened = open_first_run(&app).await;
    // not before the details are accepted
    let early = send(&app.router, get(SECOND, &opened.0)).await;
    assert_eq!((early.status(), location(&early).as_deref()), (StatusCode::SEE_OTHER, Some("/first-run")));
    let (code, to) = step_one(&app, &opened, &with(&[])).await;
    assert_eq!((code, to.as_str()), (StatusCode::SEE_OTHER, SECOND));
    assert_eq!(user_count(&app.db).await, 0, "nothing is made until the code is right");
    let (code, html) = page(&app, SECOND, &opened.0).await;
    assert_eq!(code, StatusCode::OK);
    no_inline(&html);
    let key = field(&html, "totp_secret");
    assert_eq!(totp::decode_base32(&key).unwrap().len(), 20);
    let uri = scan(&html);
    assert_eq!(uri, totp::uri("Rackhand", "alex", &totp::decode_base32(&key).unwrap()), "the QR code is the key's");
    assert!(html.contains("data-copy=\"totp-key\"") && html.contains("id=\"totp-key\""), "a copy button: {html}");
    assert!(html.contains("autocomplete=\"one-time-code\""));
    assert!(!html.contains(PASSWORD) && !html.contains(&app.recovery));
    // the same key again on a reload
    let (_, again) = page(&app, SECOND, &opened.0).await;
    assert_eq!(field(&again, "totp_secret"), key);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_code_keeps_the_key_and_loses_nothing() {
    let app = app("fr-wrong-code").await;
    let opened = open_first_run(&app).await;
    step_one(&app, &opened, &with(&[])).await;
    let (_, html) = page(&app, SECOND, &opened.0).await;
    let key = field(&html, "totp_secret");
    // an old code is as wrong as a made-up one
    let old = totp::code(&totp::decode_base32(&key).unwrap(), now_ms() / 1000 - 300);
    for wrong in [old.as_str(), "12345", "", "abcdef"] {
        let resp = second(&app, &opened, wrong).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{wrong}");
        let shown = text(resp).await;
        assert_ne!(error_of(&shown, "second-factor", "totp_code"), "", "{wrong}");
        assert_eq!(field(&shown, "totp_secret"), key, "the same key");
        assert_eq!(scan(&shown), scan(&html), "the same QR code");
    }
    assert_eq!(user_count(&app.db).await, 0);
    let done = second(&app, &opened, &code_for(&key)).await;
    assert_eq!(done.status(), StatusCode::OK);
    let done = text(done).await;
    assert!(done.contains(&app.recovery) && done.contains("cabin is set up"), "{done}");
    let (name, hash): (String, Vec<u8>) = app
        .db
        .readers()
        .with(|c| {
            c.query_row(
                "SELECT u.name, c.data FROM users u JOIN credentials c ON c.user_id = u.id AND c.kind = 'password'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
        })
        .unwrap();
    assert_eq!(name, "alex");
    assert!(crate::web::auth::password::verify(&String::from_utf8(hash).unwrap(), PASSWORD));
    let (site, tz): (String, String) = app
        .db
        .readers()
        .with(|c| c.query_row("SELECT name, timezone FROM sites", [], |r| Ok((r.get(0)?, r.get(1)?))))
        .unwrap();
    assert_eq!((site.as_str(), tz.as_str()), ("cabin", "Europe/Berlin"));
    let settings = crate::library::config::hub(&app.db).unwrap();
    assert!(settings.sources.dbip && !settings.sources.feodo && !settings.sources.spamhaus, "the sources as ticked");
    // the recovery code was shown once
    let after = send(&app.router, get(SECOND, &opened.0)).await;
    assert_eq!(after.status(), StatusCode::SEE_OTHER);
    let again = second(&app, &opened, &code_for(&key)).await;
    assert!(!text(again).await.contains(&app.recovery));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_details_can_be_changed_from_the_second_step() {
    let app = app("fr-back").await;
    let opened = open_first_run(&app).await;
    step_one(&app, &opened, &with(&[])).await;
    let (_, html) = page(&app, SECOND, &opened.0).await;
    assert!(html.contains("href=\"/first-run\""), "a way back: {html}");
    let key = field(&html, "totp_secret");
    let (_, details) = page(&app, "/first-run", &opened.0).await;
    assert!(control(&details, "first-run", "admin_name").contains("value=\"alex\""), "{details}");
    assert!(control(&details, "first-run", "site_name").contains("value=\"cabin\""));
    assert_eq!(selected(&details, "first-run", "timezone").as_deref(), Some("Europe/Berlin"));
    assert!(ticked(&details, "first-run", "source_dbip") && !ticked(&details, "first-run", "source_feodo"));
    assert!(details.contains("Setup code accepted") && !details.contains(PASSWORD), "{details}");
    let changed = [
        ("admin_name", "alex"),
        ("password", ""),
        ("site_name", "harbor"),
        ("timezone", "UTC"),
        ("source_feodo", "on"),
    ];
    assert_eq!(step_one(&app, &opened, &changed).await.0, StatusCode::SEE_OTHER);
    let (_, html) = page(&app, SECOND, &opened.0).await;
    assert_eq!(field(&html, "totp_secret"), key, "what was scanned stays right");
    assert_eq!(second(&app, &opened, &code_for(&key)).await.status(), StatusCode::OK);
    let site: String = app.db.readers().with(|c| c.query_row("SELECT name FROM sites", [], |r| r.get(0))).unwrap();
    assert_eq!(site, "harbor");
}

/// Details that stop being right take the second step away again until they are put right.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_change_of_details_is_not_finished_with_the_old_ones() {
    let app = app("fr-unaccept").await;
    let opened = open_first_run(&app).await;
    step_one(&app, &opened, &with(&[])).await;
    let (_, html) = page(&app, SECOND, &opened.0).await;
    let key = field(&html, "totp_secret");
    let refused = [("admin_name", "alex"), ("password", ""), ("site_name", "My Harbor"), ("timezone", "UTC")];
    assert_eq!(step_one(&app, &opened, &refused).await.0, StatusCode::BAD_REQUEST);
    let resp = second(&app, &opened, &code_for(&key)).await;
    assert_ne!(resp.status(), StatusCode::OK);
    assert_eq!(user_count(&app.db).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_second_step_belongs_to_the_browser_that_passed_the_first() {
    let app = app("fr-own").await;
    let opened = open_first_run(&app).await;
    step_one(&app, &opened, &with(&[])).await;
    let (_, html) = page(&app, SECOND, &opened.0).await;
    let key = field(&html, "totp_secret");
    let other = open_first_run(&app).await;
    let resp = send(&app.router, get(SECOND, &other.0)).await;
    assert_eq!(location(&resp).as_deref(), Some("/first-run"), "another browser has no second step");
    let resp = second(&app, &other, &code_for(&key)).await;
    assert_ne!(resp.status(), StatusCode::OK);
    // a key sent with the form is not taken: only the hub's own counts
    let mine = totp::encode_base32(&[7u8; 20]);
    let code = code_for(&mine);
    let fields = [("csrf", opened.1.as_str()), ("totp_secret", mine.as_str()), ("totp_code", code.as_str())];
    assert_eq!(send(&app.router, post(SECOND, &opened.0, &fields)).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(user_count(&app.db).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_step_left_too_long_returns_to_filled_in_details() {
    let clock = Arc::new(std::sync::atomic::AtomicI64::new(now_ms()));
    let c = clock.clone();
    let app = app_with("fr-expired", move |web| {
        web.with_clock(Arc::new(move || c.load(std::sync::atomic::Ordering::SeqCst)))
    })
    .await;
    let opened = open_first_run(&app).await;
    step_one(&app, &opened, &with(&[])).await;
    let (_, html) = page(&app, SECOND, &opened.0).await;
    let key = field(&html, "totp_secret");
    // what the second step's form carries besides the code, so the details outlive the hub's draft
    let carried: Vec<(&str, String)> =
        ["admin_name", "site_name", "timezone", "source_dbip"].iter().map(|n| (*n, field(&html, n))).collect();
    let hour = 61 * 60_000;
    let now = clock.fetch_add(hour, std::sync::atomic::Ordering::SeqCst) + hour;
    let code = totp::code(&totp::decode_base32(&key).unwrap(), now / 1000);
    let mut fields = vec![("csrf", opened.1.as_str()), ("totp_code", code.as_str())];
    fields.extend(carried.iter().map(|(k, v)| (*k, v.as_str())));
    let resp = send(&app.router, post(SECOND, &opened.0, &fields)).await;
    assert_eq!(resp.status(), StatusCode::GONE);
    let shown = text(resp).await;
    assert!(control(&shown, "first-run", "admin_name").contains("value=\"alex\""), "{shown}");
    assert!(control(&shown, "first-run", "site_name").contains("value=\"cabin\""));
    assert_eq!(selected(&shown, "first-run", "timezone").as_deref(), Some("Europe/Berlin"));
    assert!(ticked(&shown, "first-run", "source_dbip") && !ticked(&shown, "first-run", "source_feodo"));
    assert_ne!(error_of(&shown, "first-run", "password"), "", "the password has to be typed again, and it says so");
    assert_eq!(user_count(&app.db).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_page_left_open_for_hours_can_still_be_sent() {
    let app = app("fr-cookie").await;
    let resp = send(&app.router, get("/first-run", "")).await;
    let cookie = set_cookie(&resp, "rh_anon").unwrap();
    let age: i64 = cookie.split("Max-Age=").nth(1).unwrap().split(';').next().unwrap().parse().unwrap();
    assert!(age >= 12 * 3600, "the form's cookie outlives a working day: {cookie}");
}
