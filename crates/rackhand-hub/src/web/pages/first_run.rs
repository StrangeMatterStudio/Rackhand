//! First run (7.7.1), in two steps. The details: the installer's setup code, the admin's name and password, the site and
//! its timezone, and the outside sources; every problem is shown at once and nothing typed is lost. Then the second
//! factor: a QR code, its key and a code to check them, which can be wrong any number of times. Between the steps the
//! hub keeps a draft in memory for the browser's anonymous cookie, with the password already hashed; nothing is stored
//! until the code is right. Then the admin, both credentials, the site and the first settings revision are written in
//! one command that succeeds only while there is no user, so two first runs can't make two admins; the recovery code is
//! shown in that one response and never again.

use std::collections::HashMap;
use std::sync::Mutex;

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use rackhand_store::{Row, RowWrite, StoreError, WriteCmd};
use rusqlite::types::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{html, redirect, status};
use crate::library::config::{self, HubConfig, Sources};
use crate::registry::peers::local_site_row;
use crate::vault::Secret;
use crate::web::auth::limits::Attempt;
use crate::web::auth::password;
use crate::web::csrf::Binding;
use crate::web::forms::{self, Form, Spec};
use crate::web::{Ctx, Web, totp};

const SECOND_FACTOR: &str = "/first-run/second-factor";
/// A draft is kept this long after it was last used.
const DRAFT_MS: i64 = 60 * 60_000;
/// Drafts kept at once; those without the setup code go first, then the oldest.
const MAX_DRAFTS: usize = 256;
/// What a draft remembers of the details.
const REMEMBERED: &[&str] = &["admin_name", "site_name", forms::ZONE, "source_feodo", "source_spamhaus", "source_dbip"];

const DETAILS: &[Spec] = &[
    Spec::text("setup_code", "Setup code")
        .hint("The code the installer printed when it finished. It starts with SETUP- and has three groups of four.")
        .attrs("autocomplete=\"off\" autocapitalize=\"characters\" spellcheck=\"false\""),
    Spec::text("admin_name", "Admin name")
        .hint("The name you sign in with: 1 to 64 lower-case letters (a-z), digits, dots, dashes and underscores.")
        .pattern(r"[a-z0-9._\-]{1,64}", "Use 1 to 64 of a-z, 0-9, dot, dash and underscore, with no capitals or spaces")
        .attrs("autocomplete=\"username\" autocapitalize=\"none\" spellcheck=\"false\""),
    Spec::secret("password", "Password")
        .hint("At least 12 characters. A few unrelated words work well.")
        .length(password::MIN_LENGTH, 1024)
        .attrs("autocomplete=\"new-password\""),
    Spec::text("site_name", "Site name")
        .hint("What this place is called here and to other hubs: 1 to 32 lower-case letters (a-z), digits and dashes.")
        .pattern(r"[a-z0-9\-]{1,32}", "Use 1 to 32 of a-z, 0-9 and dash, with no capitals or spaces")
        .attrs("autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\""),
    forms::TIMEZONE,
    Spec::checkbox("source_feodo", "abuse.ch Feodo Tracker (CC0)"),
    Spec::checkbox("source_spamhaus", "Spamhaus DROP (free with credit)"),
    Spec::checkbox("source_dbip", "DB-IP Lite country and ASN (CC BY 4.0)"),
];

const CODE: &[Spec] = &[Spec::text("totp_code", "Code from the app")
    .hint("The 6 digits the app shows for Rackhand now. They change every 30 seconds; take your time, a late one can be retried.")
    .pattern("[0-9]{6}", "The code is 6 digits")
    .attrs("autocomplete=\"one-time-code\" inputmode=\"numeric\"")];

#[derive(Template)]
#[template(path = "first_run.html")]
struct DetailsPage<'a> {
    csrf: &'a str,
    form: Form,
}

#[derive(Template)]
#[template(path = "first_run_factor.html")]
struct FactorPage<'a> {
    csrf: &'a str,
    form: Form,
    admin: &'a str,
    secret: &'a str,
    uri: &'a str,
    qr: String,
    carried: Vec<(&'static str, String)>,
}

#[derive(Template)]
#[template(path = "first_run_done.html")]
struct Done<'a> {
    admin: &'a str,
    site: &'a str,
    recovery_code: &'a str,
}

/// What a browser has got to so far.
#[derive(Clone)]
struct Draft {
    /// The setup code was right, so it isn't asked for again (nor guessed at).
    setup_ok: bool,
    password_hash: Option<String>,
    /// What was typed, once the setup code was right.
    typed: HashMap<&'static str, String>,
    /// Every detail was accepted: the second step is open.
    accepted: bool,
    /// The authenticator's key, the same however often the second step is shown or the details changed.
    secret: Zeroizing<[u8; 20]>,
    used_ms: i64,
}

impl Draft {
    fn value(&self, name: &str) -> &str {
        self.typed.get(name).map(String::as_str).unwrap_or("")
    }
}

/// The drafts of first run, by the browser's anonymous cookie. In memory only: a restarted hub asks again.
#[derive(Default)]
pub(crate) struct Drafts(Mutex<HashMap<String, Draft>>);

impl Drafts {
    fn get(&self, key: &str, now_ms: i64) -> Option<Draft> {
        let mut all = self.0.lock().ok()?;
        let d = all.get_mut(key).filter(|d| now_ms - d.used_ms < DRAFT_MS)?;
        d.used_ms = now_ms;
        Some(d.clone())
    }

    fn put(&self, key: &str, mut draft: Draft, now_ms: i64) {
        let Ok(mut all) = self.0.lock() else { return };
        all.retain(|_, d| now_ms - d.used_ms < DRAFT_MS);
        while all.len() >= MAX_DRAFTS && !all.contains_key(key) {
            let Some(first) = all.iter().min_by_key(|(_, d)| (d.setup_ok, d.used_ms)).map(|(k, _)| k.clone()) else {
                return;
            };
            all.remove(&first);
        }
        draft.used_ms = now_ms;
        all.insert(key.to_string(), draft);
    }

    fn clear(&self) {
        if let Ok(mut all) = self.0.lock() {
            all.clear();
        }
    }
}

fn key(ctx: &Ctx) -> String {
    match &ctx.binding {
        Binding::Anonymous(id) => id.clone(),
        Binding::Session(hash) => hash.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

fn details_page(ctx: &Ctx, code: StatusCode, form: Form) -> Response<Body> {
    html(code, DetailsPage { csrf: &ctx.csrf, form: form.options(forms::ZONE, forms::timezones()) }.render())
}

pub(super) fn form(web: &Web, ctx: &Ctx) -> Response<Body> {
    let mut form = Form::blank("first-run", DETAILS);
    match web.0.first_run.get(&key(ctx), ctx.now_ms) {
        Some(draft) => {
            if draft.typed.is_empty() {
                form = with_default_sources(form);
            }
            for name in REMEMBERED.iter().filter(|n| draft.typed.contains_key(*n)) {
                form.set(name, draft.value(name));
            }
            show_draft(&mut form, &draft);
        }
        None => form = with_default_sources(form),
    }
    details_page(ctx, StatusCode::OK, form)
}

fn with_default_sources(form: Form) -> Form {
    form.with("source_feodo", "on").with("source_spamhaus", "on").with("source_dbip", "on")
}

/// What the hub already has isn't asked for again.
fn show_draft(form: &mut Form, draft: &Draft) {
    if draft.setup_ok {
        form.settle("setup_code", "Setup code accepted.");
    }
    if draft.password_hash.is_some() {
        form.keep("password", forms::KEPT);
    }
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The first step: everything is checked, and either all of it is accepted or all that's wrong is shown.
pub(super) async fn submit(web: &Web, ctx: &Ctx) -> Response<Body> {
    let key = key(ctx);
    let mut draft = match web.0.first_run.get(&key, ctx.now_ms) {
        Some(d) => d,
        None => {
            let Ok(secret) = totp::new_secret() else {
                return status(StatusCode::INTERNAL_SERVER_ERROR, "No randomness");
            };
            Draft {
                setup_ok: false,
                password_hash: None,
                typed: HashMap::new(),
                accepted: false,
                secret: Zeroizing::new(secret),
                used_ms: ctx.now_ms,
            }
        }
    };
    let mut form = Form::sent("first-run", DETAILS, ctx, &web.0.held);
    let typed_password = !form.value("password").is_empty();
    // guesses at the setup code count against the source like sign-in attempts (7.7.2)
    let attempt = Attempt { source: &ctx.source, account: None, known_device: None };
    if !draft.setup_ok && !web.0.limits.lock().map(|mut l| l.try_attempt(&attempt, ctx.now_ms)).unwrap_or(false) {
        form.notice("Too many attempts from here. Wait a minute, then press Continue again.");
        if typed_password {
            // not looked at, so not kept either
            draft.password_hash = None;
            form.refuse("password", "Type it again; everything else is kept");
            web.0.first_run.put(&key, draft.clone(), ctx.now_ms);
        }
        show_draft(&mut form, &draft);
        return details_page(ctx, StatusCode::TOO_MANY_REQUESTS, form);
    }
    let mut code = StatusCode::BAD_REQUEST;
    let setup = form.value("setup_code");
    if !draft.setup_ok && !setup.is_empty() {
        let given: [u8; 32] = Sha256::digest(setup.as_bytes()).into();
        if same(&given, &web.0.config.setup_code_hash) {
            draft.setup_ok = true;
        } else {
            if let Ok(mut l) = web.0.limits.lock() {
                l.fail(&attempt, ctx.now_ms);
            }
            form.refuse("setup_code", "That isn't the setup code the installer printed");
            code = StatusCode::FORBIDDEN;
        }
    }
    show_draft(&mut form, &draft);
    form.check();
    if typed_password {
        draft.password_hash = None;
        if !form.has_error("password") {
            let Ok(hash) = password::hash(form.value("password")) else {
                return status(StatusCode::INTERNAL_SERVER_ERROR, "Password hashing failed");
            };
            draft.password_hash = Some(hash);
            form.keep("password", forms::KEPT);
        } else {
            form.forget("password");
        }
    }
    if draft.setup_ok {
        draft.typed = REMEMBERED.iter().map(|n| (*n, form.value(n).to_string())).collect();
    }
    draft.accepted = form.ok();
    web.0.first_run.put(&key, draft, ctx.now_ms);
    if form.ok() { redirect(SECOND_FACTOR) } else { details_page(ctx, code, form) }
}

fn factor_page(ctx: &Ctx, code: StatusCode, draft: &Draft, form: Form) -> Response<Body> {
    let admin = draft.value("admin_name");
    let uri = totp::uri("Rackhand", admin, draft.secret.as_slice());
    let page = FactorPage {
        csrf: &ctx.csrf,
        form,
        admin,
        secret: &totp::encode_base32(draft.secret.as_slice()),
        uri: &uri,
        qr: forms::qr_svg(&uri, "QR code of the key for an authenticator app"),
        carried: REMEMBERED.iter().map(|n| (*n, draft.value(n).to_string())).collect(),
    };
    html(code, page.render())
}

pub(super) fn factor(web: &Web, ctx: &Ctx) -> Response<Body> {
    match web.0.first_run.get(&key(ctx), ctx.now_ms).filter(|d| d.accepted) {
        Some(draft) => factor_page(ctx, StatusCode::OK, &draft, Form::blank("second-factor", CODE)),
        None => redirect("/first-run"),
    }
}

/// The second step sent without accepted details behind it (left for over an hour, or the hub restarted): back to the
/// details, filled in from what the second step carried.
fn details_again(web: &Web, ctx: &Ctx, draft: Option<Draft>) -> Response<Body> {
    let mut form = Form::sent("first-run", DETAILS, ctx, &web.0.held);
    form.notice("The details have to be confirmed again: the hub keeps them for an hour, and not across a restart.");
    match draft {
        Some(d) => show_draft(&mut form, &d),
        None => {
            form.refuse("setup_code", "Enter it again");
            form.refuse("password", "Type it again; the hub doesn't keep it longer than that");
        }
    }
    details_page(ctx, StatusCode::GONE, form)
}

/// The second step: the code is checked against the draft's key, and then everything is stored at once.
pub(super) async fn factor_submit(web: &Web, ctx: &Ctx) -> Response<Body> {
    let draft = web.0.first_run.get(&key(ctx), ctx.now_ms);
    let (draft, password_hash) = match draft {
        Some(d) if d.accepted => match d.password_hash.clone() {
            Some(hash) => (d, hash),
            None => return details_again(web, ctx, Some(d)),
        },
        other => return details_again(web, ctx, other),
    };
    let mut form = Form::sent("second-factor", CODE, ctx, &web.0.held);
    let digits: String = form.value("totp_code").chars().filter(|c| !c.is_whitespace()).collect();
    form.set("totp_code", &digits);
    form.check();
    let step = totp::verify(draft.secret.as_slice(), &digits, ctx.now_ms / 1000);
    let Some(step) = step.filter(|_| form.ok()) else {
        let clock = jiff::Timestamp::from_millisecond(ctx.now_ms)
            .map(|t| t.strftime("%H:%M:%S").to_string())
            .unwrap_or_default();
        form.refuse(
            "totp_code",
            format!(
                "That code doesn't match. Enter the one the app shows now. If it keeps failing, check the clock of the \
                 device with the app: the hub's says {clock} UTC."
            ),
        );
        // a code is never right twice, so it isn't kept
        form.set("totp_code", "");
        return factor_page(ctx, StatusCode::BAD_REQUEST, &draft, form);
    };
    let (name, site, tz) = (draft.value("admin_name"), draft.value("site_name"), draft.value(forms::ZONE));
    let on = |n: &str| draft.value(n) == "on";
    let sources = Sources { feodo: on("source_feodo"), spamhaus: on("source_spamhaus"), dbip: on("source_dbip") };
    let settings = HubConfig { sources, ..HubConfig::default() }.to_toml();

    let user_id = ulid::Ulid::new().to_string();
    let vault_name = format!("totp:{user_id}");
    if web.0.vault.put(&vault_name, &Secret::new(draft.secret.to_vec())).await.is_err() {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The Vault couldn't store the second factor");
    }
    let now = ctx.now_ms;
    let user: Row = [
        ("id", Value::Text(user_id.clone())),
        ("name", Value::Text(name.into())),
        ("role", Value::Text("admin".into())),
        ("auth", Value::Text("local".into())),
        ("created_at", Value::Integer(now)),
    ]
    .into_iter()
    .collect();
    let credential = |kind: &str, data: Vec<u8>, last_step: Option<i64>| {
        let mut row: Row = [
            ("id", Value::Text(ulid::Ulid::new().to_string())),
            ("user_id", Value::Text(user_id.clone())),
            ("kind", Value::Text(kind.into())),
            ("data", Value::Blob(data)),
            ("created_at", Value::Integer(now)),
        ]
        .into_iter()
        .collect();
        if let Some(s) = last_step {
            row.insert("last_totp_step", Value::Integer(s));
        }
        RowWrite::insert("credentials", row)
    };
    let mut writes = vec![
        RowWrite { table: "users", row: user, mode: rackhand_store::writer::WriteMode::InsertIfTableEmpty },
        credential("password", password_hash.into_bytes(), None),
        // The code used here can't be used again to sign in (7.7.2).
        credential("totp", format!("vault:{vault_name}").into_bytes(), Some(step)),
        local_site_row(site, tz),
    ];
    writes.extend(config::first_revision_rows(config::HUB, &settings, name, now));
    match web.0.db.writer().send(WriteCmd::Batch(writes)).await {
        Ok(_) => web.0.first_run.clear(),
        Err(StoreError::Conflict(_)) => return redirect("/sign-in"),
        Err(e) => {
            tracing::error!(error = %e, "first run");
            form.notice("It couldn't be saved. Nothing was made; try again with the next code.");
            return factor_page(ctx, StatusCode::INTERNAL_SERVER_ERROR, &draft, form);
        }
    }
    let data = serde_json::json!({ "site": site, "timezone": tz, "sources": sources }).to_string();
    if let Err(e) = web.0.audit.append(name, "first_run.completed", Some(site), &data).await {
        tracing::error!(error = %e, "audit");
    }
    html(StatusCode::OK, Done { admin: name, site, recovery_code: &web.0.recovery_code }.render())
}
