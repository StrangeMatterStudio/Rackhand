//! The sign-in pages: the password step, the code step, step-up and sign-out.

use askama::Template;
use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode, header};

use super::devices::{self, DEVICE_COOKIE};
use super::limits::Attempt;
use super::step_up;
use super::users::{self, Account};
use super::{PENDING_COOKIE, PENDING_MS, Pending, password};
use crate::web::forms::{Form, Spec};
use crate::web::pages::{html, redirect, see_other, status};
use crate::web::session::{self, random_token};
use crate::web::ui::{self, Shell};
use crate::web::{Ctx, Web, totp};

/// Wrong codes after which the password step must be passed again.
const MAX_WRONG_CODES: u32 = 5;

#[derive(Template)]
#[template(path = "sign_in.html")]
struct PasswordForm<'a> {
    theme: &'a str,
    csrf: &'a str,
    form: Form,
    oidc: bool,
}

#[derive(Template)]
#[template(path = "sign_in_code.html")]
struct CodeForm<'a> {
    theme: &'a str,
    csrf: &'a str,
    action: &'a str,
    title: &'a str,
    form: Form,
    /// The passkey alternative: where its options come from and where the answer goes.
    passkey: Option<(&'a str, &'a str)>,
}

const SIGN_IN: &[Spec] = &[
    Spec::text("name", "Name").attrs("autocomplete=\"username\" autocapitalize=\"none\" spellcheck=\"false\""),
    Spec::secret("password", "Password").attrs("autocomplete=\"current-password\""),
];

const CODE: &[Spec] = &[Spec::text("code", "Code from your authenticator app")
    .hint("The 6 digits the app shows now. Each code works once.")
    .pattern("[0-9]{6}", "The code is 6 digits")
    .attrs("autocomplete=\"one-time-code\" inputmode=\"numeric\"")];

pub(crate) const TOO_MANY: &str = "Too many failed sign-ins from here; wait a minute and try again.";
const WRONG_CODE: &str = "That code doesn't match, or has been used. Each works once: enter the app's next one.";
const START_AGAIN: &str = "Too many wrong codes. Start again with your password.";

#[derive(Template)]
#[template(path = "step_up.html")]
struct StepUpForm<'a> {
    shell: Shell,
    csrf: &'a str,
    action: &'a str,
    form: Form,
    passkey: Option<(&'a str, &'a str)>,
}

/// To the step-up, and back to `path` after it.
pub(crate) fn to_step_up(path: &str) -> Response<Body> {
    let mut resp = redirect("/step-up");
    crate::web::remember_next(&mut resp, path);
    resp
}

/// Where the person was going, once; the overview when nowhere.
pub(crate) fn onward(ctx: &Ctx) -> Response<Body> {
    let next = ctx.cookies.get(ui::NEXT_COOKIE);
    let resp = see_other(ui::local(next.map(String::as_str).unwrap_or("/")));
    if next.is_some() { with_cookies(resp, &[expire(ui::NEXT_COOKIE)]) } else { resp }
}

fn with_cookies(mut resp: Response<Body>, cookies: &[String]) -> Response<Body> {
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp
}

fn expire(name: &str) -> String {
    format!("{name}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict")
}

pub(crate) async fn audit(web: &Web, actor: &str, action: &str, data: serde_json::Value) {
    if let Err(e) = web.0.audit.append(actor, action, None, &data.to_string()).await {
        tracing::error!(error = %e, "audit");
    }
}

fn known_device(web: &Web, ctx: &Ctx, account: Option<&Account>) -> Option<String> {
    let (account, token) = (account?, ctx.cookies.get(DEVICE_COOKIE)?);
    devices::is_known(&web.0.db, &account.id, token).then(|| devices::hash_hex(token))
}

fn password_form(web: &Web, ctx: &Ctx, code: StatusCode, form: Form) -> Response<Body> {
    html(
        code,
        PasswordForm { theme: ui::theme(ctx), csrf: &ctx.csrf, form, oidc: super::oidc::configured(web) }.render(),
    )
}

pub(crate) fn password_page(web: &Web, ctx: &Ctx) -> Response<Body> {
    let mut form = Form::blank("sign-in", SIGN_IN);
    if spent(web, ctx) {
        form.notice(START_AGAIN);
    }
    password_form(web, ctx, StatusCode::OK, form)
}

pub(crate) async fn password_step(web: &Web, ctx: &Ctx) -> Response<Body> {
    let name = ctx.form.get("name").map(|s| s.trim()).unwrap_or("");
    let given = ctx.form.get("password").map(String::as_str).unwrap_or("");
    let mut form = Form::sent("sign-in", SIGN_IN, ctx, &web.0.held);
    form.check();
    if !form.ok() {
        return password_form(web, ctx, StatusCode::UNAUTHORIZED, form);
    }
    let account = users::find(&web.0.db, name).ok().flatten();
    let device = known_device(web, ctx, account.as_ref());
    let attempt = Attempt { source: &ctx.source, account: Some(name), known_device: device.as_deref() };
    let allowed = web.0.limits.lock().map(|mut l| l.try_attempt(&attempt, ctx.now_ms)).unwrap_or(false);
    if !allowed {
        form.notice(TOO_MANY);
        return password_form(web, ctx, StatusCode::TOO_MANY_REQUESTS, form);
    }
    let stored = account.as_ref().and_then(|a| a.password_hash.as_deref());
    let ok = password::verify(stored.unwrap_or(password::dummy()), given) && stored.is_some();
    let Some(account) = account.filter(|_| ok) else {
        if let Ok(mut l) = web.0.limits.lock() {
            l.fail(&attempt, ctx.now_ms);
        }
        audit(web, name, "auth.sign_in_failed", serde_json::json!({ "source": ctx.source, "reason": "password" }))
            .await;
        form.notice("Wrong name or password.");
        return password_form(web, ctx, StatusCode::UNAUTHORIZED, form);
    };
    if !account.has_local_factor() {
        audit(
            web,
            name,
            "auth.sign_in_failed",
            serde_json::json!({ "source": ctx.source, "reason": "no_second_factor" }),
        )
        .await;
        form.notice("This account has no second factor yet; an admin has to set one up first.");
        return password_form(web, ctx, StatusCode::FORBIDDEN, form);
    }
    let Ok(token) = random_token() else { return status(StatusCode::INTERNAL_SERVER_ERROR, "No randomness") };
    if let Ok(mut pending) = web.0.pending.lock() {
        pending.retain(|_, p| ctx.now_ms - p.created_ms < PENDING_MS);
        pending
            .insert(devices::hash_hex(&token), Pending { name: account.name, wrong_codes: 0, created_ms: ctx.now_ms });
    }
    with_cookies(redirect("/sign-in/code"), &[session::cookie(PENDING_COOKIE, &token, PENDING_MS / 1000)])
}

fn find_pending(web: &Web, ctx: &Ctx) -> Option<(String, Pending)> {
    let key = devices::hash_hex(ctx.cookies.get(PENDING_COOKIE)?);
    let pending = web.0.pending.lock().ok()?.get(&key).cloned()?;
    (ctx.now_ms - pending.created_ms < PENDING_MS).then_some((key, pending))
}

pub(crate) fn pending_of(web: &Web, ctx: &Ctx) -> Option<(String, Pending)> {
    find_pending(web, ctx).filter(|(_, p)| p.wrong_codes < MAX_WRONG_CODES)
}

/// Whether the browser's password step was spent on wrong codes; kept only to say so on the sign-in page.
fn spent(web: &Web, ctx: &Ctx) -> bool {
    find_pending(web, ctx).is_some_and(|(_, p)| p.wrong_codes >= MAX_WRONG_CODES)
}

/// The passkey alternative for `account`, when passkeys are on and it has one.
fn passkey_choice(
    web: &Web,
    account: Option<&Account>,
    options: &'static str,
    action: &'static str,
) -> Option<(&'static str, &'static str)> {
    (web.passkeys_offered() && account.is_some_and(|a| !a.passkeys.is_empty())).then_some((options, action))
}

pub(crate) fn code_page(web: &Web, ctx: &Ctx) -> Response<Body> {
    sign_in_code(web, ctx, StatusCode::OK, None)
}

/// The code step, with what went wrong with it.
pub(crate) fn sign_in_code(web: &Web, ctx: &Ctx, code: StatusCode, notice: Option<&str>) -> Response<Body> {
    let mut form = Form::blank("code", CODE);
    if let Some(n) = notice {
        form.notice(n);
    }
    sign_in_code_form(web, ctx, code, form)
}

fn sign_in_code_form(web: &Web, ctx: &Ctx, code: StatusCode, form: Form) -> Response<Body> {
    let Some((_, pending)) = pending_of(web, ctx) else { return redirect("/sign-in") };
    let account = users::find(&web.0.db, &pending.name).ok().flatten();
    let passkey = passkey_choice(web, account.as_ref(), "/sign-in/passkey/options", "/sign-in/passkey");
    let page = CodeForm {
        theme: ui::theme(ctx),
        csrf: &ctx.csrf,
        action: "/sign-in/code",
        title: "Authenticator code",
        form,
        passkey,
    };
    html(code, page.render())
}

/// A refused code: malformed, wrong or used. It isn't sent back, as it can't be right later.
fn refused_code(ctx: &Ctx, web: &Web) -> Form {
    let mut form = Form::sent("code", CODE, ctx, &web.0.held);
    form.check();
    form.refuse("code", WRONG_CODE);
    form.set("code", "");
    form
}

/// Checks a TOTP code for the account: it must match and be for a later time step than any used before.
async fn code_matches(web: &Web, account: &Account, code: &str, now_ms: i64) -> bool {
    let Some((cred, vault_name, last)) = &account.totp else { return false };
    let Ok(secret) = web.0.vault.get(vault_name) else { return false };
    let Some(step) = totp::verify(secret.expose(), code, now_ms / 1000) else { return false };
    if last.is_some_and(|l| step <= l) {
        return false;
    }
    users::use_totp_step(&web.0.db, cred, step).await.unwrap_or(false)
}

pub(crate) async fn code_step(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some((key, pending)) = pending_of(web, ctx) else { return redirect("/sign-in") };
    let source_only = Attempt { source: &ctx.source, account: None, known_device: None };
    if !web.0.limits.lock().map(|mut l| l.try_attempt(&source_only, ctx.now_ms)).unwrap_or(false) {
        return sign_in_code(web, ctx, StatusCode::TOO_MANY_REQUESTS, Some(TOO_MANY));
    }
    let account = users::find(&web.0.db, &pending.name).ok().flatten();
    let code = ctx.form.get("code").map(String::as_str).unwrap_or("");
    let matched = match &account {
        Some(a) => code_matches(web, a, code, ctx.now_ms).await,
        None => false,
    };
    let Some(account) = account.filter(|_| matched) else {
        let device = known_device(web, ctx, None);
        let attempt = Attempt { source: &ctx.source, account: Some(&pending.name), known_device: device.as_deref() };
        if let Ok(mut l) = web.0.limits.lock() {
            l.fail(&attempt, ctx.now_ms);
        }
        audit(web, &pending.name, "auth.sign_in_failed", serde_json::json!({ "source": ctx.source, "reason": "code" }))
            .await;
        let wrong = web.0.pending.lock().ok().and_then(|mut p| {
            let entry = p.get_mut(&key)?;
            entry.wrong_codes += 1;
            Some(entry.wrong_codes)
        });
        if wrong.unwrap_or(MAX_WRONG_CODES) >= MAX_WRONG_CODES {
            return redirect("/sign-in");
        }
        return sign_in_code_form(web, ctx, StatusCode::UNAUTHORIZED, refused_code(ctx, web));
    };
    finish_sign_in(web, ctx, &key, &account).await
}

/// The second step passed (a code or a passkey): the session starts and the browser is remembered.
pub(crate) async fn finish_sign_in(web: &Web, ctx: &Ctx, pending_key: &str, account: &Account) -> Response<Body> {
    if let Ok(mut p) = web.0.pending.lock() {
        p.remove(pending_key);
    }
    let Ok(token) = session::create(&web.0.db, &account.id, ctx.now_ms).await else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The session couldn't be started");
    };
    let mut cookies =
        vec![session::cookie(session::COOKIE, &token, session::ABSOLUTE_MS / 1000), expire(PENDING_COOKIE)];
    match devices::remember(&web.0.db, &account.id, ctx.cookies.get(DEVICE_COOKIE).map(String::as_str), ctx.now_ms)
        .await
    {
        Ok(Some(device)) => cookies.push(session::cookie(DEVICE_COOKIE, &device, devices::MAX_AGE_S)),
        Ok(None) => {}
        Err(e) => tracing::warn!(error = %e, "device cookie"),
    }
    audit(web, &account.name, "auth.sign_in", serde_json::json!({ "source": ctx.source })).await;
    with_cookies(onward(ctx), &cookies)
}

pub(crate) async fn sign_out(web: &Web, ctx: &Ctx) -> Response<Body> {
    if let Some(user) = &ctx.user {
        if let Err(e) = session::end(&web.0.db, &user.id_hash, ctx.now_ms).await {
            tracing::warn!(error = %e, "sign-out");
        }
        audit(web, &user.name, "auth.sign_out", serde_json::json!({ "source": ctx.source })).await;
    }
    with_cookies(redirect("/sign-in"), &[expire(session::COOKIE)])
}

pub(crate) fn step_up_page(web: &Web, ctx: &Ctx) -> Response<Body> {
    step_up_code(web, ctx, StatusCode::OK, None)
}

/// The step-up page, with what went wrong with it.
pub(crate) fn step_up_code(web: &Web, ctx: &Ctx, code: StatusCode, notice: Option<&str>) -> Response<Body> {
    let mut form = Form::blank("code", CODE);
    if let Some(n) = notice {
        form.notice(n);
    }
    step_up_form(web, ctx, code, form)
}

fn step_up_form(web: &Web, ctx: &Ctx, code: StatusCode, form: Form) -> Response<Body> {
    let account = ctx.user.as_ref().and_then(|u| users::find_by_id(&web.0.db, &u.user_id).ok().flatten());
    let passkey = passkey_choice(web, account.as_ref(), "/step-up/passkey/options", "/step-up/passkey");
    let title = "Confirm with your authenticator";
    let shell = Shell::at(web, ctx, title, "/step-up");
    html(code, StepUpForm { shell, csrf: &ctx.csrf, action: "/step-up", form, passkey }.render())
}

pub(crate) async fn step_up(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let source_only = Attempt { source: &ctx.source, account: None, known_device: None };
    if !web.0.limits.lock().map(|mut l| l.try_attempt(&source_only, ctx.now_ms)).unwrap_or(false) {
        return step_up_code(web, ctx, StatusCode::TOO_MANY_REQUESTS, Some(TOO_MANY));
    }
    // By id: OIDC accounts step up with their local factor too (D49).
    let account = users::find_by_id(&web.0.db, &user.user_id).ok().flatten();
    let code = ctx.form.get("code").map(String::as_str).unwrap_or("");
    let ok = match &account {
        Some(a) => code_matches(web, a, code, ctx.now_ms).await,
        None => false,
    };
    if !ok {
        let attempt = Attempt { source: &ctx.source, account: Some(&user.name), known_device: None };
        if let Ok(mut l) = web.0.limits.lock() {
            l.fail(&attempt, ctx.now_ms);
        }
        audit(web, &user.name, "auth.step_up_failed", serde_json::json!({ "source": ctx.source })).await;
        return step_up_form(web, ctx, StatusCode::UNAUTHORIZED, refused_code(ctx, web));
    }
    if let Err(e) = session::set_step_up(&web.0.db, &user.id_hash, ctx.now_ms).await {
        tracing::error!(error = %e, "step-up");
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The step-up couldn't be recorded");
    }
    debug_assert!(step_up::fresh(&web.0.db, Some(ctx.now_ms), ctx.now_ms));
    onward(ctx)
}
