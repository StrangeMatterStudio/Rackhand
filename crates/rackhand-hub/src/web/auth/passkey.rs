//! Passkeys (7.7.2, D49): offered only when the hub is reached by hostname with a certificate the browser trusts (the
//! composition calls [`Web::with_passkeys`] then). A passkey is a second factor in place of a TOTP code, at sign-in and
//! for step-up; adding one needs a fresh step-up. Challenges are kept in memory for five minutes and used once.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode, header};
use rackhand_store::{Row, WriteCmd};
use rusqlite::types::Value;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, Url, Uuid,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

use super::devices;
use super::flow;
use super::limits::Attempt;
use super::step_up;
use super::users::{self, Account};
use super::{PENDING_COOKIE, PENDING_MS};
use crate::web::pages::{account, redirect, status};
use crate::web::session;
use crate::web::{Ctx, Web};

pub(crate) struct Passkeys {
    webauthn: Webauthn,
    /// Registrations in progress, by session.
    registering: Mutex<HashMap<[u8; 32], (PasskeyRegistration, i64)>>,
    /// Assertions in progress, by the browser's pending sign-in or by session: the account and the state.
    asserting: Mutex<HashMap<String, (String, PasskeyAuthentication, i64)>>,
}

impl std::fmt::Debug for Passkeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passkeys")
    }
}

impl Passkeys {
    pub(crate) fn new(rp_id: &str, origin: &str) -> Result<Passkeys, String> {
        let origin = Url::parse(origin).map_err(|e| e.to_string())?;
        let webauthn = WebauthnBuilder::new(rp_id, &origin)
            .and_then(|b| b.rp_name("Rackhand").build())
            .map_err(|e| e.to_string())?;
        Ok(Passkeys { webauthn, registering: Mutex::default(), asserting: Mutex::default() })
    }
}

impl Web {
    /// Turns passkeys on for a hub reached at `origin` (`https://<rp_id>`) with a trusted certificate; before the router
    /// is built.
    pub fn with_passkeys(mut self, rp_id: &str, origin: &str) -> Result<Web, String> {
        let passkeys = Passkeys::new(rp_id, origin)?;
        if let Some(inner) = std::sync::Arc::get_mut(&mut self.0) {
            inner.passkeys = Some(passkeys);
        }
        Ok(self)
    }

    pub(crate) fn passkeys_offered(&self) -> bool {
        self.0.passkeys.is_some()
    }
}

/// The WebAuthn user handle: the account's ULID as 16 bytes.
fn user_handle(user_id: &str) -> Uuid {
    Uuid::from_bytes(ulid::Ulid::from_string(user_id).map(|u| u.to_bytes()).unwrap_or([0; 16]))
}

fn json(value: &impl serde::Serialize) -> Response<Body> {
    let Ok(text) = serde_json::to_string(value) else { return status(StatusCode::INTERNAL_SERVER_ERROR, "Encoding") };
    let mut resp = Response::new(Body::from(text));
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

fn unavailable() -> Response<Body> {
    status(StatusCode::NOT_FOUND, "Passkeys need the hub's hostname with a trusted certificate")
}

fn sweep<K, V>(map: &mut HashMap<K, (V, i64)>, now_ms: i64) {
    map.retain(|_, (_, at)| now_ms - *at < PENDING_MS);
}

fn passkeys_of(account: &Account) -> Vec<Passkey> {
    account.passkeys.iter().map(|p| p.passkey.clone()).collect()
}

/// `POST /account/passkeys/options`: creation options for a signed-in, freshly stepped-up user.
pub(crate) fn register_options(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(pk) = &web.0.passkeys else { return unavailable() };
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    if !step_up::fresh(user.step_up_at, ctx.now_ms) {
        return status(StatusCode::FORBIDDEN, "Step up first: adding a passkey needs a fresh second factor");
    }
    let Ok(Some(account)) = users::find_by_id(&web.0.db, &user.user_id) else {
        return status(StatusCode::NOT_FOUND, "No such account");
    };
    let exclude = Some(account.passkeys.iter().map(|p| p.passkey.cred_id().clone()).collect());
    match pk.webauthn.start_passkey_registration(user_handle(&account.id), &account.name, &account.name, exclude) {
        Ok((options, state)) => {
            if let Ok(mut r) = pk.registering.lock() {
                sweep(&mut r, ctx.now_ms);
                r.insert(user.id_hash, (state, ctx.now_ms));
            }
            json(&options)
        }
        Err(e) => {
            tracing::warn!(error = %e, "passkey registration options");
            status(StatusCode::INTERNAL_SERVER_ERROR, "No passkey options")
        }
    }
}

/// `POST /account/passkeys`: stores the new passkey.
pub(crate) async fn register(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(pk) = &web.0.passkeys else { return unavailable() };
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let state = pk.registering.lock().ok().and_then(|mut r| r.remove(&user.id_hash));
    let Some((state, at)) = state.filter(|(_, at)| ctx.now_ms - at < PENDING_MS) else {
        return account::show(web, ctx, StatusCode::BAD_REQUEST, Some("The passkey request expired; try again."));
    };
    let _ = at;
    let Some(credential) =
        ctx.form.get("credential").and_then(|c| serde_json::from_str::<RegisterPublicKeyCredential>(c).ok())
    else {
        return account::show(web, ctx, StatusCode::BAD_REQUEST, Some("No passkey in the form."));
    };
    let passkey = match pk.webauthn.finish_passkey_registration(&credential, &state) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "passkey registration");
            return account::show(web, ctx, StatusCode::BAD_REQUEST, Some("The passkey couldn't be verified."));
        }
    };
    let Ok(data) = serde_json::to_vec(&passkey) else { return status(StatusCode::INTERNAL_SERVER_ERROR, "Encoding") };
    let row = users::credential(&user.user_id, "passkey", data, ctx.now_ms);
    if let Err(e) = web.0.db.writer().send(WriteCmd::Batch(vec![row])).await {
        tracing::error!(error = %e, "passkey");
        return account::show(web, ctx, StatusCode::INTERNAL_SERVER_ERROR, Some("The passkey couldn't be stored."));
    }
    flow::audit(web, &user.name, "auth.passkey_added", serde_json::json!({ "source": ctx.source })).await;
    redirect("/account")
}

/// Request options for `account`'s passkeys, remembered under `key`.
fn assertion_options(web: &Web, key: String, account: &Account, now_ms: i64) -> Response<Body> {
    let Some(pk) = &web.0.passkeys else { return unavailable() };
    let creds = passkeys_of(account);
    if creds.is_empty() {
        return status(StatusCode::NOT_FOUND, "This account has no passkey");
    }
    match pk.webauthn.start_passkey_authentication(&creds) {
        Ok((options, state)) => {
            if let Ok(mut a) = pk.asserting.lock() {
                a.retain(|_, (_, _, at)| now_ms - *at < PENDING_MS);
                a.insert(key, (account.id.clone(), state, now_ms));
            }
            json(&options)
        }
        Err(e) => {
            tracing::warn!(error = %e, "passkey request options");
            status(StatusCode::INTERNAL_SERVER_ERROR, "No passkey options")
        }
    }
}

/// Checks an answer against the state remembered under `key` (used once), and stores the passkey's new counter.
async fn verify(web: &Web, ctx: &Ctx, key: &str) -> Option<Account> {
    let pk = web.0.passkeys.as_ref()?;
    let (account_id, state, at) = pk.asserting.lock().ok()?.remove(key)?;
    if ctx.now_ms - at >= PENDING_MS {
        return None;
    }
    let credential = serde_json::from_str::<PublicKeyCredential>(ctx.form.get("credential")?).ok()?;
    let result = match pk.webauthn.finish_passkey_authentication(&credential, &state) {
        Ok(r) => r,
        Err(e) => {
            tracing::info!(error = %e, "passkey assertion refused");
            return None;
        }
    };
    let account = users::find_by_id(&web.0.db, &account_id).ok().flatten()?;
    let stored = account.passkeys.iter().find(|p| p.passkey.cred_id() == result.cred_id())?;
    let mut updated = stored.passkey.clone();
    if updated.update_credential(&result) == Some(true)
        && let Ok(data) = serde_json::to_vec(&updated)
    {
        let row: Row = [
            ("id", Value::Text(stored.credential_id.clone())),
            ("user_id", Value::Text(account.id.clone())),
            ("kind", Value::Text("passkey".into())),
            ("data", Value::Blob(data)),
            ("created_at", Value::Integer(stored.created_at)),
        ]
        .into_iter()
        .collect();
        if let Err(e) = web.0.db.writer().send(WriteCmd::PutCredential(row)).await {
            tracing::warn!(error = %e, "passkey counter");
        }
    }
    Some(account)
}

fn pending_key(ctx: &Ctx) -> Option<String> {
    ctx.cookies.get(PENDING_COOKIE).map(|t| format!("sign-in:{}", devices::hash_hex(t)))
}

/// `POST /sign-in/passkey/options`: after the password step.
pub(crate) fn sign_in_options(web: &Web, ctx: &Ctx) -> Response<Body> {
    if web.0.passkeys.is_none() {
        return unavailable();
    }
    let Some((_, pending)) = flow::pending_of(web, ctx) else { return redirect("/sign-in") };
    let (Some(key), Ok(Some(account))) = (pending_key(ctx), users::find(&web.0.db, &pending.name)) else {
        return redirect("/sign-in");
    };
    assertion_options(web, key, &account, ctx.now_ms)
}

/// `POST /sign-in/passkey`: the passkey answer in place of a code.
pub(crate) async fn sign_in(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some((pending_id, pending)) = flow::pending_of(web, ctx) else { return redirect("/sign-in") };
    let source_only = Attempt { source: &ctx.source, account: None, known_device: None };
    if !web.0.limits.lock().map(|mut l| l.try_attempt(&source_only, ctx.now_ms)).unwrap_or(false) {
        return flow::sign_in_code(web, ctx, StatusCode::TOO_MANY_REQUESTS, Some(flow::TOO_MANY));
    }
    let verified = match pending_key(ctx) {
        Some(key) => verify(web, ctx, &key).await.filter(|a| a.name == pending.name),
        None => None,
    };
    let Some(account) = verified else {
        let attempt = Attempt { source: &ctx.source, account: Some(&pending.name), known_device: None };
        if let Ok(mut l) = web.0.limits.lock() {
            l.fail(&attempt, ctx.now_ms);
        }
        flow::audit(
            web,
            &pending.name,
            "auth.sign_in_failed",
            serde_json::json!({ "source": ctx.source, "reason": "passkey" }),
        )
        .await;
        return flow::sign_in_code(web, ctx, StatusCode::UNAUTHORIZED, Some("The passkey wasn't accepted; try again."));
    };
    flow::finish_sign_in(web, ctx, &pending_id, &account).await
}

fn session_key(ctx: &Ctx) -> Option<String> {
    ctx.user.as_ref().map(|u| format!("step-up:{}", u.id_hash.iter().map(|b| format!("{b:02x}")).collect::<String>()))
}

/// `POST /step-up/passkey/options`.
pub(crate) fn step_up_options(web: &Web, ctx: &Ctx) -> Response<Body> {
    if web.0.passkeys.is_none() {
        return unavailable();
    }
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let (Some(key), Ok(Some(account))) = (session_key(ctx), users::find_by_id(&web.0.db, &user.user_id)) else {
        return redirect("/sign-in");
    };
    assertion_options(web, key, &account, ctx.now_ms)
}

/// `POST /step-up/passkey`.
pub(crate) async fn step_up(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let verified = match session_key(ctx) {
        Some(key) => verify(web, ctx, &key).await.filter(|a| a.id == user.user_id),
        None => None,
    };
    if verified.is_none() {
        let attempt = Attempt { source: &ctx.source, account: Some(&user.name), known_device: None };
        if let Ok(mut l) = web.0.limits.lock() {
            l.fail(&attempt, ctx.now_ms);
        }
        flow::audit(web, &user.name, "auth.step_up_failed", serde_json::json!({ "source": ctx.source })).await;
        return flow::step_up_code(web, ctx, StatusCode::UNAUTHORIZED, Some("The passkey wasn't accepted; try again."));
    }
    if let Err(e) = session::set_step_up(&web.0.db, &user.id_hash, ctx.now_ms).await {
        tracing::error!(error = %e, "step-up");
        return status(StatusCode::INTERNAL_SERVER_ERROR, "The step-up couldn't be recorded");
    }
    redirect("/")
}

#[cfg(test)]
#[path = "passkey_tests.rs"]
mod tests;
