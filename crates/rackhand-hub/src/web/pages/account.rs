//! The signed-in person's own account (7.7.2): their second factors. Adding a passkey needs a fresh step-up.

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};

use super::{html, redirect, status};
use crate::web::auth::{step_up, users};
use crate::web::{Ctx, Web};

#[derive(Template)]
#[template(path = "account.html")]
struct Account<'a> {
    csrf: &'a str,
    name: &'a str,
    totp: bool,
    passkeys: usize,
    offered: bool,
    stepped_up: bool,
    /// Why a passkey wasn't added.
    notice: Option<&'a str>,
}

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    show(web, ctx, StatusCode::OK, None)
}

/// The page, with why a passkey wasn't added.
pub(crate) fn show(web: &Web, ctx: &Ctx, code: StatusCode, notice: Option<&str>) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let Ok(Some(account)) = users::find_by_id(&web.0.db, &user.user_id) else {
        return status(StatusCode::NOT_FOUND, "No such account");
    };
    html(
        code,
        Account {
            csrf: &ctx.csrf,
            name: &account.name,
            totp: account.totp.is_some(),
            passkeys: account.passkeys.len(),
            offered: web.passkeys_offered(),
            stepped_up: step_up::fresh(user.step_up_at, ctx.now_ms),
            notice,
        }
        .render(),
    )
}
