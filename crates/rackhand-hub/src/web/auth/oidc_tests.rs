use axum::http::StatusCode;

use super::super::fake_oidc::{FakeOidc, Misbehave};
use super::super::tests::{App, Browser, PASSWORD, app_with};
use super::super::users::{self, NewUser};
use crate::policy::approvals::{ApprovalError, Role, can_approve};
use crate::web::{session, totp};
use rackhand_runbook::runbook::Risk;

const CLIENT_ID: &str = "rackhand-hub";
const CLIENT_SECRET: &str = "oidc-client-secret-value";
const REDIRECT: &str = "https://hub.example.test/sign-in/oidc/callback";

/// The hub with OIDC configured by its admin against a fake provider.
async fn configured(name: &str) -> (App, FakeOidc) {
    let app = app_with(name, |web| web).await;
    let provider = FakeOidc::start(CLIENT_ID, CLIENT_SECRET, app.clock.clone()).await;
    let mut admin = Browser::at("192.0.2.50");
    assert!(admin.sign_in(&app, PASSWORD, &app.code()).await);
    let resp = admin
        .post(
            &app,
            "/settings/oidc",
            "/",
            &[
                ("issuer", provider.issuer.as_str()),
                ("client_id", CLIENT_ID),
                ("client_secret", CLIENT_SECRET),
                ("redirect_url", REDIRECT),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    (app, provider)
}

/// Through the provider: the hub's redirect, the provider's sign-in, the callback. True if a session came of it.
async fn through_provider(app: &App, provider: &FakeOidc, b: &mut Browser, sub: &str) -> bool {
    let resp = b.send(app, axum::http::Request::get("/sign-in/oidc").body(axum::body::Body::empty()).unwrap()).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let to = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    let back = provider.authorize(&to, sub);
    let (status, _) = b.page(app, &back).await;
    status == StatusCode::OK && b.has(session::COOKIE)
}

fn session_user(app: &App, b: &Browser) -> session::SessionUser {
    let token = &b.cookies.iter().find(|(k, _)| k == session::COOKIE).unwrap().1;
    session::lookup(&app.db, token, app.now()).unwrap().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn user_signs_in_through_provider() {
    let (app, provider) = configured("oidc-sign-in").await;
    let secret = totp::new_secret().unwrap();
    users::create(&app.db, &app.vault, "olivia", Role::Responder, NewUser::Oidc { subject: "sub-123" }, &secret, 1)
        .await
        .unwrap();
    let mut b = Browser::at("192.0.2.51");
    let (_, sign_in) = b.page(&app, "/sign-in").await;
    assert!(sign_in.contains("/sign-in/oidc"), "offered on the sign-in page");
    assert!(through_provider(&app, &provider, &mut b, "sub-123").await);
    assert_eq!(session_user(&app, &b).name, "olivia");
    let (status, _) = b.page(&app, "/").await;
    assert_eq!(status, StatusCode::OK);
    // A subject with no account here gets no session.
    let mut stranger = Browser::at("192.0.2.52");
    assert!(!through_provider(&app, &provider, &mut stranger, "sub-unknown").await);
}

#[tokio::test(flavor = "multi_thread")]
async fn step_up_requires_local_factor() {
    let (app, provider) = configured("oidc-step-up").await;
    // An OIDC admin without a local factor: the provider alone can't approve high risk (D49).
    app.db
        .writer()
        .send(rackhand_store::WriteCmd::Batch(vec![rackhand_store::RowWrite::insert(
            "users",
            rackhand_store::Row::from([
                ("id", rusqlite::types::Value::Text(ulid::Ulid::new().to_string())),
                ("name", rusqlite::types::Value::Text("bare".into())),
                ("role", rusqlite::types::Value::Text("admin".into())),
                ("auth", rusqlite::types::Value::Text("oidc".into())),
                ("oidc_subject", rusqlite::types::Value::Text("sub-bare".into())),
                ("created_at", rusqlite::types::Value::Integer(1)),
            ]),
        )]))
        .await
        .unwrap();
    let mut bare = Browser::at("192.0.2.53");
    assert!(through_provider(&app, &provider, &mut bare, "sub-bare").await);
    let resp = bare.post(&app, "/step-up", "/step-up", &[("code", "123456")]).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let user = session_user(&app, &bare);
    let fresh = crate::web::auth::step_up::fresh(user.step_up_at, app.now());
    assert_eq!(can_approve(user.role, Risk::High, fresh), Err(ApprovalError::StepUpRequired));
    // An OIDC admin with the TOTP their admin issued steps up with it and can approve.
    let secret = totp::new_secret().unwrap();
    users::create(&app.db, &app.vault, "owen", Role::Admin, NewUser::Oidc { subject: "sub-owen" }, &secret, 1)
        .await
        .unwrap();
    let mut b = Browser::at("192.0.2.54");
    assert!(through_provider(&app, &provider, &mut b, "sub-owen").await);
    let code = totp::code(&secret, app.now() / 1000);
    let resp = b.post(&app, "/step-up", "/step-up", &[("code", code.as_str())]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let user = session_user(&app, &b);
    assert!(crate::web::auth::step_up::fresh(user.step_up_at, app.now()));
    assert_eq!(can_approve(user.role, Risk::High, true), Ok(()));
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_issuer_or_nonce_refused() {
    let (app, provider) = configured("oidc-refused").await;
    let secret = totp::new_secret().unwrap();
    users::create(&app.db, &app.vault, "olivia", Role::Responder, NewUser::Oidc { subject: "sub-123" }, &secret, 1)
        .await
        .unwrap();
    for (i, m) in [
        Misbehave::WrongIssuer,
        Misbehave::WrongNonce,
        Misbehave::WrongAudience,
        Misbehave::Expired,
        Misbehave::BadSignature,
        Misbehave::UnknownKid,
        Misbehave::AlgNone,
    ]
    .into_iter()
    .enumerate()
    {
        provider.misbehave(m);
        let mut b = Browser::at(&format!("192.0.2.{}", 60 + i));
        assert!(!through_provider(&app, &provider, &mut b, "sub-123").await, "{m:?} was accepted");
    }
    // A callback is used once, and only by the browser that started the sign-in.
    provider.misbehave(Misbehave::None);
    let mut b = Browser::at("192.0.2.70");
    let resp = b.send(&app, axum::http::Request::get("/sign-in/oidc").body(axum::body::Body::empty()).unwrap()).await;
    let to = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    let back = provider.authorize(&to, "sub-123");
    let mut thief = Browser::at("192.0.2.71");
    let (_, _) = thief.page(&app, &back).await;
    assert!(!thief.has(session::COOKIE), "another browser can't finish it");
    let (status, _) = b.page(&app, &back).await;
    assert!(!(status == StatusCode::OK && b.has(session::COOKIE)), "a state is used once, even after a failed try");
    let audited: i64 = app
        .db
        .readers()
        .with(|c| {
            c.query_row(
                "SELECT count(*) FROM audit_log WHERE action = 'auth.sign_in_failed' AND data LIKE '%oidc%'",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert!(audited >= 7, "{audited}");
}
