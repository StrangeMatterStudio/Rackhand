//! The one route table. Every route is public, first-run only, or guarded by a row of the permission matrix; the gate,
//! the CSRF check and the tests all read this table, so a route added later is covered without being listed again.

use axum::http::Method;

use super::perms::Permission;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Health, static files and the sign-in page: no session, no first-run redirect.
    Public,
    /// Only until an admin exists.
    FirstRun,
    Perm(Permission),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Healthz,
    Vendor,
    AppCss,
    SignIn,
    SignInSubmit,
    SignInCode,
    SignInCodeSubmit,
    SignOut,
    StepUp,
    StepUpSubmit,
    FirstRunForm,
    FirstRunSubmit,
    Overview,
    Settings,
    SettingsSources,
    AcceptHostKey,
    SettingsGitMirror,
    UserCreate,
    UserRole,
    UserDisable,
    DeviceRevoke,
}

#[derive(Debug, Clone)]
pub struct RouteSpec {
    pub method: Method,
    pub path: &'static str,
    pub access: Access,
    pub page: Page,
}

const fn r(method: Method, path: &'static str, access: Access, page: Page) -> RouteSpec {
    RouteSpec { method, path, access, page }
}

pub static ROUTES: &[RouteSpec] = &[
    r(Method::GET, "/healthz", Access::Public, Page::Healthz),
    r(Method::GET, "/static/vendor/{file}", Access::Public, Page::Vendor),
    r(Method::GET, "/static/app.css", Access::Public, Page::AppCss),
    r(Method::GET, "/sign-in", Access::Public, Page::SignIn),
    r(Method::POST, "/sign-in", Access::Public, Page::SignInSubmit),
    r(Method::GET, "/sign-in/code", Access::Public, Page::SignInCode),
    r(Method::POST, "/sign-in/code", Access::Public, Page::SignInCodeSubmit),
    r(Method::POST, "/sign-out", Access::Perm(Permission::SeeEverything), Page::SignOut),
    r(Method::GET, "/step-up", Access::Perm(Permission::SeeEverything), Page::StepUp),
    r(Method::POST, "/step-up", Access::Perm(Permission::SeeEverything), Page::StepUpSubmit),
    r(Method::GET, "/first-run", Access::FirstRun, Page::FirstRunForm),
    r(Method::POST, "/first-run", Access::FirstRun, Page::FirstRunSubmit),
    r(Method::GET, "/", Access::Perm(Permission::SeeEverything), Page::Overview),
    r(Method::GET, "/settings", Access::Perm(Permission::Administer), Page::Settings),
    r(Method::POST, "/settings/sources", Access::Perm(Permission::Administer), Page::SettingsSources),
    r(Method::POST, "/settings/git-mirror", Access::Perm(Permission::Administer), Page::SettingsGitMirror),
    r(Method::POST, "/machines/{id}/host-key/accept", Access::Perm(Permission::Administer), Page::AcceptHostKey),
    r(Method::POST, "/settings/users", Access::Perm(Permission::Administer), Page::UserCreate),
    r(Method::POST, "/settings/users/{id}/role", Access::Perm(Permission::Administer), Page::UserRole),
    r(Method::POST, "/settings/users/{id}/disable", Access::Perm(Permission::Administer), Page::UserDisable),
    r(Method::POST, "/settings/devices/{id}/revoke", Access::Perm(Permission::Administer), Page::DeviceRevoke),
];
