//! Response headers on every page (10): a strict Content-Security-Policy with no inline script or style, no framing,
//! no sniffing, no referrer.

use axum::http::{HeaderMap, HeaderValue, header};

pub const POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

pub fn apply(headers: &mut HeaderMap) {
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(POLICY));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.entry(header::CACHE_CONTROL).or_insert(HeaderValue::from_static("no-store"));
}
