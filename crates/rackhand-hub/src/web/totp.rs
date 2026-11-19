//! TOTP (RFC 6238): HMAC-SHA1, 6 digits, 30-second steps. Replay protection and limits are in sign-in (T37).

use ring::hmac;

pub const STEP_S: i64 = 30;
const DIGITS: u32 = 6;

/// A new 160-bit secret.
pub fn new_secret() -> Result<[u8; 20], getrandom::Error> {
    let mut s = [0u8; 20];
    getrandom::fill(&mut s)?;
    Ok(s)
}

pub fn step(unix_s: i64) -> i64 {
    unix_s.div_euclid(STEP_S)
}

/// The code for a time step (RFC 4226 HOTP over the step counter).
pub fn code_at_step(secret: &[u8], step: i64) -> String {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret), &step.to_be_bytes());
    let h = tag.as_ref();
    let offset = usize::from(h[h.len() - 1] & 0x0f);
    let bin = (u32::from(h[offset] & 0x7f) << 24)
        | (u32::from(h[offset + 1]) << 16)
        | (u32::from(h[offset + 2]) << 8)
        | u32::from(h[offset + 3]);
    format!("{:0width$}", bin % 10u32.pow(DIGITS), width = DIGITS as usize)
}

pub fn code(secret: &[u8], unix_s: i64) -> String {
    code_at_step(secret, step(unix_s))
}

/// The step a code matches, allowing one step of clock drift either way.
pub fn verify(secret: &[u8], code: &str, unix_s: i64) -> Option<i64> {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = step(unix_s);
    (now - 1..=now + 1).find(|s| ring_eq(code_at_step(secret, *s).as_bytes(), code.as_bytes()))
}

fn ring_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding, as authenticator apps take it.
pub fn encode_base32(data: &[u8]) -> String {
    let (mut bits, mut n, mut out) = (0u32, 0, String::new());
    for b in data {
        bits = (bits << 8) | u32::from(*b);
        n += 8;
        while n >= 5 {
            n -= 5;
            out.push(B32[((bits >> n) & 31) as usize] as char);
        }
    }
    if n > 0 {
        out.push(B32[((bits << (5 - n)) & 31) as usize] as char);
    }
    out
}

pub fn decode_base32(text: &str) -> Option<Vec<u8>> {
    let (mut bits, mut n, mut out) = (0u32, 0, Vec::new());
    for c in text.trim().trim_end_matches('=').bytes() {
        let v = B32.iter().position(|x| *x == c.to_ascii_uppercase())? as u32;
        bits = (bits << 5) | v;
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    Some(out)
}

/// The `otpauth://` URI an authenticator app reads.
pub fn uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let enc = |s: &str| form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        enc(issuer),
        enc(account),
        encode_base32(secret),
        enc(issuer)
    )
}
