//! Sign-in, second factor, step-up and limits (7.7.2): a password, then a TOTP code that works once; sessions with
//! absolute and idle limits; limits per source and per account that slow attackers without locking anyone out.

pub mod client_addr;
pub mod devices;
pub(crate) mod flow;
pub mod limits;
pub mod password;
pub mod step_up;
pub mod users;

/// A passed password step waiting for its code.
pub(crate) const PENDING_COOKIE: &str = "rh_pending";
pub(crate) const PENDING_MS: i64 = 5 * 60_000;

#[derive(Debug, Clone)]
pub(crate) struct Pending {
    pub name: String,
    pub wrong_codes: u32,
    pub created_ms: i64,
}

#[cfg(test)]
mod tests;
