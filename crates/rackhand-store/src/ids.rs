//! Ids and times (7.4.1): ULIDs, Unix milliseconds (UTC).

use std::time::{SystemTime, UNIX_EPOCH};

pub fn new_id() -> ulid::Ulid {
    ulid::Ulid::new()
}

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
