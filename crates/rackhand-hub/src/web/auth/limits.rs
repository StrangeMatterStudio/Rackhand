//! Sign-in limits (7.7.2, E41, E61). Nothing locks an account:
//! - per source: after 5 failures in 15 minutes, 1 attempt a minute;
//! - per account: after 10 failures in 15 minutes from any sources, browsers that have never signed in to the account
//!   share 1 attempt a minute; a browser with the account's device cookie has its own limit, like a source.

use std::collections::{HashMap, VecDeque};

const WINDOW_MS: i64 = 15 * 60_000;
const SLOT_MS: i64 = 60_000;
const SOURCE_FAILURES: usize = 5;
const ACCOUNT_FAILURES: usize = 10;
/// Keys kept per map; the oldest go first.
const MAX_KEYS: usize = 20_000;

#[derive(Debug, Default)]
struct Window {
    failures: VecDeque<i64>,
    /// The last attempt made while over the threshold.
    limited_attempt: Option<i64>,
}

impl Window {
    fn prune(&mut self, now: i64) {
        while self.failures.front().is_some_and(|t| *t <= now - WINDOW_MS) {
            self.failures.pop_front();
        }
    }

    fn over(&mut self, threshold: usize, now: i64) -> bool {
        self.prune(now);
        self.failures.len() >= threshold
    }

    /// Whether an attempt may go ahead now.
    fn allows(&mut self, threshold: usize, now: i64) -> bool {
        !self.over(threshold, now) || self.limited_attempt.is_none_or(|t| now - t >= SLOT_MS)
    }

    fn attempt(&mut self, threshold: usize, now: i64) {
        if self.over(threshold, now) {
            self.limited_attempt = Some(now);
        }
    }
}

#[derive(Debug, Default)]
pub struct Limits {
    sources: HashMap<String, Window>,
    accounts: HashMap<String, Window>,
    devices: HashMap<(String, String), Window>,
}

/// Who an attempt is from.
#[derive(Debug, Clone)]
pub struct Attempt<'a> {
    pub source: &'a str,
    /// The account name tried, if the attempt is for one.
    pub account: Option<&'a str>,
    /// The browser's device cookie hash, when it's known for that account.
    pub known_device: Option<&'a str>,
}

fn bounded<K: std::hash::Hash + Eq + Clone>(map: &mut HashMap<K, Window>, now: i64) {
    if map.len() < MAX_KEYS {
        return;
    }
    map.retain(|_, w| {
        w.prune(now);
        !w.failures.is_empty()
    });
    while map.len() >= MAX_KEYS {
        let oldest = map.iter().min_by_key(|(_, w)| w.failures.back().copied()).map(|(k, _)| k.clone());
        match oldest {
            Some(k) => map.remove(&k),
            None => break,
        };
    }
}

impl Limits {
    /// Whether the attempt may go ahead; if so, it is counted as made.
    pub fn try_attempt(&mut self, a: &Attempt<'_>, now: i64) -> bool {
        bounded(&mut self.sources, now);
        let source_ok = self.sources.entry(a.source.into()).or_default().allows(SOURCE_FAILURES, now);
        let account_ok = match (a.account, a.known_device) {
            (Some(acc), Some(dev)) => {
                self.devices.entry((acc.into(), dev.into())).or_default().allows(SOURCE_FAILURES, now)
            }
            (Some(acc), None) => self.accounts.entry(acc.into()).or_default().allows(ACCOUNT_FAILURES, now),
            (None, _) => true,
        };
        if !(source_ok && account_ok) {
            return false;
        }
        if let Some(w) = self.sources.get_mut(a.source) {
            w.attempt(SOURCE_FAILURES, now);
        }
        match (a.account, a.known_device) {
            (Some(acc), Some(dev)) => {
                if let Some(w) = self.devices.get_mut(&(acc.to_string(), dev.to_string())) {
                    w.attempt(SOURCE_FAILURES, now);
                }
            }
            (Some(acc), None) => {
                if let Some(w) = self.accounts.get_mut(acc) {
                    w.attempt(ACCOUNT_FAILURES, now);
                }
            }
            (None, _) => {}
        }
        true
    }

    /// Records a failure: for the source, the account (from any browser) and the known device.
    pub fn fail(&mut self, a: &Attempt<'_>, now: i64) {
        bounded(&mut self.accounts, now);
        bounded(&mut self.devices, now);
        self.sources.entry(a.source.into()).or_default().failures.push_back(now);
        if let Some(acc) = a.account {
            self.accounts.entry(acc.into()).or_default().failures.push_back(now);
            if let Some(dev) = a.known_device {
                self.devices.entry((acc.into(), dev.into())).or_default().failures.push_back(now);
            }
        }
    }
}
