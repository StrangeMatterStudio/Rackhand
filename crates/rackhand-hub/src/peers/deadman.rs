//! The dead-man URL (7.5.5, 7.7.1): a hub with no peers can call a URL every 5 minutes, so that a service outside the site
//! (such as a healthchecks.io check) notices when the hub itself goes quiet. The URL is a setting an admin changes.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// How often the URL is called.
pub const EVERY_MS: i64 = 5 * 60_000;

/// Where a request goes; a recording fake in tests.
pub trait Ping: Send + Sync {
    fn ping<'a>(&'a self, url: &'a str) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// The real thing: a GET over HTTPS.
#[derive(Debug)]
pub struct Https;

impl Ping for Https {
    fn ping<'a>(&'a self, url: &'a str) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let r =
                crate::http::request(axum::http::Method::GET, url, &[], Vec::new(), Duration::from_secs(20)).await?;
            if r.status < 400 { Ok(()) } else { Err(format!("answered {}", r.status)) }
        })
    }
}

#[derive(Debug, Default)]
pub struct Deadman {
    last_ms: Option<i64>,
}

impl Deadman {
    /// Calls the URL when it is due: only a hub with no peers calls it, and only when one is set. Returns whether it asked.
    pub async fn tick(&mut self, now_ms: i64, url: Option<&str>, has_peers: bool, ping: &dyn Ping) -> bool {
        let Some(url) = url.filter(|u| !u.is_empty()) else { return false };
        if has_peers || self.last_ms.is_some_and(|last| now_ms - last < EVERY_MS) {
            return false;
        }
        self.last_ms = Some(now_ms);
        if let Err(e) = ping.ping(url).await {
            tracing::warn!(error = %e, "the dead-man URL");
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);

    impl Ping for Recorder {
        fn ping<'a>(&'a self, url: &'a str) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            self.0.lock().unwrap().push(url.to_string());
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn requests_every_5_minutes() {
        let (mut dead, rec) = (Deadman::default(), Recorder::default());
        let url = Some("https://hc.example/ping/abc");
        let min = 60_000;
        let t0 = 1_000_000_000;
        assert!(dead.tick(t0, url, false, &rec).await, "the first is at once");
        for m in 1..5 {
            assert!(!dead.tick(t0 + m * min, url, false, &rec).await, "minute {m}");
        }
        assert!(dead.tick(t0 + 5 * min, url, false, &rec).await);
        assert!(!dead.tick(t0 + 9 * min, url, false, &rec).await);
        assert!(dead.tick(t0 + 10 * min + 1, url, false, &rec).await);
        assert_eq!(rec.0.lock().unwrap().len(), 3);
        // no URL, or a hub that has peers, calls nothing
        let (mut quiet, rec) = (Deadman::default(), Recorder::default());
        assert!(!quiet.tick(t0, None, false, &rec).await && !quiet.tick(t0, Some(""), false, &rec).await);
        assert!(!quiet.tick(t0, url, true, &rec).await, "peers watch each other instead");
        assert!(rec.0.lock().unwrap().is_empty());
    }
}
