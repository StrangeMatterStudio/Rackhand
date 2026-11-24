//! Relay lists (7.3.10, E28, AC31): a hub may subscribe to URLs that return TOML
//!
//! ```toml
//! [[relay]]
//! url = "https://relay.example.org"
//! name = "Example"
//! region = "eu"
//! operator = "Example Org"
//! ```
//!
//! Each is fetched daily over HTTPS. At most 100 valid entries are kept from a list; an invalid entry is skipped and counted,
//! and a list that can't be read at all keeps what it gave last time and shows its error. Listed relays are tried after the
//! hub's own, always as public relays, and are never sent a relay key (`rackhand_net::relays::RelayConfig::listed`).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use rackhand_net::relays::RelayConfig;

/// The most entries kept from one list.
pub const MAX_ENTRIES: usize = 100;
/// How often a list is fetched.
pub const EVERY_MS: i64 = 24 * 60 * 60_000;
/// The largest list read: 10 000 entries fit with room to spare.
const MAX_BODY: usize = 2 << 20;
const MAX_TEXT: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub url: String,
    pub name: String,
    pub region: String,
    pub operator: String,
}

/// What one list gave.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Parsed {
    pub relays: Vec<Listed>,
    /// Entries that weren't valid.
    pub skipped: usize,
    /// Valid entries past the 100th, not kept.
    pub ignored: usize,
}

fn text(table: &toml::Table, key: &str) -> Option<String> {
    let v = table.get(key)?.as_str()?.trim();
    (v.chars().count() <= MAX_TEXT && !v.chars().any(char::is_control)).then(|| v.to_string())
}

fn entry(value: &toml::Value) -> Option<Listed> {
    let table = value.as_table()?;
    let url = text(table, "url")?;
    // HTTPS only, and a URL the relay client can use
    if !url.starts_with("https://") || url.parse::<iroh::RelayUrl>().is_err() {
        return None;
    }
    let name = text(table, "name").filter(|n| !n.is_empty())?;
    let optional = |key: &str| match table.get(key) {
        None => Some(String::new()),
        Some(_) => text(table, key),
    };
    Some(Listed { url, name, region: optional("region")?, operator: optional("operator")? })
}

/// The entries of a list, or why it can't be read at all.
pub fn parse(source: &str) -> Result<Parsed, String> {
    let table: toml::Table = source.parse().map_err(|e: toml::de::Error| format!("not TOML: {}", e.message()))?;
    let entries = match table.get("relay") {
        Some(toml::Value::Array(entries)) => entries,
        Some(_) => return Err("`relay` isn't a list of `[[relay]]` entries".into()),
        None => return Err("no `[[relay]]` entries".into()),
    };
    let mut parsed = Parsed::default();
    for value in entries {
        match entry(value) {
            Some(listed) if parsed.relays.len() < MAX_ENTRIES => {
                if !parsed.relays.iter().any(|r| r.url == listed.url) {
                    parsed.relays.push(listed);
                }
            }
            Some(_) => parsed.ignored += 1,
            None => parsed.skipped += 1,
        }
    }
    Ok(parsed)
}

/// Where a list comes from; a fake in tests.
pub trait Fetch: Send + Sync {
    fn fetch<'a>(&'a self, url: &'a str) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>>;
}

/// The real thing: a GET over HTTPS.
#[derive(Debug)]
pub struct Https;

impl Fetch for Https {
    fn fetch<'a>(&'a self, url: &'a str) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            let r = crate::http::request_up_to(
                axum::http::Method::GET,
                url,
                &[],
                Vec::new(),
                Duration::from_secs(30),
                MAX_BODY,
            )
            .await?;
            if r.status != 200 {
                return Err(format!("answered {}", r.status));
            }
            String::from_utf8(r.body).map_err(|_| "not text".to_string())
        })
    }
}

/// How the last fetch of a list went, for the dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub checked_ms: i64,
    pub kept: usize,
    pub skipped: usize,
    pub ignored: usize,
    /// Why the list couldn't be read; what it gave before is still in use.
    pub error: Option<String>,
}

#[derive(Debug, Default)]
pub struct RelayLists {
    urls: Vec<String>,
    kept: BTreeMap<String, Vec<Listed>>,
    status: BTreeMap<String, Status>,
}

impl RelayLists {
    pub fn new(urls: Vec<String>) -> RelayLists {
        RelayLists { urls, ..RelayLists::default() }
    }

    pub fn status(&self, url: &str) -> Option<&Status> {
        self.status.get(url)
    }

    /// Fetches each list that is due (one never fetched, or last fetched a day ago).
    pub async fn refresh(&mut self, now_ms: i64, fetch: &dyn Fetch) {
        for url in self.urls.clone() {
            if self.status.get(&url).is_some_and(|s| now_ms - s.checked_ms < EVERY_MS) {
                continue;
            }
            let result = fetch.fetch(&url).await.and_then(|body| parse(&body));
            let mut status = Status { checked_ms: now_ms, kept: 0, skipped: 0, ignored: 0, error: None };
            match result {
                Ok(parsed) => {
                    (status.kept, status.skipped, status.ignored) =
                        (parsed.relays.len(), parsed.skipped, parsed.ignored);
                    self.kept.insert(url.clone(), parsed.relays);
                }
                Err(e) => {
                    status.kept = self.kept.get(&url).map_or(0, Vec::len);
                    status.error = Some(e);
                }
            }
            self.status.insert(url, status);
        }
    }

    /// Every listed relay, in list order, without repeats.
    pub fn listed(&self) -> Vec<Listed> {
        let mut out: Vec<Listed> = Vec::new();
        for url in &self.urls {
            for relay in self.kept.get(url).into_iter().flatten() {
                if !out.iter().any(|r| r.url == relay.url) {
                    out.push(relay.clone());
                }
            }
        }
        out
    }

    /// The relays a hub uses: its own, with the key it was given, then the listed ones, which never get it.
    pub fn relay_config(&self, own: &[String], auth_token: Option<String>) -> RelayConfig {
        RelayConfig {
            relays: own.to_vec(),
            listed: self.listed().into_iter().map(|r| r.url).collect(),
            auth_token,
            ..RelayConfig::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct Canned(Mutex<BTreeMap<String, Result<String, String>>>);

    impl Canned {
        fn with(url: &str, body: Result<String, String>) -> Canned {
            Canned(Mutex::new(BTreeMap::from([(url.to_string(), body)])))
        }

        fn set(&self, url: &str, body: Result<String, String>) {
            self.0.lock().unwrap().insert(url.to_string(), body);
        }
    }

    impl Fetch for Canned {
        fn fetch<'a>(&'a self, url: &'a str) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
            let body = self.0.lock().unwrap().get(url).cloned().unwrap_or_else(|| Err("no such list".into()));
            Box::pin(async move { body })
        }
    }

    const LIST: &str = "https://lists.example.org/relays.toml";

    fn good(n: usize) -> String {
        format!(
            "[[relay]]\nurl = \"https://relay{n}.example.org\"\nname = \"Relay {n}\"\nregion = \"eu\"\noperator = \"Org\"\n"
        )
    }

    /// 10 000 entries: every third is bad in a different way, the rest are good.
    fn mess() -> String {
        let mut out = String::new();
        for n in 0..10_000 {
            out.push_str(&match n % 3 {
                0 => format!("[[relay]]\nurl = \"http://plain{n}.example.org\"\nname = \"Plain\"\n"),
                1 => format!("[[relay]]\nname = \"No URL {n}\"\n"),
                _ => good(n),
            });
        }
        out
    }

    #[tokio::test]
    async fn garbage_and_10000_entries_keep_first_100_valid() {
        let parsed = parse(&mess()).unwrap();
        assert_eq!(parsed.relays.len(), 100, "at most 100 valid entries");
        assert_eq!(parsed.relays[0].url, "https://relay2.example.org", "the first valid entry, in order");
        assert_eq!(parsed.relays[99].url, "https://relay299.example.org");
        assert_eq!(parsed.skipped + parsed.ignored + parsed.relays.len(), 10_000);
        assert!(parsed.skipped > 100, "the invalid entries are counted: {}", parsed.skipped);

        // the dashboard's status shows what was skipped, and a list that can't be read at all shows the error
        let (mut lists, fetch) = (RelayLists::new(vec![LIST.into()]), Canned::with(LIST, Ok(mess())));
        lists.refresh(1_000, &fetch).await;
        let status = lists.status(LIST).unwrap();
        assert_eq!((status.kept, status.error.as_deref()), (100, None));
        assert!(status.skipped > 100 && status.ignored > 0, "{status:?}");
        fetch.set(LIST, Ok("this is {{ not toml".into()));
        lists.refresh(1_000 + EVERY_MS, &fetch).await;
        let status = lists.status(LIST).unwrap();
        assert!(status.error.as_deref().is_some_and(|e| e.starts_with("not TOML")), "{status:?}");
        assert_eq!(lists.listed().len(), 100, "the last good list is still in use");
        for (body, why) in [("", "no `[[relay]]`"), ("relay = 3", "isn't a list")] {
            assert!(parse(body).unwrap_err().contains(why), "{body:?}");
        }
        // an entry with a control character, an over-long name or a wrong type is skipped, the others kept
        let mixed = format!(
            "{}[[relay]]\nurl = \"https://x.example.org\"\nname = \"{}\"\n[[relay]]\nurl = 5\nname = \"n\"\n",
            good(1),
            "x".repeat(101)
        );
        let parsed = parse(&mixed).unwrap();
        assert_eq!((parsed.relays.len(), parsed.skipped), (1, 2));
    }

    #[tokio::test]
    async fn a_list_is_fetched_daily() {
        let (mut lists, fetch) = (RelayLists::new(vec![LIST.into()]), Canned::with(LIST, Ok(good(1))));
        lists.refresh(1_000, &fetch).await;
        fetch.set(LIST, Ok(format!("{}{}", good(1), good(2))));
        lists.refresh(1_000 + EVERY_MS - 1, &fetch).await;
        assert_eq!(lists.listed().len(), 1, "not yet due");
        lists.refresh(1_000 + EVERY_MS, &fetch).await;
        assert_eq!(lists.listed().len(), 2);
    }

    #[tokio::test]
    async fn listed_relays_after_own_and_never_get_keys() {
        let body =
            format!("{}{}{}", good(1), good(2), "[[relay]]\nurl = \"https://own.example.net\"\nname = \"Ours too\"\n");
        let (mut lists, fetch) = (RelayLists::new(vec![LIST.into()]), Canned::with(LIST, Ok(body)));
        lists.refresh(1_000, &fetch).await;
        let own = vec!["https://own.example.net".to_string()];
        let config = lists.relay_config(&own, Some("rk1.secret".into()));
        assert_eq!(
            config.ordered()[..3],
            ["https://own.example.net", "https://relay1.example.org", "https://relay2.example.org"],
            "own first, then the listed ones in order"
        );
        let iroh::RelayMode::Custom(map) = config.relay_mode().unwrap() else { panic!("custom relays") };
        assert_eq!(map.len(), 3, "a listed relay that is one of ours is ours, once");
        for relay in map.relays::<Vec<_>>() {
            let ours = relay.url.to_string().contains("own.example.net");
            assert_eq!(relay.auth_token.is_some(), ours, "{}: only our own relays are sent the key", relay.url);
        }
    }
}
