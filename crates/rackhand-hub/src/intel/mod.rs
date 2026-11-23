//! Outside sources (7.8.5, D19, D65, NG10): threat lists and GeoIP/ASN data the hub downloads over HTTPS on their schedules,
//! parsed strictly, and the lookups that use them. Each source can be turned off, and air-gapped mode turns them all off so
//! that the hub makes no request at all. Sources that need a key, or that send destinations out, are off unless enabled.

pub mod fetch;
pub mod parse;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use rackhand_store::ids::now_ms;

use crate::library::config::Sources;
use parse::{Cidr, ParseError, Ranges};

/// Shown on the Security page (7.8.5).
pub const DBIP_ATTRIBUTION: &str = "IP geolocation and ASN data by DB-IP.com, licensed CC BY 4.0.";
pub const SPAMHAUS_CREDIT: &str = "Threat list data from The Spamhaus Project (DROP).";
pub const FEODO_CREDIT: &str = "Threat list data from abuse.ch Feodo Tracker (CC0).";

const DAY_MS: i64 = 86_400_000;
/// After a failed fetch a source is tried again no sooner than this.
const RETRY_MS: i64 = 3_600_000;
const MB: usize = 1 << 20;

/// Which settings toggle a source follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Feodo,
    Spamhaus,
    DbIp,
}

impl Group {
    pub fn on(self, s: &Sources) -> bool {
        !s.airgapped
            && match self {
                Group::Feodo => s.feodo,
                Group::Spamhaus => s.spamhaus,
                Group::DbIp => s.dbip,
            }
    }
}

/// One list the hub downloads.
#[derive(Debug, Clone)]
pub struct Source {
    pub id: &'static str,
    pub label: &'static str,
    pub group: Group,
    pub url: String,
    /// The most the download may be (compressed, for DB-IP).
    pub max_bytes: usize,
    pub every_ms: i64,
}

/// The default sources as of `now_ms` (DB-IP's files are named by month).
pub fn sources(now_ms: i64) -> Vec<Source> {
    let (year, month) = year_month(now_ms);
    let dbip = |kind: &str| format!("https://download.db-ip.com/free/dbip-{kind}-lite-{year:04}-{month:02}.csv.gz");
    vec![
        Source {
            id: "feodo",
            label: "abuse.ch Feodo Tracker",
            group: Group::Feodo,
            url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt".into(),
            max_bytes: 5 * MB,
            every_ms: DAY_MS,
        },
        Source {
            id: "spamhaus_drop_v4",
            label: "Spamhaus DROP (IPv4)",
            group: Group::Spamhaus,
            url: "https://www.spamhaus.org/drop/drop_v4.json".into(),
            max_bytes: 5 * MB,
            every_ms: DAY_MS,
        },
        Source {
            id: "spamhaus_drop_v6",
            label: "Spamhaus DROP (IPv6)",
            group: Group::Spamhaus,
            url: "https://www.spamhaus.org/drop/drop_v6.json".into(),
            max_bytes: 5 * MB,
            every_ms: DAY_MS,
        },
        Source {
            id: "dbip_country",
            label: "DB-IP Lite country",
            group: Group::DbIp,
            url: dbip("country"),
            max_bytes: 40 * MB,
            every_ms: 30 * DAY_MS,
        },
        Source {
            id: "dbip_asn",
            label: "DB-IP Lite ASN",
            group: Group::DbIp,
            url: dbip("asn"),
            max_bytes: 40 * MB,
            every_ms: 30 * DAY_MS,
        },
    ]
}

/// The calendar year and month of a time (UTC).
pub fn year_month(ms: i64) -> (i64, i64) {
    let days = ms.div_euclid(DAY_MS);
    // days since 1970-01-01 to a civil date (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month)
}

/// What the Security page shows for a source: when it last worked, what it holds, and what went wrong last.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Freshness {
    pub last_ok_ms: Option<i64>,
    pub last_try_ms: Option<i64>,
    pub entries: usize,
    pub error: Option<String>,
}

/// Where the lists come from; a recording fake in tests.
pub trait Fetch: Send + Sync {
    fn get<'a>(
        &'a self,
        url: &'a str,
        max_bytes: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;
}

#[derive(Debug, Default)]
struct State {
    feodo: Vec<IpAddr>,
    drop: Vec<Cidr>,
    country: Ranges<String>,
    asn: Ranges<(u32, String)>,
    fresh: BTreeMap<&'static str, Freshness>,
}

/// A threat list a destination is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Threat {
    Feodo,
    SpamhausDrop,
}

impl Threat {
    pub fn name(self) -> &'static str {
        match self {
            Threat::Feodo => "abuse.ch Feodo Tracker",
            Threat::SpamhausDrop => "Spamhaus DROP",
        }
    }
}

/// An address's ASN and country, where known.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Geo {
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub country: Option<String>,
}

#[derive(Clone)]
pub struct Intel {
    state: Arc<RwLock<State>>,
    cache: Option<PathBuf>,
}

impl std::fmt::Debug for Intel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Intel").finish_non_exhaustive()
    }
}

impl Default for Intel {
    fn default() -> Intel {
        Intel::new(None)
    }
}

impl Intel {
    /// Empty lists; `cache` is where the last good download of each source is kept, so a restart has them again.
    pub fn new(cache: Option<PathBuf>) -> Intel {
        if let Some(dir) = &cache {
            let _ = std::fs::create_dir_all(dir);
        }
        Intel { state: Arc::default(), cache }
    }

    fn state(&self) -> std::sync::RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(|e| e.into_inner())
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Replaces a source's list with a download if it parses; a download that doesn't leaves the list as it was.
    pub fn load(&self, source: &Source, bytes: &[u8], now_ms: i64) -> Result<usize, ParseError> {
        let entries = match source.id {
            "feodo" => parse::feodo(bytes, source.max_bytes).map(|v| {
                let n = v.len();
                self.state().feodo = v;
                n
            }),
            "spamhaus_drop_v4" | "spamhaus_drop_v6" => parse::drop(bytes, source.max_bytes).map(|v| {
                let n = v.len();
                let mut s = self.state();
                let v6 = source.id.ends_with("v6");
                s.drop.retain(|c| c.network.is_ipv6() != v6);
                s.drop.extend(v);
                n
            }),
            "dbip_country" => parse::dbip_country(bytes, source.max_bytes, 8 * source.max_bytes).map(|r| {
                let n = r.len();
                self.state().country = r;
                n
            }),
            "dbip_asn" => parse::dbip_asn(bytes, source.max_bytes, 8 * source.max_bytes).map(|r| {
                let n = r.len();
                self.state().asn = r;
                n
            }),
            _ => Err(ParseError::Empty),
        };
        let mut s = self.state();
        let f = s.fresh.entry(source.id).or_default();
        f.last_try_ms = Some(now_ms);
        match &entries {
            Ok(n) => {
                f.last_ok_ms = Some(now_ms);
                f.entries = *n;
                f.error = None;
            }
            Err(e) => f.error = Some(e.to_string()),
        }
        drop(s);
        if entries.is_ok() {
            if let Some(dir) = &self.cache {
                let _ = std::fs::write(dir.join(format!("{}.bin", source.id)), bytes);
            }
        }
        entries
    }

    /// The last good downloads from the cache, as at start.
    pub fn load_cache(&self, now_ms: i64) {
        let Some(dir) = &self.cache else { return };
        for source in sources(now_ms) {
            if let Ok(bytes) = std::fs::read(dir.join(format!("{}.bin", source.id))) {
                let modified = std::fs::metadata(dir.join(format!("{}.bin", source.id)))
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_millis() as i64);
                let _ = self.load(&source, &bytes, modified);
            }
        }
    }

    /// The threat list an address is on, if any.
    pub fn threat(&self, ip: IpAddr) -> Option<Threat> {
        let s = self.read();
        if s.feodo.binary_search(&ip).is_ok() {
            return Some(Threat::Feodo);
        }
        s.drop.iter().any(|c| c.contains(ip)).then_some(Threat::SpamhausDrop)
    }

    pub fn geo(&self, ip: IpAddr) -> Geo {
        let s = self.read();
        let asn = s.asn.find(ip);
        Geo { asn: asn.map(|a| a.0), org: asn.map(|a| a.1.clone()), country: s.country.find(ip).cloned() }
    }

    /// What each source last did, for the Security page.
    pub fn freshness(&self) -> BTreeMap<&'static str, Freshness> {
        self.read().fresh.clone()
    }

    pub fn freshness_of(&self, id: &str) -> Freshness {
        self.read().fresh.iter().find(|(k, _)| **k == id).map(|(_, v)| v.clone()).unwrap_or_default()
    }

    /// Fetches what is due: each source that is on, whose list is older than its schedule, and not tried in the last hour
    /// after a failure. Air-gapped mode, or a source turned off, makes no request. Returns the ids fetched.
    pub async fn refresh(&self, fetch: &dyn Fetch, settings: &Sources, now_ms: i64) -> Vec<&'static str> {
        let mut fetched = Vec::new();
        if settings.airgapped {
            return fetched;
        }
        for source in sources(now_ms) {
            if !source.group.on(settings) {
                continue;
            }
            let f = self.freshness_of(source.id);
            let fresh = f.last_ok_ms.is_some_and(|t| now_ms - t < source.every_ms);
            let failed_lately = f.error.is_some() && f.last_try_ms.is_some_and(|t| now_ms - t < RETRY_MS);
            if fresh || failed_lately {
                continue;
            }
            fetched.push(source.id);
            match fetch.get(&source.url, source.max_bytes).await {
                Ok(bytes) => {
                    if let Err(e) = self.load(&source, &bytes, now_ms) {
                        tracing::warn!(source = source.id, error = %e, "an outside list was refused");
                    }
                }
                Err(e) => {
                    tracing::warn!(source = source.id, error = %e, "an outside list couldn't be fetched");
                    let mut s = self.state();
                    let f = s.fresh.entry(source.id).or_default();
                    f.last_try_ms = Some(now_ms);
                    f.error = Some(e);
                }
            }
        }
        fetched
    }
}

/// Refreshes in the background every hour from the settings as they are then.
pub fn spawn_refresh(intel: Intel, fetch: Arc<dyn Fetch>, settings: Arc<dyn Fn() -> Sources + Send + Sync>) {
    tokio::spawn(async move {
        loop {
            let now = now_ms();
            let current = settings();
            intel.refresh(fetch.as_ref(), &current, now).await;
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    });
}

#[cfg(test)]
mod tests;
