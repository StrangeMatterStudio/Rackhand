//! Outside sources (plan T69, 7.8.5, D65, NG10).

use std::io::Write;
use std::net::IpAddr;
use std::sync::Mutex;

use super::*;

const NOW: i64 = 1_795_000_000_000;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn gz(text: &str) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(text.as_bytes()).unwrap();
    e.finish().unwrap()
}

const FEODO: &str = "################################\n# abuse.ch Feodo Tracker Botnet C2 IP Blocklist\n################################\n\n203.0.113.9\n198.51.100.77\n2001:db8::bad\n198.51.100.77\n";
const DROP_V4: &str = "{\"cidr\":\"192.0.2.0/24\",\"sblid\":\"SBL1\",\"rir\":\"arin\"}\n{\"cidr\":\"203.0.113.128/25\",\"sblid\":\"SBL2\",\"rir\":\"ripencc\"}\n{\"type\":\"metadata\",\"timestamp\":1795000000,\"size\":2,\"records\":2}\n";
const DROP_V6: &str = "{\"cidr\":\"2001:db8:bad::/48\",\"sblid\":\"SBL3\",\"rir\":\"ripencc\"}\n{\"type\":\"metadata\",\"timestamp\":1795000000,\"size\":1,\"records\":1}\n";
const COUNTRY: &str = "\"1.0.0.0\",\"1.0.0.255\",\"AU\"\n\"1.0.1.0\",\"1.0.3.255\",\"CN\"\n\"93.184.216.0\",\"93.184.216.255\",\"US\"\n\"2001:db8::\",\"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\",\"ZZ\"\n";
const ASN: &str = "1.0.0.0,1.0.0.255,13335,\"Cloudflare, Inc.\"\n93.184.216.0,93.184.216.255,15133,Edgecast\n";

fn source(id: &str) -> Source {
    sources(NOW).into_iter().find(|s| s.id == id).unwrap()
}

#[test]
fn parsers_accept_fixtures_reject_garbage() {
    let intel = Intel::default();
    assert_eq!(intel.load(&source("feodo"), FEODO.as_bytes(), NOW), Ok(3), "comments, blanks and a repeat don't count");
    assert_eq!(
        intel.load(&source("spamhaus_drop_v4"), DROP_V4.as_bytes(), NOW),
        Ok(2),
        "the metadata line isn't a block"
    );
    assert_eq!(intel.load(&source("spamhaus_drop_v6"), DROP_V6.as_bytes(), NOW), Ok(1));
    assert_eq!(intel.load(&source("dbip_country"), &gz(COUNTRY), NOW), Ok(4));
    assert_eq!(intel.load(&source("dbip_asn"), &gz(ASN), NOW), Ok(2));
    // what isn't the list is refused, and the list already loaded stays
    let before = intel.threat(ip("203.0.113.9"));
    assert_eq!(before, Some(Threat::Feodo));
    let html = "<!DOCTYPE html><html><body>502 Bad Gateway</body></html>";
    assert_eq!(intel.load(&source("feodo"), html.as_bytes(), NOW + 1), Err(ParseError::Html));
    assert_eq!(intel.load(&source("feodo"), &[0u8, 159, 146, 150, 0, 1], NOW + 1), Err(ParseError::NotText));
    let huge = "1.2.3.4\n".repeat(1_000_000);
    assert_eq!(intel.load(&source("feodo"), huge.as_bytes(), NOW + 1), Err(ParseError::TooBig(5 << 20)));
    let mostly_bad = "not an address\nstill not\n10.0.0.1\nnope\nnope\nnope\nnope\nnope\nnope\nnope\nnope\n";
    assert!(matches!(intel.load(&source("feodo"), mostly_bad.as_bytes(), NOW + 1), Err(ParseError::Garbage { .. })));
    assert_eq!(intel.load(&source("feodo"), b"# only comments\n", NOW + 1), Err(ParseError::Empty));
    assert!(matches!(intel.load(&source("dbip_country"), b"not gzip at all", NOW + 1), Err(ParseError::Gzip(_))));
    assert!(intel.load(&source("spamhaus_drop_v4"), b"{\"cidr\":\"999.1.1.1/8\"}\nnonsense\n", NOW + 1).is_err());
    assert_eq!(intel.threat(ip("203.0.113.9")), before, "the loaded list survives every refusal");
    assert!(intel.geo(ip("93.184.216.34")).country.is_some());
    // a gzip that expands past its limit is refused without being read whole
    let bomb = gz(&"1.0.0.0,1.0.0.255,AU\n".repeat(2_000_000));
    let small = Source { max_bytes: 1000, ..source("dbip_country") };
    assert!(
        matches!(intel.load(&small, &bomb, NOW + 1), Err(ParseError::TooBig(_))),
        "a size cap on what it expands to"
    );
}

#[test]
fn lookup_ip_in_lists_and_asn_country() {
    let intel = Intel::default();
    for (id, bytes) in [
        ("feodo", FEODO.as_bytes().to_vec()),
        ("spamhaus_drop_v4", DROP_V4.as_bytes().to_vec()),
        ("spamhaus_drop_v6", DROP_V6.as_bytes().to_vec()),
        ("dbip_country", gz(COUNTRY)),
        ("dbip_asn", gz(ASN)),
    ] {
        intel.load(&source(id), &bytes, NOW).unwrap();
    }
    assert_eq!(intel.threat(ip("203.0.113.9")), Some(Threat::Feodo));
    assert_eq!(intel.threat(ip("2001:db8::bad")), Some(Threat::Feodo));
    assert_eq!(intel.threat(ip("192.0.2.77")), Some(Threat::SpamhausDrop), "inside a /24");
    assert_eq!(intel.threat(ip("203.0.113.200")), Some(Threat::SpamhausDrop), "inside a /25");
    assert_eq!(intel.threat(ip("203.0.113.100")), None, "outside it");
    assert_eq!(intel.threat(ip("2001:db8:bad::1")), Some(Threat::SpamhausDrop));
    assert_eq!(intel.threat(ip("2001:db8:bae::1")), None);
    assert_eq!(intel.threat(ip("8.8.8.8")), None);
    let g = intel.geo(ip("1.0.0.77"));
    assert_eq!((g.asn, g.org.as_deref(), g.country.as_deref()), (Some(13335), Some("Cloudflare, Inc."), Some("AU")));
    let g = intel.geo(ip("93.184.216.34"));
    assert_eq!((g.asn, g.country.as_deref()), (Some(15133), Some("US")));
    assert_eq!(intel.geo(ip("1.0.2.1")).country.as_deref(), Some("CN"), "a range in the middle");
    assert_eq!(intel.geo(ip("2001:db8::1")).country.as_deref(), Some("ZZ"));
    assert_eq!(intel.geo(ip("8.8.8.8")), Geo::default(), "unknown is unknown");
    assert!(Cidr::parse("10.0.0.0/8").unwrap().contains(ip("10.255.0.1")));
    assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("1.2.3.4")));
    assert!(Cidr::parse("10.0.0.0/33").is_none() && Cidr::parse("x/8").is_none());
}

/// A fetcher that records what it was asked for and answers each URL with its list.
#[derive(Default)]
struct Recording {
    asked: Mutex<Vec<String>>,
    fail: bool,
}

impl Fetch for Recording {
    fn get<'a>(
        &'a self,
        url: &'a str,
        _max: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        self.asked.lock().unwrap().push(url.to_string());
        let answer = if self.fail {
            Err("connection refused".to_string())
        } else if url.contains("feodo") {
            Ok(FEODO.as_bytes().to_vec())
        } else if url.contains("drop_v4") {
            Ok(DROP_V4.as_bytes().to_vec())
        } else if url.contains("drop_v6") {
            Ok(DROP_V6.as_bytes().to_vec())
        } else if url.contains("country") {
            Ok(gz(COUNTRY))
        } else {
            Ok(gz(ASN))
        };
        Box::pin(async move { answer })
    }
}

#[tokio::test]
async fn air_gapped_mode_makes_no_requests() {
    let intel = Intel::default();
    let fetch = Recording::default();
    let off = Sources { airgapped: true, ..Sources::default() };
    assert!(intel.refresh(&fetch, &off, NOW).await.is_empty());
    assert!(fetch.asked.lock().unwrap().is_empty(), "a request-recording fake sees nothing");
    // each source turned off is not asked; the rest are
    let some = Sources { feodo: false, spamhaus: false, ..Sources::default() };
    let got = intel.refresh(&fetch, &some, NOW).await;
    assert_eq!(got, ["dbip_country", "dbip_asn"]);
    let urls = fetch.asked.lock().unwrap().clone();
    assert!(urls.iter().all(|u| u.starts_with("https://download.db-ip.com/free/dbip-")), "{urls:?}");
    assert!(urls[0].ends_with("dbip-country-lite-2026-11.csv.gz"), "{urls:?}");
    // everything on: the others are asked, and nothing twice while its list is fresh
    let all = Sources::default();
    assert_eq!(intel.refresh(&fetch, &all, NOW + 1).await, ["feodo", "spamhaus_drop_v4", "spamhaus_drop_v6"]);
    assert!(intel.refresh(&fetch, &all, NOW + 2).await.is_empty(), "fresh");
    // a day later the daily lists are due again, the monthly ones are not
    let later = intel.refresh(&fetch, &all, NOW + DAY_MS + 5).await;
    assert_eq!(later, ["feodo", "spamhaus_drop_v4", "spamhaus_drop_v6"]);
    // and turning air-gapped mode on again stops it at once
    let before = fetch.asked.lock().unwrap().len();
    assert!(intel.refresh(&fetch, &off, NOW + 100 * DAY_MS).await.is_empty());
    assert_eq!(fetch.asked.lock().unwrap().len(), before);
}

#[test]
fn optional_sources_off_by_default() {
    let s = Sources::default();
    assert!(s.feodo && s.spamhaus && s.dbip, "the default sources are on (7.8.5)");
    assert!(!s.airgapped);
    assert!(
        !s.maxmind && !s.reputation && !s.relay_lists && !s.n0_relays,
        "MaxMind, online reputation, relay lists and n0's relays stay off unless enabled"
    );
    // a config written before these existed reads the same
    let old: Sources = toml::from_str("feodo = true\nspamhaus = false\ndbip = true\n").unwrap();
    assert_eq!((old.feodo, old.spamhaus, old.airgapped, old.maxmind), (true, false, false, false));
    // none of them is something the hub downloads
    assert!(sources(NOW).iter().all(|s| !s.url.contains("maxmind") && !s.url.contains("n0.dev")));
}

#[tokio::test]
async fn freshness_reported_for_security_page() {
    let intel = Intel::default();
    assert_eq!(intel.freshness_of("feodo"), Freshness::default(), "never fetched");
    let failing = Recording { fail: true, ..Recording::default() };
    intel.refresh(&failing, &Sources::default(), NOW).await;
    let f = intel.freshness_of("feodo");
    assert_eq!((f.last_ok_ms, f.last_try_ms, f.error.as_deref()), (None, Some(NOW), Some("connection refused")));
    // not hammered after a failure: no new request within the hour, one after it
    let calls = failing.asked.lock().unwrap().len();
    intel.refresh(&failing, &Sources::default(), NOW + 60_000).await;
    assert_eq!(failing.asked.lock().unwrap().len(), calls);
    let working = Recording::default();
    intel.refresh(&working, &Sources::default(), NOW + 2 * RETRY_MS).await;
    let all = intel.freshness();
    assert_eq!(all.len(), 5, "every source has a row");
    let f = &all["feodo"];
    assert_eq!((f.last_ok_ms, f.entries, f.error.clone()), (Some(NOW + 2 * RETRY_MS), 3, None));
    assert_eq!(all["dbip_asn"].entries, 2);
}

#[test]
fn db_ip_attribution_present() {
    // the Security page (T73) shows these exactly
    assert!(DBIP_ATTRIBUTION.contains("DB-IP.com") && DBIP_ATTRIBUTION.contains("CC BY 4.0"));
    assert!(SPAMHAUS_CREDIT.contains("The Spamhaus Project"));
    assert!(FEODO_CREDIT.contains("abuse.ch"));
}

#[test]
fn the_last_good_lists_are_kept_across_a_restart() {
    let dir = std::env::temp_dir().join(format!("rackhand-intel-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let first = Intel::new(Some(dir.clone()));
    first.load(&source("feodo"), FEODO.as_bytes(), NOW).unwrap();
    assert!(first.load(&source("feodo"), b"<html></html>", NOW + 1).is_err(), "a refused download is not kept");
    let second = Intel::new(Some(dir));
    second.load_cache(NOW + 5);
    assert_eq!(second.threat(ip("203.0.113.9")), Some(Threat::Feodo));
    assert_eq!(second.freshness_of("feodo").entries, 3);
    assert_eq!(year_month(NOW), (2026, 11));
    assert_eq!(year_month(0), (1970, 1));
}
