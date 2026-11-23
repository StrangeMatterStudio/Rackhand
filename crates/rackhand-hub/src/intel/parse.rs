//! The outside lists, parsed strictly (7.8.5, 10): a download that isn't what its source publishes (HTML from a proxy's
//! error page, binary, a list far too big, mostly unreadable lines) is refused whole, and the list the hub already has
//! stays loaded.

use std::io::Read;
use std::net::IpAddr;

/// Why a download was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("larger than the {0} bytes this list may be")]
    TooBig(usize),
    #[error("not text")]
    NotText,
    #[error("looks like a web page, not a list")]
    Html,
    #[error("too many lines it can't read ({bad} of {total})")]
    Garbage { bad: usize, total: usize },
    #[error("more than {0} entries")]
    TooMany(usize),
    #[error("not gzip, or damaged: {0}")]
    Gzip(String),
    #[error("no entries")]
    Empty,
}

/// An address block: `network/prefix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub network: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(text: &str) -> Option<Cidr> {
        let (ip, prefix) = text.trim().split_once('/')?;
        let network: IpAddr = ip.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Cidr { network, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(self.prefix)) };
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - u32::from(self.prefix)) };
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

/// The most entries any list may have.
pub const MAX_ENTRIES: usize = 200_000;
/// The share of unreadable lines past which a list is refused.
const MAX_BAD_FRACTION: f64 = 0.1;

fn text(bytes: &[u8], max: usize) -> Result<&str, ParseError> {
    if bytes.len() > max {
        return Err(ParseError::TooBig(max));
    }
    let s = std::str::from_utf8(bytes).map_err(|_| ParseError::NotText)?;
    if s.contains('\0') {
        return Err(ParseError::NotText);
    }
    let head: String = s.chars().take(512).collect::<String>().to_ascii_lowercase();
    if head.contains("<html") || head.contains("<!doctype") || head.contains("<body") {
        return Err(ParseError::Html);
    }
    Ok(s)
}

fn judge(bad: usize, total: usize) -> Result<(), ParseError> {
    if total == 0 {
        return Err(ParseError::Empty);
    }
    if bad as f64 / total as f64 > MAX_BAD_FRACTION {
        return Err(ParseError::Garbage { bad, total });
    }
    Ok(())
}

/// abuse.ch Feodo Tracker's plain IP list: one address per line, `#` comments.
pub fn feodo(bytes: &[u8], max: usize) -> Result<Vec<IpAddr>, ParseError> {
    let s = text(bytes, max)?;
    let (mut ips, mut bad, mut total) = (Vec::new(), 0, 0);
    for line in s.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        total += 1;
        match line.parse::<IpAddr>() {
            Ok(ip) => ips.push(ip),
            Err(_) => bad += 1,
        }
    }
    judge(bad, total)?;
    if ips.len() > MAX_ENTRIES {
        return Err(ParseError::TooMany(MAX_ENTRIES));
    }
    ips.sort();
    ips.dedup();
    Ok(ips)
}

/// Spamhaus DROP's JSON lines: `{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}`, and one metadata line.
pub fn drop(bytes: &[u8], max: usize) -> Result<Vec<Cidr>, ParseError> {
    let s = text(bytes, max)?;
    let (mut blocks, mut bad, mut total) = (Vec::new(), 0, 0);
    for line in s.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let value: Option<serde_json::Value> = serde_json::from_str(line).ok();
        match value {
            Some(v) if v["type"] == "metadata" => {}
            Some(v) => {
                total += 1;
                match v["cidr"].as_str().and_then(Cidr::parse) {
                    Some(c) => blocks.push(c),
                    None => bad += 1,
                }
            }
            None => {
                total += 1;
                bad += 1;
            }
        }
    }
    judge(bad, total)?;
    if blocks.len() > MAX_ENTRIES {
        return Err(ParseError::TooMany(MAX_ENTRIES));
    }
    Ok(blocks)
}

/// An inclusive address range with what it maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range<T> {
    pub start: u128,
    pub end: u128,
    pub value: T,
}

pub fn ip_key(ip: IpAddr) -> (bool, u128) {
    match ip {
        IpAddr::V4(a) => (false, u128::from(u32::from(a))),
        IpAddr::V6(a) => (true, u128::from(a)),
    }
}

/// The gunzipped text of a DB-IP file, at most `max` bytes of it.
fn gunzip(bytes: &[u8], max: usize) -> Result<Vec<u8>, ParseError> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .take(max as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| ParseError::Gzip(e.to_string()))?;
    if out.len() > max {
        return Err(ParseError::TooBig(max));
    }
    Ok(out)
}

/// DB-IP Lite rows: `start,end,value...`; the value of a country file is a two-letter code, of an ASN file the number
/// and the organization. IPv4 and IPv6 are kept apart, each sorted by start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ranges<T> {
    pub v4: Vec<Range<T>>,
    pub v6: Vec<Range<T>>,
}

impl<T> Ranges<T> {
    pub fn find(&self, ip: IpAddr) -> Option<&T> {
        let (six, key) = ip_key(ip);
        let list = if six { &self.v6 } else { &self.v4 };
        let at = list.partition_point(|r| r.start <= key);
        let r = list.get(at.checked_sub(1)?)?;
        (key <= r.end).then_some(&r.value)
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn dbip<T>(
    gz: &[u8],
    max_gz: usize,
    max_text: usize,
    value: impl Fn(&[&str]) -> Option<T>,
) -> Result<Ranges<T>, ParseError> {
    if gz.len() > max_gz {
        return Err(ParseError::TooBig(max_gz));
    }
    let raw = gunzip(gz, max_text)?;
    let s = text(&raw, max_text)?;
    let mut out = Ranges { v4: Vec::new(), v6: Vec::new() };
    let (mut bad, mut total) = (0usize, 0usize);
    for line in s.lines().map(str::trim).filter(|l| !l.is_empty()) {
        total += 1;
        let f = csv_fields(line);
        let f: Vec<&str> = f.iter().map(String::as_str).collect();
        let parsed = (|| {
            let (a, b): (IpAddr, IpAddr) = (f.first()?.parse().ok()?, f.get(1)?.parse().ok()?);
            let ((six_a, start), (six_b, end)) = (ip_key(a), ip_key(b));
            (six_a == six_b && start <= end).then_some((six_a, start, end, value(&f[2..])?))
        })();
        match parsed {
            Some((six, start, end, value)) => {
                let list = if six { &mut out.v6 } else { &mut out.v4 };
                list.push(Range { start, end, value });
            }
            None => bad += 1,
        }
    }
    judge(bad, total)?;
    out.v4.sort_by_key(|r| r.start);
    out.v6.sort_by_key(|r| r.start);
    Ok(out)
}

/// One CSV line's fields, a field in double quotes holding commas (`"Cloudflare, Inc."`) and `""` for a quote.
fn csv_fields(line: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted) = (Vec::new(), String::new(), false);
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => out.push(std::mem::take(&mut cur).trim().to_string()),
            (c, _) => cur.push(c),
        }
    }
    out.push(cur.trim().to_string());
    out
}

/// A country file's rows: a two-letter code.
pub fn dbip_country(gz: &[u8], max_gz: usize, max_text: usize) -> Result<Ranges<String>, ParseError> {
    dbip(gz, max_gz, max_text, |f| {
        let cc = f.first()?;
        (cc.len() == 2 && cc.bytes().all(|b| b.is_ascii_uppercase())).then(|| cc.to_string())
    })
}

/// An ASN file's rows: the number and the organization's name.
pub fn dbip_asn(gz: &[u8], max_gz: usize, max_text: usize) -> Result<Ranges<(u32, String)>, ParseError> {
    dbip(gz, max_gz, max_text, |f| Some((f.first()?.parse().ok()?, f.get(1).copied().unwrap_or_default().to_string())))
}
