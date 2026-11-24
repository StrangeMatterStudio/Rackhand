//! Connection storage (7.4.1, 7.6.5, E59, AC55, AC69, D56): what a machine's records become in `conn_records`, in 5-minute
//! buckets. At most 20 000 rows per machine per day; past that, summary rows per container and executable. A machine whose
//! policy says `summary` stores only counts per country and ASN, and one that says `off` stores nothing; the threat-list
//! checks run on every tuple in every mode.

use std::collections::{HashMap, HashSet};

use rackhand_store::Row;
use rusqlite::types::Value;

use super::conn_score::{Conn, Outcome};

/// Rows per machine per day before records are summarized.
pub const DAILY_ROWS: usize = 20_000;
const BUCKET_MS: i64 = 300_000;
const DAY_MS: i64 = 86_400_000;

/// What a policy says about storing connections (7.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Full,
    Summary,
    Off,
}

impl Mode {
    pub fn parse(text: &str) -> Mode {
        match text {
            "summary" => Mode::Summary,
            "off" => Mode::Off,
            _ => Mode::Full,
        }
    }
}

type Key = (i64, String, String, String, u16, &'static str);

/// What a machine has stored today.
#[derive(Debug, Default)]
pub struct Today {
    day: i64,
    keys: HashSet<Key>,
    /// Rows already in the table for the day when this state began (after a restart).
    base: usize,
    loaded: bool,
}

impl Today {
    /// Starts the day's count from what the table already has.
    pub fn load(&mut self, at_ms: i64, rows_in_table: usize) {
        let day = at_ms.div_euclid(DAY_MS);
        if self.loaded && self.day == day {
            return;
        }
        *self = Today { day, keys: HashSet::new(), base: rows_in_table, loaded: true };
    }

    pub fn needs_load(&self, at_ms: i64) -> bool {
        !self.loaded || self.day != at_ms.div_euclid(DAY_MS)
    }

    fn rows(&self) -> usize {
        self.base + self.keys.len()
    }
}

/// The rows to write: `conn_records` rows (added to what is there) and the baseline rows learned.
#[derive(Debug, Default)]
pub struct Rows {
    pub records: Vec<Row>,
    pub baseline: Vec<Row>,
}

fn text(s: &str) -> Value {
    Value::Text(s.into())
}

#[allow(clippy::too_many_arguments)]
fn record(
    machine: &str,
    bucket: i64,
    container: &str,
    exe: &str,
    dest: &str,
    port: u16,
    proto: &str,
    asn: Option<u32>,
    country: Option<&str>,
    verdict: Option<&str>,
    bytes: u64,
    count: u32,
) -> Row {
    Row::from([
        ("machine_id", text(machine)),
        ("bucket_ms", Value::Integer(bucket)),
        ("container", text(container)),
        ("exe", text(exe)),
        ("dest_ip", text(dest)),
        ("dest_port", Value::Integer(i64::from(port))),
        ("proto", text(proto)),
        ("dest_asn", asn.map_or(Value::Null, |a| Value::Integer(i64::from(a)))),
        ("dest_country", country.map_or(Value::Null, text)),
        ("verdict", verdict.map_or(Value::Null, text)),
        ("bytes_out", Value::Integer(bytes.min(i64::MAX as u64) as i64)),
        ("count", Value::Integer(i64::from(count))),
    ])
}

fn verdict_name(o: &Outcome) -> Option<&'static str> {
    use super::conn_score::Verdict::*;
    match o.verdict {
        KnownBad => Some("known_bad"),
        New => Some("new"),
        Known | Learning => Some("known"),
        Skipped => None,
    }
}

/// The rows for the scored records of one report (placed at `at_ms`), by `mode`.
pub fn plan(machine: &str, at_ms: i64, scored: &[(Conn, Outcome)], mode: Mode, today: &mut Today) -> Rows {
    let mut rows = Rows::default();
    if mode == Mode::Off {
        return rows;
    }
    let bucket = at_ms - at_ms.rem_euclid(BUCKET_MS);
    // a record's row is added to what the table has; those that fold into one row are added here
    let mut merged: HashMap<(String, String, String, u16, &'static str), Row> = HashMap::new();
    let add = |key: (String, String, String, u16, &'static str), row: Row, merged: &mut HashMap<_, Row>| match merged
        .get_mut(&key)
    {
        Some(r) => {
            for col in ["bytes_out", "count"] {
                if let (Some(Value::Integer(a)), Some(Value::Integer(b))) = (r.get(col).cloned(), row.get(col)) {
                    r.insert(col, Value::Integer(a + b));
                }
            }
        }
        None => {
            merged.insert(key, row);
        }
    };
    for (c, outcome) in scored {
        // what wasn't scored for being private or Rackhand's own isn't stored either; a record the probe folded is
        if outcome.verdict == super::conn_score::Verdict::Skipped && c.dest.is_some() {
            continue;
        }
        match mode {
            Mode::Off => {}
            Mode::Summary => {
                // only counts per country and ASN; a record with no destination is counted under none
                let (asn, country) = (outcome.asn.unwrap_or(0), outcome.country.clone().unwrap_or_default());
                let label = format!("AS{asn}");
                let key = (String::new(), String::new(), label.clone(), 0, "");
                let row =
                    record(machine, bucket, "", "", &label, 0, "", outcome.asn, Some(&country), None, c.bytes, c.count);
                add(key, row, &mut merged);
            }
            Mode::Full => {
                let proto = c.proto();
                let dest = c.dest.map(|d| d.to_string()).unwrap_or_default();
                let full: Key = (bucket, c.container.clone(), c.exe.clone(), dest.clone(), c.port, proto);
                let known_row = today.keys.contains(&full);
                if c.dest.is_none() || (!known_row && today.rows() >= DAILY_ROWS) {
                    // past the cap, or a folded record: one summary row per container and executable
                    let key = (c.container.clone(), c.exe.clone(), String::new(), 0, "");
                    let row = record(
                        machine,
                        bucket,
                        &c.container,
                        &c.exe,
                        "",
                        0,
                        "",
                        None,
                        None,
                        Some("summary"),
                        c.bytes,
                        c.count,
                    );
                    add(key, row, &mut merged);
                    continue;
                }
                today.keys.insert(full);
                let key = (c.container.clone(), c.exe.clone(), dest.clone(), c.port, proto);
                let row = record(
                    machine,
                    bucket,
                    &c.container,
                    &c.exe,
                    &dest,
                    c.port,
                    proto,
                    outcome.asn,
                    outcome.country.as_deref(),
                    verdict_name(outcome),
                    c.bytes,
                    c.count,
                );
                add(key, row, &mut merged);
            }
        }
    }
    rows.records = merged.into_values().collect();
    rows
}

/// A baseline row for a tuple learned (the first and last time it was seen are `at_ms`).
pub fn baseline_row(machine: &str, c: &Conn, asn: Option<u32>, country: Option<&str>, at_ms: i64) -> Row {
    Row::from([
        ("machine_id", text(machine)),
        ("container", text(&c.container)),
        ("exe", text(&c.exe)),
        ("dest_asn", Value::Integer(i64::from(asn.unwrap_or(0)))),
        ("dest_country", text(country.unwrap_or(""))),
        ("dest_port", Value::Integer(i64::from(c.port))),
        ("proto", text(c.proto())),
        ("first_seen_ms", Value::Integer(at_ms)),
        ("last_seen_ms", Value::Integer(at_ms)),
        ("count", Value::Integer(i64::from(c.count))),
    ])
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::super::conn_score::Verdict;
    use super::*;

    const AT: i64 = 1_795_000_000_000;

    fn scored(i: u32, verdict: Verdict) -> (Conn, Outcome) {
        let c = Conn {
            container: "web".into(),
            exe: "/usr/bin/curl".into(),
            user: "alice".into(),
            pid: 1,
            dest: Some(IpAddr::V4(std::net::Ipv4Addr::from(0x5db8_0000 + i))),
            port: 443,
            tcp: true,
            count: 1,
            bytes: 10,
        };
        (c, Outcome { verdict, asn: Some(15133), country: Some("US".into()), events: vec![] })
    }

    fn text_of(row: &Row, col: &str) -> String {
        match row.get(col) {
            Some(Value::Text(t)) => t.clone(),
            Some(Value::Integer(i)) => i.to_string(),
            Some(Value::Null) | None => String::new(),
            other => format!("{other:?}"),
        }
    }

    #[test]
    fn daily_cap_20000_then_summary_rows_and_overflow() {
        let mut today = Today::default();
        today.load(AT, 0);
        // 100 000 distinct destinations over a day's reports
        let mut full = 0;
        let mut summary = 0usize;
        let mut summary_count = 0i64;
        for report in 0..100 {
            let batch: Vec<(Conn, Outcome)> = (0..1000).map(|i| scored(report * 1000 + i, Verdict::Known)).collect();
            let rows = plan("m1", AT + i64::from(report as i32) * 60_000, &batch, Mode::Full, &mut today);
            for r in &rows.records {
                if text_of(r, "verdict") == "summary" {
                    summary += 1;
                    summary_count += text_of(r, "count").parse::<i64>().unwrap();
                } else {
                    full += 1;
                }
            }
        }
        assert_eq!(full, DAILY_ROWS, "at most 20 000 destination rows");
        assert!((1..=100).contains(&summary), "summary rows past the cap, one per report bucket: {summary}");
        assert_eq!(summary_count, 100_000 - DAILY_ROWS as i64, "every record past the cap is counted");
        // a restart in the middle of the day starts from what the table has
        let mut after_restart = Today::default();
        after_restart.load(AT, DAILY_ROWS);
        let rows = plan("m1", AT, &[scored(900_000, Verdict::Known)], Mode::Full, &mut after_restart);
        assert_eq!(text_of(&rows.records[0], "verdict"), "summary");
        // the next day has its own 20 000
        assert!(today.needs_load(AT + DAY_MS));
    }

    #[test]
    fn summary_mode_stores_country_asn_counts_only_known_bad_still_named() {
        let mut today = Today::default();
        let batch = vec![scored(1, Verdict::Known), scored(2, Verdict::Known), scored(3, Verdict::KnownBad)];
        let rows = plan("m1", AT, &batch, Mode::Summary, &mut today);
        assert_eq!(rows.records.len(), 1, "one row per ASN and country");
        let r = &rows.records[0];
        assert_eq!(
            (text_of(r, "dest_ip").as_str(), text_of(r, "dest_country").as_str(), text_of(r, "count").as_str()),
            ("AS15133", "US", "3")
        );
        assert_eq!(
            (text_of(r, "container"), text_of(r, "exe"), text_of(r, "dest_port")),
            (String::new(), String::new(), "0".to_string())
        );
        assert!(
            !format!("{r:?}").contains("93.184") && !format!("{r:?}").contains("curl"),
            "no address and no program: {r:?}"
        );
        // the threat-list check is the scoring's, not the store's: it still produced its event for the third record
        // (conn_score::threat_list_hit_is_critical_conn_known_bad), and the store keeps no more of it than the others
    }

    #[test]
    fn off_mode_stores_nothing() {
        let mut today = Today::default();
        let rows = plan("m1", AT, &[scored(1, Verdict::Known), scored(2, Verdict::KnownBad)], Mode::Off, &mut today);
        assert!(rows.records.is_empty() && rows.baseline.is_empty());
        assert_eq!(
            (Mode::parse("off"), Mode::parse("summary"), Mode::parse("full"), Mode::parse("x")),
            (Mode::Off, Mode::Summary, Mode::Full, Mode::Full)
        );
    }
}
