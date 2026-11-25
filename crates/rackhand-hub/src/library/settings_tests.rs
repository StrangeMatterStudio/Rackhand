//! 7.8.1: every setting has its default and its range. The rows kept in `config/hub.toml` are checked through
//! `parse_hub` (the save path refuses a value out of range, and names the key and the range); the rows kept per item
//! are checked through their own parsers: a service check in `config/checks.toml`, a patch window on its policy, and
//! the two ports in `/etc/rackhand/hub.toml`.

use std::sync::Arc;

use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use crate::library::config::{self, HubConfig, parse_hub};
use crate::library::items::{Kind, validate};

/// The rows of 7.8.1 kept in `config/hub.toml`: the design's row, the key, its default, its least and its most, in the
/// unit the key names.
const HUB_TOML: &[(&str, &str, i64, i64, i64)] = &[
    ("Probe interval", "probe.interval_s", 15, 5, 300),
    ("Max concurrent patch jobs per site", "patching.max_jobs_per_site", 3, 1, 20),
    ("Peer summary interval", "peers.summary_interval_s", 30, 10, 300),
    ("Assistant job deadline", "assistant.deadline_min", 30, 5, 120),
    ("Assistant max turns", "assistant.max_turns", 60, 10, 200),
    ("Assistant jobs per day per hub", "assistant.daily_cap", 20, 0, 500),
    ("Automatic runbook starts per incident per 24 h", "incidents.runbook_starts_24h", 2, 1, 10),
    ("Assistant jobs per incident per 24 h", "incidents.assistant_jobs_24h", 1, 1, 5),
    ("Wait for the condition to clear after a job", "incidents.clear_wait_min", 10, 2, 60),
    ("Connection tuples per report", "probe.connection_tuples", 500, 100, 5000),
    ("Connection records per machine per day", "connections.records_per_day", 20_000, 1_000, 200_000),
    ("Job output and transcript budget", "jobs.output_budget_mb", 100, 50, 20 * 1024),
    ("Approval expiry", "approvals.expiry_h", 24, 1, 7 * 24),
    ("Step-up freshness", "auth.step_up_min", 5, 1, 15),
    ("Baseline learning", "baseline.learning_days", 7, 1, 30),
    ("Retention tier 0", "retention.tier0_h", 48, 12, 7 * 24),
    ("Retention tier 1", "retention.tier1_days", 30, 7, 365),
    ("Retention tier 2", "retention.tier2_days", 365, 30, 3650),
    ("Local backups kept", "backups.kept", 2, 1, 14),
    ("Series cap per machine", "probe.series_cap", 200, 50, 2000),
];

/// Keys of `config/hub.toml` that aren't rows of 7.8.1: the probe's buffer (5, D114).
const OTHER_KEYS: &[&str] = &["probe.buffer_max_mb"];

/// A page that edits one setting saves the whole file again: every other setting is kept.
#[test]
fn saving_one_setting_keeps_the_others() {
    let mut cfg = parse_hub("[incidents]\nrunbook_starts_24h = 4\n\n[backups]\nkept = 9\n").unwrap();
    cfg.assistant.daily_cap = 3;
    let again = parse_hub(&cfg.to_toml()).unwrap();
    assert_eq!((again.incidents.runbook_starts_24h, again.backups.kept, again.assistant.daily_cap), (4, 9, 3));
}

/// A stored file saved before a range was checked (a daily cap of 1000 from the old form) is read with the nearer end
/// of the range, and the rest of the file still applies; saving it again is refused until it is in range.
#[tokio::test(flavor = "multi_thread")]
async fn a_stored_value_out_of_range_is_read_at_the_nearer_end() {
    let dir = std::env::temp_dir().join(format!("rackhand-settings-read-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let text =
        "[sources]\nfeodo = true\nspamhaus = true\ndbip = true\nairgapped = true\n\n[assistant]\ndaily_cap = 1000\n";
    config::put(&db, config::HUB, text, "admin", 1).await.unwrap();
    let cfg = config::hub(&db).unwrap();
    assert_eq!(cfg.assistant.daily_cap, 500);
    assert!(cfg.sources.airgapped, "the rest of the file applies");
    assert!(parse_hub(text).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The settings in the units their consumers take.
#[test]
fn settings_convert_to_their_consumers_units() {
    let (min, hour, day) = (60_000i64, 3_600_000i64, 86_400_000i64);
    let d = HubConfig::default();
    assert_eq!(d.jobs.output_budget_bytes(), crate::actions::output_budget::DEFAULT_BUDGET);
    assert_eq!(d.retention.store(), rackhand_store::retention::RetentionSettings::default(), "the store's defaults");
    let cfg = parse_hub(
        "[jobs]\noutput_budget_mb = 50\n[retention]\ntier0_h = 12\ntier1_days = 7\ntier2_days = 3650\n\
         [approvals]\nexpiry_h = 168\n[auth]\nstep_up_min = 15\n[baseline]\nlearning_days = 30\n\
         [incidents]\nclear_wait_min = 60\n[assistant]\ndeadline_min = 120\n[peers]\nsummary_interval_s = 300\n",
    )
    .unwrap();
    assert_eq!(cfg.jobs.output_budget_bytes(), 50 * 1024 * 1024);
    let r = cfg.retention.store();
    assert_eq!((r.tier0_ms, r.tier1_ms, r.tier2_ms), (12 * hour, 7 * day, 3650 * day));
    assert_eq!(r.events_ms, 90 * day, "events keep their 90 days");
    assert_eq!(cfg.approvals.expiry_ms(), 7 * 24 * hour);
    assert_eq!(cfg.auth.step_up_ms(), 15 * min);
    assert_eq!(cfg.baseline.learning_ms(), 30 * day);
    assert_eq!(cfg.incidents.clear_wait_ms(), 60 * min);
    assert_eq!(cfg.assistant.deadline_ms(), crate::assist::MAX_DEADLINE_MS);
    assert_eq!(cfg.peers.summary_every(), std::time::Duration::from_secs(300));
    assert_eq!(cfg.peers.silent_after_ms(), 15 * min, "3 intervals of 5 minutes");
}

fn file(key: &str, value: i64) -> String {
    let (section, field) = key.split_once('.').unwrap();
    format!("[{section}]\n{field} = {value}\n")
}

fn value(cfg: &HubConfig, key: &str) -> i64 {
    cfg.value(key).unwrap_or_else(|| panic!("{key} is not a setting"))
}

#[tokio::test(flavor = "multi_thread")]
async fn every_setting_in_7_8_1_has_default_and_range() {
    // config/hub.toml: the default when the key is absent, both ends accepted, one past either refused on save
    let defaults = parse_hub("").unwrap();
    for &(row, key, default, min, max) in HUB_TOML {
        assert_eq!(value(&defaults, key), default, "{row}: {key} defaults to {default}");
        for ok in [min, max] {
            let cfg = parse_hub(&file(key, ok)).unwrap_or_else(|e| panic!("{row}: {key} = {ok} is in range: {e}"));
            assert_eq!(value(&cfg, key), ok, "{row}: {key} = {ok} is kept");
            assert!(validate(Kind::Config, "hub", &file(key, ok)).is_ok(), "{row}: {key} = {ok} saves");
        }
        for bad in [min - 1, max + 1] {
            let err = parse_hub(&file(key, bad)).err().unwrap_or_else(|| panic!("{row}: {key} = {bad} is refused"));
            let field = key.split_once('.').unwrap().1;
            assert!(err.to_string().contains(field), "{row}: the error names {key}: {err}");
            if bad >= 0 {
                assert!(
                    err.to_string().contains(&format!("{min} to {max}")),
                    "{row}: the error gives the range: {err}"
                );
            }
            assert!(validate(Kind::Config, "hub", &file(key, bad)).is_err(), "{row}: {key} = {bad} isn't saved");
        }
    }
    // the registry has every row above and nothing else
    let mut registered: Vec<&str> = config::settings().iter().map(|s| s.key).collect();
    let mut designed: Vec<&str> = HUB_TOML.iter().map(|r| r.1).chain(OTHER_KEYS.iter().copied()).collect();
    registered.sort_unstable();
    designed.sort_unstable();
    assert_eq!(registered, designed, "config/hub.toml has a setting for every row of 7.8.1 it keeps");
    // an existing hub.toml with none of the new sections still parses, its keys unchanged
    let old = "[probe]\ninterval_s = 20\nconnection_tuples = 800\nbuffer_max_mb = 32\n\n[assistant]\ndaily_cap = 7\n";
    let cfg = parse_hub(old).unwrap();
    let kept = ["probe.interval_s", "probe.connection_tuples", "probe.buffer_max_mb", "assistant.daily_cap"];
    assert_eq!(kept.map(|k| value(&cfg, k)), [20, 800, 32, 7]);
    let written = HubConfig::default().to_toml();
    for &(_, key, ..) in HUB_TOML {
        let section = key.split_once('.').unwrap().0;
        assert!(!written.contains(&format!("[{section}]")), "a hub with the defaults writes none of them: {written}");
    }

    // Service check interval: per check in config/checks.toml, 60 s by default, 15 s to 1 h
    let check = |interval: Option<i64>| {
        let line = interval.map(|s| format!("interval_s = {s}\n")).unwrap_or_default();
        crate::checks::config::parse(&format!(
            "[[check]]\nname = \"web\"\nkind = \"tcp\"\ntarget = \"nas:443\"\n{line}"
        ))
    };
    assert_eq!(check(None).unwrap().check[0].interval_s, 60, "a check's interval defaults to 60 s");
    for ok in [15, 3600] {
        assert_eq!(check(Some(ok)).unwrap().check[0].interval_s, ok as u32);
    }
    for bad in [14, 3601] {
        assert!(check(Some(bad)).is_err(), "a check every {bad} s is refused");
    }

    // Security / full patch window: per policy, daily 04:00 and Sunday 03:00 for 180 minutes; any window that parses
    use crate::scheduler::rrule::Recurrence;
    assert_eq!(
        (crate::scheduler::patching::SECURITY, crate::scheduler::patching::FULL),
        ("daily 04:00", "weekly sun 03:00")
    );
    let dir = std::env::temp_dir().join(format!("rackhand-settings-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let policy = Row::from([("id", Value::Text("p".into())), ("name", Value::Text("p".into()))]);
    db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("policies", policy)])).await.unwrap();
    let length: i64 =
        db.readers().with(|c| c.query_row("SELECT window_length_min FROM policies", [], |r| r.get(0))).unwrap();
    assert_eq!(length, 180, "a policy's windows are 180 minutes unless it says otherwise");
    for ok in ["daily 04:00 180m", "weekly sun 03:00 180m", "daily 00:00 1m", "weekly sat 23:59 10080m"] {
        assert!(ok.parse::<Recurrence>().is_ok(), "{ok} is a window");
    }
    for bad in ["daily 04:00 0m", "daily 04:00 10081m", "daily 24:00 60m", "whenever"] {
        assert!(bad.parse::<Recurrence>().is_err(), "{bad} isn't a window");
    }

    // Dashboard port / hub QUIC port: 8443/tcp and 7443/udp by default (the file's defaults use these), any port
    assert_eq!((config::DASHBOARD_PORT, config::QUIC_PORT), (8443, 7443));
    for ok in ["0.0.0.0:1", "[::]:65535", "192.0.2.10:8443"] {
        assert!(ok.parse::<std::net::SocketAddr>().is_ok(), "{ok}");
    }
    assert!("0.0.0.0:65536".parse::<std::net::SocketAddr>().is_err(), "past the last port");
    let _ = std::fs::remove_dir_all(&dir);
}
