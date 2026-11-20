//! `rackhand hub detect replay` (12): reruns the threshold rules over stored tier 0 data and says what would have
//! fired, writing nothing.

use rackhand_detect::samples::Sample;
use rackhand_detect::threshold::{RuleState, evaluate};
use rackhand_store::Db;
use rackhand_store::series::chunk::{SeriesKey, Tier};

use super::lifecycle::severity_str;

/// One line per change a rule would have made, in time order: `<time> <rule> <labels> <what>`.
pub fn replay(db: &Db, machine: &str, from_ms: i64, to_ms: i64, interval_s: u32) -> Result<Vec<String>, String> {
    let mut lines: Vec<(i64, String)> = Vec::new();
    for rule in rackhand_detect::rules::default_rules() {
        let series: Vec<(i64, String)> = db
            .readers()
            .with(|c| {
                let mut s = c.prepare(
                    "SELECT DISTINCT mk.id, mk.label_set FROM metric_keys mk JOIN series_chunks sc ON sc.metric_key_id = mk.id
                     WHERE mk.name = ?1 AND sc.machine_id = ?2 AND sc.tier = 0",
                )?;
                s.query_map(rusqlite::params![rule.metric, machine], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
            })
            .map_err(|e| e.to_string())?;
        for (metric_key_id, labels) in series {
            let key = SeriesKey { machine_id: machine.to_string(), metric_key_id };
            let points = db
                .readers()
                .with(|c| {
                    rackhand_store::series::query::range(c, &key, Tier::Raw, from_ms, to_ms)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
                })
                .map_err(|e| e.to_string())?;
            let samples: Vec<Sample> = points.iter().map(|(t, v)| Sample { at_ms: *t, value: v[0] }).collect();
            let mut state = RuleState::default();
            for (i, s) in samples.iter().enumerate() {
                let next = evaluate(&rule, &samples[..=i], interval_s, s.at_ms, &state);
                let what = match (state.active, next.active) {
                    (None, Some(sev)) => Some(format!("would open {}", severity_str(sev))),
                    (Some(a), Some(b)) if a != b => Some(format!("would change to {}", severity_str(b))),
                    (Some(_), None) => Some("would resolve".to_string()),
                    _ => None,
                };
                if let Some(what) = what {
                    let at = jiff::Timestamp::from_millisecond(s.at_ms).map(|t| t.to_string()).unwrap_or_default();
                    lines.push((s.at_ms, format!("{at} {} {labels} {what}", rule.id)));
                }
                state = next;
            }
        }
    }
    lines.sort();
    Ok(lines.into_iter().map(|(_, l)| l).collect())
}
