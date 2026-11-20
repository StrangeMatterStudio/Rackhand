use crate::rules::{Op, Rule, Severity, default_rules};
use crate::samples::Sample;
use crate::threshold::{RuleState, evaluate};

const MIN: i64 = 60_000;

fn disk() -> Rule {
    default_rules().into_iter().find(|r| r.metric == "disk.used_pct").unwrap()
}

/// Feeds samples one by one at `interval_s`, evaluating after each; returns the states after each sample.
fn run(rule: &Rule, values: &[f64], interval_s: u32) -> Vec<(i64, RuleState)> {
    let mut samples = Vec::new();
    let mut state = RuleState::default();
    let mut out = Vec::new();
    for (i, v) in values.iter().enumerate() {
        let at = i as i64 * interval_s as i64 * 1000;
        samples.push(Sample { at_ms: at, value: *v });
        state = evaluate(rule, &samples, interval_s, at, &state);
        out.push((at, state.clone()));
    }
    out
}

fn first_time(states: &[(i64, RuleState)], sev: Severity) -> Option<i64> {
    states.iter().find(|(_, s)| s.active == Some(sev)).map(|(t, _)| *t)
}

#[test]
fn worked_example_opens_warning_at_5_and_critical_at_27_and_resolves() {
    // 15 s samples, each covering the interval that ends at its time: normal before minute 0, 86-87% for minutes 0
    // to 22, then 95.2% and above, then cleanup to 70%.
    let mut values = vec![80.0]; // at minute 0, covering the time before it
    for i in 1..=88 {
        values.push(if i < 20 { 86.0 } else { 87.0 }); // minute 0 to 22
    }
    values.extend([95.2; 42]); // minute 22.25 to 32.5
    values.extend([70.0, 70.0]);
    let states = run(&disk(), &values, 15);
    assert_eq!(first_time(&states, Severity::Warning), Some(5 * MIN), "warning at minute 5");
    let crit = first_time(&states, Severity::Critical).unwrap();
    assert!((27 * MIN..=27 * MIN + 15_000).contains(&crit), "critical at minute 27, got {crit}");
    assert_eq!(states.last().unwrap().1.active, None, "resolved after two samples under 83%");
    assert_eq!(states[states.len() - 2].1.active, Some(Severity::Critical), "one sample isn't enough");
}

#[test]
fn needs_80_percent_of_expected_samples() {
    let rule = disk(); // 5 minutes at 15 s = 20 expected samples
    let at = |i: i64| i * 15_000;
    let make = |present: usize| -> Vec<Sample> {
        // the last `present` slots of the 20 are filled
        (0..20).filter(|i| *i >= 20 - present as i64).map(|i| Sample { at_ms: at(i + 1), value: 90.0 }).collect()
    };
    let now = at(20);
    assert_eq!(evaluate(&rule, &make(15), 15, now, &RuleState::default()).active, None, "75% present");
    assert_eq!(evaluate(&rule, &make(16), 15, now, &RuleState::default()).active, Some(Severity::Warning), "80%");
}

#[test]
fn duration_below_4_intervals_raised_to_4() {
    let rule = disk(); // 5 minutes; at 300 s that's 1 interval, raised to 4
    let three = run(&rule, &[90.0, 90.0, 90.0], 300);
    assert!(three.iter().all(|(_, s)| s.active.is_none()), "3 samples never fire");
    let four = run(&rule, &[90.0, 90.0, 90.0, 90.0], 300);
    assert_eq!(four.last().unwrap().1.active, Some(Severity::Warning), "the 4th matching sample fires");
}

#[test]
fn clear_needs_2_samples_past_margin() {
    let mut values = vec![90.0; 21];
    values.push(82.0);
    let states = run(&disk(), &values, 15);
    assert_eq!(states.last().unwrap().1.active, Some(Severity::Warning), "one sample under 83% doesn't clear");
    values.push(82.9);
    let states = run(&disk(), &values, 15);
    assert_eq!(states.last().unwrap().1.active, None, "two do");
    let mut near = vec![90.0; 21];
    near.extend([83.5, 83.5]);
    assert!(run(&disk(), &near, 15).last().unwrap().1.active.is_some(), "under 85 but not under 83 stays open");
}

#[test]
fn flapping_between_84_and_86_stays_one_incident() {
    let mut values = vec![86.0; 21];
    for i in 0..200 {
        values.push(if i % 2 == 0 { 84.0 } else { 86.0 });
    }
    let states = run(&disk(), &values, 15);
    let opened = states.iter().position(|(_, s)| s.active.is_some()).unwrap();
    assert!(states[opened..].iter().all(|(_, s)| s.active == Some(Severity::Warning)), "never clears or reopens");
}

#[test]
fn no_new_sample_changes_nothing() {
    let rule = disk();
    let samples: Vec<Sample> = (0..21).map(|i| Sample { at_ms: i * 15_000, value: 90.0 }).collect();
    let s1 = evaluate(&rule, &samples, 15, 20 * 15_000, &RuleState::default());
    let s2 = evaluate(&rule, &samples, 15, 20 * 15_000 + 14_000, &s1);
    assert_eq!(s1, s2);
    let cleared = RuleState { active: None, last_sample_ms: Some(20 * 15_000) };
    assert_eq!(evaluate(&rule, &samples, 15, 21 * 15_000, &cleared), cleared, "the same samples don't reopen");
}

#[test]
fn same_rule_same_result_at_5_15_and_300_seconds() {
    for rule in default_rules() {
        for level in [Severity::Warning, Severity::Critical] {
            let Some(t) = rule.level(level) else { continue };
            let (bad, good) = match t.op {
                Op::Over => (t.value + 1.0, 0.0),
                Op::Under => (t.value - 1.0, t.value + 50.0),
            };
            for interval in [5u32, 15, 300] {
                // A full window of normal values first, then the breach.
                let n = (t.duration_s.max(4 * interval) / interval) as usize;
                let mut values = vec![good; n + 1];
                values.extend(vec![bad; n]);
                let states = run(&rule, &values, interval);
                let got = states.last().unwrap().1.active;
                assert!(got >= Some(level), "{} {level:?} at {interval}s: {got:?}", rule.metric);
                let short = &states[..states.len() - 1];
                assert!(
                    short.iter().all(|(_, s)| s.active < Some(level)),
                    "{} {level:?} too early at {interval}s",
                    rule.metric
                );
            }
        }
    }
}

#[test]
fn every_default_rule_in_table_present() {
    type Level = Option<(Op, f64, u32)>;
    let table: Vec<(&str, Level, Level)> = vec![
        ("cpu.busy_pct", Some((Op::Over, 90.0, 900)), Some((Op::Over, 98.0, 1800))),
        ("mem.available_pct", Some((Op::Under, 10.0, 600)), Some((Op::Under, 5.0, 300))),
        ("swap.used_pct", Some((Op::Over, 50.0, 1800)), Some((Op::Over, 90.0, 600))),
        ("disk.used_pct", Some((Op::Over, 85.0, 300)), Some((Op::Over, 95.0, 300))),
        ("disk.inodes_used_pct", Some((Op::Over, 85.0, 300)), Some((Op::Over, 95.0, 300))),
        ("load.15m_per_core", Some((Op::Over, 2.0, 1800)), Some((Op::Over, 4.0, 1800))),
        ("cpu.steal_pct", Some((Op::Over, 20.0, 900)), None),
        ("temp.c", Some((Op::Over, 80.0, 300)), Some((Op::Over, 90.0, 300))),
    ];
    let rules = default_rules();
    assert_eq!(rules.len(), table.len());
    for (metric, warn, crit) in table {
        let r = rules.iter().find(|r| r.metric == metric).unwrap_or_else(|| panic!("{metric} missing"));
        let as_tuple = |t: Option<&crate::rules::Threshold>| t.map(|t| (t.op, t.value, t.duration_s));
        assert_eq!(as_tuple(r.level(Severity::Warning)), warn, "{metric} warning");
        assert_eq!(as_tuple(r.level(Severity::Critical)), crit, "{metric} critical");
        let margin = if metric == "load.15m_per_core" { 0.2 } else { 2.0 };
        assert_eq!(r.margin, margin, "{metric} margin");
    }
}

#[test]
fn severity_falls_when_only_the_lower_level_matches() {
    // critical (over 95% for 5 minutes), then 90% for 10 minutes: still over the warning line, so it falls to warning
    // without clearing; then 70% clears it
    let mut values = vec![80.0];
    values.extend([96.0; 24]);
    values.extend([90.0; 40]);
    values.extend([70.0, 70.0]);
    let states = run(&disk(), &values, 15);
    let crit = first_time(&states, Severity::Critical).unwrap();
    let fall = states.iter().find(|(t, s)| *t > crit && s.active == Some(Severity::Warning)).map(|(t, _)| *t);
    assert_eq!(fall, Some(25 * 15_000), "warning from the first 90% sample");
    assert_eq!(states[states.len() - 3].1.active, Some(Severity::Warning));
    assert_eq!(states.last().unwrap().1.active, None);
}
