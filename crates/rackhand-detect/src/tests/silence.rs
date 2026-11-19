use crate::rules::Severity;
use crate::silence::{Context, Subject, silence};

const S: i64 = 1000;
const MIN: i64 = 60 * S;
const HUB_START: i64 = 0;
const T0: i64 = 3_600 * S; // an hour after the hub started

fn ctx(now_ms: i64) -> Context {
    Context { now_ms, hub_started_ms: HUB_START, in_maintenance: false, reboot_job_waiting: false }
}

fn machine(interval_s: u32) -> Subject {
    Subject::Machine { interval_s, expected_offline: false }
}

/// The severity after `silent_ms` without a report.
fn after(subject: &Subject, silent_ms: i64) -> Option<Severity> {
    silence(subject, T0, &ctx(T0 + silent_ms))
}

#[test]
fn machine_warning_at_max_60s_or_4_intervals() {
    assert_eq!(after(&machine(15), 59 * S), None);
    assert_eq!(after(&machine(15), 60 * S), Some(Severity::Warning));
    assert_eq!(after(&machine(5), 60 * S), Some(Severity::Warning), "60 s even when 4 intervals are 20 s");
    assert_eq!(after(&machine(300), 20 * MIN - 1), None);
    assert_eq!(after(&machine(300), 20 * MIN), Some(Severity::Warning), "4 intervals of 300 s");
}

#[test]
fn machine_critical_at_max_5min_or_20_intervals() {
    assert_eq!(after(&machine(15), 5 * MIN - 1), Some(Severity::Warning));
    assert_eq!(after(&machine(15), 5 * MIN), Some(Severity::Critical));
    assert_eq!(after(&machine(30), 10 * MIN - 1), Some(Severity::Warning), "20 intervals of 30 s");
    assert_eq!(after(&machine(30), 10 * MIN), Some(Severity::Critical));
    assert_eq!(after(&machine(300), 100 * MIN), Some(Severity::Critical));
}

#[test]
fn expected_offline_gives_info_only() {
    let s = Subject::Machine { interval_s: 15, expected_offline: true };
    assert_eq!(after(&s, 59 * S), None);
    assert_eq!(after(&s, 60 * S), Some(Severity::Info));
    assert_eq!(after(&s, 24 * 60 * MIN), Some(Severity::Info), "never more than info");
}

#[test]
fn agentless_2_and_5_polls() {
    let polls = |failed_polls| silence(&Subject::Agentless { failed_polls }, T0, &ctx(T0 + 10 * MIN));
    assert_eq!(polls(1), None);
    assert_eq!(polls(2), Some(Severity::Warning));
    assert_eq!(polls(4), Some(Severity::Warning));
    assert_eq!(polls(5), Some(Severity::Critical));
}

#[test]
fn peer_2_and_10_minutes_and_interval_scaling() {
    let peer = |summary_interval_s| Subject::Peer { summary_interval_s };
    assert_eq!(after(&peer(30), 2 * MIN - 1), None);
    assert_eq!(after(&peer(30), 2 * MIN), Some(Severity::Warning));
    assert_eq!(after(&peer(30), 10 * MIN - 1), Some(Severity::Warning));
    assert_eq!(after(&peer(30), 10 * MIN), Some(Severity::Critical));
    assert_eq!(after(&peer(120), 6 * MIN - 1), None, "3 intervals of 120 s");
    assert_eq!(after(&peer(120), 6 * MIN), Some(Severity::Warning));
    // At 300 s the warning is at 15 minutes, so down can't come before it.
    assert_eq!(after(&peer(300), 15 * MIN - 1), None);
    assert_eq!(after(&peer(300), 15 * MIN), Some(Severity::Critical));
}

#[test]
fn operator_warning_only_after_10_minutes() {
    assert_eq!(after(&Subject::Operator, 10 * MIN - 1), None);
    assert_eq!(after(&Subject::Operator, 10 * MIN), Some(Severity::Warning));
    assert_eq!(after(&Subject::Operator, 7 * 24 * 60 * MIN), Some(Severity::Warning), "never critical");
}

#[test]
fn suppressed_in_maintenance_reboot_job_and_first_3_minutes() {
    let now = T0 + 30 * MIN;
    let maintenance = Context { in_maintenance: true, ..ctx(now) };
    assert_eq!(silence(&machine(15), T0, &maintenance), None, "maintenance window");
    let reboot = Context { reboot_job_waiting: true, ..ctx(now) };
    assert_eq!(silence(&machine(15), T0, &reboot), None, "reboot job");
    // A machine last seen before the hub went down: nothing for 3 minutes after the hub starts.
    let started = 10 * 3_600 * S;
    let fresh = |now_ms| Context { hub_started_ms: started, ..ctx(now_ms) };
    assert_eq!(silence(&machine(15), T0, &fresh(started + 3 * MIN - 1)), None, "first 3 minutes");
    assert_eq!(silence(&machine(15), T0, &fresh(started + 3 * MIN)), Some(Severity::Critical));
    assert_eq!(silence(&Subject::Peer { summary_interval_s: 30 }, T0, &fresh(started + MIN)), None, "peers too");
}

#[test]
fn first_report_clears() {
    let now = T0 + 30 * MIN;
    assert_eq!(silence(&machine(15), T0, &ctx(now)), Some(Severity::Critical));
    assert_eq!(silence(&machine(15), now, &ctx(now)), None, "a report at now");
    assert_eq!(silence(&Subject::Agentless { failed_polls: 0 }, now, &ctx(now)), None, "a good poll resets the count");
}
