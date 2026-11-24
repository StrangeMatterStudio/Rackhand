use std::collections::BTreeMap;

use rackhand_release::binary::Version;
use rackhand_release::manifest::Channel;

use super::probe_rollout::*;

const MIN: i64 = 60_000;
const HOUR: i64 = 60 * MIN;

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn release(version: &str, channel: Channel) -> Release {
    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "rackhand-probe-x86_64-unknown-linux-musl".to_string(),
        ReleaseFile { sha256: [7; 32], signature: b"minisig".to_vec() },
    );
    Release { version: v(version), channel, artifacts }
}

fn probe(machine: &str, site: &str, version: &str) -> Probe {
    Probe { machine: machine.into(), site: site.into(), version: v(version), arch: "x86_64".into(), connected: true }
}

fn url(file: &str) -> String {
    format!("https://hub.test:8443/release/{file}")
}

/// What a tick offered, as `machine` names.
fn offered(plan: &Plan) -> Vec<&str> {
    let mut m: Vec<&str> = plan.offers.iter().map(|o| o.machine.as_str()).collect();
    m.sort();
    m
}

fn no_incidents(_: &str, _: i64) -> bool {
    false
}

/// Site X has x1 to x3, site Y has y1; all run 0.1.0 and a release 0.1.1 is out.
fn fleet(version_of: &dyn Fn(&str) -> &'static str) -> Vec<Probe> {
    [("x1", "X"), ("x2", "X"), ("x3", "X"), ("y1", "Y")].iter().map(|(m, s)| probe(m, s, version_of(m))).collect()
}

#[test]
fn canary_first_then_rest_after_1h_without_incidents() {
    let rel = release("0.1.1", Channel::Stable);
    let mut rollout = Rollout::new(Channel::Stable);
    let t0 = 1_000 * HOUR;
    // the first tick: one canary per site, the lowest machine id, and nobody else
    let plan = rollout.tick(t0, &rel, &fleet(&|_| "0.1.0"), &no_incidents, &url);
    assert_eq!(offered(&plan), ["x1", "y1"], "one canary per site");
    let one = &plan.offers[0].update;
    assert_eq!(one.version.as_ref().map(|v| v.version.as_str()), Some("0.1.1"));
    assert_eq!(one.url, "https://hub.test:8443/release/rackhand-probe-x86_64-unknown-linux-musl");
    assert_eq!((one.sha256.clone(), one.signature.clone()), (vec![7; 32], b"minisig".to_vec()));
    assert!(plan.events.is_empty());

    // the canaries update; the rest wait for the hour
    let canaries_updated = |m: &str| if m == "x1" || m == "y1" { "0.1.1" } else { "0.1.0" };
    let plan = rollout.tick(t0 + 5 * MIN, &rel, &fleet(&canaries_updated), &no_incidents, &url);
    assert_eq!(offered(&plan), Vec::<&str>::new(), "five minutes in");
    let plan = rollout.tick(t0 + 59 * MIN, &rel, &fleet(&canaries_updated), &no_incidents, &url);
    assert_eq!(offered(&plan), Vec::<&str>::new(), "59 minutes in");

    // an hour after the canary was offered the release, with no incident on it, the rest are offered it
    let plan = rollout.tick(t0 + 61 * MIN, &rel, &fleet(&canaries_updated), &no_incidents, &url);
    assert_eq!(offered(&plan), ["x2", "x3"]);
    // not again at once, and again when ten minutes have passed and they still haven't updated
    let plan = rollout.tick(t0 + 62 * MIN, &rel, &fleet(&canaries_updated), &no_incidents, &url);
    assert_eq!(offered(&plan), Vec::<&str>::new());
    let plan = rollout.tick(t0 + 72 * MIN, &rel, &fleet(&canaries_updated), &no_incidents, &url);
    assert_eq!(offered(&plan), ["x2", "x3"]);
    // and a machine that connects later is offered it too, while one that has updated isn't
    let mut late = fleet(&|m| if m == "x2" { "0.1.1" } else { canaries_updated(m) });
    late.push(probe("x4", "X", "0.1.0"));
    let plan = rollout.tick(t0 + 90 * MIN, &rel, &late, &no_incidents, &url);
    assert_eq!(offered(&plan), ["x3", "x4"]);
}

#[test]
fn a_canary_incident_holds_the_rest() {
    let rel = release("0.1.1", Channel::Stable);
    let mut rollout = Rollout::new(Channel::Stable);
    let t0 = 1_000 * HOUR;
    rollout.tick(t0, &rel, &fleet(&|_| "0.1.0"), &no_incidents, &url);
    let canaries_updated = |m: &str| if m == "x1" || m == "y1" { "0.1.1" } else { "0.1.0" };
    // x1 has an incident that opened after it was offered the release; y1 doesn't
    let asked = std::cell::RefCell::new(Vec::new());
    let incident = |machine: &str, since: i64| {
        asked.borrow_mut().push((machine.to_string(), since));
        machine == "x1"
    };
    let plan = rollout.tick(t0 + 61 * MIN, &rel, &fleet(&canaries_updated), &incident, &url);
    assert_eq!(offered(&plan), Vec::<&str>::new(), "x2 and x3 are held; y1's site has nobody else");
    assert!(asked.borrow().contains(&("x1".to_string(), t0)), "asked about incidents since the canary was offered it");
    assert_eq!(plan.events.len(), 1);
    assert_eq!(
        (plan.events[0].kind, plan.events[0].machine.as_str(), plan.events[0].site.as_str()),
        ("rollout.held", "x1", "X")
    );
    // still held a day later, though the incident is over: nothing is offered by itself
    let plan = rollout.tick(t0 + 24 * HOUR, &rel, &fleet(&canaries_updated), &no_incidents, &url);
    assert_eq!(offered(&plan), Vec::<&str>::new());
    assert!(plan.events.is_empty(), "said once");
    // a newer release starts again with a canary
    let newer = release("0.1.2", Channel::Stable);
    let plan = rollout.tick(t0 + 25 * HOUR, &newer, &fleet(&canaries_updated), &no_incidents, &url);
    assert_eq!(offered(&plan), ["x1", "y1"]);
}

#[test]
fn a_canary_that_does_not_come_up_on_the_new_version_holds_the_rest() {
    let rel = release("0.1.1", Channel::Stable);
    let mut rollout = Rollout::new(Channel::Stable);
    let t0 = 1_000 * HOUR;
    rollout.tick(t0, &rel, &fleet(&|_| "0.1.0"), &no_incidents, &url);
    // nine minutes in, x1 is connected on 0.1.0: the guard may still be at work
    let plan = rollout.tick(t0 + 9 * MIN, &rel, &fleet(&|_| "0.1.0"), &no_incidents, &url);
    assert!(plan.events.is_empty());
    // after ten it is back on its old version: the release was rolled back there
    let plan = rollout.tick(t0 + 11 * MIN, &rel, &fleet(&|_| "0.1.0"), &no_incidents, &url);
    let failed: Vec<_> = plan.events.iter().map(|e| (e.kind, e.machine.as_str())).collect();
    assert_eq!(failed, [("rollout.canary_failed", "x1"), ("rollout.canary_failed", "y1")]);
    let plan = rollout.tick(t0 + 3 * HOUR, &rel, &fleet(&|_| "0.1.0"), &no_incidents, &url);
    assert_eq!(offered(&plan), Vec::<&str>::new(), "x2 and x3 never get it, and x1 isn't offered it again");
}

#[test]
fn beta_channel_offered_beta_stable_not() {
    let beta = release("0.2.0", Channel::Beta);
    let probes = vec![probe("x1", "X", "0.1.0")];
    let on_stable = Rollout::new(Channel::Stable).tick(1_000 * HOUR, &beta, &probes, &no_incidents, &url);
    assert_eq!(offered(&on_stable), Vec::<&str>::new(), "a hub on stable never offers a beta release");
    let on_beta = Rollout::new(Channel::Beta).tick(1_000 * HOUR, &beta, &probes, &no_incidents, &url);
    assert_eq!(offered(&on_beta), ["x1"]);
    let stable = release("0.2.0", Channel::Stable);
    assert_eq!(
        offered(&Rollout::new(Channel::Stable).tick(1_000 * HOUR, &stable, &probes, &no_incidents, &url)),
        ["x1"]
    );
    assert_eq!(offered(&Rollout::new(Channel::Beta).tick(1_000 * HOUR, &stable, &probes, &no_incidents, &url)), ["x1"]);
}

#[test]
fn only_machines_the_release_has_a_file_for_and_that_are_behind_are_offered_it() {
    let rel = release("0.1.1", Channel::Stable);
    let mut rollout = Rollout::new(Channel::Stable);
    let mut probes = vec![
        probe("a-arm", "X", "0.1.0"),
        probe("b-current", "X", "0.1.1"),
        probe("c-newer", "X", "0.2.0"),
        probe("d-offline", "X", "0.1.0"),
        probe("e-ok", "X", "0.1.0"),
    ];
    probes[0].arch = "aarch64".into();
    probes[3].connected = false;
    let plan = rollout.tick(1_000 * HOUR, &rel, &probes, &no_incidents, &url);
    assert_eq!(
        offered(&plan),
        ["e-ok"],
        "no file for aarch64, none for a machine up to date, one that is ahead, or away"
    );
}

#[test]
fn a_restarted_hub_goes_on_where_it_was() {
    let rel = release("0.1.1", Channel::Stable);
    let t0 = 1_000 * HOUR;
    let mut before = Rollout::new(Channel::Stable);
    let first = before.tick(t0, &rel, &fleet(&|_| "0.1.0"), &no_incidents, &url);
    let rows: Vec<_> = first.saved.clone();
    assert_eq!(rows.len(), 2, "a row for each site's canary");
    let canaries_updated = |m: &str| if m == "x1" || m == "y1" { "0.1.1" } else { "0.1.0" };

    // restarted 61 minutes in: the canary is the same and the hour counts from when it was offered the release
    let mut after = Rollout::new(Channel::Stable);
    after.restore(&rows);
    let plan = after.tick(t0 + 61 * MIN, &rel, &fleet(&canaries_updated), &no_incidents, &url);
    assert_eq!(offered(&plan), ["x2", "x3"]);
    assert!(plan.offers.iter().all(|o| o.machine != "x1"));

    // and restarted before the hour is up: nothing yet
    let mut after = Rollout::new(Channel::Stable);
    after.restore(&rows);
    assert_eq!(
        offered(&after.tick(t0 + 30 * MIN, &rel, &fleet(&canaries_updated), &no_incidents, &url)),
        Vec::<&str>::new()
    );

    // a hold is kept across a restart
    let mut held = Rollout::new(Channel::Stable);
    held.restore(&rows);
    let plan = held.tick(t0 + 61 * MIN, &rel, &fleet(&canaries_updated), &|m: &str, _| m == "x1", &url);
    assert_eq!(plan.events.len(), 1);
    let mut again = Rollout::new(Channel::Stable);
    again.restore(&plan.saved);
    again.restore(&rows);
    let plan = again.tick(t0 + 2 * HOUR, &rel, &fleet(&canaries_updated), &no_incidents, &url);
    assert_eq!(offered(&plan), Vec::<&str>::new(), "still held");

    // a rest that was started stays started
    let mut started = Rollout::new(Channel::Stable);
    started.restore(&rows);
    let plan = started.tick(t0 + 61 * MIN, &rel, &fleet(&canaries_updated), &no_incidents, &url);
    let mut after = Rollout::new(Channel::Stable);
    after.restore(&rows);
    after.restore(&plan.saved);
    let plan = after.tick(t0 + 62 * MIN, &rel, &fleet(&canaries_updated), &|_: &str, _| true, &url);
    assert_eq!(offered(&plan), ["x2", "x3"], "a later incident on the canary doesn't take back what the hour allowed");
}

#[test]
fn a_canary_that_stays_away_is_replaced_after_six_hours() {
    let rel = release("0.1.1", Channel::Stable);
    let mut rollout = Rollout::new(Channel::Stable);
    let t0 = 1_000 * HOUR;
    rollout.tick(t0, &rel, &fleet(&|_| "0.1.0"), &no_incidents, &url);
    let mut away = fleet(&|_| "0.1.0");
    away[0].connected = false;
    assert_eq!(offered(&rollout.tick(t0 + 5 * HOUR, &rel, &away, &no_incidents, &url)), Vec::<&str>::new());
    let plan = rollout.tick(t0 + 7 * HOUR, &rel, &away, &no_incidents, &url);
    assert_eq!(
        offered(&plan),
        ["x2"],
        "x2 is the site's canary now; y1 came up connected on the old version and is held"
    );
}
