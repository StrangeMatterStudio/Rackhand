use super::*;

const MIN: i64 = 60_000;
const START: i64 = 1_795_068_000_000;
const END: i64 = START + 180 * MIN;

fn machine(id: &str, site: &str) -> Candidate {
    Candidate {
        id: id.into(),
        site: site.into(),
        kind: "linux".into(),
        roles: Vec::new(),
        managed: true,
        patch: PatchMode::Auto,
        pending_security: 2,
        pending_total: 5,
        in_maintenance: false,
        quarantined: false,
        approved: false,
    }
}

fn with(id: &str, site: &str, f: impl FnOnce(&mut Candidate)) -> Candidate {
    let mut c = machine(id, site);
    f(&mut c);
    c
}

fn starts(orders: &[Order]) -> Vec<String> {
    let mut ids: Vec<String> =
        orders.iter().filter_map(|o| if let Order::Start(id) = o { Some(id.clone()) } else { None }).collect();
    ids.sort();
    ids
}

/// Managed `auto` machines with pending updates for the window, outside maintenance and quarantine (FR-13, AC58).
#[test]
fn auto_pending_not_maintenance_not_quarantined_managed_only() {
    let cases: Vec<(Candidate, Option<How>, &str)> = vec![
        (machine("a", "s"), Some(How::Run), "auto with security updates"),
        (with("b", "s", |c| c.managed = false), None, "monitor: no account to patch with"),
        (with("c", "s", |c| c.in_maintenance = true), None, "in a maintenance window"),
        (with("d", "s", |c| c.quarantined = true), None, "quarantined"),
        (with("e", "s", |c| c.pending_security = 0), None, "nothing for the security window"),
        (with("f", "s", |c| c.patch = PatchMode::ApproveOnly), Some(How::Approval), "approve-only asks"),
        (
            with("g", "s", |c| {
                c.patch = PatchMode::ApproveOnly;
                c.approved = true
            }),
            Some(How::Run),
            "an approval it carries",
        ),
    ];
    for (c, want, why) in cases {
        assert_eq!(eligible(&c, Window::Security), want, "{why}");
    }
    assert_eq!(
        eligible(&with("e", "s", |c| c.pending_security = 0), Window::Full),
        Some(How::Run),
        "full has 5 pending"
    );
    assert_eq!(
        eligible(
            &with("h", "s", |c| {
                c.pending_security = 0;
                c.pending_total = 0
            }),
            Window::Full
        ),
        None
    );
}

/// At most 3 per site at once; hypervisors and the hub after every other machine at their site, one at a time, the hub
/// last (7.5.3 step 2).
#[test]
fn max_3_per_site_hypervisors_and_hub_last_one_at_a_time() {
    let mut cands: Vec<Candidate> = (1..=5).map(|n| machine(&format!("a{n}"), "a")).collect();
    cands.push(with("pve", "a", |c| c.roles = vec!["hypervisor".into()]));
    cands.push(with("hub", "a", |c| c.roles = vec!["hub".into()]));
    cands.push(machine("b1", "b"));
    let mut run = Run::new(Window::Security, START, END, cands, 3);
    let online = |_: &str| true;
    let first = starts(&run.step(START, online));
    assert_eq!(first.len(), 4, "3 at site a, 1 at site b: {first:?}");
    assert!(
        first.contains(&"b1".to_string()) && !first.contains(&"pve".to_string()) && !first.contains(&"hub".to_string())
    );
    assert!(starts(&run.step(START + MIN, online)).is_empty(), "the site is full");
    run.finished(&first[0]);
    let next = starts(&run.step(START + 2 * MIN, online));
    assert_eq!(next.len(), 1, "one more at site a: {next:?}");
    assert_eq!(next, ["a4"]);
    for id in ["a2", "a3", "a4"] {
        run.finished(id);
    }
    assert_eq!(starts(&run.step(START + 3 * MIN, online)), ["a5"], "the last ordinary machine before the hypervisor");
    run.finished("a5");
    run.finished("b1");
    assert_eq!(starts(&run.step(START + 4 * MIN, online)), ["pve"], "the hypervisor once the others are done");
    assert!(starts(&run.step(START + 5 * MIN, online)).is_empty(), "one at a time");
    run.finished("pve");
    assert_eq!(starts(&run.step(START + 6 * MIN, online)), ["hub"], "the hub last");
}

/// The limit and the order are the site's, across the windows of its policies: what other runs have running counts, and
/// a hypervisor or the hub waits while another run still has machines to patch there.
#[test]
fn other_runs_at_the_site_count() {
    let mut run = Run::new(Window::Security, START, END, vec![machine("a", "s"), machine("b", "s")], 3);
    let two = Others { running: [("s".to_string(), 2)].into(), waiting: Default::default() };
    assert_eq!(starts(&run.step_with(START, |_| true, &two)).len(), 1, "2 of 3 places are taken");
    let hub = with("hub", "s", |c| c.roles = vec!["hub".into()]);
    let mut last = Run::new(Window::Security, START, END, vec![hub], 3);
    let waiting = Others { running: Default::default(), waiting: ["s".to_string()].into() };
    assert!(starts(&last.step_with(START, |_| true, &waiting)).is_empty(), "another run has machines left at the site");
    assert!(starts(&last.step_with(START, |_| true, &two)).is_empty(), "another run's jobs are running at the site");
    assert_eq!(starts(&last.step_with(START, |_| true, &Others::default())), ["hub"]);
}

/// `hold` machines are never patched (E10, AC20).
#[test]
fn hold_never_patched() {
    let held = with("h", "s", |c| c.patch = PatchMode::Hold);
    assert_eq!(eligible(&held, Window::Full), None);
    let mut run = Run::new(Window::Full, START, END, vec![held], 3);
    assert!(run.step(START, |_| true).is_empty());
}

/// Approve-only (7.5.3 step 3): an approval at window start that expires at its end; approved in the window, the job
/// starts; decided after the end, it waits for the next window.
#[test]
fn approve_only_approval_expires_at_window_end_late_approval_waits() {
    let ask = with("x", "s", |c| c.patch = PatchMode::ApproveOnly);
    let mut run = Run::new(Window::Security, START, END, vec![ask.clone()], 3);
    assert_eq!(run.step(START, |_| true), [Order::AskApproval { id: "x".into(), expires_at_ms: END }]);
    assert!(run.step(START + MIN, |_| true).is_empty(), "asked once, nothing runs until it's approved");
    assert!(run.approved("x", START + 10 * MIN));
    assert_eq!(starts(&run.step(START + 10 * MIN, |_| true)), ["x"]);
    // not decided in its window: a decision after the end doesn't start anything now
    let mut run = Run::new(Window::Security, START, END, vec![ask.clone()], 3);
    run.step(START, |_| true);
    assert!(!run.approved("x", END + MIN), "after the window");
    assert!(run.step(END + MIN, |_| true).is_empty());
    // the next window: a machine carrying that approval runs without asking again
    let carried = Candidate { approved: true, ..ask };
    let mut next = Run::new(Window::Security, START + 24 * 60 * MIN, END + 24 * 60 * MIN, vec![carried], 3);
    assert_eq!(starts(&next.step(START + 24 * 60 * MIN, |_| true)), ["x"]);
}

/// A machine offline at window start is tried every 15 minutes until the window ends (7.5.3 step 2).
#[test]
fn offline_machine_retried_every_15_min_until_window_end() {
    let mut run = Run::new(Window::Security, START, END, vec![machine("m", "s")], 3);
    let offline = |_: &str| false;
    assert!(run.step(START, offline).is_empty());
    assert!(run.step(START + 14 * MIN, |_| true).is_empty(), "not tried before 15 minutes");
    assert!(run.step(START + 15 * MIN, offline).is_empty());
    assert_eq!(starts(&run.step(START + 30 * MIN, |_| true)), ["m"], "online at the next try");
    // never online: nothing after the window ends
    let mut run = Run::new(Window::Security, START, END, vec![machine("n", "s")], 3);
    let mut at = START;
    while at < END {
        assert!(run.step(at, offline).is_empty());
        at += 15 * MIN;
    }
    assert!(run.step(END + MIN, |_| true).is_empty(), "the window is over: the next one tries again");
}

/// Alpine has no security marker, so it patches only in the full window (D54).
#[test]
fn alpine_only_in_full_window() {
    let alpine = with("al", "s", |c| c.kind = "alpine".into());
    assert_eq!(eligible(&alpine, Window::Security), None);
    assert_eq!(eligible(&alpine, Window::Full), Some(How::Run));
}
