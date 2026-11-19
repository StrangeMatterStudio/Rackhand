use std::sync::Arc;

use jiff::Timestamp;
use jiff::tz::TimeZone;
use rackhand_store::Db;

use super::rrule::Recurrence;
use super::tasks::{Schedule, Scheduler, Task, load_state, state_cmd};
use super::windows::{Target, Window, maintenance_active};

fn ms(s: &str) -> i64 {
    s.parse::<Timestamp>().unwrap().as_millisecond()
}

fn tz(name: &str) -> TimeZone {
    TimeZone::get(name).unwrap()
}

#[test]
fn daily_window_in_site_timezone() {
    let r: Recurrence = "daily 04:00 180m".parse().unwrap();
    assert_eq!(r.next_start(&tz("America/New_York"), ms("2026-11-19T00:00:00Z")), ms("2026-11-19T09:00:00Z"));
    assert_eq!(r.next_start(&tz("Europe/Berlin"), ms("2026-11-19T00:00:00Z")), ms("2026-11-19T03:00:00Z"));
    assert_eq!(
        r.next_start(&tz("Europe/Berlin"), ms("2026-11-19T03:00:00Z")),
        ms("2026-11-20T03:00:00Z"),
        "strictly after"
    );
    let w: Recurrence = "weekly sun 03:00 180m".parse().unwrap();
    // 2026-11-22 is a Sunday; Tokyo is UTC+9 with no daylight saving.
    assert_eq!(w.next_start(&tz("Asia/Tokyo"), ms("2026-11-19T00:00:00Z")), ms("2026-11-21T18:00:00Z"));
    assert!("hourly 04:00 10m".parse::<Recurrence>().is_err());
    assert!("daily 24:00 10m".parse::<Recurrence>().is_err());
    assert!("weekly sun 03:00".parse::<Recurrence>().is_err(), "duration required");
}

#[test]
fn spring_forward_runs_at_next_valid_minute() {
    // New York moves from 02:00 EST to 03:00 EDT on 2027-03-14, so 02:30 doesn't exist.
    let r: Recurrence = "daily 02:30 60m".parse().unwrap();
    let ny = tz("America/New_York");
    let start = r.next_start(&ny, ms("2027-03-14T05:00:00Z"));
    assert_eq!(start, ms("2027-03-14T07:00:00Z"), "03:00 EDT");
    assert_eq!(r.next_start(&ny, start), ms("2027-03-15T06:30:00Z"), "02:30 EDT the next day");
}

#[test]
fn fall_back_repeated_time_runs_once() {
    // New York repeats 01:00 to 02:00 on 2026-11-01.
    let r: Recurrence = "daily 01:30 30m".parse().unwrap();
    let ny = tz("America/New_York");
    let first = r.next_start(&ny, ms("2026-11-01T04:00:00Z"));
    assert_eq!(first, ms("2026-11-01T05:30:00Z"), "the first 01:30 (EDT)");
    assert_eq!(r.next_start(&ny, first), ms("2026-11-02T06:30:00Z"), "not the second 01:30 (EST)");
}

#[test]
fn maintenance_window_active_for_machine_and_tag() {
    let windows = vec![
        Window {
            id: "w1".into(),
            target: Target::Machine("m1".into()),
            recurrence: "daily 02:00 60m".parse().unwrap(),
            tz: tz("UTC"),
        },
        Window {
            id: "w2".into(),
            target: Target::Tag("db".into()),
            recurrence: "weekly sun 03:00 120m".parse().unwrap(),
            tz: tz("Europe/Berlin"),
        },
        Window {
            id: "w3".into(),
            target: Target::Machine("m3".into()),
            recurrence: "daily 23:00 120m".parse().unwrap(),
            tz: tz("UTC"),
        },
    ];
    let none: &[&str] = &[];
    assert!(maintenance_active(&windows, "m1", none, ms("2026-11-19T02:30:00Z")));
    assert!(!maintenance_active(&windows, "m1", none, ms("2026-11-19T03:00:00Z")), "the end is exclusive");
    assert!(!maintenance_active(&windows, "m2", none, ms("2026-11-19T02:30:00Z")), "another machine");
    // Sunday 2026-11-22 03:30 in Berlin is 02:30 UTC.
    assert!(maintenance_active(&windows, "m2", &["web", "db"], ms("2026-11-22T02:30:00Z")));
    assert!(!maintenance_active(&windows, "m2", &["web"], ms("2026-11-22T02:30:00Z")), "without the tag");
    assert!(!maintenance_active(&windows, "m2", &["db"], ms("2026-11-21T02:30:00Z")), "Saturday");
    assert!(maintenance_active(&windows, "m3", none, ms("2026-11-20T00:30:00Z")), "a window across midnight");
}

fn db(name: &str) -> Arc<Db> {
    let dir = std::env::temp_dir().join(format!("rackhand-scheduler-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Arc::new(Db::open(&dir.join("hub.db")).unwrap())
}

fn tasks() -> Vec<Task> {
    vec![
        Task {
            kind: "patch_window".into(),
            key: "policy-1/security".into(),
            schedule: Schedule::Window { recurrence: "daily 04:00 180m".parse().unwrap(), tz: tz("Europe/Berlin") },
        },
        Task { kind: "retention".into(), key: "".into(), schedule: Schedule::Every { period_ms: 3_600_000 } },
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn state_survives_restart_without_double_firing() {
    let db = db("restart");
    let window_start = ms("2026-11-19T03:00:00Z"); // 04:00 in Berlin
    let mut s = Scheduler::new(tasks(), load_state(db.readers()).unwrap(), window_start - 60_000);
    let fired = s.due(window_start + 30_000);
    let keys: Vec<&str> = fired.iter().map(|f| f.kind.as_str()).collect();
    assert_eq!(keys, ["patch_window", "retention"]);
    assert_eq!(fired[0].at_ms, window_start, "fires for the scheduled start");
    for f in &fired {
        db.writer().send(state_cmd(s.state(&f.kind, &f.key).unwrap())).await.unwrap();
    }
    drop(s);

    // The hub restarts a minute later, inside the window.
    let now = window_start + 60_000;
    let mut s = Scheduler::new(tasks(), load_state(db.readers()).unwrap(), now);
    assert!(s.due(now).is_empty(), "nothing runs twice");
    // Without the saved state, the open window would run again.
    let mut fresh = Scheduler::new(tasks(), Vec::new(), now);
    assert_eq!(fresh.due(now).len(), 2);

    let next_day = ms("2026-11-20T03:00:10Z");
    let fired = s.due(next_day);
    assert_eq!(fired.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>(), ["patch_window", "retention"]);
}
