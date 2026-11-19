use crate::counted::{check_failing, container_restarts, security_updates, service_not_active};
use crate::rules::Severity;

const MIN: i64 = 60_000;
const DAY: i64 = 24 * 60 * MIN;

#[test]
fn service_not_active_2_and_4_reports() {
    assert_eq!(service_not_active(0), None);
    assert_eq!(service_not_active(1), None);
    assert_eq!(service_not_active(2), Some(Severity::Warning));
    assert_eq!(service_not_active(3), Some(Severity::Warning));
    assert_eq!(service_not_active(4), Some(Severity::Critical));
}

#[test]
fn container_restarts_3_and_10_in_10_minutes() {
    let now = 100 * MIN;
    let restarts = |n: i64| -> Vec<i64> { (0..n).map(|i| now - i * 30_000).collect() };
    assert_eq!(container_restarts(&restarts(3), now), None, "3 is not more than 3");
    assert_eq!(container_restarts(&restarts(4), now), Some(Severity::Warning));
    assert_eq!(container_restarts(&restarts(10), now), Some(Severity::Warning));
    assert_eq!(container_restarts(&restarts(11), now), Some(Severity::Critical));
    let mut old = restarts(3);
    old.push(now - 10 * MIN); // exactly 10 minutes ago is outside the window
    assert_eq!(container_restarts(&old, now), None);
    old.push(now - 10 * MIN + 1);
    assert_eq!(container_restarts(&old, now), Some(Severity::Warning));
}

#[test]
fn check_failing_2_and_4_in_a_row() {
    assert_eq!(check_failing(1), None);
    assert_eq!(check_failing(2), Some(Severity::Warning));
    assert_eq!(check_failing(3), Some(Severity::Warning));
    assert_eq!(check_failing(4), Some(Severity::Critical));
}

#[test]
fn security_updates_older_than_7_and_14_days() {
    let now = 1_000 * DAY;
    assert_eq!(security_updates(None, now), None, "nothing pending");
    assert_eq!(security_updates(Some(now - 7 * DAY), now), None, "7 days is not older than 7");
    assert_eq!(security_updates(Some(now - 7 * DAY - 1), now), Some(Severity::Warning));
    assert_eq!(security_updates(Some(now - 14 * DAY), now), Some(Severity::Warning));
    assert_eq!(security_updates(Some(now - 14 * DAY - 1), now), Some(Severity::Critical));
}
