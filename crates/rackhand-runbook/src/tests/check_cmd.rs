use super::runbook::COMPOSE_RESTART;
use crate::check_cmd::check;

#[test]
fn reports_sudo_coverage() {
    let report = check(COMPOSE_RESTART);
    assert!(report.errors.is_empty() && report.uncovered.is_empty(), "{report:?}");
    assert!(report.summary().contains("1 root step"), "{}", report.summary());

    // A root step that doesn't go through the command wrapper isn't in the automation user's sudo allow-list.
    let direct = COMPOSE_RESTART.replace("\"sudo\", \"/usr/local/lib/rackhand/run\", ", "\"sudo\", ");
    let report = check(&direct);
    assert_eq!(report.uncovered.len(), 1, "{report:?}");
    assert!(report.uncovered[0].contains("restart") && report.uncovered[0].contains("/usr/bin/docker"), "{report:?}");
    assert!(!report.ok());
    // The assistant identity has sudo for everything (7.3.7), so nothing is uncovered.
    let assistant = direct.replace("identity = \"automation\"", "identity = \"assistant\"");
    assert!(check(&assistant).uncovered.is_empty());
    // A parse error is reported with its line, not as coverage.
    let broken = check("name = ");
    assert!(!broken.ok() && broken.errors[0].contains("line 1"), "{broken:?}");
}
