use super::*;

/// D45: the hub rolls a guest back only when it never reported in the 15 minutes after a reboot, the policy has
/// `auto_rollback`, the machine isn't the hub, and there is a snapshot to go back to. Otherwise a person decides.
#[test]
fn only_when_no_report_15_min_auto_rollback_on_not_hub() {
    let all = Failure { no_report_after_reboot: true, auto_rollback: true, hub: false, snapshot_taken: true };
    assert!(rolls_back(&all));
    assert!(!rolls_back(&Failure { no_report_after_reboot: false, ..all }), "it reported: verify failed instead");
    assert!(!rolls_back(&Failure { auto_rollback: false, ..all }), "the policy doesn't allow it");
    assert!(!rolls_back(&Failure { hub: true, ..all }), "never the hub's own machine");
    assert!(!rolls_back(&Failure { snapshot_taken: false, ..all }), "nothing to go back to");
}

/// 7.5.3 step 9: `snapshot` required, `auto_rollback` off; `auto_reboot` on for Linux guests and off for kind
/// `windows` and roles `desktop`, `hypervisor` and `hub`.
#[test]
fn defaults_auto_rollback_off_no_reboot_windows_desktop() {
    let linux = defaults("linux", &[]);
    assert_eq!(linux, Defaults { snapshot_required: true, auto_rollback: false, auto_reboot: true });
    assert!(defaults("alpine", &[]).auto_reboot);
    for (kind, roles) in
        [("windows", vec![]), ("linux", vec!["desktop"]), ("linux", vec!["hypervisor"]), ("linux", vec!["hub"])]
    {
        let d = defaults(kind, &roles);
        assert!(!d.auto_reboot, "{kind} {roles:?}");
        assert!(!d.auto_rollback && d.snapshot_required);
    }
}
