use crate::policy::decide::{Access, Action, Decision, Deny, Request, Requester, Target, decide};
use crate::policy::exclusions::quarantine_excluded;

#[test]
fn never_quarantined_roles_and_tag() {
    for role in ["hub", "operator", "relay", "hypervisor"] {
        assert!(quarantine_excluded(&[role], &[]), "{role}");
    }
    assert!(quarantine_excluded(&[], &["web", "no-quarantine"]));
    assert!(!quarantine_excluded(&["proxmox-guest"], &["dmz"]));
    // The exclusion wins before any rule: an enabled auto rule on a hypervisor gives an incident only.
    let hypervisor = Target { access: Access::Managed, roles: &["hypervisor"], tags: &["dmz"] };
    let auto = Request {
        requester: Requester::Local,
        action: Action::AutoQuarantine { rule_enabled: true },
        target: hypervisor,
        peer_auto: false,
        auto_rollback: false,
    };
    assert_eq!(decide(&auto), Decision::Deny(Deny::Excluded));
    let tagged = Target { access: Access::Managed, roles: &[], tags: &["no-quarantine"] };
    let manual = Request { requester: Requester::Person, action: Action::Quarantine, target: tagged, ..auto };
    assert_eq!(decide(&manual), Decision::Deny(Deny::Excluded), "not even by hand");
}
