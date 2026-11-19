use rackhand_runbook::runbook::Risk;

use crate::policy::decide::{Access, Action, Decision, Deny, Request, Requester, Target, decide};

const ORDINARY: Target<'static> = Target { access: Access::Managed, roles: &[], tags: &[] };
const MONITOR: Target<'static> = Target { access: Access::Monitor, roles: &[], tags: &[] };

fn runbook(risk: Risk, level: u8) -> Action<'static> {
    Action::Runbook { risk, level, needs_account: true, assistant_commands: &[] }
}

fn req(requester: Requester, action: Action<'static>, target: Target<'static>) -> Request<'static> {
    Request { requester, action, target, peer_auto: false, auto_rollback: false }
}

/// `A` allow, `N` approval, `S` approval with step-up, `D` deny.
fn code(d: Decision) -> char {
    match d {
        Decision::Allow => 'A',
        Decision::NeedsApproval { step_up: false, .. } => 'N',
        Decision::NeedsApproval { step_up: true, .. } => 'S',
        Decision::Deny(_) => 'D',
    }
}

#[test]
fn table_levels_by_risk_by_requester() {
    use Requester::*;
    use Risk::*;
    // (requester, level, risk, expected)
    let table: &[(Requester, u8, Risk, char)] = &[
        // Local triggers follow the level; level 0 only tells; high always needs step-up.
        (Local, 0, Low, 'D'),
        (Local, 0, Normal, 'D'),
        (Local, 0, High, 'D'),
        (Local, 1, Low, 'N'),
        (Local, 1, Normal, 'N'),
        (Local, 1, High, 'S'),
        (Local, 2, Low, 'A'),
        (Local, 2, Normal, 'A'),
        (Local, 2, High, 'S'),
        (Local, 3, Low, 'A'),
        (Local, 3, Normal, 'A'),
        (Local, 3, High, 'S'),
        // Assistant jobs calling run_runbook: the same.
        (AssistantJob, 0, Low, 'D'),
        (AssistantJob, 0, Normal, 'D'),
        (AssistantJob, 0, High, 'D'),
        (AssistantJob, 1, Low, 'N'),
        (AssistantJob, 1, Normal, 'N'),
        (AssistantJob, 1, High, 'S'),
        (AssistantJob, 2, Low, 'A'),
        (AssistantJob, 2, Normal, 'A'),
        (AssistantJob, 2, High, 'S'),
        (AssistantJob, 3, Low, 'A'),
        (AssistantJob, 3, Normal, 'A'),
        (AssistantJob, 3, High, 'S'),
        // Peers need an approval at every level and risk (no auto policy here).
        (Peer, 0, Low, 'N'),
        (Peer, 0, Normal, 'N'),
        (Peer, 0, High, 'S'),
        (Peer, 1, Low, 'N'),
        (Peer, 1, Normal, 'N'),
        (Peer, 1, High, 'S'),
        (Peer, 2, Low, 'N'),
        (Peer, 2, Normal, 'N'),
        (Peer, 2, High, 'S'),
        (Peer, 3, Low, 'N'),
        (Peer, 3, Normal, 'N'),
        (Peer, 3, High, 'S'),
        // Personal MCP keys are always level 1.
        (PersonalKey, 0, Low, 'N'),
        (PersonalKey, 0, Normal, 'N'),
        (PersonalKey, 0, High, 'S'),
        (PersonalKey, 1, Low, 'N'),
        (PersonalKey, 1, Normal, 'N'),
        (PersonalKey, 1, High, 'S'),
        (PersonalKey, 2, Low, 'N'),
        (PersonalKey, 2, Normal, 'N'),
        (PersonalKey, 2, High, 'S'),
        (PersonalKey, 3, Low, 'N'),
        (PersonalKey, 3, Normal, 'N'),
        (PersonalKey, 3, High, 'S'),
        // A person in the dashboard is the decision; high still needs step-up.
        (Person, 1, Low, 'A'),
        (Person, 2, Normal, 'A'),
        (Person, 3, High, 'S'),
    ];
    let mut rows = 0;
    for (requester, level, risk, want) in table {
        let got = code(decide(&req(*requester, runbook(*risk, *level), ORDINARY)));
        assert_eq!(got, *want, "{requester:?} level {level} {risk:?}");
        rows += 1;
    }
    // Peer auto, monitor targets and assistant exec.
    let peer_auto = |risk| Request { peer_auto: true, ..req(Peer, runbook(risk, 1), ORDINARY) };
    let extra: Vec<(Request<'static>, char)> = vec![
        (peer_auto(Low), 'A'),
        (peer_auto(Normal), 'A'),
        (peer_auto(High), 'S'),
        (
            req(Local, Action::Runbook { risk: Low, level: 3, needs_account: false, assistant_commands: &[] }, MONITOR),
            'N',
        ),
        (
            req(
                Local,
                Action::Runbook { risk: Normal, level: 2, needs_account: false, assistant_commands: &[] },
                MONITOR,
            ),
            'N',
        ),
        (
            req(
                Local,
                Action::Runbook { risk: High, level: 3, needs_account: false, assistant_commands: &[] },
                MONITOR,
            ),
            'S',
        ),
        (req(Local, runbook(Low, 3), MONITOR), 'D'),
        (req(AssistantJob, Action::Exec { command: "systemctl restart nginx", level: 2 }, ORDINARY), 'A'),
        (req(AssistantJob, Action::Exec { command: "systemctl restart nginx", level: 1 }, ORDINARY), 'N'),
        (req(AssistantJob, Action::Exec { command: "systemctl restart nginx", level: 0 }, ORDINARY), 'D'),
        (req(PersonalKey, Action::Exec { command: "uptime", level: 3 }, ORDINARY), 'D'),
        (req(AssistantJob, Action::Exec { command: "uptime", level: 3 }, MONITOR), 'D'),
    ];
    for (r, want) in &extra {
        assert_eq!(code(decide(r)), *want, "{r:?}");
        rows += 1;
    }
    assert!(rows >= 60, "{rows} rows");
    assert_eq!(decide(&req(Local, runbook(Low, 0), ORDINARY)), Decision::Deny(Deny::TellOnly));
    assert_eq!(decide(&req(Local, runbook(Low, 3), MONITOR)), Decision::Deny(Deny::MonitorOnly));
}

#[test]
fn high_risk_always_approval_with_step_up() {
    for role in ["operator", "relay", "hypervisor"] {
        let roles: &'static [&'static str] = Box::leak(Box::new([role]));
        let target = Target { access: Access::Managed, roles, tags: &[] };
        let d = decide(&req(Requester::AssistantJob, Action::Exec { command: "uptime", level: 3 }, target));
        assert_eq!(d, Decision::NeedsApproval { risk: Risk::High, step_up: true }, "exec on {role}");
    }
    for level in 1..=3 {
        let d = decide(&req(Requester::Local, runbook(Risk::High, level), ORDINARY));
        assert_eq!(d, Decision::NeedsApproval { risk: Risk::High, step_up: true });
    }
    // A runbook run as the assistant is treated like an exec of each of its commands.
    let as_assistant = Action::Runbook {
        risk: Risk::Low,
        level: 3,
        needs_account: true,
        assistant_commands: &["apt-get clean", "mkfs.ext4 /dev/sdb1"],
    };
    let d = decide(&req(Requester::Local, as_assistant, ORDINARY));
    assert_eq!(d, Decision::NeedsApproval { risk: Risk::High, step_up: true });
    let d = decide(&req(Requester::Person, Action::Quarantine, ORDINARY));
    assert_eq!(d, Decision::NeedsApproval { risk: Risk::High, step_up: true }, "quarantine and release");
}

#[test]
fn monitor_machine_always_needs_approval_and_no_auto_policy() {
    let auto_q = |target| req(Requester::Local, Action::AutoQuarantine { rule_enabled: true }, target);
    assert_eq!(decide(&auto_q(ORDINARY)), Decision::Allow, "an enabled rule applies without approval");
    assert_eq!(decide(&auto_q(MONITOR)), Decision::NeedsApproval { risk: Risk::High, step_up: true });
    let disabled = req(Requester::Local, Action::AutoQuarantine { rule_enabled: false }, ORDINARY);
    assert_eq!(code(decide(&disabled)), 'S');
    let rollback =
        |target, auto_rollback| Request { auto_rollback, ..req(Requester::Local, Action::AutoRollback, target) };
    assert_eq!(decide(&rollback(ORDINARY, true)), Decision::Allow);
    assert_eq!(code(decide(&rollback(ORDINARY, false))), 'S', "auto_rollback off");
    assert_eq!(code(decide(&rollback(MONITOR, true))), 'S', "never automatic on a monitor machine");
    let hub = Target { access: Access::Managed, roles: &["hub"], tags: &[] };
    assert_eq!(code(decide(&rollback(hub, true))), 'S', "never on the hub (D45)");
    // Hypervisor-side snapshot of a monitor guest at level 3, low risk: still an approval.
    let snapshot = Action::Runbook { risk: Risk::Low, level: 3, needs_account: false, assistant_commands: &[] };
    assert_eq!(code(decide(&req(Requester::Local, snapshot, MONITOR))), 'N');
}

#[test]
fn personal_key_always_level_1() {
    let key = |action| decide(&req(Requester::PersonalKey, action, ORDINARY));
    assert_eq!(code(key(runbook(Risk::Low, 3))), 'N', "every run_runbook from a device");
    for sensitive in ["journal", "docker_logs"] {
        assert_eq!(code(key(Action::Diagnostic { name: sensitive, level: 3 })), 'N', "{sensitive}");
    }
    assert_eq!(key(Action::Diagnostic { name: "df", level: 3 }), Decision::Allow);
    let job = decide(&req(Requester::AssistantJob, Action::Diagnostic { name: "journal", level: 0 }, ORDINARY));
    assert_eq!(job, Decision::Allow, "read tools run at every level for jobs");
    let monitor = decide(&req(Requester::AssistantJob, Action::Diagnostic { name: "df", level: 3 }, MONITOR));
    assert_eq!(monitor, Decision::Deny(Deny::MonitorOnly));
}

#[test]
fn peer_request_auto_only_when_policy_says_and_never_high() {
    let peer = |risk, peer_auto| Request { peer_auto, ..req(Requester::Peer, runbook(risk, 3), ORDINARY) };
    assert_eq!(code(decide(&peer(Risk::Normal, false))), 'N');
    assert_eq!(decide(&peer(Risk::Normal, true)), Decision::Allow);
    assert_eq!(decide(&peer(Risk::High, true)), Decision::NeedsApproval { risk: Risk::High, step_up: true });
    // Auto never reaches past a monitor machine's approval.
    let monitor = Request {
        peer_auto: true,
        ..req(
            Requester::Peer,
            Action::Runbook { risk: Risk::Low, level: 3, needs_account: false, assistant_commands: &[] },
            MONITOR,
        )
    };
    assert_eq!(code(decide(&monitor)), 'N');
}

#[test]
fn exec_step_up_patterns() {
    let step_up = [
        "rm -rf /",
        "sudo rm -rf /etc",
        "rm -fr /home/",
        "rm -r -f /var",
        "mkfs.ext4 /dev/sdb1",
        "mkfs -t xfs /dev/vdb",
        "dd if=/dev/zero of=/dev/sda bs=1M",
        "zpool destroy tank",
        "zfs destroy tank/data",
        "zfs destroy -r tank/vm-200-disk-0@before",
        "qm destroy 200",
        "pct destroy 100 --purge",
        "do-release-upgrade -f DistUpgradeViewNonInteractive",
        "echo 'deb http://x y main' >> /etc/apt/sources.list",
        "sed -i s/bookworm/trixie/ /etc/apt/sources.list.d/debian.sources",
        "shutdown -h now",
        "systemctl poweroff",
        "cd /tmp && poweroff",
        "sudo -u root shutdown -r now",
        "bash -c 'mkfs.ext4 /dev/sdb1'",
        "env FOO=1 nohup qm destroy 200",
        "xargs -a list.txt rm -rf /srv",
    ];
    for cmd in step_up {
        let d = decide(&req(Requester::AssistantJob, Action::Exec { command: cmd, level: 3 }, ORDINARY));
        assert_eq!(d, Decision::NeedsApproval { risk: Risk::High, step_up: true }, "`{cmd}`");
    }
    let ordinary = [
        "zfs destroy pool/rackhand-patch-x",
        "zfs destroy tank/vm-200-disk-0@rackhand-patch-20261119-0400",
        "rm -rf /tmp/build",
        "rm -rf ./cache",
        "dd if=/dev/sda of=/tmp/mbr.bin bs=512 count=1",
        "cat /etc/apt/sources.list",
        "grep -r bookworm /etc/apt/sources.list.d/",
        "systemctl restart nginx",
    ];
    for cmd in ordinary {
        let d = decide(&req(Requester::AssistantJob, Action::Exec { command: cmd, level: 2 }, ORDINARY));
        assert_eq!(d, Decision::Allow, "`{cmd}` is normal risk");
    }
}
