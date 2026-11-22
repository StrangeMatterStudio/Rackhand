//! The built-in runbooks (7.8.7, plan T59c): shipped with the hub and seeded into the Library.

use crate::builtin;
use crate::runbook::{Runbook, StepKind};

const WRAPPER: &str = "/usr/local/lib/rackhand/run";

fn ids(r: &Runbook) -> Vec<&str> {
    r.steps.iter().map(|s| s.id.as_str()).collect()
}

/// 7.5.3 step 4: precheck, snapshot, record, update and install (both detached), reboot if required, wait for a report,
/// verify, in that order, every command through the wrapper.
#[test]
fn patch_runbooks_follow_the_designed_steps() {
    let names: Vec<&str> = builtin::runbooks().iter().map(|(n, _)| *n).collect();
    for name in ["patch-debian", "patch-alpine"] {
        assert!(names.contains(&name), "{name} is built in: {names:?}");
        let source = builtin::runbook(name).unwrap();
        let r = Runbook::parse(source).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(r.name, name);
        assert_eq!(
            ids(&r),
            ["precheck", "snapshot", "record", "update", "install", "reboot", "report", "verify"],
            "{name}"
        );
        let kinds: Vec<StepKind> = r.steps.iter().map(|s| s.kind).collect();
        use StepKind::*;
        assert_eq!(kinds, [Verify, Snapshot, Verify, Ssh, Ssh, RebootIfRequired, WaitReport, Verify], "{name}");
        let checks = |id: &str| r.steps.iter().find(|s| s.id == id).unwrap().checks.clone().unwrap_or_default();
        assert_eq!(checks("precheck"), ["patch_precheck"]);
        assert_eq!(checks("record"), ["record_state"]);
        assert_eq!(checks("verify"), ["as_recorded", "required_mounts", "bound_checks"]);
        for s in r.steps.iter().filter(|s| s.kind == Ssh) {
            let cmd = s.cmd.clone().unwrap();
            assert_eq!(&cmd[..2], ["sudo", WRAPPER], "{name}/{}: through the wrapper", s.id);
            assert!(s.detached, "{name}/{}: detached, so a cut connection doesn't stop it (AC63)", s.id);
        }
    }
}

/// 7.5.3 steps 7 and 8: a Proxmox host takes a full upgrade (S4: never a plain one) and has no snapshot, being no guest;
/// the hub's own host is patched as any Debian machine, its reboot step being the one that differs when it runs.
#[test]
fn host_runbooks_follow_the_designed_steps() {
    let parsed = |name: &str| {
        let source = builtin::runbook(name).unwrap_or_else(|| panic!("{name} is built in"));
        let r = Runbook::parse(source).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!((r.name.as_str(), r.risk), (name, crate::runbook::Risk::Normal));
        r
    };
    let pve = parsed("patch-proxmox-host");
    assert_eq!(ids(&pve), ["precheck", "record", "update", "install", "reboot", "report", "verify"]);
    let install = pve.steps.iter().find(|s| s.id == "install").unwrap().cmd.clone().unwrap().join(" ");
    assert!(install.ends_with("dist-upgrade") && install.contains("DPkg::Lock::Timeout=600"), "{install}");
    assert!(install.contains("--force-confold") && install.contains("DEBIAN_FRONTEND=noninteractive"), "{install}");
    let hub = parsed("patch-hub-host");
    assert_eq!(ids(&hub), ["precheck", "snapshot", "record", "update", "install", "reboot", "report", "verify"]);
    let debian = Runbook::parse(builtin::runbook("patch-debian").unwrap()).unwrap();
    let cmds = |r: &Runbook, id: &str| r.steps.iter().find(|s| s.id == id).unwrap().cmd.clone();
    for id in ["update", "install"] {
        assert_eq!(cmds(&hub, id), cmds(&debian, id), "patched as any Debian machine: {id}");
    }
    assert_eq!(cmds(&pve, "update"), cmds(&debian, "update"), "the same wait for the lists' lock");
    for r in [&pve, &hub] {
        for s in r.steps.iter().filter(|s| s.kind == StepKind::Ssh) {
            assert!(s.detached && s.cmd.as_ref().unwrap()[1] == WRAPPER, "{}/{}", r.name, s.id);
        }
    }
}

/// Owner review (B6): Debian and Ubuntu take every pending update, and the package manager waits up to 10 minutes for
/// a lock held by someone else (E9). Nothing else on the machine is changed: no sources, no settings files.
#[test]
fn patch_commands_wait_for_the_lock_and_take_full_updates() {
    let cmd = |name: &str, id: &str| {
        let r = Runbook::parse(builtin::runbook(name).unwrap()).unwrap();
        r.steps.into_iter().find(|s| s.id == id).unwrap().cmd.unwrap().join(" ")
    };
    for id in ["update", "install"] {
        let apt = cmd("patch-debian", id);
        assert!(apt.contains("/usr/bin/apt-get") && apt.contains("-o DPkg::Lock::Timeout=600"), "{apt}");
        assert!(apt.contains("DEBIAN_FRONTEND=noninteractive"), "the wrapper clears the environment: {apt}");
        let apk = cmd("patch-alpine", id);
        assert!(apk.contains("/sbin/apk") && apk.contains("--wait 600"), "{apk}");
    }
    let update = cmd("patch-debian", "update");
    assert!(update.contains("WAIT_S=600") && update.contains("Unable to lock directory"), "the lists' lock: {update}");
    let install = cmd("patch-debian", "install");
    assert!(install.ends_with("upgrade --with-new-pkgs"), "every pending update, nothing removed: {install}");
    assert!(install.contains("--force-confold"), "a changed config file keeps the machine's version: {install}");
    assert!(cmd("patch-alpine", "install").ends_with("upgrade"));
    assert!(builtin::runbook("no-such").is_none());
}

/// The `rollback` runbook: one step, high risk, for the patch job it is given (a job id, nothing else).
#[test]
fn rollback_runbook_takes_a_job_id() {
    let r = Runbook::parse(builtin::runbook("rollback").expect("built in")).unwrap();
    assert_eq!(r.risk, crate::runbook::Risk::High);
    assert_eq!(r.steps.iter().map(|s| s.kind).collect::<Vec<_>>(), [StepKind::Rollback]);
    let param = &r.params["job"];
    assert!(crate::params::check_value(param, "01JDPATCHED000000000000001").is_ok());
    assert!(crate::params::check_value(param, "rackhand-patch-1; reboot").is_err());
}

/// E13: a hypervisor's reboot is its own runbook, high risk, so it always needs an approval with step-up.
#[test]
fn reboot_host_is_high_risk_and_verifies() {
    let r = Runbook::parse(builtin::runbook("reboot-host").expect("built in")).unwrap();
    assert_eq!((r.risk, r.autonomy), (crate::runbook::Risk::High, 1));
    use StepKind::*;
    assert_eq!(r.steps.iter().map(|s| s.kind).collect::<Vec<_>>(), [Verify, RebootIfRequired, WaitReport, Verify]);
    assert_eq!(r.targets.roles, ["hypervisor"]);
    assert!(r.params.is_empty(), "nothing in it can be widened after the approval");
}
