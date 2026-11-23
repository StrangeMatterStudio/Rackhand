//! The built-in runbooks (7.8.7, plan T59c): shipped with the hub and seeded into the Library.

use crate::builtin;
use crate::runbook::{Runbook, Step, StepKind};

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
    assert_eq!(r.targets.roles, ["hypervisor", "hub"]);
    assert!(r.params.is_empty(), "nothing in it can be widened after the approval");
}

/// 7.6.8 and 7.8.7: every built-in parses, carries the risk the design gives it, and one that takes a parameter has no
/// trigger (an incident starts a runbook without parameters).
#[test]
fn all_parse_and_have_design_risk() {
    use crate::runbook::Risk::{High, Low, Normal};
    let risks = [
        ("patch-debian", Normal),
        ("patch-alpine", Normal),
        ("patch-proxmox-host", Normal),
        ("patch-hub-host", Normal),
        ("reboot-host", High),
        ("rollback", High),
        ("reboot", Normal),
        ("snapshot", Normal),
        ("service-restart", Low),
        ("compose-restart", Low),
        ("compose-update", Normal),
        ("sudoers-refresh", High),
        ("keys-rotate", High),
        ("unenroll", High),
        ("provision-vm", Normal),
        ("provision-lxc", Normal),
        ("quarantine", High),
        ("quarantine-release", High),
        ("conntrack-flush", High),
    ];
    for (name, source) in builtin::runbooks() {
        let r = Runbook::parse(source).unwrap_or_else(|e| panic!("{name}: {e}"));
        let expected = risks.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("{name}: no risk given here"));
        assert_eq!((r.name.as_str(), r.risk), (*name, expected.1));
        assert!(r.params.is_empty() || r.triggers.is_none(), "{name}");
        assert!(r.steps.iter().all(|s| s.timeout_s().is_some()), "{name}: every step has its own limit");
    }
    assert_eq!(builtin::runbooks().len(), risks.len());
}

/// What restarts something waits for a report from after it before it judges, and takes only the names it is meant for.
#[test]
fn restart_runbooks_judge_a_fresh_report() {
    use crate::params::check_value;
    let parsed = |name: &str| Runbook::parse(builtin::runbook(name).unwrap_or_else(|| panic!("{name}"))).unwrap();
    let kinds = |r: &Runbook| r.steps.iter().map(|s| s.kind).collect::<Vec<_>>();
    use StepKind::{RebootIfRequired, Snapshot, Ssh, Verify, WaitReport};
    let compose = parsed("compose-restart");
    assert_eq!(kinds(&compose), [Ssh, WaitReport, Verify]);
    assert_eq!(compose.steps[2].checks.as_deref(), Some(&["containers_running:{{project}}".to_string()][..]));
    assert_eq!(
        compose.steps[0].cmd.as_ref().unwrap()[1..].join(" "),
        format!("{WRAPPER} /usr/bin/docker compose -p {{{{project}}}} restart")
    );
    let update = parsed("compose-update");
    assert_eq!(kinds(&update), [Ssh, Ssh, WaitReport, Verify]);
    assert!(update.steps[..2].iter().all(|s| s.detached), "a pull outlives a cut connection");
    let service = parsed("service-restart");
    assert_eq!(kinds(&service), [Ssh, Ssh, WaitReport, Verify]);
    assert_eq!(kinds(&parsed("snapshot")), [Snapshot]);
    let reboot = parsed("reboot");
    assert_eq!(kinds(&reboot), [Verify, RebootIfRequired, WaitReport, Verify]);
    assert!(reboot.steps[1].always, "asked for, it reboots whether the machine wants it or not");
    assert!(!parsed("patch-debian").steps.iter().any(|s| s.always));
    for (value, ok) in [("web", true), ("my_app-2", true), ("-v", false), ("a b", false), ("a;b", false), ("", false)] {
        assert_eq!(check_value(&compose.params["project"], value).is_ok(), ok, "project {value:?}");
    }
    for (value, ok) in [
        ("nginx.service", true),
        ("getty@tty1.service", true),
        ("nginx", false),
        ("--now.service", false),
        ("a b.service", false),
        ("docker.socket", false),
    ] {
        assert_eq!(check_value(&service.params["unit"], value).is_ok(), ok, "unit {value:?}");
    }
    for (value, ok) in [
        ("/opt/web/compose.yml", true),
        ("/srv/a-b/docker-compose.yaml", true),
        ("compose.yml", false),
        ("/etc/shadow", false),
        ("/opt/../etc/compose.yml", false),
        ("/opt/a b/compose.yml", false),
    ] {
        assert_eq!(check_value(&update.params["file"], value).is_ok(), ok, "file {value:?}");
    }
}

/// 7.8.7: a `hub` step is something the hub does itself, from a short fixed list; it carries no command.
#[test]
fn hub_steps_name_a_known_call() {
    let source = |extra: &str| {
        format!(
            "name = \"r\"\ndescription = \"d\"\nidentity = \"automation\"\nrisk = \"high\"\nautonomy = 1\n\
             [[step]]\nid = \"s\"\nkind = \"hub\"\n{extra}"
        )
    };
    for call in ["send_commands", "rotate_keys", "revoke"] {
        let r = Runbook::parse(&source(&format!("call = \"{call}\"\n"))).unwrap_or_else(|e| panic!("{call}: {e}"));
        assert_eq!(r.steps[0].kind, StepKind::Hub);
    }
    for bad in ["", "call = \"format_disk\"\n", "call = \"send_commands\"\ncmd = [\"/bin/sh\"]\n", "call = \"\"\n"] {
        let err = Runbook::parse(&source(bad)).unwrap_err().to_string();
        assert!(err.contains("hub") || err.contains("call"), "{bad:?}: {err}");
    }
    // sending the list or rotating the keys needs an account on the machine; revoking is the hub's alone (7.3.12)
    let needs = |call: &str| Runbook::parse(&source(&format!("call = \"{call}\"\n"))).unwrap().steps[0].needs_account();
    assert_eq!((needs("send_commands"), needs("rotate_keys"), needs("revoke")), (true, true, false));
    let ssh = Runbook::parse(
        &source("call = \"send_commands\"\n").replace("kind = \"hub\"", "kind = \"ssh\"\ncmd = [\"x\"]"),
    );
    assert!(ssh.unwrap().steps[0].needs_account());
}

/// `sudoers-refresh`: one hub step, high risk, no parameter (what it sends is the hub's own list).
#[test]
fn sudoers_refresh_sends_the_hubs_list() {
    let r = Runbook::parse(builtin::runbook("sudoers-refresh").expect("built in")).unwrap();
    assert_eq!((r.risk, r.autonomy), (crate::runbook::Risk::High, 1));
    assert_eq!(r.steps.iter().map(|s| s.kind).collect::<Vec<_>>(), [StepKind::Hub]);
    assert_eq!(r.steps[0].call.as_deref(), Some("send_commands"));
    assert!(r.params.is_empty() && r.triggers.is_none());
}

/// `keys-rotate`: one hub step, high risk, no parameter: the hub's own keys are what changes.
#[test]
fn keys_rotate_is_one_hub_step() {
    let r = Runbook::parse(builtin::runbook("keys-rotate").expect("built in")).unwrap();
    assert_eq!((r.risk, r.autonomy), (crate::runbook::Risk::High, 1));
    assert_eq!(r.steps.iter().map(|s| s.kind).collect::<Vec<_>>(), [StepKind::Hub]);
    assert_eq!(r.steps[0].call.as_deref(), Some("rotate_keys"));
    assert!(r.params.is_empty() && r.triggers.is_none());
    assert!(r.steps[0].needs_account());
}

/// 7.3.12: `unenroll` has the machine remove what the hub put there, scheduled so that its answer comes first, and then
/// the hub revokes the machine; not detached (its account is gone at the end), and with no parameter.
#[test]
fn unenroll_uninstalls_then_revokes() {
    let r = Runbook::parse(builtin::runbook("unenroll").expect("built in")).unwrap();
    assert_eq!((r.risk, r.autonomy), (crate::runbook::Risk::High, 1));
    assert_eq!(r.steps.iter().map(|s| s.kind).collect::<Vec<_>>(), [StepKind::Ssh, StepKind::Hub]);
    let uninstall = &r.steps[0];
    assert_eq!(
        uninstall.cmd.as_deref().unwrap(),
        ["sudo", WRAPPER, "/usr/local/lib/rackhand/rackhand-probe", "uninstall", "--after", "5"]
    );
    assert!(!uninstall.detached, "nothing is left to poll it with");
    assert_eq!(r.steps[1].call.as_deref(), Some("revoke"));
    assert!(r.params.is_empty() && r.triggers.is_none());
    assert!(!r.steps[1].needs_account(), "revoking needs no account on the machine");
}

/// A `hub` step's `call` is a name and then `key=value` words (T64): `parse` checks the name against the fixed list.
#[test]
fn a_call_is_a_name_and_key_value_words() {
    use crate::runbook::call_parts;
    assert_eq!(call_parts("revoke"), ("revoke", vec![]));
    let (name, args) = call_parts("clone vmid=9000 newid=120 name=web-1 set.cicustom=user=local:snippets/x.yml");
    assert_eq!(name, "clone");
    assert_eq!(
        args,
        [("vmid", "9000"), ("newid", "120"), ("name", "web-1"), ("set.cicustom", "user=local:snippets/x.yml")]
            .map(|(k, v)| (k.to_string(), v.to_string()))
    );
    assert_eq!(call_parts("  a   b=c ").0, "a", "extra spaces make no empty word");
    assert_eq!(call_parts("a b c=d").1, [("c".to_string(), "d".to_string())], "a word without `=` is no argument");
    let source = |call: &str| {
        format!(
            "name = \"r\"
description = \"d\"
identity = \"automation\"
risk = \"normal\"
autonomy = 1
             [[step]]
id = \"s\"
kind = \"hub\"
call = \"{call}\"
"
        )
    };
    assert!(Runbook::parse(&source("bind_guest kind=qemu vmid=1 name=web")).is_ok());
    assert!(Runbook::parse(&source("format_disk vmid=1")).is_err(), "the name is checked, not the whole text");
}

/// `provision-vm` and `provision-lxc` (FR-23): the guest is made on the hypervisor, enrolls itself, and is bound by the
/// runbook that made it. Each parameter is a whole value of a known shape, so nothing in a call can be widened.
#[test]
fn provision_runbooks_make_start_enroll_and_bind() {
    use crate::params::check_value;
    use StepKind::{Api, Hub};
    let parsed = |name: &str| Runbook::parse(builtin::runbook(name).unwrap_or_else(|| panic!("{name}"))).unwrap();
    let calls = |r: &Runbook| {
        r.steps
            .iter()
            .map(|s| s.call.as_deref().unwrap_or("").split(' ').next().unwrap_or("").to_string())
            .collect::<Vec<_>>()
    };
    let vm = parsed("provision-vm");
    assert_eq!(vm.steps.iter().map(|s| s.kind).collect::<Vec<_>>(), [Hub, Api, Hub, Api, Api, Hub, Hub]);
    assert_eq!(
        calls(&vm),
        ["provision_machine", "clone", "send_guest", "config_set", "power", "bind_guest", "await_machine"]
    );
    let lxc = parsed("provision-lxc");
    assert_eq!(lxc.steps.iter().map(|s| s.kind).collect::<Vec<_>>(), [Hub, Api, Api, Hub, Hub, Hub]);
    assert_eq!(calls(&lxc), ["provision_machine", "create_lxc", "power", "send_guest", "bind_guest", "await_machine"]);
    let needs = |r: &Runbook| r.steps.iter().map(Step::needs_account).collect::<Vec<_>>();
    assert_eq!(
        needs(&vm),
        [false, false, true, false, false, false, false],
        "only the guest's enrollment uses an account"
    );
    assert_eq!(needs(&lxc), [false, false, false, true, false, false]);
    for r in [&vm, &lxc] {
        assert_eq!((r.risk, r.autonomy), (crate::runbook::Risk::Normal, 1));
        assert_eq!(r.targets.kinds, ["hypervisor"]);
        assert!(r.triggers.is_none(), "an incident never makes a guest");
        assert!(r.steps.iter().all(|s| !s.always && !s.detached));
    }
    for (value, ok) in [("web-1", true), ("a.b_c", true), ("-x", false), ("a b", false), ("a;b", false), ("", false)] {
        assert_eq!(check_value(&vm.params["name"], value).is_ok(), ok, "name {value:?}");
    }
    for (value, ok) in [("120", true), ("x", false), ("1 2", false), ("-1", false)] {
        assert_eq!(check_value(&vm.params["newid"], value).is_ok(), ok, "newid {value:?}");
    }
    for (value, ok) in [
        ("local:vztmpl/alpine-3.20-default_20240908_amd64.tar.xz", true),
        ("tank:vztmpl/debian-12.tar.zst", true),
        ("local:iso/x.iso", false),
        ("local:vztmpl/../../etc", false),
        ("x", false),
    ] {
        assert_eq!(check_value(&lxc.params["template"], value).is_ok(), ok, "template {value:?}");
    }
}

/// `quarantine` and `quarantine-release` (7.5.6, D61, D104): always high risk, so an approval with step-up; no trigger of their own
/// (the policy's automatic rules start `quarantine`, not an incident's routing); and neither needs an account on the machine,
/// because a Proxmox guest is isolated from its hypervisor, and an in-guest quarantine checks for the account itself.
#[test]
fn quarantine_runbooks_isolate_snapshot_and_release() {
    let parsed = |name: &str| Runbook::parse(builtin::runbook(name).unwrap_or_else(|| panic!("{name}"))).unwrap();
    let calls = |r: &Runbook| r.steps.iter().map(|s| s.call.clone().unwrap_or_default()).collect::<Vec<_>>();
    let q = parsed("quarantine");
    let release = parsed("quarantine-release");
    assert_eq!(calls(&q), ["quarantine_isolate", "quarantine_snapshot"]);
    assert_eq!(q.steps.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(), ["isolate", "snapshot"]);
    assert_eq!(calls(&release), ["quarantine_release"]);
    for r in [&q, &release] {
        assert_eq!((r.risk, r.autonomy), (crate::runbook::Risk::High, 1));
        assert!(r.triggers.is_none() && r.params.is_empty());
        assert!(r.steps.iter().all(|s| s.kind == StepKind::Hub && !s.needs_account() && s.timeout_s().is_some()));
        for kind in ["linux", "alpine", "windows"] {
            assert!(r.targets.kinds.iter().any(|k| k == kind), "{kind}");
        }
        assert!(!r.targets.kinds.iter().any(|k| k == "hypervisor"), "a hypervisor is never quarantined");
    }
}

/// `conntrack-flush` (7.5.6, D112): what a quarantine of a Proxmox guest runs on the hypervisor through its managed enrollment;
/// the command is in the hypervisor's list because this runbook is, and its one parameter is an address and nothing else.
#[test]
fn conntrack_flush_takes_one_address_for_the_hypervisor() {
    use crate::params::check_value;
    let r = Runbook::parse(builtin::runbook("conntrack-flush").expect("built in")).unwrap();
    assert_eq!(r.targets.kinds, ["hypervisor"]);
    assert_eq!((r.risk, r.autonomy), (crate::runbook::Risk::High, 1));
    assert!(r.triggers.is_none());
    let lines: Vec<String> = r.steps.iter().map(|s| s.cmd.as_ref().unwrap()[1..].join(" ")).collect();
    assert_eq!(
        lines,
        [
            format!("{WRAPPER} /usr/sbin/conntrack -D -s {{{{addr}}}}"),
            format!("{WRAPPER} /usr/sbin/conntrack -D -d {{{{addr}}}}"),
        ]
    );
    for (value, ok) in [
        ("192.0.2.151", true),
        ("2001:db8::10", true),
        ("fe80::1", true),
        ("192.0.2.1 -F", false),
        ("-F", false),
        ("a;b", false),
        ("", false),
        ("192.0.2.1/24", false),
    ] {
        assert_eq!(check_value(&r.params["addr"], value).is_ok(), ok, "{value:?}");
    }
    // the hypervisor's list has both commands
    let list = crate::templates::command_list(&[r]);
    assert_eq!(list.commands.len(), 2);
}

/// 7.8.8: the seven built-in playbooks parse, name the tools a job may use (and only real ones), and the ones an incident
/// starts say which kinds they are for.
#[test]
fn seven_playbooks_parse() {
    use crate::playbook::{Hosts, Playbook};
    const TOOLS: [&str; 18] = [
        "list_machines",
        "get_machine",
        "get_vitals",
        "list_incidents",
        "get_incident",
        "list_security_events",
        "get_connections",
        "run_diagnostic",
        "exec",
        "list_runbooks",
        "get_runbook",
        "run_runbook",
        "list_playbooks",
        "get_playbook",
        "propose_library_change",
        "get_approval",
        "add_incident_note",
        "finish_job",
    ];
    let names = [
        "patch-failure",
        "service-down",
        "disk-filling",
        "security-finding",
        "machine-silent",
        "backup-stale",
        "guided-install",
    ];
    assert_eq!(builtin::playbooks().iter().map(|(n, _)| *n).collect::<Vec<_>>(), names);
    for (name, source) in builtin::playbooks() {
        let p = Playbook::parse(source).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(p.name, *name);
        assert_eq!(p.autonomy, 1, "{name}: a playbook starts at level 1, a policy raises it");
        assert!(p.tools.iter().all(|t| TOOLS.contains(&t.as_str())), "{name}: {:?}", p.tools);
        assert!(p.tools.contains(&"finish_job".to_string()), "{name}: a job must be able to end itself");
        assert!(p.max_runtime_s().is_some_and(|s| s <= 1800), "{name}");
        assert!(!p.tools.contains(&"approve".to_string()), "no tool approves anything");
        let for_incidents = *name != "guided-install";
        assert_eq!(!p.incident_kinds.is_empty(), for_incidents, "{name}");
        assert_eq!(p.hosts, if for_incidents { Hosts::Incident } else { Hosts::Site }, "{name}");
    }
}
