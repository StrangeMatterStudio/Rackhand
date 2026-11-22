use super::runbook::COMPOSE_RESTART;
use crate::runbook::Runbook;
use crate::templates::{Arg, command_list};

#[test]
fn commands_json_generated_from_enabled_runbooks() {
    let compose = Runbook::parse(COMPOSE_RESTART).unwrap();
    let service = Runbook::parse(
        r#"
name = "service-restart"
description = "Restart a systemd service"
targets = { kinds = ["linux"] }
identity = "automation"
risk = "low"
autonomy = 1
[params.unit]
type = "string"
pattern = "[a-zA-Z0-9@._-]{1,128}\\.service"
[[step]]
id = "status"
kind = "ssh"
cmd = ["/usr/bin/systemctl", "is-active", "{{unit}}"]
[[step]]
id = "restart"
kind = "ssh"
cmd = ["sudo", "/usr/local/lib/rackhand/run", "/usr/bin/systemctl", "restart", "{{unit}}"]
[[step]]
id = "check"
kind = "verify"
checks = ["service_active:{{unit}}"]
"#,
    )
    .unwrap();
    let list = command_list(&[compose, service]);
    assert_eq!(list.commands.len(), 2, "only steps through the wrapper: {list:?}");
    let c = &list.commands[0];
    assert_eq!((c.runbook.as_str(), c.step.as_str()), ("compose-restart", "restart"));
    assert_eq!(c.args.len(), 5, "the wrapper path itself isn't part of the template");
    assert_eq!(c.args[0], Arg::Literal("/usr/bin/docker".into()));
    assert_eq!(c.args[2], Arg::Literal("-p".into()));
    let Arg::Param { name, regex, allow_leading_dash } = &c.args[3] else { panic!("{:?}", c.args[3]) };
    assert_eq!((name.as_str(), *allow_leading_dash), ("project", false));
    assert_eq!(regex, "^(?:^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,63}$)$", "one anchored regex per parameter");
    let json = serde_json::to_value(&list).unwrap();
    assert_eq!(json["commands"][1]["args"][2]["param"], "unit");
    assert_eq!(json["commands"][1]["args"][0]["literal"], "/usr/bin/systemctl");
}

/// A `reboot_if_required` step has no `cmd`: its fixed reboot command is in the list for the runbooks that have one.
#[test]
fn reboot_step_adds_its_fixed_command() {
    let patch = crate::runbook::Runbook::parse(crate::builtin::runbook("patch-debian").unwrap()).unwrap();
    let list = command_list(&[patch]);
    let reboot: Vec<_> = list.commands.iter().filter(|t| t.step == "reboot").collect();
    assert_eq!(reboot.len(), 2);
    assert_eq!(reboot[0].args, [Arg::Literal("/sbin/reboot".into())]);
    let scheduled: Vec<Arg> = crate::templates::REBOOT_IN_60S.iter().map(|a| Arg::Literal((*a).to_string())).collect();
    assert_eq!(reboot[1].args, scheduled, "the reboot of the machine the hub runs on (7.5.3 step 8)");
    assert_eq!(crate::templates::REBOOT_IN_60S[1], "--on-active=60");
    assert!(list.commands.iter().all(|t| t.step == "reboot" || !t.args.contains(&Arg::Literal("/sbin/reboot".into()))));
}
