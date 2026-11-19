use crate::runbook::{Identity, Risk, Runbook, StepKind};

/// The example in design 7.8.7.
pub(crate) const COMPOSE_RESTART: &str = r#"
name = "compose-restart"
description = "Restart one Docker Compose project and check its containers"
targets = { kinds = ["linux"] }
identity = "automation"          # or "assistant"
risk = "low"                     # low | normal | high
autonomy = 1
triggers = { incident_kinds = ["container.restarting"], auto = false }
[params.project]
type = "string"
pattern = "^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,63}$"   # whole value; a leading "-" is refused in any case (7.3.7)
[[step]]
id = "restart"
kind = "ssh"
cmd = ["sudo", "/usr/local/lib/rackhand/run", "/usr/bin/docker", "compose", "-p", "{{project}}", "restart"]
timeout = "5m"
[[step]]
id = "verify"
kind = "verify"
checks = ["containers_running:{{project}}"]
on_failure = { playbook = "compose-failure" }
"#;

#[test]
fn compose_restart_example_parses() {
    let rb = Runbook::parse(COMPOSE_RESTART).unwrap();
    assert_eq!(rb.name, "compose-restart");
    assert_eq!(rb.targets.kinds, ["linux"]);
    assert_eq!((rb.identity, rb.risk, rb.autonomy), (Identity::Automation, Risk::Low, 1));
    let triggers = rb.triggers.as_ref().unwrap();
    assert_eq!((triggers.incident_kinds.as_slice(), triggers.auto), (&["container.restarting".to_string()][..], false));
    assert_eq!(rb.params["project"].pattern.as_deref(), Some("^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,63}$"));
    assert_eq!(rb.steps.len(), 2);
    assert_eq!((rb.steps[0].kind, rb.steps[0].timeout_s()), (StepKind::Ssh, Some(300)));
    assert_eq!(rb.steps[0].cmd.as_ref().unwrap()[5], "{{project}}");
    assert_eq!(rb.steps[1].kind, StepKind::Verify);
    assert_eq!(rb.steps[1].on_failure.as_ref().unwrap().playbook, "compose-failure");
}

#[test]
fn unknown_step_kind_or_field_is_an_error_with_location() {
    let kind = COMPOSE_RESTART.replace("kind = \"verify\"", "kind = \"teleport\"");
    let err = Runbook::parse(&kind).unwrap_err();
    let line = 1 + kind[..kind.find("teleport").unwrap()].matches('\n').count();
    assert_eq!(err.line, Some(line), "{err}");
    assert!(err.to_string().contains(&format!("line {line}")), "{err}");
    assert!(err.to_string().contains("teleport"), "{err}");

    // Step ids follow the wrapper's job-step format (`a-z`, `0-9`, `-`, not starting with `-`), so a detached step
    // can't fail on its id at run time.
    for bad in ["Restart", "re start", "-restart", "restart/now", ""] {
        let src = COMPOSE_RESTART.replace("id = \"restart\"", &format!("id = \"{bad}\""));
        let err = Runbook::parse(&src).unwrap_err();
        assert!(err.to_string().contains("step id"), "{bad:?}: {err}");
    }
    let field = COMPOSE_RESTART.replace("timeout = \"5m\"", "timeout = \"5m\"\nshell = true");
    let err = Runbook::parse(&field).unwrap_err();
    let line = 1 + field[..field.find("shell = true").unwrap()].matches('\n').count();
    assert_eq!(err.line, Some(line), "{err}");
    assert!(err.to_string().contains("shell"), "{err}");
}

#[test]
fn retries_without_idempotent_refused() {
    let src = COMPOSE_RESTART.replace("timeout = \"5m\"", "timeout = \"5m\"\nretries = 2");
    let err = Runbook::parse(&src).unwrap_err();
    assert!(err.to_string().contains("restart") && err.to_string().contains("idempotent"), "{err}");
    let line = 1 + src[..src.find("id = \"restart\"").unwrap()].matches('\n').count();
    assert_eq!(err.line, Some(line), "the error points at the step");
    let ok = COMPOSE_RESTART.replace("timeout = \"5m\"", "timeout = \"5m\"\nretries = 2\nidempotent = true");
    assert_eq!(Runbook::parse(&ok).unwrap().steps[0].retries, 2);
}

#[test]
fn detached_step_is_resumable() {
    let src = COMPOSE_RESTART.replace("timeout = \"5m\"", "timeout = \"5m\"\ndetached = true");
    let rb = Runbook::parse(&src).unwrap();
    assert!(rb.steps[0].detached && rb.steps[0].is_resumable(), "detached implies resumable");
    assert!(!rb.steps[1].is_resumable());
    let not_ssh = COMPOSE_RESTART.replace("on_failure", "detached = true\non_failure");
    let err = Runbook::parse(&not_ssh).unwrap_err();
    assert!(err.to_string().contains("detached"), "only ssh steps run detached: {err}");
}
