use crate::playbook::{Hosts, Playbook};
use crate::runbook::Risk;

/// The example in design 7.8.8, with some text in each section.
const PATCH_FAILURE: &str = r#"+++
name = "patch-failure"
incident_kinds = ["patch_failed"]
autonomy = 1
risk = "normal"
tools = ["get_incident", "get_machine", "get_vitals", "run_diagnostic", "exec", "run_runbook", "add_incident_note", "finish_job"]
hosts = "incident"               # incident | site
max_runtime = "30m"
+++
## When
A patch job failed.
## Read first
The job transcript.
## Do
Find out why.
## Done when
The machine is patched.
## Stop and ask if
A rollback looks needed.
"#;

#[test]
fn front_matter_and_sections_parse() {
    let pb = Playbook::parse(PATCH_FAILURE).unwrap();
    assert_eq!(pb.name, "patch-failure");
    assert_eq!(pb.incident_kinds, ["patch_failed"]);
    assert_eq!((pb.autonomy, pb.risk, pb.hosts), (1, Risk::Normal, Hosts::Incident));
    assert_eq!(pb.tools.len(), 8);
    assert!(pb.tools.iter().any(|t| t == "exec"));
    assert_eq!(pb.max_runtime_s(), Some(1800));
    assert_eq!(pb.section("When"), Some("A patch job failed."));
    assert_eq!(pb.section("Stop and ask if"), Some("A rollback looks needed."));
    assert!(Playbook::parse("no front matter").is_err());
    let missing = PATCH_FAILURE.replace("## Done when\nThe machine is patched.\n", "");
    let err = Playbook::parse(&missing).unwrap_err();
    assert!(err.to_string().contains("Done when"), "{err}");
    let site = PATCH_FAILURE.replace("hosts = \"incident\"", "hosts = \"everywhere\"");
    assert!(Playbook::parse(&site).is_err());
}
