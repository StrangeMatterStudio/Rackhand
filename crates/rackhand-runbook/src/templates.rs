//! `commands.json` (7.3.7, D92): one argument template per runbook step that runs as root through the command wrapper,
//! with an anchored regular expression for each parameter. The wrapper runs a request only if it matches one exactly.

use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};

use crate::runbook::{Runbook, StepKind};

/// What a `reboot_if_required` step runs through the wrapper, on systemd and OpenRC alike.
pub const REBOOT: &str = "/sbin/reboot";

/// The reboot of a machine the hub runs on, or of the hypervisor under it (7.5.3 steps 7 and 8): a minute away, so the
/// job's state is stored before the hub goes down with it.
pub const REBOOT_IN_60S: [&str; 4] = ["/usr/bin/systemd-run", "--on-active=60", "/usr/bin/systemctl", "reboot"];

/// The automation user's only sudo entry.
pub const WRAPPER: &str = "/usr/local/lib/rackhand/run";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    Literal(String),
    Param { name: String, regex: String, allow_leading_dash: bool },
}

impl Serialize for Arg {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Arg::Literal(text) => {
                let mut m = s.serialize_map(Some(1))?;
                m.serialize_entry("literal", text)?;
                m.end()
            }
            Arg::Param { name, regex, allow_leading_dash } => {
                let mut m = s.serialize_map(Some(3))?;
                m.serialize_entry("param", name)?;
                m.serialize_entry("regex", regex)?;
                m.serialize_entry("allow_leading_dash", allow_leading_dash)?;
                m.end()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Template {
    pub runbook: String,
    pub step: String,
    /// The arguments after the wrapper path.
    pub args: Vec<Arg>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CommandList {
    pub commands: Vec<Template>,
}

/// The argument list of an `ssh` step after `sudo <wrapper>`, if it has one.
pub(crate) fn wrapped(cmd: &[String]) -> Option<&[String]> {
    match cmd {
        [sudo, wrapper, rest @ ..] if sudo == "sudo" && wrapper == WRAPPER => Some(rest),
        _ => None,
    }
}

/// The command list for the enabled runbooks: their wrapped `ssh` steps, and the reboot of those that may reboot.
pub fn command_list(runbooks: &[Runbook]) -> CommandList {
    let mut commands = Vec::new();
    for rb in runbooks {
        for step in rb.steps.iter().filter(|s| s.kind == StepKind::Ssh) {
            let Some(args) = step.cmd.as_deref().and_then(wrapped) else { continue };
            let args = args
                .iter()
                .map(|a| {
                    let name = a.trim().strip_prefix("{{").and_then(|r| r.strip_suffix("}}")).map(str::trim);
                    match name.and_then(|n| rb.params.get(n).map(|p| (n, p))) {
                        Some((n, p)) => Arg::Param {
                            name: n.to_string(),
                            regex: p.regex(),
                            allow_leading_dash: p.allow_leading_dash,
                        },
                        None => Arg::Literal(a.clone()),
                    }
                })
                .collect();
            commands.push(Template { runbook: rb.name.clone(), step: step.id.clone(), args });
        }
        for step in rb.steps.iter().filter(|s| s.kind == StepKind::RebootIfRequired) {
            for args in [&[REBOOT][..], &REBOOT_IN_60S[..]] {
                let args = args.iter().map(|a| Arg::Literal((*a).to_string())).collect();
                commands.push(Template { runbook: rb.name.clone(), step: step.id.clone(), args });
            }
        }
    }
    CommandList { commands }
}
