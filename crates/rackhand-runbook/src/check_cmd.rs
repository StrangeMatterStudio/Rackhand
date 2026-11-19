//! `rackhand hub runbook check <file>` (12): syntax, parameters and step kinds, and sudo coverage: every step that
//! runs as root must be one the target's sudo rules allow.

use crate::runbook::{Identity, Runbook, StepKind};
use crate::templates::{WRAPPER, wrapped};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckReport {
    pub name: Option<String>,
    pub errors: Vec<String>,
    pub root_steps: usize,
    /// Root steps the automation user's sudo allow-list doesn't cover.
    pub uncovered: Vec<String>,
}

impl CheckReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty() && self.uncovered.is_empty()
    }

    pub fn summary(&self) -> String {
        let name = self.name.as_deref().unwrap_or("runbook");
        if !self.errors.is_empty() {
            return format!("{name}: invalid\n{}", self.errors.join("\n"));
        }
        let steps =
            if self.root_steps == 1 { "1 root step".to_string() } else { format!("{} root steps", self.root_steps) };
        if self.uncovered.is_empty() {
            format!("{name}: valid; {steps}, all allowed by sudo")
        } else {
            format!(
                "{name}: valid; {steps}, {} not allowed by sudo:\n{}",
                self.uncovered.len(),
                self.uncovered.join("\n")
            )
        }
    }
}

pub fn check(source: &str) -> CheckReport {
    let rb = match Runbook::parse(source) {
        Ok(rb) => rb,
        Err(e) => return CheckReport { errors: vec![e.to_string()], ..CheckReport::default() },
    };
    let mut report = CheckReport { name: Some(rb.name.clone()), ..CheckReport::default() };
    for step in rb.steps.iter().filter(|s| s.kind == StepKind::Ssh) {
        let Some(cmd) = step.cmd.as_deref() else { continue };
        if cmd.first().map(String::as_str) != Some("sudo") {
            continue;
        }
        report.root_steps += 1;
        // The assistant has sudo for everything (7.3.7); the automation user only for the wrapper.
        if rb.identity == Identity::Automation && wrapped(cmd).is_none() {
            let program = cmd.get(1).map(String::as_str).unwrap_or("");
            report.uncovered.push(format!(
                "step `{}` runs `sudo {program}`, which the automation user's sudo rules don't allow; run it as `sudo {WRAPPER} {program} ...`",
                step.id
            ));
        }
    }
    report
}
