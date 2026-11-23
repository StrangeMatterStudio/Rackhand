//! Checks a parsed runbook against the rules of 7.8.7 and 7.3.7.

use std::collections::HashSet;

use regex::Regex;

use crate::error::ModelError;
use crate::runbook::{HUB_CALLS, Runbook, Step, StepKind};

const MAX_AUTONOMY: u8 = 3;

/// `{{name}}` anywhere in a string.
fn placeholders(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else { break };
        out.push(after[..end].trim().to_string());
        rest = &after[end + 2..];
    }
    out
}

/// The line of a step's `id = "..."`, so errors point at the step.
fn step_line(source: &str, id: &str) -> Option<usize> {
    let re = Regex::new(&format!(r#"(?m)^\s*id\s*=\s*["']{}["']"#, regex::escape(id))).ok()?;
    re.find(source).map(|m| crate::error::line_of(source, m.start()))
}

pub(crate) fn runbook(rb: &Runbook, source: &str) -> Result<(), ModelError> {
    let top = |msg: String| Err(ModelError::new(msg, None));
    if rb.name.is_empty() || !rb.name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        return top(format!("runbook name `{}`: use a-z, 0-9 and -", rb.name));
    }
    if rb.autonomy > MAX_AUTONOMY {
        return top(format!("autonomy {} is above {MAX_AUTONOMY}", rb.autonomy));
    }
    if rb.steps.is_empty() {
        return top("a runbook needs at least one [[step]]".into());
    }
    for (name, param) in &rb.params {
        param.compile().map_err(|e| ModelError::new(format!("parameter `{name}`: {e}"), None))?;
    }
    let mut ids = HashSet::new();
    for step in &rb.steps {
        let fail =
            |msg: String| Err(ModelError::new(format!("step `{}`: {msg}", step.id), step_line(source, &step.id)));
        let id_ok = (1..=64).contains(&step.id.len())
            && step.id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !step.id.starts_with('-');
        if !id_ok {
            return fail("a step id is 1 to 64 of a-z, 0-9 and -, not starting with -".into());
        }
        if !ids.insert(step.id.as_str()) {
            return fail("the id is used twice".into());
        }
        if let Err(msg) = step_rules(rb, step) {
            return fail(msg);
        }
    }
    Ok(())
}

fn step_rules(rb: &Runbook, step: &Step) -> Result<(), String> {
    if step.retries > 0 && !step.idempotent {
        return Err("`retries` needs `idempotent = true`".into());
    }
    if step.detached && step.kind != StepKind::Ssh {
        return Err("only `ssh` steps can be `detached`".into());
    }
    if step.kind == StepKind::Hub {
        if !step.call.as_deref().is_some_and(|c| HUB_CALLS.contains(&crate::runbook::call_parts(c).0)) {
            return Err(format!("a `hub` step needs `call` to be one of {}", HUB_CALLS.join(", ")));
        }
        if step.cmd.is_some() || step.windows_script.is_some() {
            return Err("a `hub` step carries no command: the hub does what its `call` names".into());
        }
    }
    if step.always && step.kind != StepKind::RebootIfRequired {
        return Err("only `reboot_if_required` steps can be `always`".into());
    }
    if step.timeout.is_some() && step.timeout_s().is_none() {
        return Err(format!("timeout `{}`: use a number with s, m or h", step.timeout.as_deref().unwrap_or("")));
    }
    if step.kind == StepKind::Ssh {
        match (&step.cmd, &step.windows_script) {
            (Some(cmd), None) if !cmd.is_empty() => {}
            (None, Some(_)) => {}
            _ => return Err("an `ssh` step needs either `cmd` or `windows_script`".into()),
        }
    }
    let known = |name: &str| rb.params.contains_key(name);
    for arg in step.cmd.iter().flatten() {
        for name in placeholders(arg) {
            if !known(&name) {
                return Err(format!("`{{{{{name}}}}}` isn't a declared parameter"));
            }
            if arg.trim() != format!("{{{{{name}}}}}") {
                return Err(format!("`{arg}`: a parameter must be a whole argument"));
            }
        }
    }
    let texts =
        step.checks.iter().flatten().chain(step.message.iter()).chain(step.source.iter()).chain(step.dest.iter());
    for text in texts {
        if let Some(name) = placeholders(text).into_iter().find(|n| !known(n)) {
            return Err(format!("`{{{{{name}}}}}` isn't a declared parameter"));
        }
    }
    Ok(())
}
