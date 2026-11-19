//! Detached steps (7.3.7, D97, E54): `run job-start` starts the command in its own unit and returns; the hub polls
//! `run job-status` until the unit ends, then `run job-clean`. A failed poll (a dropped connection, sshd restarting) is
//! retried at the next interval: the command doesn't depend on the session.

use std::time::Duration;

use rackhand_runbook::templates::WRAPPER;
use serde::Deserialize;

use crate::actions::runner::{StepOutcome, StepResult};
use crate::ssh::client::{OUTPUT_CAP, TRUNCATED};

#[derive(Debug, Deserialize)]
pub(crate) struct Status {
    pub state: String,
    pub exit_code: Option<i64>,
    #[serde(default)]
    pub output: String,
    pub next_offset: u64,
}

fn wrapper(args: &[&str]) -> Vec<String> {
    ["sudo", WRAPPER].iter().chain(args).map(|s| s.to_string()).collect()
}

/// `sudo <wrapper> job-start <job>/<step> -- <args...>` for a step's `sudo <wrapper> <args...>`.
pub(crate) fn start_argv(job_ref: &str, step_argv: &[String]) -> Option<Vec<String>> {
    let rest = match step_argv {
        [sudo, w, rest @ ..] if sudo == "sudo" && w == WRAPPER => rest,
        _ => return None,
    };
    let mut argv = wrapper(&["job-start", job_ref, "--"]);
    argv.extend(rest.iter().cloned());
    Some(argv)
}

pub(crate) fn status_argv(job_ref: &str, offset: u64) -> Vec<String> {
    wrapper(&["job-status", job_ref, &offset.to_string()])
}

pub(crate) fn clean_argv(job_ref: &str) -> Vec<String> {
    wrapper(&["job-clean", job_ref])
}

/// Output gathered over the polls, capped like a plain step's.
#[derive(Debug, Default)]
pub(crate) struct Collected {
    pub offset: u64,
    pub output: Vec<u8>,
    cut: bool,
}

impl Collected {
    pub(crate) fn add(&mut self, status: &Status) {
        self.offset = status.next_offset.max(self.offset);
        if self.cut {
            return;
        }
        let data = status.output.as_bytes();
        let room = OUTPUT_CAP - self.output.len();
        if data.len() <= room {
            self.output.extend_from_slice(data);
        } else {
            self.output.extend_from_slice(&data[..room]);
            self.output.extend_from_slice(TRUNCATED.as_bytes());
            self.cut = true;
        }
    }
}

/// What a status means for the step: `None` while it runs (or has more output to read).
pub(crate) fn outcome(status: &Status) -> Option<(StepOutcome, Option<i64>)> {
    match status.state.as_str() {
        "running" | "starting" => None,
        // The rest of the output first.
        "exited" if !status.output.is_empty() => None,
        "exited" => Some(match status.exit_code {
            Some(0) => (StepOutcome::Succeeded, Some(0)),
            Some(n) => (StepOutcome::Failed(format!("exit_code {n}")), Some(n)),
            None => (StepOutcome::Failed("no_exit_status".into()), None),
        }),
        "stopped" => Some((StepOutcome::Failed("stopped".into()), status.exit_code)),
        "lost" => Some((StepOutcome::Failed("lost".into()), None)),
        _ => Some((StepOutcome::Failed("unknown".into()), None)),
    }
}

pub(crate) fn result(command: String, collected: Collected, end: (StepOutcome, Option<i64>)) -> StepResult {
    StepResult {
        outcome: end.0,
        command: Some(command),
        exit_code: end.1,
        stdout: collected.output,
        stderr: Vec::new(),
    }
}

/// The interval between polls (5 s in the design; shorter in tests).
pub const POLL: Duration = Duration::from_secs(5);
