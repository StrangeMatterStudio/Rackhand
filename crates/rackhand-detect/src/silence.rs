//! Silence (7.6.3): how long a subject may go without a report, scaled to its interval.

use crate::rules::Severity;

const SEC_MS: i64 = 1000;
const MIN_MS: i64 = 60 * SEC_MS;
/// No silence for this long after the hub starts.
const HUB_START_GRACE_MS: i64 = 3 * MIN_MS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    /// An enrolled probe, at its own report interval.
    Machine {
        interval_s: u32,
        expected_offline: bool,
    },
    /// An agentless machine, counted in failed driver polls in a row.
    Agentless {
        failed_polls: u32,
    },
    /// A peer hub, at its summary interval.
    Peer {
        summary_interval_s: u32,
    },
    Operator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub now_ms: i64,
    pub hub_started_ms: i64,
    /// A maintenance window covers the machine.
    pub in_maintenance: bool,
    /// A job on the machine includes a reboot and its wait step hasn't ended.
    pub reboot_job_waiting: bool,
}

fn intervals(n: i64, interval_s: u32) -> i64 {
    n * i64::from(interval_s) * SEC_MS
}

/// The silence severity of a subject last heard from at `last_seen_ms`.
pub fn silence(subject: &Subject, last_seen_ms: i64, ctx: &Context) -> Option<Severity> {
    if ctx.in_maintenance || ctx.reboot_job_waiting || ctx.now_ms - ctx.hub_started_ms < HUB_START_GRACE_MS {
        return None;
    }
    let silent = ctx.now_ms - last_seen_ms;
    let at = |warning_ms: i64, critical_ms: Option<i64>| {
        if critical_ms.is_some_and(|c| silent >= c) {
            Some(Severity::Critical)
        } else if silent >= warning_ms {
            Some(Severity::Warning)
        } else {
            None
        }
    };
    match *subject {
        Subject::Machine { interval_s, expected_offline } => {
            let warning = (60 * SEC_MS).max(intervals(4, interval_s));
            if expected_offline {
                return (silent >= warning).then_some(Severity::Info);
            }
            at(warning, Some((5 * MIN_MS).max(intervals(20, interval_s))))
        }
        Subject::Agentless { failed_polls } => match failed_polls {
            0..=1 => None,
            2..=4 => Some(Severity::Warning),
            _ => Some(Severity::Critical),
        },
        Subject::Peer { summary_interval_s } => {
            let warning = (2 * MIN_MS).max(intervals(3, summary_interval_s));
            // The design doesn't scale down; at long intervals it can't come before silent.
            at(warning, Some((10 * MIN_MS).max(warning)))
        }
        Subject::Operator => at(10 * MIN_MS, None),
    }
}
