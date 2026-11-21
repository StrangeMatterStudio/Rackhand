//! `wait_report` steps (7.8.7): a step succeeds once a report from its machine arrives after the step started, and
//! fails `timeout` if none arrives within the step's timeout.

use std::time::Duration;

use rackhand_runbook::runbook::{Step, StepKind};
use rackhand_store::ids::now_ms;

use super::Ingest;
use crate::actions::runner::{BoxFuture, StepCtx, StepOutcome, StepResult, StepRunner};

const POLL: Duration = Duration::from_millis(250);

impl StepRunner for Ingest {
    fn run<'a>(&'a self, ctx: &'a StepCtx, step: &'a Step, _argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            if step.kind != StepKind::WaitReport {
                return StepResult::failed("wait_report_only");
            }
            let started = now_ms();
            let deadline = tokio::time::Instant::now() + ctx.timeout;
            loop {
                if self.last_seen(&ctx.machine_id).is_some_and(|seen| seen > started) {
                    return StepResult { outcome: StepOutcome::Succeeded, ..StepResult::failed("") };
                }
                if tokio::time::Instant::now() >= deadline {
                    return StepResult::failed("timeout");
                }
                tokio::time::sleep(POLL).await;
            }
        })
    }
}
