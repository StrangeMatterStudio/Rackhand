//! `probe_check` steps (7.8.7, D115): each check of the step goes to the machine's connected probe as `RunCheck` on
//! stream 0, one after the other, and the probe answers `CheckResult`. The step passes when every check passes and
//! fails with the first failing check's name, its detail in the step's stderr.

use std::sync::Arc;
use std::time::Duration;

use rackhand_proto::probe::{HubToProbe, RunCheck, hub_to_probe};
use rackhand_runbook::runbook::{Step, StepKind};

use super::probe_server::Outbound;
use crate::actions::runner::{BoxFuture, StepCtx, StepOutcome, StepResult, StepRunner};

/// The longest one check may take on the probe.
const MAX_CHECK: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct ProbeChecks {
    outbound: Arc<Outbound>,
}

impl ProbeChecks {
    pub(crate) fn new(outbound: Arc<Outbound>) -> ProbeChecks {
        ProbeChecks { outbound }
    }

    /// One check on the machine's probe: `Ok(detail)` when it passed, `Err(reason)` otherwise.
    async fn one(&self, machine: &str, check: &str, timeout: Duration) -> Result<String, String> {
        let Some(probe) = self.outbound.to(machine) else { return Err("probe_not_connected".into()) };
        let id = ulid::Ulid::new().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.outbound.pending().insert(id.clone(), tx);
        let timeout_ms = timeout.min(MAX_CHECK).as_millis() as u32;
        let msg = HubToProbe {
            msg: Some(hub_to_probe::Msg::RunCheck(RunCheck { id: id.clone(), check: check.into(), timeout_ms })),
        };
        if probe.send(msg).await.is_err() {
            self.outbound.pending().remove(&id);
            return Err("probe_not_connected".into());
        }
        // the probe's own timeout plus the round trip
        let answer = tokio::time::timeout(timeout + Duration::from_secs(5), rx).await;
        self.outbound.pending().remove(&id);
        match answer {
            Ok(Ok(r)) if r.ok => Ok(r.detail),
            Ok(Ok(r)) => Err(r.detail),
            Ok(Err(_)) => Err("the probe went away".into()),
            Err(_) => Err("no answer from the probe".into()),
        }
    }
}

impl StepRunner for ProbeChecks {
    fn run<'a>(&'a self, ctx: &'a StepCtx, step: &'a Step, _argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            if step.kind != StepKind::ProbeCheck {
                return StepResult::failed("probe_check_only");
            }
            let checks = step.checks.clone().unwrap_or_default();
            let deadline = tokio::time::Instant::now() + ctx.timeout;
            let mut passed = String::new();
            for check in &checks {
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                match self.one(&ctx.machine_id, check, left.min(MAX_CHECK)).await {
                    Ok(detail) => passed.push_str(&format!("{check} passed: {detail}\n")),
                    Err(reason) if reason == "probe_not_connected" => return StepResult::failed(reason),
                    Err(reason) => {
                        return StepResult {
                            stdout: passed.into_bytes(),
                            stderr: format!("{check}: {reason}\n").into_bytes(),
                            ..StepResult::failed(check.clone())
                        };
                    }
                }
            }
            StepResult { outcome: StepOutcome::Succeeded, stdout: passed.into_bytes(), ..StepResult::failed("") }
        })
    }
}
