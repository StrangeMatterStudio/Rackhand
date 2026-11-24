//! The `tunnel` runbook step (7.3.11): the step's `port` on the job's machine must be one its policy allows, and a tunnel to it
//! must open (through the machine's probe in remote mode). The step opens it and closes it again; what a runbook does with the
//! path, such as a sync to the server on that port, is the next step's own command.

use std::sync::Arc;

use rackhand_proto::tunnel::TunnelError;
use rackhand_runbook::runbook::Step;
use rackhand_store::Db;

use super::{StepCtx, StepResult, StepRunner};
use crate::actions::runner::BoxFuture;
use crate::peers::tunnel::{Backend, policy_ports, target};

pub struct TunnelStep {
    db: Arc<Db>,
    backend: Arc<dyn Backend>,
}

impl std::fmt::Debug for TunnelStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TunnelStep")
    }
}

impl TunnelStep {
    pub fn new(db: Arc<Db>, backend: Arc<dyn Backend>) -> TunnelStep {
        TunnelStep { db, backend }
    }
}

fn reason(e: TunnelError) -> &'static str {
    match e {
        TunnelError::OutOfScope => "out_of_scope",
        TunnelError::PortNotAllowed => "port_not_allowed",
        TunnelError::MachineUnreachable => "machine_unreachable",
        // a monitor machine has no account for the hub to use
        TunnelError::Unsupported => "monitor_only",
        TunnelError::Unspecified => "machine_unreachable",
    }
}

impl StepRunner for TunnelStep {
    fn run<'a>(&'a self, ctx: &'a StepCtx, step: &'a Step, _argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            let Some(port) = step.port else { return StepResult::failed("tunnel_needs_port") };
            let Some(machine) = target(&self.db, &ctx.machine_id) else { return StepResult::failed("out_of_scope") };
            if !policy_ports(&self.db, &ctx.machine_id).contains(&port) {
                return StepResult::failed("port_not_allowed");
            }
            match self.backend.open(&machine, port).await {
                Ok(stream) => {
                    drop(stream);
                    StepResult {
                        command: Some(format!("tunnel {port}")),
                        outcome: super::StepOutcome::Succeeded,
                        ..StepResult::failed("")
                    }
                }
                Err(e) => StepResult { command: Some(format!("tunnel {port}")), ..StepResult::failed(reason(e)) },
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rackhand_runbook::runbook::{Identity, StepKind};
    use rackhand_store::{Row, RowWrite, WriteCmd};
    use rusqlite::types::Value;

    use super::*;
    use crate::executor::StepOutcome;
    use crate::peers::tunnel::{Io, Target};

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    /// Opens into a pipe for ports it knows, and says unreachable for the rest.
    struct Fake(Vec<u16>);

    impl Backend for Fake {
        fn open<'a>(&'a self, _t: &'a Target, port: u16) -> BoxFuture<'a, Result<Box<dyn Io>, TunnelError>> {
            Box::pin(async move {
                if self.0.contains(&port) {
                    Ok(Box::new(tokio::io::duplex(8).0) as Box<dyn Io>)
                } else {
                    Err(TunnelError::MachineUnreachable)
                }
            })
        }
    }

    fn step(port: Option<u16>) -> Step {
        let toml =
            format!("id = \"path\"\nkind = \"tunnel\"\n{}", port.map(|p| format!("port = {p}\n")).unwrap_or_default());
        let step: Step = toml::from_str(&toml).expect("a step");
        assert_eq!(step.kind, StepKind::Tunnel);
        step
    }

    fn ctx(machine: &str) -> StepCtx {
        StepCtx {
            job_id: "j".into(),
            machine_id: machine.into(),
            machine_kind: "linux".into(),
            address: None,
            identity: Identity::Automation,
            timeout: Duration::from_secs(5),
        }
    }

    async fn db() -> Arc<Db> {
        let dir = std::env::temp_dir().join(format!("rackhand-tunnel-step-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
        let row = |table: &'static str, cols: Vec<(&'static str, Value)>| RowWrite::insert(table, Row::from_iter(cols));
        let machine = |id: &str, name: &str, policy: Option<&str>| {
            let mut cols = vec![
                ("id", t(id)),
                ("site_id", t("s1")),
                ("name", t(name)),
                ("kind", t("linux")),
                ("state", t("enrolled")),
            ];
            if let Some(p) = policy {
                cols.push(("policy_id", t(p)));
            }
            row("machines", cols)
        };
        db.writer()
            .send(WriteCmd::Batch(vec![
                row(
                    "sites",
                    vec![
                        ("id", t("s1")),
                        ("name", t("alpha")),
                        ("timezone", t("UTC")),
                        ("is_local", Value::Integer(1)),
                    ],
                ),
                row("policies", vec![("id", t("pbs")), ("name", t("pbs")), ("tunnel_ports", t("[22, 8007]"))]),
                machine("01J1000000000000000000000A", "backup", Some("pbs")),
                machine("01J1000000000000000000000B", "plain", None),
            ]))
            .await
            .unwrap();
        db
    }

    #[tokio::test]
    async fn tunnel_step_checks_policy_and_reachability() {
        let runner = TunnelStep::new(db().await, Arc::new(Fake(vec![8007, 22])));
        let (backup, plain) = ("01J1000000000000000000000A", "01J1000000000000000000000B");
        let outcome = |r: StepResult| r.outcome;
        // a port the policy allows and that opens
        let ok = runner.run(&ctx(backup), &step(Some(8007)), None).await;
        assert_eq!((ok.outcome, ok.command.as_deref()), (StepOutcome::Succeeded, Some("tunnel 8007")));
        // a port the policy doesn't allow is refused before anything is opened, and the default is 22 only
        assert_eq!(
            outcome(runner.run(&ctx(backup), &step(Some(9999)), None).await),
            StepOutcome::Failed("port_not_allowed".into())
        );
        assert_eq!(
            outcome(runner.run(&ctx(plain), &step(Some(8007)), None).await),
            StepOutcome::Failed("port_not_allowed".into())
        );
        assert_eq!(outcome(runner.run(&ctx(plain), &step(Some(22)), None).await), StepOutcome::Succeeded);
        // an allowed port nothing answers on, a step with no port, and a machine that isn't this site's
        let runner = TunnelStep::new(db().await, Arc::new(Fake(vec![])));
        assert_eq!(
            outcome(runner.run(&ctx(backup), &step(Some(8007)), None).await),
            StepOutcome::Failed("machine_unreachable".into())
        );
        assert_eq!(
            outcome(runner.run(&ctx(backup), &step(None), None).await),
            StepOutcome::Failed("tunnel_needs_port".into())
        );
        assert_eq!(
            outcome(runner.run(&ctx("01J1000000000000000000000Z"), &step(Some(22)), None).await),
            StepOutcome::Failed("out_of_scope".into())
        );
    }
}
