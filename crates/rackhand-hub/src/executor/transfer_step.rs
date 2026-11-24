//! The `transfer` runbook step (7.3.11): a backup tool's stream from the job's machine to another machine, with no file in
//! between. The step's `cmd` is `zfs-send <dataset>@<snapshot>`, run on the job's machine through the wrapper; its output is
//! piped into `zfs-recv <dataset>` on the machine in `dest`, which is `<site>/<machine>:zfs-recv <dataset>`. A machine of this
//! hub's own site is written to directly; one of a peer's goes over `rackhand/xfer/1` to that peer, direct paths only unless the
//! step sets `allow_relay` (E29), and the peer hub takes it only where the machine's policy takes streams from peers.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use iroh::{EndpointAddr, EndpointId, TransportAddr};
use prost::Message;
use rackhand_net::xfer;
use rackhand_proto::peer::SiteSummary;
use rackhand_runbook::runbook::Step;
use rackhand_store::Db;
use rusqlite::OptionalExtension;
use tokio::io::AsyncWriteExt;

use super::{StepCtx, StepOutcome, StepResult, StepRunner};
use crate::actions::runner::{BoxFuture, display};
use crate::peers::tunnel::Network;
use crate::peers::xfer::Sink;
use crate::peers::xfer_machine::MachineOpener;
use crate::ssh::keys::Identity as SshIdentity;
use crate::ssh::quote;

const WRAPPER: &str = "/usr/local/lib/rackhand/run";

/// What the step needs once the Executor and the hub's endpoint exist.
struct Bound {
    executor: Arc<super::Executor>,
    machines: Arc<MachineOpener>,
}

pub struct TransferStep {
    db: Arc<Db>,
    network: Arc<Network>,
    bound: OnceLock<Bound>,
}

impl std::fmt::Debug for TransferStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransferStep")
    }
}

/// Where a stream goes: `<site>/<machine>:<command>`.
#[derive(Debug, PartialEq, Eq)]
struct Dest {
    site: String,
    machine: String,
    command: String,
}

fn parse_dest(dest: &str) -> Option<Dest> {
    let (place, command) = dest.split_once(':')?;
    let (site, machine) = place.split_once('/')?;
    let plain = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
    (plain(site) && plain(machine) && !command.is_empty()).then(|| Dest {
        site: site.into(),
        machine: machine.into(),
        command: command.into(),
    })
}

impl TransferStep {
    pub fn new(db: Arc<Db>, network: Arc<Network>) -> TransferStep {
        TransferStep { db, network, bound: OnceLock::new() }
    }

    /// The Executor that runs the sending command, and what opens the receiving ones; set when both exist.
    pub fn bind(&self, executor: Arc<super::Executor>, machines: Arc<MachineOpener>) {
        let _ = self.bound.set(Bound { executor, machines });
    }

    fn local_site(&self) -> Option<String> {
        self.db
            .readers()
            .with(|c| {
                c.query_row("SELECT name FROM sites WHERE is_local = 1", [], |r| r.get::<_, String>(0)).optional()
            })
            .ok()
            .flatten()
    }

    fn machine_here(&self, name: &str) -> Option<String> {
        self.db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT m.id FROM machines m JOIN sites s ON s.id = m.site_id WHERE s.is_local = 1 AND m.name = ?1",
                    [name],
                    |r| r.get(0),
                )
                .optional()
            })
            .ok()
            .flatten()
    }

    /// The peer's endpoint and the id of the machine named `name` in its last summary.
    fn machine_there(&self, site: &str, name: &str) -> Result<(EndpointId, Vec<u8>), String> {
        let row: Option<(String, Vec<u8>)> = self
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT p.endpoint_id, s.summary FROM peers p JOIN peer_summaries s ON s.peer_id = p.id
                     WHERE p.site = ?1 AND p.revoked_at IS NULL",
                    [site],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
            })
            .ok()
            .flatten();
        let (endpoint, summary) =
            row.ok_or_else(|| format!("no_such_peer: {site} is not a linked site this hub has heard from"))?;
        let summary =
            SiteSummary::decode(summary.as_slice()).map_err(|_| "the peer's summary can't be read".to_string())?;
        let machine = summary
            .machines
            .iter()
            .find(|m| m.name == name)
            .ok_or_else(|| format!("no_such_machine: {site} has no machine named {name}"))?;
        let id: EndpointId = endpoint.parse().map_err(|_| "the peer's endpoint id isn't one".to_string())?;
        Ok((id, machine.id.clone()))
    }

    async fn run_stream(&self, ctx: &StepCtx, step: &Step, argv: &[String]) -> Result<String, String> {
        let bound = self.bound.get().ok_or("transfer_unavailable")?;
        if argv.len() != 2 || argv[0] != "zfs-send" {
            return Err("transfer_cmd_not_allowed: a stream is `zfs-send <dataset>@<snapshot>`".into());
        }
        let dest = step
            .dest
            .as_deref()
            .and_then(parse_dest)
            .ok_or("transfer_needs_dest: `<site>/<machine>:zfs-recv <dataset>`")?;
        let mut line = vec!["sudo".to_string(), WRAPPER.to_string()];
        line.extend(argv.iter().cloned());
        let mut source = bound
            .executor
            .stream(ctx, SshIdentity::Automation, &quote::join(&line), ctx.timeout)
            .await
            .map_err(|e| format!("machine_unreachable: {e}"))?;
        let sent: u64;
        if self.local_site().as_deref() == Some(dest.site.as_str()) {
            let machine =
                self.machine_here(&dest.machine).ok_or_else(|| format!("no_such_machine: {}", dest.machine))?;
            let mut sink: Box<dyn Sink> = bound.machines.local_stream_sink(&machine, &dest.command)?;
            let (mut index, mut total) = (0u64, 0u64);
            while let Some(data) = source.read().await {
                total += data.len() as u64;
                if let Err(e) = sink.write(index, &data).await {
                    sink.abandon().await;
                    return Err(e);
                }
                index += 1;
            }
            sink.finish().await?;
            sent = total;
        } else {
            let (peer, machine) = self.machine_there(&dest.site, &dest.machine)?;
            let endpoint = self.network.endpoint().ok_or("the hub's endpoint isn't up")?;
            let mut addr = EndpointAddr::new(peer);
            for relay in self.network.relays() {
                addr.addrs.insert(TransportAddr::Relay(relay.clone()));
            }
            let conn =
                tokio::time::timeout(Duration::from_secs(30), endpoint.connect(addr, rackhand_proto::alpn::XFER))
                    .await
                    .map_err(|_| "machine_unreachable: the peer didn't answer".to_string())?
                    .map_err(|e| format!("machine_unreachable: {e}"))?;
            let now = || rackhand_store::ids::now_ms();
            xfer::wait_for_direct(&conn, step.allow_relay, &now, &mut || tracing::info!("bulk_waiting_direct_path"))
                .await;
            let (mut write, mut read) = tokio::io::duplex(4 << 20);
            let pump = tokio::spawn(async move {
                while let Some(data) = source.read().await {
                    if write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                drop(write);
                source
            });
            let result = xfer::send_stream(&conn, &machine, &dest.command, &mut read).await;
            drop(read);
            source = pump.await.map_err(|e| e.to_string())?;
            sent = result.map_err(|e| e.to_string())?;
        }
        let out = source.finish(Duration::from_secs(60)).await.map_err(|e| format!("machine_unreachable: {e}"))?;
        match out.exit_code {
            Some(0) => Ok(format!("{sent} bytes")),
            code => Err(format!("{} failed (exit {code:?}): {}", argv[0], String::from_utf8_lossy(&out.stderr).trim())),
        }
    }
}

impl StepRunner for TransferStep {
    fn run<'a>(&'a self, ctx: &'a StepCtx, step: &'a Step, argv: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async move {
            let Some(argv) = argv.filter(|a| !a.is_empty()) else { return StepResult::failed("transfer_needs_cmd") };
            let command = format!("{} -> {}", display(argv), step.dest.as_deref().unwrap_or("?"));
            match self.run_stream(ctx, step, argv).await {
                Ok(note) => StepResult {
                    command: Some(command),
                    outcome: StepOutcome::Succeeded,
                    stdout: note.into_bytes(),
                    ..StepResult::failed("")
                },
                Err(why) => StepResult { command: Some(command), ..StepResult::failed(why) },
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_destination_is_a_site_a_machine_and_a_command() {
        assert_eq!(
            parse_dest("offsite/backup-1:zfs-recv tank/replica"),
            Some(Dest { site: "offsite".into(), machine: "backup-1".into(), command: "zfs-recv tank/replica".into() })
        );
        for bad in [
            "",
            "offsite",
            "offsite/backup-1",
            "offsite/backup-1:",
            "/m:zfs-recv a",
            "s/:zfs-recv a",
            "a b/m:zfs-recv a",
            "s/m x:c",
        ] {
            assert_eq!(parse_dest(bad), None, "{bad:?}");
        }
    }
}
