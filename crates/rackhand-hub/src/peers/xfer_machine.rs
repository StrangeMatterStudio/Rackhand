//! Transfers to a machine (7.3.11, FR-19, E30): a device with a responder or admin account sends a file to a machine of this
//! site, or pipes a stream into its `zfs-recv`. The hub writes a file over SSH as `rackhand`, through the wrapper command `run
//! receive <dest> <blake3> <offset>`, which keeps the partial file for the next attempt; a stream goes to `run zfs-recv
//! <dataset>`. The wrapper checks the destination against the policy's `transfer_roots` again, on the machine.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::EndpointId;
use rackhand_net::xfer::CHUNK;
use rackhand_proto::tunnel::{XferKind, XferOffer};
use rackhand_runbook::runbook::Identity;
use rackhand_store::Db;
use rusqlite::OptionalExtension;

use super::tunnel::{Target, person, target};
use super::xfer::{Opener, Sink};
use crate::actions::runner::{BoxFuture, StepCtx};
use crate::audit::Audit;
use crate::executor::Executor;
use crate::ssh::client::Exec;
use crate::ssh::keys::Identity as SshIdentity;
use crate::ssh::quote;

const WRAPPER: &str = "/usr/local/lib/rackhand/run";
const DEFAULT_ROOT: &str = "/var/lib/rackhand-run/incoming";
/// How long a chunk write or the whole-file check may take.
const STEP: Duration = Duration::from_secs(3600);

/// A partial file that ended up not matching its hash must start again: (machine, destination, hash).
type Restarts = Arc<Mutex<HashSet<(String, String, String)>>>;

pub struct MachineOpener {
    db: Arc<Db>,
    audit: Audit,
    executor: Arc<Executor>,
    restarts: Restarts,
}

impl std::fmt::Debug for MachineOpener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MachineOpener")
    }
}

impl MachineOpener {
    pub fn new(db: Arc<Db>, audit: Audit, executor: Arc<Executor>) -> MachineOpener {
        MachineOpener { db, audit, executor, restarts: Restarts::default() }
    }

    fn roots(&self, machine: &str) -> Vec<String> {
        let json: Option<String> = self
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT p.transfer_roots FROM machines m LEFT JOIN policies p ON p.id = m.policy_id WHERE m.id = ?1",
                    [machine],
                    |r| r.get(0),
                )
                .optional()
            })
            .ok()
            .flatten()
            .flatten();
        json.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_else(|| vec![DEFAULT_ROOT.to_string()])
    }

    fn ctx(&self, t: &Target) -> StepCtx {
        let kind: String = self
            .db
            .readers()
            .with(|c| c.query_row("SELECT kind FROM machines WHERE id = ?1", [&t.id], |r| r.get(0)))
            .unwrap_or_else(|_| "linux".into());
        StepCtx {
            job_id: "xfer".into(),
            machine_id: t.id.clone(),
            machine_kind: kind,
            address: t.address.clone(),
            identity: Identity::Automation,
            timeout: STEP,
        }
    }

    /// The site of the linked peer behind this endpoint, if it is one.
    fn peer_site(&self, caller: EndpointId) -> Option<String> {
        self.db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT site FROM peers WHERE endpoint_id = ?1 AND revoked_at IS NULL",
                    [caller.to_string()],
                    |r| r.get(0),
                )
                .optional()
            })
            .ok()
            .flatten()
    }

    /// A stream from a peer (a backup tool's output, 7.3.11): an action on this hub's machine that a peer asked for, so the
    /// machine's policy must take them without an approval (`peer_requests = "auto"`, 7.5.5). Nothing else comes from a peer.
    fn check_peer(&self, site: &str, offer: &XferOffer) -> Result<(Target, String), String> {
        if offer.kind != XferKind::Stream as i32 {
            return Err("a peer sends a stream to a machine, or its backup to this hub, and nothing else".into());
        }
        let (t, _) = self.checked_machine(offer)?;
        let auto: Option<String> = self
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT p.peer_requests FROM machines m LEFT JOIN policies p ON p.id = m.policy_id WHERE m.id = ?1",
                    [&t.id],
                    |r| r.get(0),
                )
                .optional()
            })
            .ok()
            .flatten()
            .flatten();
        if auto.as_deref() != Some("auto") {
            return Err("needs_approval: the machine's policy doesn't take streams from peers without one".into());
        }
        Ok((t, format!("peer:{site}")))
    }

    /// A sink for the hub's own job: the machine's `command`, which a stream is piped into.
    pub fn local_stream_sink(&self, machine_id: &str, dest: &str) -> Result<Box<dyn Sink>, String> {
        let t = target(&self.db, machine_id).ok_or("no such machine at this site")?;
        if t.access == "monitor" {
            return Err("monitor_only: the machine has no account for the hub to write with".into());
        }
        let argv = stream_command(dest)?;
        Ok(Box::new(StreamSink { executor: self.executor.clone(), ctx: self.ctx(&t), argv, exec: None }))
    }

    /// The machine an offer names: of this site, with an account for the hub, and not isolated.
    fn checked_machine(&self, offer: &XferOffer) -> Result<(Target, String), String> {
        let id = <[u8; 16]>::try_from(offer.target.as_slice()).map_err(|_| "no such machine")?;
        let machine = ulid::Ulid::from_bytes(id).to_string();
        let t = target(&self.db, &machine).ok_or("no such machine at this site")?;
        if t.access == "monitor" {
            return Err("monitor_only: the machine has no account for the hub to write with".into());
        }
        let quarantined: String = self
            .db
            .readers()
            .with(|c| c.query_row("SELECT quarantine FROM machines WHERE id = ?1", [&machine], |r| r.get(0)))
            .unwrap_or_else(|_| "none".into());
        if quarantined != "none" {
            return Err("machine_quarantined: nothing is sent to a machine that is isolated".into());
        }
        Ok((t, machine))
    }

    /// Why this offer can't go to the machine, or the machine.
    fn check(&self, caller: EndpointId, offer: &XferOffer) -> Result<(Target, String), String> {
        if let Some(site) = self.peer_site(caller) {
            return self.check_peer(&site, offer);
        }
        let who = person(&self.db, caller).ok_or("this device isn't one that may send")?;
        if !matches!(who.role.as_str(), "responder" | "admin") {
            return Err("only a responder or an admin may send files".into());
        }
        let (t, _) = self.checked_machine(offer)?;
        Ok((t, format!("user:{}", who.user)))
    }
}

/// The receiving command of a stream: only `zfs-recv <dataset>`, and what the wrapper takes for it.
fn stream_command(dest: &str) -> Result<Vec<String>, String> {
    let words: Vec<&str> = dest.split(' ').collect();
    match words.as_slice() {
        ["zfs-recv", dataset] if !dataset.is_empty() => Ok(vec!["zfs-recv".into(), (*dataset).into()]),
        _ => Err("a stream goes to `zfs-recv <dataset>` and nothing else".into()),
    }
}

/// Whether `dest` is a plain absolute path strictly inside one of the roots.
fn within(dest: &str, roots: &[String]) -> bool {
    let plain = dest.starts_with('/')
        && !dest.chars().any(char::is_control)
        && !dest.ends_with('/')
        && !dest.split('/').skip(1).any(|c| c.is_empty() || c == "." || c == "..");
    plain && roots.iter().any(|r| dest.strip_prefix(r.as_str()).is_some_and(|rest| rest.starts_with('/')))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Opener for MachineOpener {
    fn open<'a>(&'a self, caller: EndpointId, offer: &'a XferOffer) -> BoxFuture<'a, Result<Box<dyn Sink>, String>> {
        Box::pin(async move {
            let checked = self.check(caller, offer);
            let who = self
                .peer_site(caller)
                .map(|s| format!("peer:{s}"))
                .or_else(|| person(&self.db, caller).map(|p| format!("user:{}", p.user)))
                .unwrap_or_else(|| format!("endpoint:{}", caller.fmt_short()));
            let machine = hex(&offer.target);
            let (t, actor) = match checked {
                Ok(ok) => ok,
                Err(why) => {
                    let data = serde_json::json!({ "dest": offer.dest, "reason": why });
                    let _ = self.audit.append(&who, "xfer.refused", Some(&machine), &data.to_string()).await;
                    return Err(why);
                }
            };
            let stream = offer.kind == XferKind::Stream as i32;
            let sink: Result<Box<dyn Sink>, String> = if stream {
                stream_command(&offer.dest).map(|argv| {
                    Box::new(StreamSink { executor: self.executor.clone(), ctx: self.ctx(&t), argv, exec: None })
                        as Box<dyn Sink>
                })
            } else if within(&offer.dest, &self.roots(&t.id)) {
                Ok(Box::new(FileSink {
                    executor: self.executor.clone(),
                    ctx: self.ctx(&t),
                    dest: offer.dest.clone(),
                    hash: hex(&offer.blake3),
                    size: offer.size,
                    restarts: self.restarts.clone(),
                    start: 0,
                    exec: None,
                }) as Box<dyn Sink>)
            } else {
                Err("the destination isn't under the machine's transfer roots".to_string())
            };
            let action = if sink.is_ok() { "xfer.opened" } else { "xfer.refused" };
            let data = serde_json::json!({ "dest": offer.dest, "size": offer.size, "stream": stream });
            let _ = self.audit.append(&actor, action, Some(&t.id), &data.to_string()).await;
            sink
        })
    }
}

fn receive_line(dest: &str, hash: &str, offset: u64) -> String {
    quote::join(&[
        "sudo".to_string(),
        WRAPPER.to_string(),
        "receive".into(),
        dest.to_string(),
        hash.to_string(),
        offset.to_string(),
    ])
}

/// The partial file's size, from the wrapper's refusal of an offset that can't be right.
fn partial_size(stderr: &[u8]) -> Option<u64> {
    let text = String::from_utf8_lossy(stderr);
    let rest = text.split("the partial file has ").nth(1)?;
    rest.split_whitespace().next()?.parse().ok()
}

/// Closes a command's input and waits a little for it to end, so that what was written is not cut off.
async fn settle(mut exec: Exec) {
    if exec.close_stdin().await.is_ok() {
        let _ = exec.finish(Duration::from_secs(30)).await;
    }
}

struct FileSink {
    executor: Arc<Executor>,
    ctx: StepCtx,
    dest: String,
    hash: String,
    size: u64,
    restarts: Restarts,
    /// Where the machine's partial file ends: the byte `receive` goes on from.
    start: u64,
    exec: Option<Exec>,
}

impl FileSink {
    async fn begin(&mut self) -> Result<&mut Exec, String> {
        if self.exec.is_none() {
            let line = receive_line(&self.dest, &self.hash, self.start);
            let exec = self.executor.stream(&self.ctx, SshIdentity::Automation, &line, STEP).await;
            self.exec = Some(exec.map_err(|e| format!("machine_unreachable: {e}"))?);
        }
        self.exec.as_mut().ok_or_else(|| "no connection".to_string())
    }
}

impl Sink for FileSink {
    fn resume(&mut self) -> BoxFuture<'_, Result<u64, String>> {
        Box::pin(async move {
            let key = (self.ctx.machine_id.clone(), self.dest.clone(), self.hash.clone());
            let restart = self.restarts.lock().is_ok_and(|mut r| r.remove(&key));
            if restart {
                return Ok(0);
            }
            // an offset that can't be the partial file's size makes the wrapper say what its size is
            let line = receive_line(&self.dest, &self.hash, u64::MAX);
            let mut probe = self
                .executor
                .stream(&self.ctx, SshIdentity::Automation, &line, Duration::from_secs(60))
                .await
                .map_err(|e| format!("machine_unreachable: {e}"))?;
            let _ = probe.close_stdin().await;
            let out = probe.finish(Duration::from_secs(60)).await.map_err(|e| format!("machine_unreachable: {e}"))?;
            match out.exit_code {
                Some(4) => {
                    let size = partial_size(&out.stderr).unwrap_or(0);
                    // a partial file longer than the file isn't this file's
                    self.start = if size > self.size { 0 } else { size };
                    Ok(self.start / CHUNK as u64)
                }
                Some(126) => Err("the destination isn't under the machine's transfer roots".into()),
                code => Err(format!(
                    "the machine couldn't take the file (exit {code:?}): {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )),
            }
        })
    }

    fn write<'a>(&'a mut self, index: u64, data: &'a [u8]) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            // the machine already has the first bytes of the chunk it went on from
            let first = self.start / CHUNK as u64;
            let skip = if index == first { (self.start % CHUNK as u64) as usize } else { 0 };
            let exec = self.begin().await?;
            exec.write(&data[skip.min(data.len())..]).await.map_err(|e| format!("machine_unreachable: {e}"))
        })
    }

    fn finish(mut self: Box<Self>) -> BoxFuture<'static, Result<(), String>> {
        Box::pin(async move {
            // a file the machine already had every byte of (or an empty one) is only left to check and rename
            self.begin().await?;
            let mut exec = self.exec.take().ok_or("no connection")?;
            exec.close_stdin().await.map_err(|e| format!("machine_unreachable: {e}"))?;
            let out = exec.finish(STEP).await.map_err(|e| format!("machine_unreachable: {e}"))?;
            match out.exit_code {
                Some(0) => Ok(()),
                Some(3) => {
                    if let Ok(mut r) = self.restarts.lock() {
                        r.insert((self.ctx.machine_id.clone(), self.dest.clone(), self.hash.clone()));
                    }
                    Err("the file on the machine doesn't match its hash; send it again and it starts over".into())
                }
                Some(126) => Err("the destination isn't under the machine's transfer roots".into()),
                code => Err(format!(
                    "the machine couldn't finish the file (exit {code:?}): {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )),
            }
        })
    }

    fn abandon(mut self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            // end the input the way a finished file does, so that `receive` is given everything already sent and keeps it
            if let Some(exec) = self.exec.take() {
                settle(exec).await;
            }
        })
    }
}

struct StreamSink {
    executor: Arc<Executor>,
    ctx: StepCtx,
    argv: Vec<String>,
    exec: Option<Exec>,
}

impl Sink for StreamSink {
    fn resume(&mut self) -> BoxFuture<'_, Result<u64, String>> {
        Box::pin(async { Ok(0) })
    }

    fn write<'a>(&'a mut self, _index: u64, data: &'a [u8]) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            if self.exec.is_none() {
                let mut argv = vec!["sudo".to_string(), WRAPPER.to_string()];
                argv.extend(self.argv.clone());
                let exec = self.executor.stream(&self.ctx, SshIdentity::Automation, &quote::join(&argv), STEP).await;
                self.exec = Some(exec.map_err(|e| format!("machine_unreachable: {e}"))?);
            }
            let exec = self.exec.as_mut().ok_or("no connection")?;
            exec.write(data).await.map_err(|e| format!("the receiving command stopped: {e}"))
        })
    }

    fn finish(mut self: Box<Self>) -> BoxFuture<'static, Result<(), String>> {
        Box::pin(async move {
            let Some(mut exec) = self.exec.take() else { return Ok(()) };
            exec.close_stdin().await.map_err(|e| format!("machine_unreachable: {e}"))?;
            let out = exec.finish(STEP).await.map_err(|e| format!("machine_unreachable: {e}"))?;
            match out.exit_code {
                Some(0) => Ok(()),
                code => Err(format!(
                    "{} failed (exit {code:?}): {}",
                    self.argv[0],
                    String::from_utf8_lossy(&out.stderr).trim()
                )),
            }
        })
    }

    fn abandon(mut self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            if let Some(exec) = self.exec.take() {
                settle(exec).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stream_goes_only_to_zfs_recv_with_one_dataset() {
        assert_eq!(stream_command("zfs-recv tank/backup"), Ok(vec!["zfs-recv".into(), "tank/backup".into()]));
        for bad in ["zfs-recv", "zfs-recv a b", "zfs-send tank@s", "sh -c id", "", "zfs-recv "] {
            assert!(stream_command(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_file_goes_inside_a_root_and_nowhere_else() {
        let roots = vec!["/var/lib/rackhand-run/incoming".to_string()];
        assert!(within("/var/lib/rackhand-run/incoming/a.tar", &roots));
        assert!(within("/var/lib/rackhand-run/incoming/sub/a.tar", &roots));
        for bad in [
            "/var/lib/rackhand-run/incoming",
            "/var/lib/rackhand-run/incoming/",
            "/var/lib/rackhand-run/incoming/../../etc/passwd",
            "/var/lib/rackhand-run/incoming-x/a",
            "/etc/passwd",
            "relative/a",
            "/var/lib/rackhand-run/incoming/a\nb",
        ] {
            assert!(!within(bad, &roots), "{bad:?}");
        }
    }

    #[test]
    fn the_partial_size_is_read_from_the_wrappers_answer() {
        assert_eq!(partial_size(b"run: the partial file has 3145728 bytes; resume from there\n"), Some(3_145_728));
        assert_eq!(partial_size(b"run: the partial file has 0 bytes; resume from there"), Some(0));
        assert_eq!(partial_size(b"something else"), None);
    }

    #[test]
    fn the_receive_command_is_quoted_for_sh() {
        assert_eq!(
            receive_line("/var/lib/rackhand-run/incoming/it's", "ab", 5),
            r"'sudo' '/usr/local/lib/rackhand/run' 'receive' '/var/lib/rackhand-run/incoming/it'\''s' 'ab' '5'"
        );
    }
}
