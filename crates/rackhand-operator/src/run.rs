//! `rackhand operator run` (7.3.5): one connection to each joined hub, over which the hub offers jobs. The operator declines
//! past its limit, accepts the rest, runs each with its runner (whose only way to the hub is the bridge), forwards the events
//! and the end, and keeps a job's runner for up to 5 minutes while its hub can't be reached.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream};
use prost::Message;
use rackhand_net::ticket::Ticket;
use rackhand_proto::common::{RunnerInfo, SemVer};
use rackhand_proto::frame::{self, MAX_FRAME};
use rackhand_proto::operator::{
    HubToOperator, JobDone, JobEvent, JobReply, OperatorHello, OperatorToHub, hub_to_operator, job_reply,
    operator_to_hub,
};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::bridge::{BoxStream, Broker, Dialer, bridge_command, socket_path};
use crate::runner::{Done, JobSpec, Runner, now_ms};
use crate::state::{Dirs, Hub};

/// How long a job's runner is kept while its hub can't be reached (E16).
pub const UNREACHABLE_LIMIT: Duration = Duration::from_secs(5 * 60);
/// Messages kept for a hub that can't be reached: its events and ends, oldest dropped first.
const QUEUE_LIMIT: usize = 10_000;
const CONNECT_WAIT: Duration = Duration::from_secs(10);

#[allow(missing_debug_implementations)]
pub struct Operator {
    pub dirs: Dirs,
    pub runner: Arc<dyn Runner>,
    pub max_jobs: u32,
    /// The `rackhand` binary the runner starts as its MCP bridge.
    pub exe: PathBuf,
}

/// Cancels `cancel` once `connected` has been false for `limit` without a break; a hub that comes back in time resets the
/// wait. Returns whether it cancelled.
pub async fn kill_after_unreachable(
    mut connected: watch::Receiver<bool>,
    limit: Duration,
    cancel: CancellationToken,
) -> bool {
    loop {
        while *connected.borrow() {
            if connected.changed().await.is_err() {
                return false;
            }
        }
        match tokio::time::timeout(limit, connected.wait_for(|c| *c)).await {
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => return false,
            Err(_) => {
                cancel.cancel();
                return true;
            }
        }
    }
}

/// What the hub is told when the run ended: the runner's own account, unless the operator stopped it for the hub's silence.
pub fn final_done(done: Done, killed_for_silence: bool) -> Done {
    if killed_for_silence {
        return Done {
            outcome: rackhand_proto::operator::Outcome::Failed,
            summary: "the hub couldn't be reached for 5 minutes; the run was stopped".into(),
        };
    }
    done
}

/// Frames to a hub, kept while it can't be reached.
struct Outbox {
    tx: Option<mpsc::UnboundedSender<OperatorToHub>>,
    queue: VecDeque<OperatorToHub>,
}

struct Link {
    hub: Hub,
    outbox: Mutex<Outbox>,
    connected: watch::Sender<bool>,
    running: Mutex<HashMap<String, CancellationToken>>,
}

impl Link {
    fn send(&self, msg: OperatorToHub) {
        let Ok(mut out) = self.outbox.lock() else { return };
        if let Some(tx) = &out.tx {
            if tx.send(msg.clone()).is_ok() {
                return;
            }
            out.tx = None;
        }
        if out.queue.len() >= QUEUE_LIMIT {
            out.queue.pop_front();
        }
        out.queue.push_back(msg);
    }

    fn running_ids(&self) -> Vec<Vec<u8>> {
        let ids: HashSet<String> = self.running.lock().map(|r| r.keys().cloned().collect()).unwrap_or_default();
        ids.iter().filter_map(|id| ulid::Ulid::from_string(id).ok()).map(|u| u.to_bytes().to_vec()).collect()
    }
}

/// The hub's MCP streams, one connection kept for all of a job's.
struct IrohDialer {
    endpoint: iroh::Endpoint,
    ticket: Ticket,
    conn: tokio::sync::Mutex<Option<Connection>>,
}

#[async_trait::async_trait]
impl Dialer for IrohDialer {
    async fn dial(&self) -> Result<BoxStream, String> {
        let mut held = self.conn.lock().await;
        if held.as_ref().is_none_or(|c| c.close_reason().is_some()) {
            let addr = self.ticket.endpoint_addr()?;
            let conn = tokio::time::timeout(CONNECT_WAIT, self.endpoint.connect(addr, rackhand_proto::alpn::MCP))
                .await
                .map_err(|_| "the hub didn't answer".to_string())?
                .map_err(|e| e.to_string())?;
            *held = Some(conn);
        }
        let conn = held.as_ref().ok_or("no connection")?;
        let (send, recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
        Ok(Box::new(tokio::io::join(recv, send)))
    }
}

async fn read_frame(recv: &mut RecvStream) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.ok()?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return None;
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await.ok()?;
    Some(body)
}

fn id_text(bytes: &[u8]) -> Option<String> {
    let b: [u8; 16] = bytes.try_into().ok()?;
    Some(ulid::Ulid::from_bytes(b).to_string())
}

fn spec_of(offer: &rackhand_proto::operator::JobOffer, job_id: &str) -> JobSpec {
    JobSpec {
        job_id: job_id.to_string(),
        incident_id: id_text(&offer.incident_id).unwrap_or_default(),
        playbook: offer.playbook.clone(),
        playbook_rev: offer.playbook_rev,
        brief_markdown: offer.brief_markdown.clone(),
        allowed_tools: offer.allowed_tools.clone(),
        autonomy: offer.autonomy,
        hosts: offer.hosts.iter().filter_map(|h| id_text(h)).collect(),
        deadline_ms: offer.deadline_ms,
        max_turns: offer.max_turns,
    }
}

fn reply(link: &Link, accepted: Result<(), String>) {
    let reply = match accepted {
        Ok(()) => job_reply::Reply::Accepted(true),
        Err(why) => job_reply::Reply::Declined(why),
    };
    link.send(OperatorToHub { msg: Some(operator_to_hub::Msg::Reply(JobReply { reply: Some(reply) })) });
}

impl Operator {
    fn hello(&self, link: &Link) -> OperatorHello {
        let info = self.runner.info();
        OperatorHello {
            operator_version: Some(SemVer { version: env!("CARGO_PKG_VERSION").into() }),
            runners: vec![RunnerInfo { name: info.name, version: info.version }],
            max_jobs: self.max_jobs,
            running: link.running_ids(),
        }
    }

    async fn on_offer(
        self: &Arc<Self>,
        link: &Arc<Link>,
        dialer: &Arc<IrohDialer>,
        offer: rackhand_proto::operator::JobOffer,
    ) {
        let Some(job_id) = id_text(&offer.job_id) else { return reply(link, Err("bad job id".into())) };
        let busy = link.running.lock().map(|r| r.len() as u32 >= self.max_jobs).unwrap_or(true);
        if busy {
            return reply(link, Err("busy".into()));
        }
        if offer.deadline_ms <= now_ms() {
            return reply(link, Err("the deadline has passed".into()));
        }
        let cancel = CancellationToken::new();
        if let Ok(mut r) = link.running.lock() {
            r.insert(job_id.clone(), cancel.clone());
        }
        reply(link, Ok(()));
        let (op, link, dialer) = (self.clone(), link.clone(), dialer.clone());
        tokio::spawn(async move { op.job(link, dialer, offer, job_id, cancel).await });
    }

    /// One job from acceptance to its end.
    async fn job(
        self: Arc<Self>,
        link: Arc<Link>,
        dialer: Arc<IrohDialer>,
        offer: rackhand_proto::operator::JobOffer,
        job_id: String,
        cancel: CancellationToken,
    ) {
        let id_bytes = offer.job_id.clone();
        let end = |done: Done| {
            link.send(OperatorToHub {
                msg: Some(operator_to_hub::Msg::Done(JobDone {
                    job_id: id_bytes.clone(),
                    outcome: done.outcome as i32,
                    summary: done.summary,
                })),
            });
            if let Ok(mut r) = link.running.lock() {
                r.remove(&job_id);
            }
        };
        let spec = spec_of(&offer, &job_id);
        // the token goes into the broker and nowhere else
        let socket = socket_path(&self.dirs.sockets(), &job_id);
        let broker = match Broker::start(socket, dialer.clone(), offer.job_token.clone()) {
            Ok(b) => b,
            Err(e) => {
                return end(Done {
                    outcome: rackhand_proto::operator::Outcome::Failed,
                    summary: format!("the bridge's socket: {e}"),
                });
            }
        };
        let bridge = bridge_command(&self.exe, &link.hub.id, &job_id, &self.dirs.0);
        let mut handle = match self.runner.start(&spec, bridge).await {
            Ok(h) => h,
            Err(e) => {
                return end(Done {
                    outcome: rackhand_proto::operator::Outcome::Failed,
                    summary: format!("the runner didn't start: {e}"),
                });
            }
        };
        let relay = cancel.clone();
        let stop = handle.cancel.clone();
        let hub_cancel = tokio::spawn(async move {
            relay.cancelled().await;
            stop.cancel();
        });
        let silence =
            tokio::spawn(kill_after_unreachable(link.connected.subscribe(), UNREACHABLE_LIMIT, handle.cancel.clone()));
        while let Some(ev) = handle.events.recv().await {
            link.send(OperatorToHub {
                msg: Some(operator_to_hub::Msg::Event(JobEvent {
                    job_id: id_bytes.clone(),
                    at_ms: ev.at_ms,
                    kind: ev.kind as i32,
                    text: ev.text,
                })),
            });
        }
        let done = handle.done.await.unwrap_or(Done {
            outcome: rackhand_proto::operator::Outcome::Failed,
            summary: "the runner ended without saying how".into(),
        });
        hub_cancel.abort();
        let killed = if silence.is_finished() {
            silence.await.unwrap_or(false)
        } else {
            silence.abort();
            false
        };
        drop(broker);
        end(final_done(done, killed));
    }

    /// One hub: connect, say hello, take offers until the connection ends; and again, with a growing wait.
    async fn hub_loop(self: Arc<Self>, endpoint: iroh::Endpoint, link: Arc<Link>) {
        let Ok(ticket) = link.hub.ticket() else {
            tracing::error!(hub = %link.hub.site, "the stored hub address is unreadable");
            return;
        };
        let dialer =
            Arc::new(IrohDialer { endpoint: endpoint.clone(), ticket: ticket.clone(), conn: Default::default() });
        let mut wait = Duration::from_secs(1);
        loop {
            let started = std::time::Instant::now();
            match self.serve(&endpoint, &ticket, &link, &dialer).await {
                Ok(()) => tracing::info!(hub = %link.hub.site, "the hub closed the connection"),
                Err(e) => tracing::warn!(hub = %link.hub.site, error = %e, "the hub can't be reached"),
            }
            if let Ok(mut out) = link.outbox.lock() {
                out.tx = None;
            }
            let _ = link.connected.send(false);
            wait = if started.elapsed() > Duration::from_secs(60) {
                Duration::from_secs(1)
            } else {
                (wait * 2).min(Duration::from_secs(30))
            };
            tokio::time::sleep(wait).await;
        }
    }

    async fn serve(
        self: &Arc<Self>,
        endpoint: &iroh::Endpoint,
        ticket: &Ticket,
        link: &Arc<Link>,
        dialer: &Arc<IrohDialer>,
    ) -> Result<(), String> {
        let conn = tokio::time::timeout(
            CONNECT_WAIT,
            endpoint.connect(ticket.endpoint_addr()?, rackhand_proto::alpn::OPERATOR),
        )
        .await
        .map_err(|_| "the hub didn't answer".to_string())?
        .map_err(|e| e.to_string())?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
        let hello = OperatorToHub { msg: Some(operator_to_hub::Msg::Hello(self.hello(link))) };
        send.write_all(&frame::encode(&hello).map_err(|e| e.to_string())?).await.map_err(|e| e.to_string())?;
        let (tx, mut rx) = mpsc::unbounded_channel::<OperatorToHub>();
        {
            // what was kept while the hub was away goes first
            let mut out = link.outbox.lock().map_err(|_| "poisoned")?;
            for msg in out.queue.drain(..) {
                let _ = tx.send(msg);
            }
            out.tx = Some(tx);
        }
        let _ = link.connected.send(true);
        let writer = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let Ok(bytes) = frame::encode(&msg) else { continue };
                if send.write_all(&bytes).await.is_err() {
                    break;
                }
            }
        });
        while let Some(body) = read_frame(&mut recv).await {
            let Ok(msg) = HubToOperator::decode(body.as_slice()) else { break };
            match msg.msg {
                Some(hub_to_operator::Msg::Offer(offer)) => self.on_offer(link, dialer, offer).await,
                Some(hub_to_operator::Msg::Cancel(c)) => {
                    let token = id_text(&c.job_id).and_then(|id| link.running.lock().ok()?.get(&id).cloned());
                    if let Some(token) = token {
                        token.cancel();
                    }
                }
                None => {}
            }
        }
        writer.abort();
        Ok(())
    }
}

/// Runs the operator until it is stopped: one task per joined hub.
pub async fn run(op: Arc<Operator>) -> Result<(), String> {
    let hubs = crate::state::load(&op.dirs);
    if hubs.is_empty() {
        return Err("this host hasn't joined a hub: run `rackhand operator join` first".into());
    }
    let relays: Vec<String> = hubs.iter().flat_map(|h| h.relays.clone()).collect();
    let endpoint = crate::join::endpoint(&op.dirs, relays).await?;
    for hub in hubs {
        let (connected, _) = watch::channel(false);
        let link = Arc::new(Link {
            hub,
            outbox: Mutex::new(Outbox { tx: None, queue: VecDeque::new() }),
            connected,
            running: Mutex::new(HashMap::new()),
        });
        tokio::spawn(op.clone().hub_loop(endpoint.clone(), link));
    }
    let _ = tokio::signal::ctrl_c().await;
    endpoint.close().await;
    Ok(())
}

#[cfg(test)]
mod operator {
    use std::process::Command;

    use rackhand_proto::operator::Outcome;

    use super::*;
    use crate::runner::{Info, RunHandle, RunnerError};

    /// A runner that runs until it is cancelled.
    struct Stuck;

    #[async_trait::async_trait]
    impl Runner for Stuck {
        fn info(&self) -> Info {
            Info { name: "stuck".into(), version: "0".into() }
        }

        async fn start(&self, _job: &JobSpec, _bridge: Command) -> Result<RunHandle, RunnerError> {
            let (_events, rx) = mpsc::channel(1);
            let (done_tx, done) = tokio::sync::oneshot::channel();
            let cancel = CancellationToken::new();
            let stop = cancel.clone();
            tokio::spawn(async move {
                stop.cancelled().await;
                let _ = done_tx.send(Done { outcome: Outcome::Failed, summary: "the run was cancelled".into() });
                drop(_events);
            });
            Ok(RunHandle { events: rx, cancel, done })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn tools_fail_hub_unreachable_then_runner_killed_after_5_min() {
        let handle = Stuck
            .start(
                &JobSpec {
                    job_id: "j".into(),
                    incident_id: String::new(),
                    playbook: String::new(),
                    playbook_rev: 0,
                    brief_markdown: String::new(),
                    allowed_tools: vec![],
                    autonomy: 1,
                    hosts: vec![],
                    deadline_ms: 0,
                    max_turns: 1,
                },
                Command::new("/bin/true"),
            )
            .await
            .unwrap();
        let (connected, rx) = watch::channel(true);
        let watcher = tokio::spawn(kill_after_unreachable(rx, UNREACHABLE_LIMIT, handle.cancel.clone()));
        // the hub drops, and comes back after 4 minutes: the runner is kept, and the wait starts again at the next drop
        connected.send(false).unwrap();
        tokio::time::sleep(Duration::from_secs(4 * 60)).await;
        assert!(!handle.cancel.is_cancelled(), "kept for up to 5 minutes");
        connected.send(true).unwrap();
        tokio::time::sleep(Duration::from_secs(60)).await;
        connected.send(false).unwrap();
        tokio::time::sleep(Duration::from_secs(4 * 60 + 30)).await;
        assert!(!handle.cancel.is_cancelled(), "a hub that came back in time reset the wait");
        // gone for 5 minutes: the runner is stopped, and the hub is told on reconnect that it failed
        tokio::time::sleep(Duration::from_secs(31)).await;
        assert!(handle.cancel.is_cancelled());
        assert!(watcher.await.unwrap(), "the watcher says it stopped the run");
        let done = final_done(handle.done.await.unwrap(), true);
        assert_eq!(done.outcome, Outcome::Failed);
        assert!(done.summary.contains("5 minutes"), "{done:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_hub_that_stays_reachable_never_costs_the_job_its_runner() {
        let cancel = CancellationToken::new();
        let (connected, rx) = watch::channel(true);
        let watcher = tokio::spawn(kill_after_unreachable(rx, UNREACHABLE_LIMIT, cancel.clone()));
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert!(!cancel.is_cancelled());
        drop(connected);
        assert!(
            !watcher.await.unwrap(),
            "and when the link is gone for good the watcher ends without stopping anything"
        );
    }

    #[test]
    fn messages_for_an_unreachable_hub_are_kept_oldest_dropped_first() {
        let (connected, _) = watch::channel(false);
        let link = Link {
            hub: Hub { id: "ab".repeat(32), site: "home".into(), addrs: vec![], relays: vec![] },
            outbox: Mutex::new(Outbox { tx: None, queue: VecDeque::new() }),
            connected,
            running: Mutex::new(HashMap::new()),
        };
        for i in 0..(QUEUE_LIMIT + 5) {
            link.send(OperatorToHub {
                msg: Some(operator_to_hub::Msg::Event(JobEvent {
                    job_id: vec![],
                    at_ms: i as i64,
                    kind: 1,
                    text: String::new(),
                })),
            });
        }
        let out = link.outbox.lock().unwrap();
        assert_eq!(out.queue.len(), QUEUE_LIMIT);
        let first = match &out.queue[0].msg {
            Some(operator_to_hub::Msg::Event(e)) => e.at_ms,
            _ => -1,
        };
        assert_eq!(first, 5, "the oldest five were dropped");
    }
}
