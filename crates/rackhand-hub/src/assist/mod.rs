//! Assist (7.3.5): assistant jobs offered to operators over `rackhand/operator/1`. An operator keeps one connection and
//! one stream to the hub; the first frame is its `OperatorHello`, then each side sends length-prefixed frames
//! (`HubToOperator`, `OperatorToHub`). Offers go to operators in their configured order; a decline moves to the next,
//! and with no operator or 3 declines the job ends and the incident goes to a person. A job's events are stored through
//! Actions (5 MB each, later ones counted), and its `JobDone` ends it. After a hub restart an operator's hello names
//! its running jobs, and they are attached again.

mod cap;
mod offers;
mod resume;
mod transcripts;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use iroh::endpoint::{Connection, RecvStream, SendStream};
use prost::Message;
use rackhand_proto::frame::MAX_FRAME;
use rackhand_proto::operator::{HubToOperator, OperatorToHub, operator_to_hub};
use rackhand_store::Db;
use rusqlite::OptionalExtension;
use tokio::sync::{mpsc, oneshot};

use crate::actions::Actions;
use crate::audit::Audit;

pub use offers::{AssistRequest, AssistResult};

/// Jobs a day the assistant may take, by default (7.7.1 Settings).
pub const DEFAULT_DAILY_CAP: u32 = 20;
pub const DEFAULT_DEADLINE_MS: i64 = 30 * 60_000;
pub const MAX_DEADLINE_MS: i64 = 2 * 60 * 60_000;
pub const DEFAULT_MAX_TURNS: u32 = 60;
/// How long after its deadline a job may stay silent before it ends `timed_out`.
pub const SWEEP_GRACE_MS: i64 = 5 * 60_000;
/// Declines after which the incident goes to a person.
pub const MAX_DECLINES: usize = 3;

/// One operator's connection.
struct Link {
    operator_id: String,
    max_jobs: u32,
    tx: mpsc::UnboundedSender<HubToOperator>,
    /// The answer to the one offer in flight; offers on a link are made one at a time.
    reply: Mutex<Option<oneshot::Sender<bool>>>,
    offering: tokio::sync::Mutex<()>,
    running: Mutex<HashSet<String>>,
}

/// A job an operator runs.
#[derive(Debug, Default)]
struct Track {
    operator_id: String,
    seq: i64,
    stored: usize,
    dropped: usize,
}

struct Inner {
    db: Arc<Db>,
    audit: Audit,
    actions: Actions,
    daily_cap: u32,
    links: Mutex<HashMap<String, Arc<Link>>>,
    jobs: Mutex<HashMap<String, Track>>,
}

#[derive(Clone)]
pub struct Assist {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Assist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Assist")
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

async fn write_frame(send: &mut SendStream, msg: &HubToOperator) -> bool {
    let body = msg.encode_to_vec();
    send.write_all(&(body.len() as u32).to_be_bytes()).await.is_ok() && send.write_all(&body).await.is_ok()
}

pub(crate) fn ulid_text(bytes: &[u8]) -> Option<String> {
    let b: [u8; 16] = bytes.try_into().ok()?;
    Some(ulid::Ulid::from_bytes(b).to_string())
}

impl Assist {
    pub fn new(db: Arc<Db>, audit: Audit, actions: Actions) -> Assist {
        Assist {
            inner: Arc::new(Inner {
                db,
                audit,
                actions,
                daily_cap: DEFAULT_DAILY_CAP,
                links: Mutex::new(HashMap::new()),
                jobs: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The daily cap from the settings (`assistant_daily_cap`); before serving.
    pub fn with_daily_cap(mut self, cap: u32) -> Assist {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.daily_cap = cap;
        }
        self
    }

    /// The router handler for `rackhand/operator/1`.
    pub fn handler(&self) -> rackhand_net::router::Handler {
        let assist = self.clone();
        rackhand_net::router::handler(move |conn: Connection| {
            let assist = assist.clone();
            async move { assist.serve(conn).await }
        })
    }

    /// Every minute, ends the jobs whose operator never reported after their deadline and a grace of 5 minutes.
    pub fn spawn_sweep(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                match self.inner.actions.sweep_assistant_jobs(rackhand_store::ids::now_ms(), SWEEP_GRACE_MS).await {
                    Ok(0) => {}
                    Ok(n) => tracing::warn!(jobs = n, "assistant jobs ended without a report"),
                    Err(e) => tracing::warn!(error = %e, "sweeping assistant jobs"),
                }
            }
        })
    }

    /// The operators connected now, by id.
    pub fn connected_operators(&self) -> Vec<String> {
        self.inner.links.lock().map(|l| l.keys().cloned().collect()).unwrap_or_default()
    }

    /// Whether the job is attached to a connected operator.
    pub fn attached(&self, job_id: &str) -> bool {
        let operator = self.inner.jobs.lock().ok().and_then(|j| j.get(job_id).map(|t| t.operator_id.clone()));
        operator.is_some_and(|op| self.inner.links.lock().is_ok_and(|l| l.contains_key(&op)))
    }

    async fn serve(&self, conn: Connection) {
        let peer = conn.remote_id().to_string();
        let operator: Option<String> = self
            .inner
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT id FROM operators WHERE endpoint_id = ?1 AND revoked_at IS NULL", [&peer], |r| {
                    r.get(0)
                })
                .optional()
            })
            .ok()
            .flatten();
        let Some(operator_id) = operator else { return };
        let Ok((mut send, mut recv)) = conn.accept_bi().await else { return };
        let hello = read_frame(&mut recv).await.and_then(|b| OperatorToHub::decode(b.as_slice()).ok());
        let Some(OperatorToHub { msg: Some(operator_to_hub::Msg::Hello(hello)) }) = hello else { return };
        let (tx, mut rx) = mpsc::unbounded_channel::<HubToOperator>();
        let link = Arc::new(Link {
            operator_id: operator_id.clone(),
            max_jobs: hello.max_jobs.max(1),
            tx,
            reply: Mutex::new(None),
            offering: tokio::sync::Mutex::new(()),
            running: Mutex::new(HashSet::new()),
        });
        self.reattach(&link, &hello.running);
        if let Ok(mut links) = self.inner.links.lock() {
            links.insert(operator_id.clone(), link.clone());
        }
        let writer = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if !write_frame(&mut send, &msg).await {
                    break;
                }
            }
        });
        while let Some(body) = read_frame(&mut recv).await {
            let Ok(msg) = OperatorToHub::decode(body.as_slice()) else { break };
            match msg.msg {
                Some(operator_to_hub::Msg::Reply(r)) => {
                    let accepted = matches!(r.reply, Some(rackhand_proto::operator::job_reply::Reply::Accepted(true)));
                    if let Some(tx) = link.reply.lock().ok().and_then(|mut r| r.take()) {
                        let _ = tx.send(accepted);
                    }
                }
                Some(operator_to_hub::Msg::Event(e)) => self.event(&operator_id, e).await,
                Some(operator_to_hub::Msg::Done(d)) => self.done(&operator_id, d).await,
                Some(operator_to_hub::Msg::Hello(_)) | None => {}
            }
        }
        // Gone: the operator keeps its runners for up to 5 minutes and reconnects; its jobs wait for it.
        writer.abort();
        if let Ok(mut links) = self.inner.links.lock()
            && links.get(&operator_id).is_some_and(|l| Arc::ptr_eq(l, &link))
        {
            links.remove(&operator_id);
        }
    }

    /// Jobs the operator says it still runs, whose tokens are its own and still valid, are tracked again (E17).
    fn reattach(&self, link: &Link, running: &[Vec<u8>]) {
        let now = rackhand_store::ids::now_ms();
        for job in running.iter().filter_map(|b| ulid_text(b)) {
            let ours: Option<i64> = self
                .inner
                .db
                .readers()
                .with(|c| {
                    c.query_row(
                        "SELECT 1 FROM job_tokens t JOIN jobs j ON j.id = t.job_id
                         WHERE t.job_id = ?1 AND t.operator_id = ?2 AND t.revoked_at IS NULL AND t.expires_at > ?3
                           AND j.state = 'running'",
                        rusqlite::params![job, link.operator_id, now],
                        |r| r.get(0),
                    )
                    .optional()
                })
                .ok()
                .flatten();
            if ours.is_none() {
                continue;
            }
            let (seq, stored) = transcripts::stored_so_far(&self.inner.db, &job);
            if let Ok(mut jobs) = self.inner.jobs.lock() {
                jobs.entry(job.clone()).or_insert(Track {
                    operator_id: link.operator_id.clone(),
                    seq,
                    stored,
                    dropped: 0,
                });
            }
            if let Ok(mut r) = link.running.lock() {
                r.insert(job);
            }
        }
    }

    fn connected(&self) -> Vec<Arc<Link>> {
        self.inner.links.lock().map(|l| l.values().cloned().collect()).unwrap_or_default()
    }
}
