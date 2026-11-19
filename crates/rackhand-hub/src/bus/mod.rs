//! In-process typed messages between hub systems (design 7.2, Bus; 7.3.8; D102).
//!
//! Each consumer has its own bounded queue (1024). `ReportIngested` is a notice: it adds the machine to the consumer's
//! set of machines with fresh data and never waits, so ingest is never held up by rule evaluation. Every other event
//! records a change already committed to the database; senders wait for queue space, except Actions sending
//! `JobFinished`, which never waits and leaves a full queue to the consumer's reconciliation.

mod coalesce;

use std::sync::{Arc, Mutex};

use tokio::sync::{Notify, mpsc};

pub use coalesce::Notices;

pub const QUEUE: usize = 1024;

pub type Ulid = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MachineId(pub Ulid);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobOutcome {
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleKind {
    PatchWindow,
    Checks,
    Retention,
    Rollup,
    Backup,
    IntelRefresh,
    GitMirror,
    DeadMan,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusEvent {
    ReportIngested { machine: MachineId },
    IncidentChanged { id: Ulid },
    JobFinished { job: Ulid, outcome: JobOutcome },
    ApprovalDecided { id: Ulid, approved: bool },
    Tick(ScheduleKind),
}

/// What a consumer receives: a machine with fresh data, or a state event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    Notice(MachineId),
    Event(BusEvent),
}

#[derive(Debug)]
struct Consumer {
    tx: mpsc::Sender<BusEvent>,
    notices: Arc<Notices>,
    notify: Arc<Notify>,
    missed_jobs: Arc<Mutex<Vec<Ulid>>>,
}

#[derive(Debug, Clone, Default)]
pub struct Bus {
    consumers: Arc<Mutex<Vec<Arc<Consumer>>>>,
}

impl Bus {
    pub fn new() -> Bus {
        Bus::default()
    }

    pub fn subscribe(&self, name: &'static str) -> Subscription {
        let (tx, rx) = mpsc::channel(QUEUE);
        let consumer = Arc::new(Consumer {
            tx,
            notices: Arc::new(Notices::default()),
            notify: Arc::new(Notify::new()),
            missed_jobs: Arc::default(),
        });
        let sub = Subscription {
            name,
            rx,
            notices: consumer.notices.clone(),
            notify: consumer.notify.clone(),
            missed_jobs: consumer.missed_jobs.clone(),
        };
        self.consumers.lock().unwrap_or_else(|e| e.into_inner()).push(consumer);
        sub
    }

    fn consumers(&self) -> Vec<Arc<Consumer>> {
        self.consumers.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Publishes an event. Notices never wait; state events wait for space in each consumer's queue.
    pub async fn publish(&self, event: BusEvent) {
        for c in self.consumers() {
            match &event {
                BusEvent::ReportIngested { machine } => {
                    if c.notices.add(*machine) {
                        c.notify.notify_one();
                    }
                }
                other => {
                    // An error means the consumer system has stopped; the database row is still the record (7.3.8).
                    if c.tx.send(other.clone()).await.is_ok() {
                        c.notify.notify_one();
                    }
                }
            }
        }
    }

    /// `JobFinished` from Actions: never waits. A consumer with a full queue records the job as missed, and its
    /// reconciliation picks it up. Returns how many consumers missed it.
    pub fn publish_job_finished(&self, job: Ulid, outcome: JobOutcome) -> usize {
        let mut missed = 0;
        for c in self.consumers() {
            match c.tx.try_send(BusEvent::JobFinished { job, outcome }) {
                Ok(()) => c.notify.notify_one(),
                Err(_) => {
                    c.missed_jobs.lock().unwrap_or_else(|e| e.into_inner()).push(job);
                    missed += 1;
                }
            }
        }
        missed
    }
}

#[derive(Debug)]
pub struct Subscription {
    pub name: &'static str,
    rx: mpsc::Receiver<BusEvent>,
    notices: Arc<Notices>,
    notify: Arc<Notify>,
    missed_jobs: Arc<Mutex<Vec<Ulid>>>,
}

impl Subscription {
    /// The next delivery: queued state events first, then machines with fresh data. `None` once the bus is gone.
    pub async fn recv(&mut self) -> Option<Delivery> {
        loop {
            if let Ok(event) = self.rx.try_recv() {
                return Some(Delivery::Event(event));
            }
            if let Some(machine) = self.notices.pop() {
                return Some(Delivery::Notice(machine));
            }
            tokio::select! {
                event = self.rx.recv() => return event.map(Delivery::Event),
                _ = self.notify.notified() => {}
            }
        }
    }

    pub fn pending_notices(&self) -> usize {
        self.notices.len()
    }

    /// Jobs whose `JobFinished` arrived while this consumer's queue was full.
    pub fn take_missed_jobs(&mut self) -> Vec<Ulid> {
        std::mem::take(&mut *self.missed_jobs.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

#[cfg(test)]
mod tests;
