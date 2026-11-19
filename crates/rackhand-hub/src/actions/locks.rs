//! One job per machine (AC50): a job of any kind holds its machine's lock from its first step to its last recorded
//! result. Waiters are served in arrival order.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::OwnedMutexGuard;

#[derive(Debug, Default)]
pub(crate) struct MachineLocks {
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

pub(crate) type MachineGuard = OwnedMutexGuard<()>;

impl MachineLocks {
    /// The machine's lock, or `None` once `wait` has passed.
    pub(crate) async fn acquire(&self, machine_id: &str, wait: Duration) -> Option<MachineGuard> {
        let lock = self.locks.lock().unwrap_or_else(|e| e.into_inner()).entry(machine_id.into()).or_default().clone();
        tokio::time::timeout(wait, lock.lock_owned()).await.ok()
    }
}
