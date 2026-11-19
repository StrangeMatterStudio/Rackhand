//! The set of machines with fresh data, per consumer: any number of notices for one machine collapse into one.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Mutex;

use super::MachineId;

#[derive(Debug, Default)]
pub struct Notices {
    inner: Mutex<(VecDeque<MachineId>, BTreeSet<MachineId>)>,
}

impl Notices {
    /// Adds a machine; returns false if it was already pending.
    pub fn add(&self, machine: MachineId) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.1.insert(machine) {
            g.0.push_back(machine);
            true
        } else {
            false
        }
    }

    /// The oldest pending machine.
    pub fn pop(&self) -> Option<MachineId> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let m = g.0.pop_front()?;
        g.1.remove(&m);
        Some(m)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
