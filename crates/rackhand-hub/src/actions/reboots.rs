//! The machines a running job reboots: from the job's start until the wait step after its last reboot ends, or the job
//! does. Kept in memory, so a job that a stopped hub left behind doesn't count.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use rackhand_runbook::runbook::{Runbook, StepKind};

#[derive(Debug, Default, Clone)]
pub(super) struct Reboots {
    /// How many holds each machine has: a job can start as the one before it is still letting go.
    machines: Arc<Mutex<HashMap<String, usize>>>,
}

impl Reboots {
    pub(super) fn awaiting(&self, machine: &str) -> bool {
        self.machines.lock().unwrap_or_else(PoisonError::into_inner).contains_key(machine)
    }

    /// Holds the machine as awaited until the returned guard is dropped; nothing for a runbook that doesn't reboot it.
    /// A rollback restarts its guest.
    pub(super) fn hold(&self, machine: &str, runbook: &Runbook) -> Option<Awaiting> {
        let last =
            runbook.steps.iter().rposition(|s| matches!(s.kind, StepKind::RebootIfRequired | StepKind::Rollback))?;
        let wait = runbook.steps[last..].iter().position(|s| s.kind == StepKind::WaitReport).map(|i| last + i);
        let mut hold = self.hold_machine(machine);
        hold.wait = wait;
        Some(hold)
    }

    /// Holds the machine whatever the runbook: a job taken up again while its machine restarts.
    pub(super) fn hold_machine(&self, machine: &str) -> Awaiting {
        self.machines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(machine.to_string())
            .and_modify(|n| *n += 1)
            .or_insert(1);
        Awaiting { reboots: self.clone(), machine: machine.to_string(), wait: None }
    }
}

pub(super) struct Awaiting {
    reboots: Reboots,
    machine: String,
    /// The step whose end ends the wait; without one, the job's end does.
    pub(super) wait: Option<usize>,
}

impl Drop for Awaiting {
    fn drop(&mut self) {
        let mut machines = self.reboots.machines.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = machines.get_mut(&self.machine) {
            *n -= 1;
            if *n == 0 {
                machines.remove(&self.machine);
            }
        }
    }
}
