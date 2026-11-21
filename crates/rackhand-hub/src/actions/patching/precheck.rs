//! Precheck (7.5.3 step 4): what must hold before a machine is patched. On every machine: 1 GB free on `/`, no package
//! manager lock held, no other job on it, no open critical incident on it. On a Proxmox guest, for its snapshot: the
//! guest binding confirmed (7.3.12), the datastore with 10% and 5 GB free, and storage that can snapshot. Under the
//! policy's `snapshot = "optional"` the guest's conditions don't stop the patch: it goes ahead without a snapshot and
//! the job log says so (E12).

/// Free space `/` needs.
pub const ROOT_FREE_BYTES: u64 = 1 << 30;
/// Free space the datastore needs for the snapshot: a share and an amount.
pub const DATASTORE_FREE_PCT: f64 = 10.0;
pub const DATASTORE_FREE_BYTES: u64 = 5 << 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Snapshot {
    Required,
    Optional,
}

impl Snapshot {
    pub fn parse(s: &str) -> Snapshot {
        if s == "optional" { Snapshot::Optional } else { Snapshot::Required }
    }
}

/// A Proxmox guest, as its hypervisor's driver sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Guest {
    pub binding_confirmed: bool,
    pub datastore_free_pct: f64,
    pub datastore_free_bytes: u64,
    pub snapshots_supported: bool,
}

/// What the precheck looks at, gathered when the job starts.
#[derive(Debug, Clone, PartialEq)]
pub struct Facts {
    /// From the machine's latest report; none without one.
    pub root_free_bytes: Option<u64>,
    pub lock_held: bool,
    pub other_job: bool,
    pub open_critical: bool,
    /// Set when the machine is a Proxmox guest.
    pub guest: Option<Guest>,
}

/// `Ok` with notes for the job log, or the reason the patch doesn't start.
pub fn precheck(f: &Facts, snapshot: Snapshot) -> Result<Vec<String>, String> {
    match f.root_free_bytes {
        None => return Err("no_report".into()),
        Some(free) if free < ROOT_FREE_BYTES => return Err("root_disk_low".into()),
        Some(_) => {}
    }
    if f.lock_held {
        return Err("package_lock_held".into());
    }
    if f.other_job {
        return Err("machine_busy".into());
    }
    if f.open_critical {
        return Err("open_critical_incident".into());
    }
    let Some(g) = &f.guest else { return Ok(Vec::new()) };
    let blocked = if !g.binding_confirmed {
        Some(("guest_binding_unconfirmed", "the guest binding isn't confirmed"))
    } else if !g.snapshots_supported {
        Some(("snapshot_unsupported", "the guest's storage can't snapshot"))
    } else if g.datastore_free_pct < DATASTORE_FREE_PCT || g.datastore_free_bytes < DATASTORE_FREE_BYTES {
        Some(("datastore_low", "the datastore has less than 10% or 5 GB free"))
    } else {
        None
    };
    match (blocked, snapshot) {
        (None, _) => Ok(Vec::new()),
        (Some((reason, _)), Snapshot::Required) => Err(reason.into()),
        (Some((_, why)), Snapshot::Optional) => Ok(vec![format!("patched without a snapshot: {why}")]),
    }
}

#[cfg(test)]
#[path = "precheck_tests.rs"]
mod tests;
