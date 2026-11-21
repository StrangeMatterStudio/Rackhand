use super::*;

const GB: u64 = 1 << 30;

fn ready() -> Facts {
    Facts { root_free_bytes: Some(20 * GB), lock_held: false, other_job: false, open_critical: false, guest: None }
}

fn guest() -> Guest {
    Guest {
        binding_confirmed: true,
        datastore_free_pct: 40.0,
        datastore_free_bytes: 100 * GB,
        snapshots_supported: true,
    }
}

#[test]
fn machine_checks_fail_whatever_the_snapshot_policy() {
    for policy in [Snapshot::Required, Snapshot::Optional] {
        assert_eq!(precheck(&ready(), policy), Ok(Vec::new()));
        let low = Facts { root_free_bytes: Some(GB - 1), ..ready() };
        assert_eq!(precheck(&low, policy), Err("root_disk_low".into()), "1 GB free on / (7.5.3)");
        let unknown = Facts { root_free_bytes: None, ..ready() };
        assert_eq!(precheck(&unknown, policy), Err("no_report".into()));
        assert_eq!(precheck(&Facts { lock_held: true, ..ready() }, policy), Err("package_lock_held".into()));
        assert_eq!(precheck(&Facts { other_job: true, ..ready() }, policy), Err("machine_busy".into()));
        assert_eq!(precheck(&Facts { open_critical: true, ..ready() }, policy), Err("open_critical_incident".into()));
    }
}

/// E12: a guest whose storage can't snapshot fails the precheck under `snapshot = "required"`; with `optional` it is
/// patched without one, and the job log says so.
#[test]
fn snapshot_unsupported_fails_unless_optional() {
    let f = Facts { guest: Some(Guest { snapshots_supported: false, ..guest() }), ..ready() };
    assert_eq!(precheck(&f, Snapshot::Required), Err("snapshot_unsupported".into()));
    let notes = precheck(&f, Snapshot::Optional).unwrap();
    assert!(notes.iter().any(|n| n.contains("without a snapshot")), "{notes:?}");
    // the datastore needs 10% and 5 GB free for the snapshot
    let full = Facts { guest: Some(Guest { datastore_free_pct: 9.0, ..guest() }), ..ready() };
    assert_eq!(precheck(&full, Snapshot::Required), Err("datastore_low".into()));
    let small = Facts { guest: Some(Guest { datastore_free_bytes: 5 * GB - 1, ..guest() }), ..ready() };
    assert_eq!(precheck(&small, Snapshot::Required), Err("datastore_low".into()));
    assert!(precheck(&small, Snapshot::Optional).is_ok());
    assert_eq!(precheck(&Facts { guest: Some(guest()), ..ready() }, Snapshot::Required), Ok(Vec::new()));
}

/// 7.3.12: a Proxmox guest's binding must be confirmed before the hub snapshots it, unless snapshots are optional.
#[test]
fn unconfirmed_guest_binding_fails_unless_optional() {
    let f = Facts { guest: Some(Guest { binding_confirmed: false, ..guest() }), ..ready() };
    assert_eq!(precheck(&f, Snapshot::Required), Err("guest_binding_unconfirmed".into()));
    let notes = precheck(&f, Snapshot::Optional).unwrap();
    assert!(notes.iter().any(|n| n.contains("binding")), "{notes:?}");
}
