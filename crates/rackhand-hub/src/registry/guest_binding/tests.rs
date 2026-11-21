//! Guest binding (7.3.12, D93, E50).

use std::sync::Arc;

use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use super::*;
use crate::bus::Bus;
use crate::ingest::{DiskSpace, Ingest};

const HOST: &str = "01JD0000000000000000000001";
const GUEST: &str = "01JD0000000000000000000002";
const T0: i64 = 1_795_068_000_000;

#[derive(Debug)]
struct Roomy;

impl DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

async fn env(name: &str) -> (Arc<Db>, GuestBindings) {
    let dir = std::env::temp_dir().join(format!("rackhand-binding-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let machine = |id: &str, name: &str, kind: &str| {
        RowWrite::insert(
            "machines",
            Row::from([
                ("id", t(id)),
                ("site_id", t("s1")),
                ("name", t(name)),
                ("kind", t(kind)),
                ("state", t("enrolled")),
            ]),
        )
    };
    let rows = vec![
        RowWrite::insert("sites", Row::from([("id", t("s1")), ("name", t("home")), ("timezone", t("UTC"))])),
        machine(HOST, "pve", "hypervisor"),
        machine(GUEST, "ct-test", "linux"),
    ];
    db.writer().send(WriteCmd::Batch(rows)).await.unwrap();
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    (db.clone(), GuestBindings::new(db, ingest))
}

/// The two guests on the host: LXC 100 and VM 200.
fn guests() -> Vec<GuestMacs> {
    vec![
        GuestMacs {
            host: HOST.into(),
            node: "pve8".into(),
            vmid: 100,
            kind: "lxc".into(),
            macs: vec!["BC:24:11:82:F7:1A".into()],
        },
        GuestMacs {
            host: HOST.into(),
            node: "pve8".into(),
            vmid: 200,
            kind: "qemu".into(),
            macs: vec!["BC:24:11:00:00:C8".into()],
        },
    ]
}

fn binding(db: &Db) -> (Option<String>, String) {
    db.readers()
        .with(|c| {
            c.query_row("SELECT proxmox_ref, proxmox_ref_state FROM machines WHERE id = ?1", [GUEST], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
        })
        .unwrap()
}

fn mismatch_events(db: &Db) -> Vec<(String, String)> {
    db.readers()
        .with(|c| {
            let mut s = c.prepare("SELECT severity, data FROM events WHERE kind = 'machine.guest_binding_mismatch'")?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })
        .unwrap()
}

fn reference(vmid: u64, kind: &str) -> String {
    serde_json::json!({ "cluster": HOST, "node": "pve8", "vmid": vmid, "type": kind }).to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn proposes_guest_by_mac() {
    let (db, b) = env("propose").await;
    // a MAC the probe reports in another case and with dashes still matches
    let seen =
        b.observe(GUEST, &["bc-24-11-82-f7-1a".into(), "02:42:AC:11:00:02".into()], &guests(), T0).await.unwrap();
    assert_eq!(seen, Outcome::Proposed);
    assert_eq!(binding(&db), (Some(reference(100, "lxc")), "proposed".into()));
    // nothing matches: nothing proposed
    let (db2, b2) = env("propose-none").await;
    assert_eq!(b2.observe(GUEST, &["02:00:00:00:00:01".into()], &guests(), T0).await.unwrap(), Outcome::Unchanged);
    assert_eq!(binding(&db2).1, "none");
    // a MAC that two guests' configs both carry (a cloned config) proves nothing
    let (db3, b3) = env("propose-ambiguous").await;
    let mut twins = guests();
    twins[1].macs = twins[0].macs.clone();
    assert_eq!(b3.observe(GUEST, &["BC:24:11:82:F7:1A".into()], &twins, T0).await.unwrap(), Outcome::Unchanged);
    assert_eq!(binding(&db3).1, "none");
}

#[tokio::test(flavor = "multi_thread")]
async fn confirm_fixes_binding() {
    let (db, b) = env("confirm").await;
    b.observe(GUEST, &["BC:24:11:82:F7:1A".into()], &guests(), T0).await.unwrap();
    assert!(b.confirm(GUEST, &reference(100, "lxc"), "admin", T0 + 1).await.unwrap());
    assert_eq!(binding(&db), (Some(reference(100, "lxc")), "confirmed".into()));
    let by: String = db
        .readers()
        .with(|c| c.query_row("SELECT proxmox_ref_confirmed_by FROM machines WHERE id = ?1", [GUEST], |r| r.get(0)))
        .unwrap();
    assert_eq!(by, "admin");
    // later reports of the same guest change nothing
    assert_eq!(b.observe(GUEST, &["BC:24:11:82:F7:1A".into()], &guests(), T0 + 2).await.unwrap(), Outcome::Unchanged);
    assert_eq!(binding(&db).0, Some(reference(100, "lxc")));
    // a guest that isn't one the machine is or looks like can't be confirmed
    assert!(!b.confirm(GUEST, &reference(300, "qemu"), "admin", T0 + 3).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn reported_mac_of_other_guest_sets_mismatch_and_event() {
    let (db, b) = env("mismatch").await;
    b.observe(GUEST, &["BC:24:11:82:F7:1A".into()], &guests(), T0).await.unwrap();
    b.confirm(GUEST, &reference(100, "lxc"), "admin", T0 + 1).await.unwrap();
    // the probe now claims VM 200's MAC
    let seen = b.observe(GUEST, &["BC:24:11:00:00:C8".into()], &guests(), T0 + 2).await.unwrap();
    assert_eq!(seen, Outcome::Mismatch);
    assert_eq!(binding(&db), (Some(reference(100, "lxc")), "mismatch".into()), "the binding itself doesn't move");
    assert_eq!(b.observe(GUEST, &["BC:24:11:00:00:C8".into()], &guests(), T0 + 3).await.unwrap(), Outcome::Unchanged);
    let events = mismatch_events(&db);
    assert_eq!(events.len(), 1, "one warning: {events:?}");
    assert_eq!(events[0].0, "warning");
    assert!(events[0].1.contains("\"vmid\":200"), "it names the guest seen: {}", events[0].1);
    // an admin confirms the guest it now looks like: that becomes the binding
    assert!(b.confirm(GUEST, &reference(200, "qemu"), "admin", T0 + 4).await.unwrap());
    assert_eq!(binding(&db), (Some(reference(200, "qemu")), "confirmed".into()));
    // and a guest whose MACs it no longer reports at all is a mismatch too
    let (db2, b2) = env("mismatch-gone").await;
    b2.observe(GUEST, &["BC:24:11:82:F7:1A".into()], &guests(), T0).await.unwrap();
    b2.confirm(GUEST, &reference(100, "lxc"), "admin", T0 + 1).await.unwrap();
    assert_eq!(b2.observe(GUEST, &["02:00:00:00:00:01".into()], &guests(), T0 + 2).await.unwrap(), Outcome::Mismatch);
    assert_eq!(binding(&db2).1, "mismatch");
}
