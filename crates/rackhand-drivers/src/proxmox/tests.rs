//! The Proxmox driver against the simulator, which serves the answers recorded from the lab's PVE 8 and 9 nodes
//! (`cargo xtask lab record-proxmox`, plan T47).

use std::time::Duration;

use serde_json::json;

use super::sim::Sim;
use super::*;
use crate::{Driver, DriverError, DriverOp, DriverTarget};

const TOKEN: &str = "rackhand@pve!hub=00000000-1111-2222-3333-444444444444";

fn target(sim: &Sim) -> DriverTarget {
    DriverTarget {
        target: sim.url.clone(),
        settings: json!({ "token": TOKEN, "fingerprint": sim.fingerprint }),
        timeout: Duration::from_secs(5),
    }
}

fn op(name: &str, args: serde_json::Value) -> DriverOp {
    DriverOp { name: name.into(), args }
}

fn point(r: &crate::DriverReading, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    r.points
        .iter()
        .find(|p| p.name == name && labels.iter().all(|(k, v)| p.labels.get(*k).map(String::as_str) == Some(*v)))
        .map(|p| p.value)
}

#[tokio::test]
async fn poll_maps_every_catalogue_metric() {
    for (version, node) in [("pve8", "pve8"), ("pve9", "pve9")] {
        let sim = Sim::start(version).await;
        let r = Proxmox::new().poll(&target(&sim)).await.unwrap();
        assert!(r.ok, "{version}: {}", r.detail);
        let n = [("node", node)];
        assert!(point(&r, "pve.node.cpu_pct", &n).is_some_and(|v| (0.0..=100.0).contains(&v)), "{version}");
        assert!(point(&r, "pve.node.mem_used_bytes", &n).is_some_and(|v| v > 0.0), "{version}");
        assert!(point(&r, "pve.node.mem_used_pct", &n).is_some_and(|v| v > 0.0 && v < 100.0), "{version}");
        for storage in ["local", "tank"] {
            let s = [("node", node), ("storage", storage)];
            assert!(point(&r, "pve.storage.used_pct", &s).is_some(), "{version}: {storage} in {:?}", r.points);
            assert!(point(&r, "pve.storage.total_bytes", &s).is_some_and(|v| v > 0.0), "{version}: {storage}");
        }
        for vmid in ["100", "200"] {
            let g = [("node", node), ("vmid", vmid)];
            assert_eq!(point(&r, "pve.guest.up", &g), Some(1.0), "{version}: guest {vmid} runs");
            assert!(point(&r, "pve.guest.cpu_pct", &g).is_some(), "{version}: {vmid}");
            assert!(point(&r, "pve.guest.mem_used_bytes", &g).is_some_and(|v| v > 0.0), "{version}: {vmid}");
        }
        let auth = sim.requests().iter().all(|q| q.authorization == format!("PVEAPIToken={TOKEN}"));
        assert!(auth, "every request carries the API token");
    }
}

#[tokio::test]
async fn certificate_fingerprint_mismatch_refused() {
    let sim = Sim::start("pve8").await;
    let mut t = target(&sim);
    t.settings["fingerprint"] =
        json!("00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF");
    let r = Proxmox::new().poll(&t).await.unwrap();
    assert!(!r.ok && r.detail.contains("fingerprint"), "{}", r.detail);
    let called = Proxmox::new().call(&t, op("snapshot", json!({ "kind": "lxc", "vmid": 100, "name": "x" }))).await;
    assert!(matches!(called, Err(DriverError::Failed(ref e)) if e.contains("fingerprint")), "{called:?}");
    assert!(sim.requests().is_empty(), "nothing was sent: {:?}", sim.requests());
    // without a pin there is nothing to trust
    t.settings = json!({ "token": TOKEN });
    assert!(matches!(Proxmox::new().poll(&t).await, Err(DriverError::Invalid(_))));
}

#[tokio::test]
async fn snapshot_and_rollback_requests_match_api() {
    let sim = Sim::start("pve9").await;
    let pve = Proxmox::new();
    let args = json!({ "kind": "lxc", "vmid": 100, "name": "rackhand-patch-20261121-1200" });
    let made = pve.call(&target(&sim), op("snapshot", args.clone())).await.unwrap();
    assert_eq!(made.output["snapshot"], "rackhand-patch-20261121-1200");
    pve.call(&target(&sim), op("rollback", args)).await.unwrap();
    let calls: Vec<(String, String, String)> =
        sim.requests().into_iter().filter(|q| q.method != "GET").map(|q| (q.method, q.path, q.body)).collect();
    assert_eq!(
        calls,
        vec![
            (
                "POST".to_string(),
                "/api2/json/nodes/pve9/lxc/100/snapshot".to_string(),
                "snapname=rackhand-patch-20261121-1200".to_string()
            ),
            (
                "POST".to_string(),
                "/api2/json/nodes/pve9/lxc/100/snapshot/rackhand-patch-20261121-1200/rollback".to_string(),
                String::new()
            ),
        ]
    );
    // each waited for its task
    let tasks =
        sim.requests().into_iter().filter(|q| q.path.contains("/tasks/") && q.path.ends_with("/status")).count();
    assert!(tasks >= 2, "{:?}", sim.requests());
}

#[tokio::test]
async fn firewall_config_read_and_restore_round_trip() {
    let sim = Sim::start("pve8").await;
    let pve = Proxmox::new();
    let guest = json!({ "kind": "lxc", "vmid": 100 });
    let saved = pve.call(&target(&sim), op("firewall_read", guest.clone())).await.unwrap().output;
    assert!(saved["options"].is_object() && saved["rules"].is_array(), "{saved}");
    assert!(saved["devices"]["net0"].as_str().is_some_and(|n| n.contains("hwaddr")), "the device line: {saved}");
    // a quarantine changes all three: the policies, the rules and the device's firewall flag
    sim.quarantine(100);
    let changed = pve.call(&target(&sim), op("firewall_read", guest.clone())).await.unwrap().output;
    assert_ne!(changed, saved, "the quarantine changed something");
    let mut restore = guest.clone();
    restore["saved"] = saved.clone();
    pve.call(&target(&sim), op("firewall_restore", restore)).await.unwrap();
    let back = pve.call(&target(&sim), op("firewall_read", guest)).await.unwrap().output;
    assert_eq!(back, saved, "read back identically");
}

#[tokio::test]
async fn task_polling_reports_failure_detail() {
    let sim = Sim::start("pve8").await;
    let gone = json!({ "kind": "lxc", "vmid": 100, "name": "rackhand-missing" });
    let r = Proxmox::new().call(&target(&sim), op("delete_snapshot", gone)).await;
    assert_eq!(r, Err(DriverError::Failed("snapshot 'rackhand-missing' does not exist".into())));
    let unknown = Proxmox::new().call(&target(&sim), op("explode", json!({}))).await;
    assert!(matches!(unknown, Err(DriverError::Invalid(_))), "{unknown:?}");
}

/// The guests' configured MACs, for guest binding (7.3.12): every guest, or none at all.
#[tokio::test]
async fn guests_op_lists_each_guest_with_its_configured_macs() {
    let sim = Sim::start("pve8").await;
    let out = Proxmox::new().call(&target(&sim), op("guests", json!({}))).await.unwrap().output;
    let list = out.as_array().expect("a list");
    assert!(
        list.contains(&json!({ "node": "pve8", "vmid": 100, "type": "lxc", "macs": ["BC:24:11:82:F7:1A"] })),
        "{out}"
    );
    assert!(
        list.contains(&json!({ "node": "pve8", "vmid": 200, "type": "qemu", "macs": ["BC:24:11:E6:A8:A6"] })),
        "{out}"
    );
    assert_eq!(list.len(), 2, "{out}");
    // a guest whose configuration doesn't load: no list, rather than one without it
    sim.fail_config(200);
    assert!(Proxmox::new().call(&target(&sim), op("guests", json!({}))).await.is_err());
}

/// T59c2: a guest's snapshots (without Proxmox's `current` entry), kept as the simulator's state so a snapshot made or
/// deleted shows in the next list.
#[tokio::test]
async fn snapshots_op_lists_the_guests_snapshots() {
    let sim = Sim::start("pve9").await;
    let pve = Proxmox::new();
    let names = |out: &serde_json::Value| -> Vec<String> {
        out.as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap().to_string()).collect()
    };
    let guest = json!({ "kind": "lxc", "vmid": 100 });
    let before = pve.call(&target(&sim), op("snapshots", guest.clone())).await.unwrap().output;
    assert_eq!(names(&before), ["rackhand-fixture"], "{before}");
    assert!(before[0]["snaptime"].is_i64(), "{before}");
    let named = json!({ "kind": "lxc", "vmid": 100, "name": "rackhand-patch-20261121-1200" });
    pve.call(&target(&sim), op("snapshot", named.clone())).await.unwrap();
    let after = pve.call(&target(&sim), op("snapshots", guest.clone())).await.unwrap().output;
    assert_eq!(names(&after), ["rackhand-fixture", "rackhand-patch-20261121-1200"]);
    pve.call(&target(&sim), op("delete_snapshot", named)).await.unwrap();
    let gone = pve.call(&target(&sim), op("snapshots", guest)).await.unwrap().output;
    assert_eq!(names(&gone), ["rackhand-fixture"]);
}

async fn room_of(sim: &Sim, kind: &str, vmid: u32) -> serde_json::Value {
    let args = json!({ "kind": kind, "vmid": vmid });
    Proxmox::new().call(&target(sim), op("snapshot_room", args)).await.unwrap().output
}

/// T59c2: where a guest's disks live, for the patch precheck (7.5.3): each storage its disks use (a CD drive left out),
/// with its type, free and total bytes and whether it can snapshot those disks.
#[tokio::test]
async fn snapshot_room_reports_the_storage_of_each_disk() {
    let sim = Sim::start("pve9").await;
    let room = |kind: &'static str, vmid: u32| room_of(&sim, kind, vmid);
    let vm = room("qemu", 200).await;
    let storages = vm["storages"].as_array().unwrap();
    assert_eq!(storages.len(), 1, "scsi0 on tank; the cloud-init CD drive isn't a disk: {vm}");
    assert_eq!(storages[0]["storage"], "tank");
    assert_eq!(storages[0]["type"], "zfspool");
    assert_eq!(storages[0]["snapshots"], true);
    assert_eq!(storages[0]["avail"], 15894540800u64);
    assert_eq!(storages[0]["total"], 16122904576u64);
    let ct = room("lxc", 100).await;
    assert_eq!(ct["storages"][0]["storage"], "tank", "{ct}");
    // a directory storage snapshots only qcow2 images, and a container on one not at all
    sim.set_storage("tank", "dir", 1 << 30, 16 << 30);
    let dir = room("lxc", 100).await;
    assert_eq!(
        (dir["storages"][0]["snapshots"].clone(), dir["storages"][0]["avail"].clone()),
        (json!(false), json!(1u64 << 30))
    );
    assert_eq!(room("qemu", 200).await["storages"][0]["snapshots"], false, "a raw image on a directory");
}

/// 7.5.3 step 7: what goes down with the host, and which nodes it shares a cluster with.
#[tokio::test]
async fn host_lists_its_guests_and_the_clusters_nodes() {
    let sim = sim::Sim::start("pve9").await;
    let target = |node: Option<&str>| {
        let mut settings = serde_json::json!({ "token": "rackhand@pve!hub=secret", "fingerprint": sim.fingerprint });
        if let Some(n) = node {
            settings["node"] = n.into();
        }
        DriverTarget { target: sim.url.clone(), settings, timeout: std::time::Duration::from_secs(5) }
    };
    let op = || DriverOp { name: "host".into(), args: Value::Null };
    let one = Proxmox.call(&target(None), op()).await.unwrap().output;
    assert_eq!((one["node"].as_str(), &one["nodes"]), (Some("pve9"), &serde_json::json!(["pve9"])));
    let guests = one["guests"].as_array().unwrap();
    let ct = guests.iter().find(|g| g["vmid"] == 100).unwrap();
    assert_eq!(
        (ct["type"].as_str(), ct["name"].as_str(), ct["running"].as_bool()),
        (Some("lxc"), Some("ct-test"), Some(true))
    );
    assert!(guests.iter().any(|g| g["type"] == "qemu"), "{guests:?}");
    // a node of a cluster: its guests only, the cluster's nodes all, one that is down among them
    sim.set_nodes(&[("pve9", "online"), ("other", "offline")]);
    let all = Proxmox.call(&target(Some("pve9")), op()).await.unwrap().output;
    assert_eq!((all["node"].as_str(), &all["nodes"]), (Some("pve9"), &serde_json::json!(["other", "pve9"])));
    assert_eq!(all["guests"], one["guests"]);
    let which = Proxmox.call(&target(None), op()).await;
    assert!(which.is_err_and(|e| e.to_string().contains("`node`")), "which of the cluster's nodes this host is");
}
