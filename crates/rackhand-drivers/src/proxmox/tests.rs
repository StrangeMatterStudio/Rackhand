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
