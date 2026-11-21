//! The TrueNAS driver against the simulator, which replays the answers recorded in S9 (plan T14), over JSON-RPC on the
//! WebSocket at `/api/current` and, for a release without it, REST at `/api/v2.0`.

use std::time::Duration;

use serde_json::json;

use super::sim::{Api, Sim};
use super::*;
use crate::{Driver, DriverTarget};

const KEY: &str = "1-invented-api-key";

fn target(sim: &Sim) -> DriverTarget {
    DriverTarget {
        target: sim.url.clone(),
        settings: json!({ "api_key": KEY, "fingerprint": sim.fingerprint }),
        timeout: Duration::from_secs(5),
    }
}

fn point(r: &crate::DriverReading, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    r.points
        .iter()
        .find(|p| p.name == name && labels.iter().all(|(k, v)| p.labels.get(*k).map(String::as_str) == Some(*v)))
        .map(|p| p.value)
}

#[tokio::test]
async fn pool_disk_smart_alerts_metrics() {
    for api in [Api::WebSocket, Api::Rest] {
        let sim = Sim::start(api).await;
        let r = TrueNas::new().poll(&target(&sim)).await.unwrap();
        assert!(r.ok, "{api:?}: {}", r.detail);
        let pool = [("pool", "tank1")];
        assert_eq!(point(&r, "truenas.pool.healthy", &pool), Some(1.0), "{api:?}");
        // the two recordings were a moment apart: what each says
        let dir = if api == Api::WebSocket { "ws" } else { "rest" };
        let file = format!("{}/tests/fixtures/truenas/{dir}/pool.json", env!("CARGO_MANIFEST_DIR"));
        let recorded: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
        let (size, used) = (recorded[0]["size"].as_f64().unwrap(), recorded[0]["allocated"].as_f64().unwrap());
        assert_eq!(point(&r, "truenas.pool.total_bytes", &pool), Some(size), "{api:?}");
        assert_eq!(point(&r, "truenas.pool.used_bytes", &pool), Some(used), "{api:?}");
        assert_eq!(point(&r, "truenas.pool.used_pct", &pool), Some(77.42), "{api:?}: {used} of {size}");
        assert_eq!(point(&r, "truenas.disk.temp_c", &[("disk", "sdb")]), Some(38.0), "{api:?}");
        assert_eq!(point(&r, "truenas.disk.temp_c", &[("disk", "sda")]), None, "no sensor reading isn't 0 °C");
        for disk in ["sdb", "sdc", "sdd", "sde"] {
            assert_eq!(point(&r, "truenas.disk.smart_ok", &[("disk", disk)]), Some(1.0), "{api:?}: {disk}");
        }
        // sda has had no SMART test yet: no reading, rather than a pass
        assert_eq!(point(&r, "truenas.disk.smart_ok", &[("disk", "sda")]), None, "{api:?}");
        // the dismissed critical doesn't count; the open warning does
        assert_eq!(point(&r, "truenas.alerts.critical", &[]), Some(0.0), "{api:?}");
        assert_eq!(point(&r, "truenas.alerts.warning", &[]), Some(1.0), "{api:?}");
        // reads only, with the API key
        let calls = sim.calls();
        assert!(!calls.is_empty() && calls.iter().all(|c| sim::READS.contains(&c.as_str())), "{api:?}: {calls:?}");
        assert!(sim.authorized(), "{api:?}: the API key was given");
        // a disk whose latest SMART test failed
        sim.fail_smart("sdc");
        let r = TrueNas::new().poll(&target(&sim)).await.unwrap();
        assert_eq!(point(&r, "truenas.disk.smart_ok", &[("disk", "sdc")]), Some(0.0), "{api:?}");
        assert_eq!(point(&r, "truenas.disk.smart_ok", &[("disk", "sdb")]), Some(1.0), "{api:?}");
    }
}

#[tokio::test]
async fn truenas_certificate_fingerprint_mismatch_refused() {
    let sim = Sim::start(Api::WebSocket).await;
    let mut t = target(&sim);
    t.settings["fingerprint"] = json!("AA".repeat(32));
    let r = TrueNas::new().poll(&t).await.unwrap();
    assert!(!r.ok && r.detail.contains("fingerprint"), "{}", r.detail);
    assert!(sim.calls().is_empty(), "nothing was asked");
}
