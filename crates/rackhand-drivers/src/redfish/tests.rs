//! The Redfish driver against the simulator's invented responses (plan T48).

use std::time::Duration;

use serde_json::json;

use super::sim::Sim;
use super::*;
use crate::{Driver, DriverTarget};

fn target(sim: &Sim) -> DriverTarget {
    DriverTarget {
        target: sim.url.clone(),
        settings: json!({ "username": "rackhand", "password": "invented", "fingerprint": sim.fingerprint }),
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
async fn power_fans_temps_psu_health() {
    let sim = Sim::start().await;
    let r = Redfish::new().poll(&target(&sim)).await.unwrap();
    assert!(r.ok, "{}", r.detail);
    let system = [("sensor", "1")];
    assert_eq!(point(&r, "redfish.power_on", &system), Some(1.0));
    assert_eq!(point(&r, "redfish.health", &system), Some(1.0), "the rollup is Warning: 0 OK, 1 Warning, 2 Critical");
    assert_eq!(point(&r, "redfish.temp_c", &[("sensor", "CPU1 Temp")]), Some(46.0));
    assert_eq!(point(&r, "redfish.temp_c", &[("sensor", "Inlet Temp")]), Some(24.0));
    assert_eq!(
        point(&r, "redfish.temp_c", &[("sensor", "Absent Sensor")]),
        None,
        "an absent sensor's stale 0 isn't a reading"
    );
    assert_eq!(point(&r, "redfish.fan_rpm", &[("sensor", "Fan1")]), Some(5400.0));
    assert_eq!(point(&r, "redfish.fan_rpm", &[("sensor", "Fan2")]), Some(5520.0));
    assert_eq!(point(&r, "redfish.psu_ok", &[("sensor", "PSU1")]), Some(1.0));
    assert_eq!(point(&r, "redfish.psu_ok", &[("sensor", "PSU2")]), Some(0.0), "PSU2 is Critical");
    // GETs only, with the account, along the links the service gives
    let requests = sim.requests();
    assert!(requests.iter().all(|(method, _, auth)| method == "GET" && auth.starts_with("Basic ")), "{requests:?}");
    assert!(requests.iter().any(|(_, path, _)| path == "/redfish/v1/Chassis/1/Power"));
    // a wrong password is the reading's failure, not a crash
    let mut wrong = target(&sim);
    wrong.settings["password"] = json!("nope");
    let r = Redfish::new().poll(&wrong).await.unwrap();
    assert!(!r.ok && r.detail.contains("401"), "{}", r.detail);
}
