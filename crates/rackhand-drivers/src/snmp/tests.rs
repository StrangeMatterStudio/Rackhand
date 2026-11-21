//! The SNMP driver against the simulated agent, which serves an invented walk (plan T48).

use std::time::Duration;

use serde_json::json;

use super::sim::Sim;
use super::*;
use crate::{Driver, DriverTarget};

fn point(r: &crate::DriverReading, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    r.points
        .iter()
        .find(|p| p.name == name && labels.iter().all(|(k, v)| p.labels.get(*k).map(String::as_str) == Some(*v)))
        .map(|p| p.value)
}

fn target(sim: &Sim, settings: serde_json::Value) -> DriverTarget {
    DriverTarget { target: sim.addr.clone(), settings, timeout: Duration::from_secs(3) }
}

fn v2c() -> serde_json::Value {
    json!({ "version": "2c", "community": "public-lab", "oids": ["1.3.6.1.4.1.2021.10.1.5.1"] })
}

fn v3() -> serde_json::Value {
    json!({
        "version": "3", "user": "rackhand", "auth": "sha", "auth_password": "invented-auth",
        "priv": "aes", "priv_password": "invented-priv", "oids": ["1.3.6.1.4.1.2021.10.1.5.1"]
    })
}

#[tokio::test]
async fn v2c_and_v3_read_interfaces_and_configured_oids() {
    for (name, settings) in [("v2c", v2c()), ("v3 authPriv", v3())] {
        let sim = Sim::start().await;
        let r = Snmp::new().poll(&target(&sim, settings)).await.unwrap();
        assert!(r.ok, "{name}: {}", r.detail);
        assert_eq!(point(&r, "snmp.sysuptime_s", &[]), Some(123_456.0), "{name}: timeticks are hundredths");
        assert_eq!(point(&r, "snmp.if_in_octets", &[("ifName", "eth0")]), Some(1_000_000.0), "{name}");
        assert_eq!(point(&r, "snmp.if_out_octets", &[("ifName", "eth0")]), Some(2_000_000.0), "{name}");
        assert_eq!(point(&r, "snmp.if_in_octets", &[("ifName", "eth1")]), Some(5_000.0), "{name}");
        assert_eq!(point(&r, "snmp.if_oper_up", &[("ifName", "eth0")]), Some(1.0), "{name}");
        assert_eq!(point(&r, "snmp.if_oper_up", &[("ifName", "eth1")]), Some(0.0), "{name}: down is 2");
        assert_eq!(point(&r, "snmp.oid", &[("oid", "1.3.6.1.4.1.2021.10.1.5.1")]), Some(42.0), "{name}");
        if name.starts_with("v3") {
            assert!(sim.saw_encrypted(), "authPriv: the scoped PDUs went encrypted");
        }
    }
    // the wrong community, or the wrong v3 passwords, get nothing
    let sim = Sim::start().await;
    let mut bad = v2c();
    bad["community"] = json!("public");
    assert!(!Snmp::new().poll(&target(&sim, bad)).await.unwrap().ok);
    let mut bad = v3();
    bad["auth_password"] = json!("not-the-password");
    let r = Snmp::new().poll(&target(&sim, bad)).await.unwrap();
    assert!(!r.ok, "a message the agent can't authenticate gets no answer: {}", r.detail);
}

#[tokio::test]
async fn no_set_requests_ever_sent() {
    let sim = Sim::start().await;
    for settings in [v2c(), v3()] {
        Snmp::new().poll(&target(&sim, settings)).await.unwrap();
    }
    let kinds = sim.pdu_kinds();
    assert!(!kinds.is_empty());
    assert!(kinds.iter().all(|k| matches!(*k, ber::GET | ber::GET_NEXT)), "only get and get-next: {kinds:x?}");
    // and a setting asking for writes isn't one
    let write = json!({ "version": "2c", "community": "private", "write": true });
    assert!(matches!(Snmp::new().poll(&target(&sim, write)).await, Err(crate::DriverError::Invalid(_))));
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The security code against published vectors, since the agent above shares it.
#[test]
fn usm_matches_published_vectors() {
    // RFC 3414 A.3.1: "maplesyrup" localized to engine 00..02 with SHA-1
    let key = usm::localized_key("maplesyrup", &hex("000000000000000000000002"));
    assert_eq!(key.to_vec(), hex("6695febc9288e36282235fc7151f128497b38f3f"));
    // RFC 2202 test case 1 for HMAC-SHA1, truncated to 96 bits
    let mut k = [0u8; 20];
    k.fill(0x0b);
    assert_eq!(usm::hmac_sha96(&k, b"Hi There").to_vec(), hex("b617318655057264e28bc0b6"));
    // NIST SP 800-38A F.3.13 (CFB128-AES128), the IV split as boots, time and salt
    let mut aes_key = [0u8; 20];
    aes_key[..16].copy_from_slice(&hex("2b7e151628aed2a6abf7158809cf4f3c"));
    let salt: [u8; 8] = hex("08090a0b0c0d0e0f").try_into().unwrap();
    let plain = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
    let cipher = usm::aes_cfb(&aes_key, 0x0001_0203, 0x0405_0607, &salt, &plain, false);
    assert_eq!(cipher, hex("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"));
    assert_eq!(usm::aes_cfb(&aes_key, 0x0001_0203, 0x0405_0607, &salt, &cipher, true), plain);
}
