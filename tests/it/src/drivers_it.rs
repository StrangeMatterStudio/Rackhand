//! Appliances added through the Add page's forms (7.3.12), against the drivers' simulators running in this process:
//! each reports its readings (7.4.2), and once its API stops answering it is silent after 2 polls (7.6.3, AC11).

use std::time::Duration;

use crate::probe_hub::{Hub, field, within};

const PVE_TOKEN: &str = "rackhand@pve!hub=00000000-1111-2222-3333-444444444444";

fn hub(name: &str) -> Hub {
    let mut hub = Hub::init(name);
    hub.start();
    hub.first_run();
    hub
}

/// A dashboard form, as the admin submits it.
fn submit(hub: &Hub, path: &str, fields: &[(&str, &str)]) -> String {
    let csrf = field(&hub.curl(&["/add"]), "csrf");
    let mut args = vec!["--data-urlencode".to_string(), format!("csrf={csrf}")];
    for (k, v) in fields {
        args.push("--data-urlencode".into());
        args.push(format!("{k}={v}"));
    }
    args.push(path.into());
    hub.curl(&args.iter().map(String::as_str).collect::<Vec<_>>())
}

/// Adds an appliance through the Add page: its address, then (shown the certificate) its credentials.
fn add(hub: &Hub, driver: &str, name: &str, address: &str, fingerprint: Option<&str>, credentials: &[(&str, &str)]) {
    let shown = submit(hub, "/add/appliance", &[("driver", driver), ("name", name), ("address", address)]);
    if let Some(fp) = fingerprint {
        assert!(shown.contains(fp), "{driver}: the certificate to accept: {shown}");
    }
    let token = field(&shown, "token");
    let mut fields = vec![("token", token.as_str())];
    if let Some(fp) = fingerprint {
        fields.push(("fingerprint", fp));
    }
    fields.extend_from_slice(credentials);
    let done = submit(hub, "/add/appliance/accept", &fields);
    assert_eq!(state(hub, name), "enrolled", "{driver}: {done}");
}

fn query(hub: &Hub, sql: &str, name: &str) -> Vec<String> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let _in = rt.enter();
    let db = rackhand_store::Db::open(&hub.data.join("hub.db")).unwrap();
    db.readers()
        .with(|c| {
            let mut s = c.prepare(sql)?;
            s.query_map([name], |r| r.get::<_, String>(0))?.collect()
        })
        .unwrap()
}

fn state(hub: &Hub, name: &str) -> String {
    query(hub, "SELECT state FROM machines WHERE name = ?1", name).pop().unwrap_or_default()
}

/// The open `machine.silent` incident of the machine, as `severity`.
fn silent(hub: &Hub, name: &str) -> Option<String> {
    query(
        hub,
        "SELECT i.severity FROM incidents i JOIN machines m ON m.id = i.machine_id
         WHERE m.name = ?1 AND i.kind = 'machine.silent' AND i.state != 'resolved'",
        name,
    )
    .pop()
}

/// The machine's polls, newest first: whether it answered and what the driver said.
fn polls(hub: &Hub, name: &str) -> Vec<String> {
    query(
        hub,
        "SELECT ?1 || ': ' || r.ok || ' ' || coalesce(r.detail, '') FROM check_results r JOIN machines m
         ON r.check_id = 'driver:' || m.id WHERE m.name = ?1 ORDER BY r.at_ms DESC LIMIT 3",
        name,
    )
}

/// How many of the machine's polls failed in a row, newest first.
fn failed_polls(hub: &Hub, name: &str) -> usize {
    query(
        hub,
        "SELECT CAST(r.ok AS TEXT) FROM check_results r JOIN machines m ON r.check_id = 'driver:' || m.id
         WHERE m.name = ?1 ORDER BY r.at_ms DESC LIMIT 10",
        name,
    )
    .iter()
    .take_while(|ok| *ok == "0")
    .count()
}

mod drivers {
    use super::*;

    #[test]
    fn form_added_simulators_report_and_silence_after_2_polls() {
        let hub = hub("drivers-forms");
        let sims = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let (pve, nas, bmc, switch) = sims.block_on(async {
            (
                rackhand_drivers::proxmox::sim::Sim::start("pve8").await,
                rackhand_drivers::truenas::sim::Sim::start(rackhand_drivers::truenas::sim::Api::WebSocket).await,
                rackhand_drivers::redfish::sim::Sim::start().await,
                rackhand_drivers::snmp::sim::Sim::start().await,
            )
        });
        add(&hub, "proxmox", "pve1", &pve.url, Some(&pve.fingerprint), &[("token_value", PVE_TOKEN)]);
        add(&hub, "truenas", "nas1", &nas.url, Some(&nas.fingerprint), &[("api_key", "1-invented-api-key")]);
        add(
            &hub,
            "redfish",
            "bmc1",
            &bmc.url,
            Some(&bmc.fingerprint),
            &[("username", "rackhand"), ("password", "invented")],
        );
        add(&hub, "snmp", "switch1", &switch.addr, None, &[("version", "2c"), ("community", "public-lab")]);

        // each reports its readings
        let names = ["pve1", "nas1", "bmc1", "switch1"];
        let reporting = || {
            let m = hub.metrics();
            names.iter().all(|n| m.contains(&format!("machine=\"{n}\"")))
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        while !reporting() {
            if std::time::Instant::now() > deadline {
                let polls: Vec<String> = names.iter().flat_map(|n| polls(&hub, n)).collect();
                let checks = query(
                    &hub,
                    "SELECT id || ' ' || coalesce(machine_id, '') || ' ' || interval_s FROM checks WHERE ?1 = ?1",
                    "x",
                );
                panic!(
                    "not within 120s: every appliance's readings on /metrics\npolls: {polls:#?}\nchecks: {checks:#?}\nmetrics: {}",
                    hub.metrics()
                );
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let metrics = hub.metrics();
        for (name, series) in [
            ("pve1", "rackhand_pve_node_cpu_pct"),
            ("nas1", "rackhand_truenas_pool_healthy"),
            ("bmc1", "rackhand_redfish_temp_c"),
            ("switch1", "rackhand_snmp_if_in_octets"),
        ] {
            let line = metrics.lines().find(|l| l.starts_with(series) && l.contains(&format!("machine=\"{name}\"")));
            assert!(line.is_some(), "{name}: `{series}` reported: {metrics}");
        }
        assert!(names.iter().all(|n| silent(&hub, n).is_none()), "answering appliances aren't silent");

        // the APIs stop answering: silent, a warning, after 2 failed polls
        drop((pve, nas, bmc, switch));
        sims.shutdown_background();
        within(Duration::from_secs(330), "every appliance silent", || names.iter().all(|n| silent(&hub, n).is_some()));
        for name in names {
            assert_eq!(silent(&hub, name).as_deref(), Some("warning"), "{name}");
            let failed = failed_polls(&hub, name);
            assert!((2..5).contains(&failed), "{name}: silent after 2 failed polls, not yet critical: {failed}");
        }
    }
}
