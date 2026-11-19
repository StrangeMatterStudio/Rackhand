//! Live checks of the lab itself (plan L1): profile `lab` is up.

use std::time::Duration;

use crate::{eventually, lab, ok_on, on};

const MACHINES: &[&str] = &["hub", "target", "alpine", "pve8", "pve9"];

#[test]
fn machines_boot_and_answer_ssh() {
    for m in MACHINES {
        assert!(eventually(Duration::from_secs(300), || ok_on(m, "true")), "{m} doesn't answer SSH");
    }
}

#[test]
fn site_a_machines_reach_each_other() {
    assert!(ok_on("hub", "ping -c 1 -W 2 192.0.2.20"), "hub can't reach target on site A");
    assert!(ok_on("target", "ping -c 1 -W 2 192.0.2.40"), "target can't reach alpine on site A");
}

#[test]
fn reset_restores_the_pristine_disk() {
    on("target", "touch /home/lab/rackhand-reset-marker");
    lab(&["reset", "target"]);
    assert!(ok_on("target", "test ! -e /home/lab/rackhand-reset-marker"), "the marker survived a reset");
}

#[test]
fn pause_and_cut_stop_traffic() {
    let reach = || ok_on("hub", "ping -c 1 -W 2 192.0.2.20");
    assert!(reach());
    lab(&["pause", "target"]);
    assert!(!reach(), "a paused target still answers");
    lab(&["resume", "target"]);
    assert!(eventually(Duration::from_secs(30), reach), "target didn't come back after resume");
    lab(&["cut", "target"]);
    assert!(!reach(), "a cut target still answers");
    lab(&["heal", "target"]);
    assert!(eventually(Duration::from_secs(30), reach), "target didn't come back after heal");
}

#[test]
fn proxmox_nodes_run_an_lxc_guest() {
    for (node, major) in [("pve8", "8"), ("pve9", "9")] {
        let version = on(node, "sudo pveversion");
        assert!(version.contains(&format!("pve-manager/{major}.")), "{node}: {version}");
        assert!(
            eventually(Duration::from_secs(120), || on(node, "sudo pct status 100").contains("running")),
            "ct-test isn't running on {node}"
        );
    }
}

#[test]
fn proxmox_vm_guest_boots() {
    let mode = on("pve9", "sudo cat /root/rackhand-lab-nested");
    println!("vm-test on pve9 runs with {}", mode.trim());
    assert!(on("pve9", "sudo qm status 200").contains("running"));
    // vm-test is 192.0.2.162; with emulation it can take a few minutes to boot.
    assert!(
        eventually(Duration::from_secs(600), || ok_on("hub", "ping -c 1 -W 2 192.0.2.162")),
        "vm-test ({}) never answered on site A",
        mode.trim()
    );
}
