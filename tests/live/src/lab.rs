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
    // A Proxmox node's extra disk, which holds its ZFS pool, is reset too.
    on("pve9", "sudo zfs create tank/rackhand-reset-marker");
    lab(&["reset", "pve9"]);
    assert!(eventually(Duration::from_secs(300), || ok_on("pve9", "sudo zpool list tank")), "the pool is back");
    assert!(ok_on("pve9", "! sudo zfs list tank/rackhand-reset-marker"), "the marker dataset survived a reset");
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

/// The guests on site A: ct-test and vm-test on each node (node address + 100 and + 110).
const GUESTS: &[(&str, &str, &str)] = &[
    ("pve8", "ct-test", "192.0.2.151"),
    ("pve8", "vm-test", "192.0.2.161"),
    ("pve9", "ct-test", "192.0.2.152"),
    ("pve9", "vm-test", "192.0.2.162"),
];

#[test]
fn proxmox_vm_guest_boots() {
    for node in ["pve8", "pve9"] {
        let mode = on(node, "sudo cat /root/rackhand-lab-nested");
        println!("vm-test on {node} runs with {}", mode.trim());
        assert!(on(node, "sudo qm status 200").contains("running"), "vm-test isn't running on {node}");
    }
    // With emulation a guest can take a few minutes to boot.
    for (node, guest, ip) in GUESTS {
        assert!(
            eventually(Duration::from_secs(600), || ok_on("hub", &format!("ping -c 1 -W 2 {ip}"))),
            "{guest} on {node} ({ip}) never answered on site A"
        );
    }
}

#[test]
fn proxmox_guests_answer_every_time() {
    // One answer can be luck: a bridge that learned a guest's MAC on the wrong port still answers now and then.
    for (node, _, ip) in GUESTS {
        assert!(eventually(Duration::from_secs(600), || ok_on("hub", &format!("ping -c 1 -W 2 {ip}"))));
        let out = on("hub", &format!("ping -c 10 -i 0.3 -W 1 {ip} | grep -o '[0-9]* received' || true"));
        assert_eq!(out.trim(), "10 received", "{ip} on {node} dropped pings");
    }
    for node in ["pve8", "pve9"] {
        // The site NIC is the bridge's only port that isn't a guest's.
        let links = on(node, "sudo bridge -d link show");
        let blocks = split_ports(&links.lines().collect::<Vec<_>>());
        let site: Vec<&String> = blocks.iter().filter(|b| !is_guest_port(b)).collect();
        assert_eq!(site.len(), 1, "{node}: one site NIC on vmbr0: {links}");
        assert!(site[0].contains("learning off"), "{node}: learning is on for the site NIC: {}", site[0]);
    }
}

/// Splits `bridge -d link show` output into one block per port.
fn split_ports(lines: &[&str]) -> Vec<String> {
    let mut blocks: Vec<String> = Vec::new();
    for line in lines {
        if line.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            blocks.push(String::new());
        }
        if let Some(b) = blocks.last_mut() {
            b.push_str(line);
            b.push('\n');
        }
    }
    blocks
}

fn is_guest_port(block: &str) -> bool {
    let name = block.split(": ").nth(1).unwrap_or("");
    ["tap", "veth", "fwpr", "fwln"].iter().any(|p| name.starts_with(p))
}
