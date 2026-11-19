//! Tests for the lab configuration and its guards (plan L1).

use super::config::*;
use super::images::*;

fn lab() -> Lab {
    Lab::load().unwrap()
}

#[test]
fn profiles_reference_known_machines() {
    let lab = lab();
    assert!(lab.check().is_empty(), "{:?}", lab.check());
    let mut broken = lab.clone();
    broken.profiles.insert("bad".into(), vec!["hub".into(), "nonexistent".into()]);
    let problems = broken.check();
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("nonexistent"));
}

#[test]
fn image_checksum_mismatch_is_refused() {
    let dir = std::env::temp_dir().join(format!("rackhand-lab-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("image.qcow2");
    std::fs::write(&file, b"not an image").unwrap();
    let image = Image {
        name: "test".into(),
        url: "https://example.invalid/image.qcow2".into(),
        sha256: None,
        sha512: Some("0".repeat(128)),
    };
    let err = image.verify(&file).unwrap_err().to_string();
    assert!(err.contains("SHA-512"), "{err}");
    assert!(!file.exists(), "a mismatched image must be deleted");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn profile_over_memory_budget_is_refused() {
    let lab = lab();
    // m2 is the largest profile: 13.5 GB. With 20 GB available and 12 GB kept for builds it doesn't fit.
    let err = lab.check_budget("m2", 20 * 1024, 12 * 1024).unwrap_err().to_string();
    assert!(err.contains("m2"), "{err}");
    lab.check_budget("m2", 28 * 1024, 12 * 1024).unwrap();
    assert_eq!(lab.profile_memory_mb("m2").unwrap(), 13_824);
}

#[test]
fn site_networks_use_documentation_ranges() {
    let lab = lab();
    for machine in &lab.machines {
        for nic in &machine.nics {
            assert!(
                nic.address.starts_with("192.0.2.") || nic.address.starts_with("198.51.100."),
                "{} uses {}",
                machine.name,
                nic.address
            );
            let site = &lab.sites[&nic.site];
            assert!(site.contains(&nic.address), "{} {} outside site {}", machine.name, nic.address, nic.site);
        }
    }
}

#[test]
fn provision_stamp_follows_the_inputs() {
    use super::is_provisioned;
    let stamp =
        |image: &str, parts: &[&str]| super::stamp(image, &parts.iter().map(|p| p.as_bytes()).collect::<Vec<_>>());
    let a = stamp("debian-12", &["user-data", "script 1"]);
    assert_eq!(a, stamp("debian-12", &["user-data", "script 1"]), "stable");
    assert_ne!(a, stamp("debian-12", &["user-data", "script 2"]), "a changed script re-provisions");
    assert_ne!(a, stamp("debian-13", &["user-data", "script 1"]), "a changed image re-provisions");
    assert_ne!(a, stamp("debian-12", &["user-data", "script", " 1"]), "parts are delimited");
    let dir = std::env::temp_dir().join(format!("rackhand-lab-stamp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    assert!(!is_provisioned(&dir, &a), "never provisioned");
    std::fs::write(dir.join("base.provisioned"), b"ok").unwrap();
    assert!(!is_provisioned(&dir, &a), "a stamp from before stamps were hashed is stale");
    std::fs::write(dir.join("base.provisioned"), &a).unwrap();
    assert!(is_provisioned(&dir, &a));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn extra_disk_is_an_overlay_that_reset_replaces() {
    use super::qemu::{Stage, drives};
    let lab = lab();
    let (pve, target) = (lab.machine("pve9").unwrap(), lab.machine("target").unwrap());
    let dir = std::path::Path::new("/m");
    // Provisioning writes the bases (the ZFS pool lands on `extra-base.qcow2`); a running machine uses overlays.
    assert_eq!(drives(dir, pve, Stage::Provision), [dir.join("base.qcow2"), dir.join("extra-base.qcow2")]);
    assert_eq!(drives(dir, pve, Stage::Run), [dir.join("disk.qcow2"), dir.join("extra.qcow2")]);
    assert_eq!(drives(dir, target, Stage::Run), [dir.join("disk.qcow2")]);
    assert_eq!(super::reset_files(pve), ["disk.qcow2", "extra.qcow2"]);
    assert_eq!(super::reset_files(target), ["disk.qcow2"]);
}
