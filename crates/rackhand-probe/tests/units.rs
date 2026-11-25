//! The probe's systemd units (7.3.3, D196): the probe keeps `CAP_BPF` only, to read the maps the root helper passes;
//! the helper is the root process that loads and attaches the eBPF capture.

use std::path::PathBuf;

fn unit(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/systemd").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn values<'a>(text: &'a str, key: &str) -> Vec<&'a str> {
    text.lines().filter_map(|l| l.strip_prefix(key)?.strip_prefix('=')).collect()
}

#[test]
fn probe_keeps_cap_bpf_only() {
    let probe = unit("rackhand-probe.service");
    assert_eq!(values(&probe, "AmbientCapabilities"), ["CAP_BPF"]);
    assert_eq!(values(&probe, "CapabilityBoundingSet"), ["CAP_BPF"]);
    assert_eq!(values(&probe, "User"), ["rackhand-probe"]);
    assert_eq!(values(&probe, "NoNewPrivileges"), ["yes"]);
}

#[test]
fn helper_is_the_root_process() {
    let helper = unit("rackhand-probe-helper.service");
    assert!(values(&helper, "User").is_empty(), "the helper runs as root");
    assert!(values(&helper, "CapabilityBoundingSet").is_empty(), "loading and attaching needs root's capabilities");
}
