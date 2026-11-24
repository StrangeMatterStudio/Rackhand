use rackhand_release::slots::Slot;

use super::*;

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn state(state: &str, version: &str) -> String {
    format!(r#"{{"state":"{state}","version":"{version}","at_ms":1}}"#)
}

/// The probe is up for the guard only when its state file says `connected` with exactly the new version.
#[test]
fn only_connected_with_the_new_version_counts() {
    assert!(connected_with(&state("connected", "0.1.1"), v("0.1.1")));
    for (name, says) in [
        ("old version connected", state("connected", "0.1.0")),
        ("new version connecting", state("connecting", "0.1.1")),
        ("new version waiting to retry", state("disconnected", "0.1.1")),
        ("a state that isn't json", "connected 0.1.1".to_string()),
        ("a newer version than the one installed", state("connected", "0.1.2")),
        ("connected without a version", r#"{"state":"connected"}"#.to_string()),
    ] {
        assert!(!connected_with(&says, v("0.1.1")), "{name}");
    }
}

#[test]
fn the_slots_are_named_by_the_helper_and_nothing_else_is_accepted() {
    // the slots' own names: `probe-a` on Linux, `probe-a.exe` on Windows
    let [a, b] = crate::update::apply::paths(std::path::Path::new("/")).slots;
    let (plan, version) = parse_args(&[a.into(), b.into(), "0.1.1".into()]).unwrap();
    assert_eq!((plan.old, plan.new, version), (Slot::A, Slot::B, v("0.1.1")));
    assert_eq!(plan.layout.link, if cfg!(windows) { "rackhand-probe.exe" } else { "rackhand-probe" });
    for bad in [
        vec![a, a, "0.1.1"],
        vec!["/etc/passwd", b, "0.1.1"],
        vec![a, "../probe-b", "0.1.1"],
        vec!["rackhand-a", "rackhand-b", "0.1.1"],
        vec![a, b, "latest"],
        vec![a, b],
        vec![a, b, "0.1.1", "extra"],
    ] {
        let args: Vec<String> = bad.iter().map(|s| s.to_string()).collect();
        assert!(parse_args(&args).is_err(), "{bad:?}");
    }
}
