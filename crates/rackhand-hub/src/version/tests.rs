use super::accepts;

#[test]
fn own_minor_any_patch_accepted() {
    assert!(accepts("0.4.2", "0.4.2"));
    assert!(accepts("0.4.2", "0.4.0"));
    assert!(accepts("0.4.2", "0.4.9"), "a newer patch of the same minor");
}

#[test]
fn one_minor_older_accepted() {
    assert!(accepts("0.4.2", "0.3.0"));
    assert!(accepts("0.4.2", "0.3.17"));
    assert!(!accepts("1.0.0", "0.9.5"), "the major differs");
}

#[test]
fn two_minors_older_refused() {
    assert!(!accepts("0.4.2", "0.2.9"));
    assert!(!accepts("0.4.2", "0.1.0"));
}

#[test]
fn newer_minor_or_major_refused() {
    assert!(!accepts("0.4.2", "0.5.0"));
    assert!(!accepts("0.4.2", "1.4.2"));
}

#[test]
fn minor_zero_has_no_older_minor() {
    assert!(accepts("0.0.3", "0.0.1"));
    assert!(!accepts("1.0.0", "0.9.9"));
}

#[test]
fn unparsable_versions_refused() {
    for bad in ["", "0.4", "0.4.2-beta", "v0.4.2", "0.04.2", "0.4.2.1", " 0.4.2"] {
        assert!(!accepts("0.4.2", bad), "{bad:?}");
    }
    assert!(!accepts("garbage", "0.4.2"), "a hub version that doesn't parse accepts nothing");
}

#[test]
fn the_largest_minor_does_not_overflow() {
    let max = u64::MAX;
    assert!(!accepts("0.5.0", &format!("0.{max}.0")));
    assert!(accepts(&format!("0.{max}.0"), &format!("0.{max}.1")));
    assert!(accepts(&format!("0.{max}.0"), &format!("0.{}.0", max - 1)));
}
