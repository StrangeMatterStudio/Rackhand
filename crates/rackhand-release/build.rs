//! The test release keys never reach a release build (13, D90): T91's release build sets `RACKHAND_RELEASE=1`, and a
//! build that also has the `test-keys` feature (which `lab-build` turns on) stops here.

fn main() {
    println!("cargo:rerun-if-env-changed=RACKHAND_RELEASE");
    let test_keys = std::env::var_os("CARGO_FEATURE_TEST_KEYS").is_some();
    if test_keys && std::env::var("RACKHAND_RELEASE").as_deref() == Ok("1") {
        panic!(
            "rackhand-release: the `test-keys` feature (turned on by `lab-build`) pins the test release keys of \
             tests/keys/ and can't be in a release build (RACKHAND_RELEASE=1)"
        );
    }
}
