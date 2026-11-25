//! Notifiers trust the public roots only (D113): T91's release build sets `RACKHAND_RELEASE=1`, and a build that also has
//! the offline test's `test-smtp-roots` feature (plan T97), which trusts a root file for its LAN mail server, stops here.

fn main() {
    println!("cargo:rerun-if-env-changed=RACKHAND_RELEASE");
    let test_roots = std::env::var_os("CARGO_FEATURE_TEST_SMTP_ROOTS").is_some();
    if test_roots && std::env::var("RACKHAND_RELEASE").as_deref() == Ok("1") {
        panic!(
            "rackhand-hub: the `test-smtp-roots` feature trusts /etc/rackhand/test-smtp-roots.pem for SMTP, for the offline \
             test only, and can't be in a release build (RACKHAND_RELEASE=1)"
        );
    }
}
