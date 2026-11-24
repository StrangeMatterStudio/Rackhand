//! Network tier (design 14): network namespaces and nftables NAT, run as root inside a QEMU VM by
//! `cargo xtask ci net`.

#[cfg(test)]
mod holepunch;
#[cfg(test)]
mod smoke;
#[cfg(test)]
mod topology;
#[cfg(test)]
mod xfer;

/// Panics unless the test runs inside the network tier's VM.
#[cfg(test)]
pub(crate) fn require_vm() {
    assert_eq!(
        std::env::var("RACKHAND_TIER").as_deref(),
        Ok("net"),
        "network tests run as root inside a VM: use `cargo xtask ci net`"
    );
}
