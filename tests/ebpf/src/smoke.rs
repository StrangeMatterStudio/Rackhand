//! Checks that each eBPF tier VM runs the requested kernel with BTF.

#[test]
fn kernel_has_btf() {
    let expected = std::env::var("RACKHAND_EXPECT_KERNEL")
        .expect("eBPF tests run inside a VM for one kernel series: use `cargo xtask ci ebpf`");
    assert!(std::path::Path::new("/sys/kernel/btf/vmlinux").exists(), "no BTF in kernel {expected}");
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").expect("osrelease is readable");
    assert!(
        release.trim().starts_with(&format!("{expected}.")),
        "running kernel {} is not series {expected}",
        release.trim()
    );
}
