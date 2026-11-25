//! Embeds the eBPF program (T68): `RACKHAND_PROBE_EBPF` names the object `cargo xtask ebpf build` made. Without it the
//! probe has no program and captures by sampling, which keeps ordinary builds on the stable toolchain.

fn main() {
    println!("cargo:rerun-if-env-changed=RACKHAND_PROBE_EBPF");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let dest = out.join("rackhand-probe-ebpf.o");
    let bytes = match std::env::var_os("RACKHAND_PROBE_EBPF") {
        Some(path) => {
            println!("cargo:rerun-if-changed={}", std::path::Path::new(&path).display());
            std::fs::read(&path).unwrap_or_else(|e| panic!("RACKHAND_PROBE_EBPF={}: {e}", path.to_string_lossy()))
        }
        None => Vec::new(),
    };
    std::fs::write(&dest, bytes).expect("writing the eBPF object into OUT_DIR");
}
