//! What this probe can do (E36): `Hello.capabilities` says whether connections come from eBPF or from sampling, whether the
//! root helper is there and whether it sees containers. The Machine page shows the capture as "eBPF" or "sampling".

use rackhand_proto::probe::Capability;

use crate::collect::Host;

/// The kernel's type information, which an eBPF program that runs on any kernel needs (CO-RE).
const BTF: &str = "sys/kernel/btf/vmlinux";

/// `Ebpf` when the capture is loaded and the kernel has BTF; otherwise `Sampling`.
pub fn capture(host: &dyn Host, ebpf_loaded: bool) -> Capability {
    if ebpf_loaded && host.read(BTF).is_some() { Capability::Ebpf } else { Capability::Sampling }
}

/// The capability list a Hello carries.
pub fn all(host: &dyn Host, ebpf_loaded: bool, helper: bool, containers: bool) -> Vec<i32> {
    let mut out = vec![capture(host, ebpf_loaded) as i32];
    if helper {
        out.push(Capability::Helper as i32);
    }
    if containers {
        out.push(Capability::Containers as i32);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::RootHost;

    #[test]
    fn no_ebpf_reports_sampling() {
        let dir = std::env::temp_dir().join(format!("rackhand-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sys/kernel")).unwrap();
        let host = RootHost::new(&dir);
        // a kernel without BTF can't load the capture, whatever was asked
        assert_eq!(capture(&host, true), Capability::Sampling);
        assert_eq!(all(&host, true, true, false), [Capability::Sampling as i32, Capability::Helper as i32]);
        // with BTF and the capture loaded, eBPF; with BTF and no capture, sampling still
        std::fs::create_dir_all(dir.join("sys/kernel/btf")).unwrap();
        std::fs::write(dir.join("sys/kernel/btf/vmlinux"), "btf").unwrap();
        assert_eq!(capture(&host, true), Capability::Ebpf);
        assert_eq!(capture(&host, false), Capability::Sampling);
        assert_eq!(
            all(&host, true, true, true),
            [Capability::Ebpf as i32, Capability::Helper as i32, Capability::Containers as i32]
        );
    }
}
