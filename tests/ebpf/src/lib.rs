//! eBPF tier (design 14): kernel tests run as root inside a QEMU VM for each kernel in `kernels.toml`, by
//! `cargo xtask ci ebpf`.

#[cfg(test)]
mod smoke;
