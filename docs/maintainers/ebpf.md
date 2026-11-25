# Building the probe's eBPF programs

The probe's eBPF capture (design FR-4, FR-5) lives in `crates/rackhand-probe-ebpf`, licensed `GPL-2.0 OR MIT` (D111).
It isn't a workspace member: it builds for `bpfel-unknown-none` with its own dated nightly toolchain (its
`rust-toolchain.toml`) and `bpf-linker`, so ordinary builds stay on the stable toolchain.

## Tools

- The nightly named in `crates/rackhand-probe-ebpf/rust-toolchain.toml`, with `rust-src`. rustup installs it the first
  time you build in that directory.
- `bpf-linker` 0.13.0. Its LLVM (23) must match the nightly's (`rustc +nightly -vV` prints `LLVM version`). Use the
  release's static build rather than `cargo install`, which needs a system LLVM of the same version:

  ```sh
  mkdir -p ~/dl/bpf-linker && cd ~/dl/bpf-linker
  curl -fsSLo bpf-linker.tar.zst \
    https://github.com/aya-rs/bpf-linker/releases/download/v0.13.0/bpf-linker-x86_64-unknown-linux-musl.tar.zst
  echo "0e9b2b30f68898177f1cb6f0ecbfa909a82479473a49a0ef66529fd088e3e410  bpf-linker.tar.zst" | sha256sum -c
  tar --zstd -xf bpf-linker.tar.zst && install -m 0755 bpf-linker ~/.local/bin/bpf-linker
  bpf-linker --version
  ```

## Building

```sh
cargo xtask ebpf build
```

It prints the object's path. A probe build carries the capture when `RACKHAND_PROBE_EBPF` names that object at build
time (the probe's `build.rs` embeds it); without it the probe captures by sampling. `cargo xtask ci ebpf` builds the
object and the eBPF tier's tests with it, then runs them in a VM for each kernel in `tests/ebpf/kernels.toml`.
