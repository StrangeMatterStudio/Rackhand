#!/bin/sh
# Builds /cache/kernels/bzImage-<version> from /cache/src/linux-<version>.tar.xz (already checked against its
# SHA-256 by `cargo xtask kernels fetch`) with the options in kernel.config.
set -eu
version="$1"
build="/cache/build/linux-$version"
rm -rf "$build"
mkdir -p /cache/build /cache/kernels
tar -xf "/cache/src/linux-$version.tar.xz" -C /cache/build
cd "$build"
make -s defconfig
make -s kvm_guest.config
grep -v '^#' /cfg/kernel.config | grep . | while read -r line; do
  name="${line%%=*}"
  value="${line#*=}"
  case "$value" in
    y) ./scripts/config --enable "${name#CONFIG_}" ;;
    n) ./scripts/config --disable "${name#CONFIG_}" ;;
    *) ./scripts/config --set-val "${name#CONFIG_}" "$value" ;;
  esac
done
make -s olddefconfig
for opt in CONFIG_DEBUG_INFO_BTF CONFIG_BPF_SYSCALL CONFIG_9P_FS CONFIG_NET_9P_VIRTIO CONFIG_VIRTIO_CONSOLE CONFIG_VETH CONFIG_NF_TABLES; do
  grep -q "^$opt=y" .config || { echo "kernel $version: $opt is not built in" >&2; exit 1; }
done
make -s -j"$(nproc)" bzImage
cp arch/x86/boot/bzImage "/cache/kernels/bzImage-$version"
cd /
rm -rf "$build"
echo "built /cache/kernels/bzImage-$version"
