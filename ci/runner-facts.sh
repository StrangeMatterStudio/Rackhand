#!/usr/bin/env bash
# Prints what a runner offers (T04): kernel, CPUs, memory, disk, Docker and /dev/kvm.
set -u
echo "kernel: $(uname -r)"
echo "cpus: $(nproc)"
echo "memory: $(awk '/MemTotal/ {printf "%.1f GB", $2/1048576}' /proc/meminfo)"
echo "disk: $(df -h "${RUNNER_WORKSPACE:-$PWD}" | awk 'NR==2 {print $4 " free"}')"
if command -v docker >/dev/null && docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then
  echo "docker: $(docker info --format '{{.ServerVersion}}')"
else
  echo "docker: none"
fi
if [ -w /dev/kvm ]; then echo "kvm: writable /dev/kvm"; else echo "kvm: none"; fi
