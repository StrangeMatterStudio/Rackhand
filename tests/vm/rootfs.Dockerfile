# Root filesystem for the network and eBPF tier VMs (vmtest needs qemu-guest-agent in the guest).
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends qemu-guest-agent iproute2 nftables iputils-ping procps bash \
    ca-certificates kmod \
 && rm -rf /var/lib/apt/lists/*
