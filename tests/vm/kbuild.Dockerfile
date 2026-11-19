# Builds test kernels (with BTF, so pahole from dwarves is needed).
FROM debian:bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential bc bison flex libelf-dev libssl-dev dwarves python3 \
    cpio xz-utils kmod rsync zstd ca-certificates \
 && rm -rf /var/lib/apt/lists/*
