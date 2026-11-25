#!/usr/bin/env bash
# Installs the Rust toolchain and the named tools without sudo (CI runners have none). Cached under CARGO_HOME and
# RUSTUP_HOME when the runner provides a persistent cache. Tools: nextest, deny, vmtest, pwsh, ebpf (the eBPF crate's
# pinned nightly with rust-src, and bpf-linker; docs/maintainers/ebpf.md).
set -euo pipefail
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export PATH="$CARGO_HOME/bin:$HOME/.local/bin:$PATH"
mkdir -p "$HOME/.local/bin"
if ! command -v rustup >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none --no-modify-path
fi
rustup show active-toolchain >/dev/null # installs the version in rust-toolchain.toml
for tool in "$@"; do
  case "$tool" in
    nextest) command -v cargo-nextest >/dev/null || cargo install --locked cargo-nextest ;;
    deny) command -v cargo-deny >/dev/null || cargo install --locked cargo-deny ;;
    vmtest) command -v vmtest >/dev/null || cargo install --locked vmtest ;;
    pwsh)
      if ! command -v pwsh >/dev/null; then
        v=7.4.6
        curl -sSfL "https://github.com/PowerShell/PowerShell/releases/download/v$v/powershell-$v-linux-x64.tar.gz" -o /tmp/pwsh.tgz
        mkdir -p "$HOME/.local/pwsh" && tar -xzf /tmp/pwsh.tgz -C "$HOME/.local/pwsh"
        chmod +x "$HOME/.local/pwsh/pwsh" && ln -sf "$HOME/.local/pwsh/pwsh" "$HOME/.local/bin/pwsh"
      fi
      pwsh -NoProfile -c 'if (-not (Get-Module -ListAvailable Pester | ? { $_.Version.Major -ge 5 })) { Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck -MinimumVersion 5.0 }'
      ;;
    ebpf)
      # the nightly named by the eBPF crate's rust-toolchain.toml
      nightly=$(sed -n 's/^channel = "\(.*\)"$/\1/p' crates/rackhand-probe-ebpf/rust-toolchain.toml)
      rustup toolchain install "$nightly" --profile minimal --component rust-src
      if ! bpf-linker --version 2>/dev/null | grep -q '0\.13\.0'; then
        url=https://github.com/aya-rs/bpf-linker/releases/download/v0.13.0/bpf-linker-x86_64-unknown-linux-musl.tar.zst
        dir=$(mktemp -d)
        curl -sSfL "$url" -o "$dir/bpf-linker.tar.zst"
        echo "0e9b2b30f68898177f1cb6f0ecbfa909a82479473a49a0ef66529fd088e3e410  $dir/bpf-linker.tar.zst" | sha256sum -c -
        if command -v zstd >/dev/null; then
          tar --zstd -xf "$dir/bpf-linker.tar.zst" -C "$dir"
        elif command -v node >/dev/null; then
          # a runner without zstd: Node's own zstd decompressor
          node -e "process.stdin.pipe(require('zlib').createZstdDecompress()).pipe(process.stdout)" \
            < "$dir/bpf-linker.tar.zst" | tar -x -C "$dir"
        else
          echo "unpacking bpf-linker needs zstd or node" >&2
          exit 1
        fi
        install -m 0755 "$dir/bpf-linker" "$CARGO_HOME/bin/bpf-linker"
        rm -rf "$dir"
      fi
      bpf-linker --version
      ;;
    *) echo "unknown tool $tool" >&2; exit 1 ;;
  esac
done
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$CARGO_HOME/bin" >> "$GITHUB_PATH"
  echo "$HOME/.local/bin" >> "$GITHUB_PATH"
fi
