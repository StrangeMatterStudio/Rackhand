# 0001 Rackhand architecture and v0.1: Run Log

Result words: OK, degraded, failed (no symbols, per the maintainers' rules).

## Run 1: 2026-11-19
- **Started by:** Owen Ravelo ("start running ... don't stop until it's done and be sure to test along the way")
- **Branch:** `design/0001-architecture` (feature branch; continued without asking) - **Starting commit:** `3119d36`
- **Scope:** all steps, T01 to T99 and L1 to L9
- **Stop points:** none (plan)

### Preflight
| Requirement | Check | Result | Notes |
| --- | --- | --- | --- |
| Plan and design approved | headers of `plan.md` and `design.md` | OK | plan approved 2026-11-18 (Owen), design approved 2026-11-18 |
| Branch | `git branch --show-current` | OK | `design/0001-architecture`; default branch `main` |
| Working tree | `git status --short` | OK | clean at start (local-only `HANDOFF.local.md` is excluded) |
| Push access | `git push --dry-run` | OK | pushes to `origin` |
| PR tooling | `gh auth status` | OK | `repo` and `workflow` scopes |
| WSL Ubuntu 22.04 | `uname -r`, `/etc/os-release` | OK | WSL2 kernel 6.18, Ubuntu 22.04.5 |
| System packages | `dpkg -s ...` | OK | installed by the owner 2026-11-18 |
| `/dev/kvm` | QEMU `-accel kvm`, `info kvm` | OK | `kvm support: enabled`; user in group `kvm` |
| Docker Engine | `docker info`, `docker run --rm hello-world`, privileged container | OK | 29.10.0, cgroup v2 |
| Rust stable | `rustc --version` | OK | installed by the run: 1.100.0, pinned in `rust-toolchain.toml` (T01) |
| Rust targets | `rustup target list --installed` | OK | musl x86_64 and aarch64, `x86_64-pc-windows-gnu` |
| Nightly with `rust-src` | `cargo +nightly --version` | OK | installed by the run |
| `bpf-linker` | `bpf-linker --version` | OK | 0.13.0; `cargo install` needs a system libLLVM matching rustc's LLVM 23 (Ubuntu has 14), so the project's static release binary is used instead |
| `cargo-nextest`, `cargo-deny`, `cargo-audit`, `cargo-zigbuild` | `--version` | OK | installed by the run |
| `vmtest`, `zig`, `actionlint`, `pwsh` with Pester 5 | `--version` | see timeline | installed by the run after T01 started |
| `CARGO_TARGET_DIR` | in `~/.profile` | OK | `~/.cache/rackhand-target` (Linux filesystem) |
| Disk | `df -h` | OK | 946 GB free in WSL |
| Baseline | build and tests | OK | empty repository: no code or tests before T01 |

No preflight problems needed the owner. The user-level tools were installed by the run, as the plan allows; that ran in
the background while T01 was written, since T01 needs only Rust.

### Timeline
| Time | Event |
| --- | --- |
| 2026-11-19 | Preflight; user-level toolchain installed |
| 2026-11-19 | T01 started; `arch::` tests failed first (27 compile errors: `Model`, `check`, `load` and the rest missing) |
| 2026-11-19 | T01 done: 5 passed; `arch-check` no violations; build, fmt and clippy clean |
