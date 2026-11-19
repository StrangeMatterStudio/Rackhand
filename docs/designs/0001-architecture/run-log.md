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
| 2026-11-19 | T01 done: 5 passed; `arch-check` no violations; build, fmt and clippy clean. Commit `0049131` |
| 2026-11-19 | T02 started; tests failed first (compile errors). Kernels built from pinned tarballs in a container (D3); vmtest needed a container-built rootfs and a clean PATH (D4) |
| 2026-11-19 | T02 done: every tier exits 0 with its smoke test (eBPF on 5.10.274, 6.1.192, 6.17.13). Commit `d782953` |
| 2026-11-19 | T03 done: 6 guard tests, actionlint clean, 6 fixtures as expected (D6, D7). Commit `772eb83` |
| 2026-11-19 | T04: the push ran both workflows with every job skipped (no runner variables). Runner listing needs org admin. T04 `unverified (MV1)`; tiers run in WSL until the owner sets up the profiles |
| 2026-11-19 | L1 started (lab tests failed first: unresolved `config` and `images`). First bring-up failed on Debian 12: its cloud-init 22.4 needs `ds=nocloud-net` for an HTTP seed; fixed, bring-up restarted |
| 2026-11-19 | T05 recorder started on the WSL host at 06:28 UTC for 24 hours; T06 measuring for 30 minutes in a VM; owner asked for the T13 sign-in and the T14 TrueNAS key (OWNER-ACTIONS.local.md) |
| 2026-11-19 | T07 done: git2 chosen (gix can't push). Design 5.3 and 17 updated |
| 2026-11-19 | T08 done: relay admission, server-wide rate and priority work; per-key rate and daily quota not possible (owner decision pending, T82). T09 done: path detection works; masquerade-to-masquerade never goes direct (D9) |
| 2026-11-19 | L1 bring-up fixes: Alpine `lab` account unlocked for sshd; Proxmox phase 1 static DNS and grub preseed; cloud-init disabled before the first reboot; static uplink (no dhclient for ifupdown2). The pve9 node runs kernel 7.0.14, so the eBPF tier's third kernel moved from 6.17 to 7.0 (D5) |
| 2026-11-19 | T10: eBPF capture works on 5.10, 6.1 and 7.0; an MIT-only license is refused (GPL-only helper); LXC part waits for the lab. T11 and T06 re-running (S6's first run was invalid: VM loopback down). T15 done |
| 2026-11-19 | D10: M1 started while T05 (24 h recording), T06, T10 to T14 finish; each M1 step still waits for the spikes in its own Depends on |
| 2026-11-19 | T16 to T18, T20, T21, T23, T24 done (wire format, Net, Store, Audit, Vault, probe buffer, Bus); evidence in plan.md. T24's first commit `208b422` had a clippy error (the exit status was read from the wrong shell); fixed in `95604f1` and the fast tier is now checked by its own output |
| 2026-11-19 | T28 done (`635b7cd`): the worked-example test was corrected before implementing (D19) |
| 2026-11-19 | T29 done (`f4f3b6f`); T30 done (`d3ed31a`, D16: peer down no earlier than silent); T31 done (`0f1aac6`, D17: baseline clock, clearing and freezing) |
| 2026-11-19 | T34 done (`a6c98ae`): jiff with its bundled timezone database; D18 sets the window text and restart rules |
| 2026-11-19 | L1 live run: 5 of 6 passed. pve9's container template was arm64 (`sort -V` put it last), and guest traffic was blackholed because QEMU's multicast socket NIC hands frames back to their sender, so the bridge learned guest MACs on the uplink. Fixed: amd64 template, learning off on the uplink port, and base images re-provision when their inputs change (`5fda043`). Re-provisioning and re-running |
