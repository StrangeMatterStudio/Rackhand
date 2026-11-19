# Rackhand

A self-hosted operations hub for homelabs, in Rust. The design is
[docs/designs/0001-architecture/design.md](docs/designs/0001-architecture/design.md) and the implementation plan is
[plan.md](docs/designs/0001-architecture/plan.md) next to it, with the run log in `run-log.md`.

## Build and test

Everything builds and runs in WSL Ubuntu (or any Linux). Keep `CARGO_TARGET_DIR` on the Linux filesystem.

| What | Command |
| --- | --- |
| Build | `cargo build --workspace --all-targets` |
| Fast tier (the regression suite) | `cargo xtask ci fast` |
| One crate or module | `cargo nextest run -p <crate> -E 'test(<module>::)'` |
| Integration tier (Docker) | `cargo xtask ci it` |
| Network and eBPF tiers (QEMU with KVM) | `cargo xtask ci net`, `cargo xtask ci ebpf` |
| Windows tier (cross build and Pester) | `cargo xtask ci win` |
| Performance tier | `cargo xtask ci perf` |
| Live tier (local lab) | `cargo xtask ci live --target local --milestone <name>` |
| Dependency rules | `cargo xtask arch-check` |
| Lint and format | `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings` |
| Licenses and advisories | `cargo deny check && cargo audit` |

## Rules

- The design is the source of truth. A change to designed behaviour, contracts or acceptance criteria is agreed with
  the maintainer first and recorded in the design's change log.
- Tests first: every change comes with tests that were seen failing before it.
- Dependency rules (design 7.2) are enforced by `cargo xtask arch-check`: policy crates depend on nothing of ours, hub
  systems never depend on Web, and Incidents reaches Actions only through `StartJob`.
- Run the tests and report the results; never weaken or skip a test to get a pass.
- American English, no emojis, and no AI attribution in commits or pull requests.
- Versions stay `0.x`; the workspace version is `0.1.0` until the maintainer releases.
- Public wording only: no maintainer lab host names, addresses or internal tool names in the repository.
