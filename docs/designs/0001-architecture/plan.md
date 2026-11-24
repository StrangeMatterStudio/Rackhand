# 0001 Rackhand architecture and v0.1: Implementation Plan

| | |
| --- | --- |
| Design | [design.md](design.md) (Approved 2026-11-18 by Owen Ravelo) |
| Status | In progress |
| Plan approved by | Owen Ravelo (2026-11-18), including the local lab downloads listed under *Environment and tools* |
| Branch | `design/0001-architecture` |
| Run log | [run-log.md](run-log.md) (written by `/design:run`) |

Step IDs are `T01` to `T99` so they don't clash with the design's spike IDs (`S1` to `S11`, section 17); the live
passes against the lab are `L1` to `L9` (D107). Each step is one commit named `T<nn>: <title>` or `L<n>: <title>`. Status words: `todo`, `in progress`, `done`, `unverified`, `blocked`.

## Environment and tools

Development and every test tier run in **WSL Ubuntu 22.04** on the maintainer's Windows machine (owner decision,
2026-11-18). The source stays on the Windows drive; the build target directory lives on the Linux filesystem for
speed. Every command in this plan runs inside WSL, in the repository root, unless a row says otherwise. From
PowerShell, run a command as `wsl -d Ubuntu --cd <repo> -- bash -lc '<command>'`.

Tests never write to the repository tree for files that need Unix modes, sockets or ownership: they use temporary
directories under `/tmp` (the Windows drive mounted in WSL doesn't keep Unix modes).

| Requirement | Needed for | Check command | Expected |
| --- | --- | --- | --- |
| WSL Ubuntu 22.04 | everything | `uname -r && . /etc/os-release && echo $VERSION_ID` | a `*-microsoft-standard-WSL2` kernel; `22.04` |
| System packages (the owner runs the install command below once; it needs sudo) | C deps, musl, protoc, eBPF, QEMU, Windows cross build, nftables tests | `dpkg -s build-essential clang llvm libelf-dev musl-tools protobuf-compiler mingw-w64 qemu-system-x86 pkg-config nftables iproute2 sqlite3 >/dev/null && echo ok` | `ok` |
| Access to `/dev/kvm` (owner adds the user to group `kvm` once) | network and eBPF tiers (tests run inside QEMU VMs) | `test -r /dev/kvm -a -w /dev/kvm && echo ok` | `ok` |
| rustup with stable Rust, at least the MSRV iroh 1.x requires | build, tests | `rustc --version` | `rustc 1.9x.y` (the version pinned in `rust-toolchain.toml` by T01) |
| Rust targets | static Linux builds, Windows probe and CLI cross build | `rustup target list --installed` | includes `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-pc-windows-gnu` |
| Nightly Rust with `rust-src`, and `bpf-linker` | eBPF programs (aya) | `cargo +nightly --version && bpf-linker --version` | both print versions |
| `cargo-nextest` | all test tiers | `cargo nextest --version` | `cargo-nextest 0.9.*` |
| `cargo-deny`, `cargo-audit` | licenses, advisories | `cargo deny --version && cargo audit --version` | both print versions |
| `zig` and `cargo-zigbuild` | aarch64 musl builds with C dependencies (bundled SQLite, zstd) | `zig version && cargo zigbuild --version` | both print versions |
| `vmtest` | network and eBPF tiers | `vmtest --version` | prints a version |
| `actionlint` | workflow lint | `actionlint --version` | prints a version |
| PowerShell 7 (`pwsh`) with Pester 5 | Windows dispatcher and script tests (run on Linux) | `pwsh -NoProfile -c "(Get-Module -ListAvailable Pester).Version.Major"` | `5` |
| Docker Engine in WSL (installed by the owner on 2026-11-18; Docker Desktop's WSL integration stays off for Ubuntu) | integration tier (containers with sshd, systemd, Alpine) | `docker info --format '{{.ServerVersion}}'` | a version number |
| `strip` (binutils, already there for linking; D100) | integration tier (binaries put in containers) | `strip --version` | prints a version |
| `CARGO_TARGET_DIR` on the Linux filesystem | build speed | `echo $CARGO_TARGET_DIR` | a path under `$HOME`, not under `/mnt/` |
| GitHub CLI signed in with `repo` and `workflow` scopes | CI runs, PR | `gh auth status` (from PowerShell) | signed in to github.com |
| Push access | commit and push after each step | `git push --dry-run origin design/0001-architecture` (from PowerShell) | no error |
| Runner profiles for Rackhand (added in T04) | CI tiers on self-hosted runners | `gh variable list --repo StrangeMatterStudio/Rackhand` (from PowerShell) | `RACKHAND_CI_LINUX`, `RACKHAND_CI_DOCKER`, `RACKHAND_CI_KVM` set for the runners that exist |
| Local lab: QEMU/KVM machines in WSL, including nested Proxmox VE 8 and 9 (built by L1) | spikes T10 to T12; live passes L1 to L8 | `cargo xtask lab doctor` | KVM usable, images present with matching checksums, the chosen profile fits in memory |
| Owner's real lab: a hub VM or LXC and one managed VM reachable by SSH key with sudo; Proxmox VE 8 and 9 test nodes; a TrueNAS instance; a Windows 10/11 machine | T14; real-lab pass L9; Windows checks | `cargo xtask ci live --target real --milestone real -- --list` (reads the untracked `lab/real.env`) | every configured host answers |
| A Claude Code login (the owner signs in when the run asks) | T13, L6 | the spike or the lab operator reports a signed-in account | signed in |

One-time setup the owner runs in WSL (needs the sudo password, so the run can't do it). Done on 2026-11-18, together
with Docker Engine from Docker's apt repository:

```bash
sudo apt-get update && sudo apt-get install -y build-essential clang llvm libelf-dev musl-tools protobuf-compiler \
  mingw-w64 qemu-system-x86 pkg-config nftables iproute2 sqlite3 && sudo usermod -aG kvm "$USER"
```

Then, without sudo (the run may do this part): install rustup and the stable and nightly toolchains, the three
targets, `rust-src` for nightly, and `cargo install --locked cargo-nextest cargo-deny cargo-audit cargo-zigbuild
bpf-linker vmtest`; install `zig`, `actionlint` and `pwsh` (with `Install-Module Pester -Scope CurrentUser`) under
`$HOME/.local`; add `export CARGO_TARGET_DIR=$HOME/.cache/rackhand-target` to `~/.bashrc`.

**Local lab downloads** (approved with this plan). L1 pins each SHA-256 in `lab/images.toml` from the publisher's
signed checksum file and caches the files under `~/.cache/rackhand-lab`:

| Download | Source | Approximate size |
| --- | --- | --- |
| Debian 12 and Debian 13 `genericcloud` amd64 images | `cloud.debian.org` | 350 MB each |
| Ubuntu 24.04 server cloud image | `cloud-images.ubuntu.com` | 600 MB |
| Alpine 3.20 cloud-init (`nocloud`) image | `dl-cdn.alpinelinux.org` | 150 MB |
| Proxmox VE 8 and 9 packages, installed inside `pve8` and `pve9` | `download.proxmox.com` (no-subscription repository) | 1.5 GB per node |
| Alpine LXC template, fetched inside the nodes with `pveam` | Proxmox's template mirror | 5 MB |
| Docker, Compose and `snmpd`, installed inside lab machines | the distributions' own package archives | 150 MB |
| A small Compose test image (`nginx:alpine`) on `target` | Docker Hub | 20 MB |
| Claude Code (native binary) on `operator` | Anthropic's official installer | 200 MB |

**Lab memory budget.** WSL has 30 GB. The largest profile (`m2`) needs 13.5 GB; `lab up` keeps 12 GB free for builds,
and live passes cap `CARGO_BUILD_JOBS` at 12.

## How to build and test

Checked in WSL on 2026-11-18: the system packages are installed; QEMU started with `-accel kvm` reports `kvm support:
enabled`; Docker Engine runs `hello-world` and a privileged container without sudo. Rust isn't installed yet, so the
cargo commands below haven't been run: T01, T02 and L1 create them, and preflight in `/design:run` checks the
environment above first. From T02 on, every step's regression is the fast tier.

| Purpose | Command | Expected (green) result |
| --- | --- | --- |
| Build | `cargo build --workspace --all-targets` | exit 0 |
| Fast tier (regression): fmt, clippy, dependency rules, `cargo deny`, unit, contract and collector tests | `cargo xtask ci fast` | exit 0; nextest summary `0 failed` |
| Targeted tests | `cargo nextest run -p <crate> -E 'test(<module>::)'` | the named tests run, `0 failed` |
| Integration tier (Docker: sshd, systemd and Alpine containers) | `cargo xtask ci it` | exit 0; `0 failed` |
| Network tier (network namespaces and nftables NAT inside a QEMU VM) | `cargo xtask ci net` | exit 0; `0 failed` |
| eBPF tier (kernels 5.10, 6.1 and the current Proxmox kernel series, inside QEMU) | `cargo xtask ci ebpf` | exit 0; `0 failed` on every kernel |
| Windows tier (cross builds and Pester tests of the shipped PowerShell) | `cargo xtask ci win` | exit 0; Pester `Failed: 0` |
| Performance tier (soak, load, fill; nightly in CI) | `cargo xtask ci perf` | exit 0; every budget assertion passes |
| Local lab | `cargo xtask lab up <profile>`, `cargo xtask lab reset`, `cargo xtask lab destroy` | the profile's machines answer SSH |
| Live tier (local lab; WSL only, never in CI) | `cargo xtask ci live --target local --milestone <lab, m1 to m8, or all>` | exit 0; `0 failed` |
| Real-lab pass | `cargo xtask ci live --target real --milestone real` | every configured test passes |
| Lint and format | `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings` | clean |
| Dependency rules | `cargo xtask arch-check` | `no violations` |
| Licenses and advisories | `cargo deny check && cargo audit` | clean |
| Workflow checks | `actionlint && cargo xtask ci-guard` | clean; every recorded payload gives its expected result |

## Approach and ordering

1. **Prerequisites (T01 to T04).** The workspace matching the crate table in design 7.2, the test tiers, both CI
   workflows with the AC44 guard test, and the runner profiles. Then the local lab harness (L1), which spikes T10 to
   T12 use.
2. **Spikes (T05 to T15), all before any feature work (D87).** Each spike answers the questions listed in design
   section 17 with a scripted measurement against a stated threshold. Spike code is throwaway and is not committed;
   the commit holds the finding (appended under the spike in design section 17, with a change-log row) and redacted
   evidence in `docs/designs/0001-architecture/spikes/`. A finding that contradicts the design is a design-level stop:
   the run pauses and asks the owner before any dependent step starts.
3. **Milestones as usable vertical slices, single-site monitoring first** (design section 17, first risk):
   - **M1 Single-site monitoring (T16 to T45):** wire format, mesh endpoint, store, probe collection and buffering,
     ingest, rollups and retention, detection, incidents, callouts, enrollment, dashboard with sign-in, `/metrics`,
     installer, backups. At the end a hub watches Linux machines and calls out.
   - **M2 Checks and agentless drivers (T46 to T49).**
   - **M3 Actions (T50 to T65):** runbooks, command wrapper, SSH, policy and approvals, executor, library and git
     mirror, routing to runbooks, patching, built-in runbooks, access levels, diagnostics, provisioning.
   - **M4 Security watch (T66 to T73):** helper scans, sampling and eBPF capture, threat intel, connection scoring,
     security events, quarantine.
   - **M5 Assistant (T74 to T79):** MCP, operator, runners, routing to playbooks.
   - **M6 Multi-site (T80 to T88):** peers, peer watch, relay, hole punching, tunnels, transfers, CLI, address changes.
   - **M7 Windows (T89 to T90).**
   - **M8 Lifecycle, release and performance (T91 to T99):** signing and reproducible builds, probe self-update, hub
     updater, site bootstrap, version compatibility, performance, offline operation, documentation.
4. **Contracts before implementations inside each slice.** Proto messages and contract suites come before the systems
   that implement them, so each system is tested against its contract with a real endpoint pair in-process.
5. **Pure policy first.** Detect, Runbook model and Policy are pure crates or modules with table-driven unit tests,
   written before the systems that call them.
6. **Dependency rules are enforced from T01** (`cargo xtask arch-check`): Detect and Runbook model depend on nothing of
   ours; hub systems never depend on Web; Incidents reaches Actions only through `StartJob` and hears back only through
   the Bus.

**Local lab first, real lab last (D107).** At the end of each milestone a live pass (L2 to L8) deploys the build to
the local lab and runs that milestone's live tests against real machines: a hub VM managing a Linux VM, nested
Proxmox VE 8 and 9 nodes, and a second site behind a relay. The lab belongs to the run, which may create, break and
reset anything in it. Each live test is written first and run against the lab with the previous milestone's build
deployed, where it fails on the missing feature; then the new build is deployed and it passes. The real-lab pass (L9)
runs once at the end against the owner's hub VM or LXC and one managed VM, plus the checks that need real hardware.
A live pass is part of its milestone being done; it is not a stop point.

**Gated steps.** Every step whose design depends on a spike lists that spike's step under *Depends on*:

| Spike | Step | Gates |
| --- | --- | --- |
| S8 time-series encoding | T05 | T19 (encoding), T27 (rollups and storage budget), T96 (fill test) |
| S6 probe footprint | T06 | T22, T42 (probe runtime choices), T68 (eBPF in the probe), T96 |
| S7 git mirror library | T07 | T56 (library and git mirror) |
| S2 iroh relay | T08 | T17 (relay config), T82 (relay), AC31's priority clause |
| S3 iroh path detection | T09 | T17, T83, T85 (bulk transfers wait for a direct path) |
| S1 aya eBPF | T10 | T68 (eBPF capture), the eBPF program's declared license |
| S11 collectors | T11 | T22 (memory readings), T66 (authentication events) |
| S4 Proxmox | T12 | T47 (Proxmox driver), T59 and T60 (snapshot, `patch-proxmox-host`), T64, T72 (guest firewall) |
| S5 Claude Code headless | T13 | T77 (Claude Code runner) |
| S9 TrueNAS API | T14 | T48 (TrueNAS driver) |
| S10 intel terms | T15 | T69 (default outside sources) |

**Tests by tier.** Unit, contract and collector tests (design section 14) run in the fast tier on every step.
Dashboard tests (`web::`, `auth::`, `oidc::`, `pages::`, `metrics::`) start the real hub web server in-process over
HTTPS with a real database in a temporary directory, and drive it with an HTTP client; this plan counts them as
integration tests for the ACs whose design verification says integration (AC40, AC49).
Container tests run in the integration tier, namespace tests in the network tier, kernel tests in the eBPF tier, the
soak, load and fill tests in the performance tier, and the shipped PowerShell in the Windows tier. A step's
verification names the tier it needs. The live tier runs the built product in the local lab (L1 to L8) and in the real
lab (L9). Checks that need real hardware or the internet are run by the run itself in L9 with access the owner
provides; only checks that need the owner's own accounts, devices or offline keys are done by the owner (design
section 14). All of them are listed under *Manual verifications*.

**Live, real-lab and owner checks don't block the run.** A step whose remaining proof is a live test is marked
`unverified` until its live pass (L2 to L8) passes, then `done`. Real-lab confirmations in L9 and owner checks are
recorded on their MV rows; a step whose only remaining proof is one of them stays `unverified` with the MV ID, and a
failed confirmation reopens the step. The run pauses only where later steps need the owner: T13 (Claude Code sign-in),
T14 (the TrueNAS key), L6 (Claude Code sign-in on the lab hub) and L9 (access to the real lab).

**Versions and releases (D106).** The workspace version is `0.1.0` throughout. The run builds and verifies release
artifacts (T91) but schedules no release: publishing one, and signing it offline, are the maintainer's decisions after
the run.

**Large steps.** T22, T36, T55, T59, T68, T72 and T89 are larger than one commit should be. The run splits each into
consecutive commits (`T22a`, `T22b`, ...), each with its own tests seen failing first, and records every split as a
plan-level deviation (owner decision, 2026-11-18).

**What the run never does:** hold or use a release signing key (D90, design section 13), publish a release, change
the runner service's configuration, or touch the owner's real lab beyond the hosts and test guests named in the
untracked `lab/real.env`. Inside the local lab it may create, break, snapshot and delete anything.

**Evidence** committed to the repository uses documentation IP ranges and invented names (D71, D82). No lab host
names, addresses or account names appear in this plan, the run log or the evidence. The local lab uses documentation
ranges for its site networks; the real lab's details live only in the untracked `lab/real.env`.

**Notes on the maintainers' rules** (raised with the owner at plan review; the design wins where it is explicit):
- The design's `ci-github-hosted.yml` (D37, section 13) is off by default and exists for forks. The maintainers' rule says
  never to use GitHub-hosted labels. This plan follows the design and reports the conflict.
- During initial development the schema has one baseline migration that is edited in place, per the maintainers' rule
  "write no migrations during initial development". Forward-only migrations (design 13) begin with the first
  released version.

## Stop points

| After step | Why |
| --- | --- |
| None | The maintainers' rule: once a plan is approved, run it to completion. The run still pauses for a spike finding that contradicts the design (design-level deviation), and where it needs the owner: the Claude Code sign-ins in T13 and L6, the TrueNAS key in T14, and access to the real lab in L9. |

## Steps overview

| ID | Title | Depends on | Verification type | Status |
| --- | --- | --- | --- | --- |
| T01 | Workspace scaffold and dependency-rule check | - | unit (xtask), static | done |
| T02 | Test tiers and `cargo xtask ci` | T01 | scripted | done |
| T03 | CI workflows and the guard test | T02 | unit (xtask), lint | done |
| T04 | Runner profiles for Rackhand | T03 | scripted (CI run), owner setup | unverified (MV1) |
| L1 | Local lab harness | T02 | unit (xtask) + live (local lab) | done |
| T05 | Spike S8: time-series encoding | T02 | scripted measurement | done |
| T06 | Spike S6: probe footprint | T02 | scripted measurement | done |
| T07 | Spike S7: git mirror library | T02 | scripted measurement | done |
| T08 | Spike S2: iroh relay admission and limits | T02 | scripted measurement (network VM) | done |
| T09 | Spike S3: iroh path detection | T02 | scripted measurement (network VM) | done |
| T10 | Spike S1: aya eBPF | T02, L1 | scripted measurement (eBPF VMs, local Proxmox) | done |
| T11 | Spike S11: collectors on current distributions | T02, L1 | scripted measurement (containers, local Proxmox) | done |
| T12 | Spike S4: Proxmox privileges, firewall, upgrade command | T02, L1 | scripted measurement (local Proxmox) | done |
| T13 | Spike S5: Claude Code headless | T02 | scripted measurement (owner's login) | done |
| T14 | Spike S9: TrueNAS API | T02 | lab measurement | done |
| T15 | Spike S10: threat list and GeoIP terms | T02 | scripted measurement + reading | done (owner decision pending for T69) |
| T16 | Wire format: framing, limits, close codes, messages | T15 | unit, golden | done |
| T17 | Net: endpoint, node key, registry, contract harness | T16, T08, T09 | contract | done |
| T18 | Store: schema, writer task, read pool | T16 | unit | done |
| T19 | Time-series encoding and chunks | T18, T05 | unit, property | done |
| T20 | Audit log with hash chain and checkpoints | T18 | unit | done |
| T21 | Vault | T18 | unit | done |
| T22 | Probe Linux collectors | T16, T06, T11 | collector (fixtures) | done |
| T23 | Probe buffer, epochs and label table | T16 | unit | done |
| T24 | Bus | T18 | unit | done |
| T25 | Ingest: staging, acks, compaction, recent window, clock | T18, T19, T24 | unit | done |
| T26 | Probe contract `rackhand/probe/1` | T17, T23, T25 | contract | done |
| T27 | Rollups and retention | T19, T25, T05 | unit | done |
| T28 | Detect: threshold rules | T01 | unit | done |
| T29 | Detect: forecasts | T28 | unit | done |
| T30 | Detect: silence | T28 | unit | done |
| T31 | Detect: baselines and counted rules | T28 | unit | done |
| T32 | Incidents: lifecycle and evaluation | T25, T24, T28 to T31 | unit | done |
| T33 | Notify: Discord, SMTP, grouping, retries | T32 | unit (HTTP and SMTP fakes) | done |
| T32b | Incidents: forecasts, baselines, machine silence and counted rules | T32, T27, T29 to T31 | unit | done |
| T34 | Scheduler and windows | T24 | unit | done |
| T35 | Join contract and Registry | T17, T18, T21 | contract | done |
| T36 | Web foundation and first run | T18, T20, T21 | unit (HTTP) | done |
| T37 | Sign-in, second factor, step-up and limits | T36 | unit (HTTP) | done |
| T38 | Passkeys, OIDC and account settings | T37 | unit (HTTP, fake provider) | done |
| T39 | Dashboard pages for monitoring | T32, T36 | unit (HTTP) | done |
| T40 | `/metrics` endpoint | T25, T36 | unit (HTTP) | done |
| T41 | Hub composition and `rackhand hub` commands | T24 to T40, T32b | integration | done |
| T42 | Probe daemon | T22 to T26, T41 | integration | done |
| T43 | Helper basics and package-list refresh | T42 | integration (containers) | done |
| T44 | Linux and Alpine installer and enrollment | T35, T43 | integration (containers) | done |
| T45 | Hub self-watch, integrity and backups | T41 | unit + integration | done |
| T39b | Settings: add or replace a notifier | T39, T41 | unit (HTTP) | done |
| L2 | Live tier and the M1 pass | T44, T45, L1 | live (local lab) | done (MV12 page walk waits for the owner) |
| T46 | Service checks and network drivers | T41 | unit + integration | done |
| T47 | Proxmox driver | T46, T12 | unit (recorded API) | done |
| T48 | TrueNAS, Redfish and SNMP drivers | T46, T14 | unit (simulators) + integration | done |
| T49 | Add page, agentless enrollment and guest binding | T47, T48, T39 | unit + integration | done |
| L3 | Live pass for M2: agentless and Proxmox | T49, L2 | live (local lab) | done (the M2 page walk waits for the owner, as MV12) |
| T50 | Runbook and playbook model | T01 | unit | done |
| T51 | Command wrapper and signed command lists | T50, T16 | unit + integration | done |
| T52 | Wrapper detached steps and file receive | T51 | integration (systemd and OpenRC containers) | done |
| T53 | SSH system | T21, T35 | unit + integration | done |
| T54 | Policy: decisions and approvals | T18 | unit | done |
| T55 | Actions and Executor | T52 to T54, T24 | unit + integration | done |
| T56 | Library and git mirror | T50, T21, T07 | unit + integration | done |
| T57 | Incident routing to runbooks and attempt limits | T32, T55 | unit | done |
| T58 | Dashboard: approvals, jobs, library, patching | T55, T56, T37 | unit (HTTP) | done |
| T59 | Patching | T55, T34, T47, T12 | unit + integration + live (L4, L9) | done |
| T60 | Hypervisor and hub-host patching | T59 | unit + integration + live (L4, L9) | done |
| T61 | Remaining built-in runbooks and key rotation | T55, T43 | unit + integration | done (its compose integration test moves to L4, D109) |
| T62 | Access levels and monitor enforcement | T44, T55, T49 | unit + integration | done |
| T63 | Diagnostics allow-list | T55 | unit + integration | done |
| T64 | Provisioning VMs and LXCs | T59, T49 | unit (recorded API) + live (L4, L9) | done (live passes L4 and L9 to come) |
| T65 | Hub restart recovery for jobs | T55, T59 | integration | done |
| L4 | Live pass for M3: actions and patching | T65, L3 | live (local lab) | todo |
| T66 | Helper security scans | T43, T11 | integration (containers) | done |
| T67 | Probe sampling capture and security signals | T66, T42 | collector + integration | done |
| T68 | eBPF capture | T67, T10, T06 | eBPF tier | todo |
| T69 | Threat intel and outside sources | T41, T15 | unit | done |
| T70 | Connection scoring and connection storage | T67, T69 | unit + integration | done |
| T71 | Security events, severities and exemptions | T70, T61 | unit + integration | done |
| T72 | Quarantine | T71, T55, T47 | unit + integration + live (L5, L9) | done |
| T73 | Dashboard: security pages | T71, T72 | unit (HTTP) | done |
| L5 | Live pass for M4: security watch and quarantine | T73, L4 | live (local lab) | todo |
| T74 | MCP server and read tools | T17, T54 | contract | done |
| T75 | MCP gated tools and approval binding | T74, T55, T63 | contract | done |
| T76 | Operator contract and Assist | T75 | contract | done |
| T77 | Operator binary and runners | T76, T13 | integration (fake runner) + live (L6) | done |
| T78 | Incident routing to playbooks and briefs | T77, T57 | unit + integration | done |
| T79 | Dashboard: assistant pages and settings | T78 | unit (HTTP) | done |
| L6 | Live pass for M5: a real Claude Code operator | T79, L5 | live (local lab, owner's sign-in) | todo |
| T80 | Peer contract | T35, T41 | contract | done |
| T81 | Peer watch and callout election | T80 | unit + network | done |
| T82 | Relay | T17, T08 | unit + network | done |
| T83 | Hole punching and relay fallback | T82, T09 | network | done |
| T84 | Tunnels and remote mode | T83, T55 | contract + network | done |
| T85 | Transfers and backup streams | T84, T09, T45 | contract + network | done |
| T86 | `rackhand-cli` | T84, T75 | integration + network | done |
| T87 | Address changes, `set-hub` and identity conflicts | T42, T61 | integration | done |
| T88 | Dashboard: peers, relays and peer sites | T81, T82 | unit (HTTP) | done |
| L7 | Live pass for M6: two sites | T88, L6 | live (local lab) | todo |
| T89 | Windows probe and helper | T22, T23, T26, T66, T67 | collector (recorded outputs) + Windows tier + manual | done |
| T90 | Windows installer, SSH setup, dispatcher and scripts | T89, T61, T72 | Windows tier (Pester) + manual | done |
| T91 | Release signing, manifests and reproducible builds | T44 | unit + scripted | done |
| T92 | Probe self-update | T91, T43 | unit + integration | done |
| T93 | Hub, relay and operator updater | T91, T45 | unit + integration | todo |
| T94 | Site bootstrap and LXC script | T93, T44 | integration + live (L8, L9) | todo |
| T95 | Version compatibility | T42, T77, T82, T86 | contract | todo |
| T96 | Performance tier | T42, T68, T05, T06 | performance | todo |
| T97 | Offline operation | T59 | integration | todo |
| T98 | Retention for every table and settings ranges | T85, T76, T70 | unit | todo |
| T99 | Documentation and command check | T94 | scripted | todo |
| L8 | Final local pass for M8 | T99, L7 | live (local lab) | todo |
| L9 | Real-lab pass | L8 | live (real lab, owner's access) | todo |

## Steps

### Prerequisites

### T01: Workspace scaffold and dependency-rule check
- **Design refs:** 7.2 (systems, locations, dependency rules), 5.3 (constraints), D8, D42
- **Goal:** the Cargo workspace has every crate and hub module from 7.2 as an empty skeleton, and
  `cargo xtask arch-check` fails on any dependency that breaks the 7.2 rules.
- **Depends on:** none
- **Changes:**
  - `Cargo.toml` (workspace version `0.1.0` (D106), shared lints, `resolver = "2"`), `rust-toolchain.toml` (the stable version installed at
    preflight, at least iroh 1.x's MSRV; components `rustfmt`, `clippy`), `rustfmt.toml`, `clippy.toml`, `deny.toml`
    (allowed licenses compatible with MIT OR Apache-2.0), `.cargo/config.toml` (`xtask` alias).
  - Crates: `crates/rackhand-proto`, `rackhand-net`, `rackhand-detect`, `rackhand-runbook`, `rackhand-drivers`,
    `rackhand-store`, `rackhand-hub` (modules `registry`, `ingest`, `checks`, `incidents`, `policy`, `actions`,
    `executor`, `ssh`, `assist`, `mcp`, `notify`, `peers`, `library`, `vault`, `intel`, `scheduler`, `audit`, `web`,
    `bus`), `rackhand-relay`, `rackhand-operator`, `rackhand-probe` (with `src/helper`), `rackhand-cli`, `rackhand`
    (binary), `xtask`.
  - `xtask/src/arch.rs`: reads `cargo metadata` and scans `use crate::<module>` in `rackhand-hub`; rules from 7.2.
  - `CLAUDE.md` (build and test commands, the maintainers' rules that apply, where the design and plan live) and
    `.claude/settings.json` enabling the maintainers' Claude Code plugins (their repository baseline).
  - `.gitignore`: add `spikes/` (spike code is never committed) and `target/`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `arch::policy_crate_with_internal_dependency_is_reported` | a fixture where `rackhand-detect` depends on `rackhand-store` gives one violation naming both | 7.2 dependency rules |
  | `arch::hub_module_using_web_is_reported` | a fixture `use crate::web` in `incidents` gives a violation | 7.2 |
  | `arch::incidents_calling_actions_beyond_start_job_is_reported` | a fixture where `incidents` calls an `actions` item other than the `StartJob` command gives a violation | 7.2 (no cycle) |
  | `arch::clean_workspace_has_no_violations` | the real workspace passes | 7.2 |
  | `arch::no_node_or_interpreter_in_server_crates` | a fixture with a `package.json`, or a build script that runs `node` or `python`, is reported | 5.2 (language), D8 |
- **Fails first:** compile error, `xtask::arch` doesn't exist.
- **Verification:**
  ```bash
  cargo nextest run -p xtask -E 'test(arch::)' && cargo xtask arch-check && cargo build --workspace --all-targets
  ```
  Expected: 5 passed, 0 failed; `no violations`; build exit 0.
- **Regression:** `cargo test --workspace`: all pass (the fast tier doesn't exist until T02).
- **Manual verification:** None.
- **Done when:**
  - [x] New tests observed failing before the implementation (missing module)
  - [x] New tests pass; `arch-check` clean; workspace builds
  - [x] `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` clean
  - [x] Evidence recorded below
- **Risk / rollback:** the MSRV may move when iroh is added in T17; bump `rust-toolchain.toml` then. Revert the commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p xtask -E 'test(arch::)' | compile errors: Model, CrateNode, FileFact, check, load, scan_hub_source, build_script_programs, run missing |
  | 2026-11-19 | cargo nextest run -p xtask -E 'test(arch::)' && cargo xtask arch-check && cargo build --workspace --all-targets | 5 passed, 0 failed; no violations; build exit 0 |
  | 2026-11-19 | cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings; cargo test --workspace | clean; 5 passed, 0 failed |

### T02: Test tiers and `cargo xtask ci`
- **Design refs:** 14 (testing strategy layers), 13 (CI)
- **Goal:** `cargo xtask ci <tier>` runs each test tier the same way locally and in CI, and the default workspace test
  run is the fast tier only.
- **Depends on:** T01
- **Changes:**
  - Test crates excluded from `default-members`: `tests/it` (`rackhand-it`, Docker), `tests/net` (`rackhand-net-tests`,
    run inside a QEMU VM with `vmtest`), `tests/ebpf` (`rackhand-ebpf-tests`, one VM per kernel), `tests/perf`
    (`rackhand-perf`).
  - `.config/nextest.toml` profiles `ci`, `it`, `net`, `ebpf`, `perf` (timeouts, retries 0, JUnit output to
    `target/nextest/`).
  - `xtask`: `ci fast` (fmt check, clippy `-D warnings`, `arch-check`, `cargo deny check`, nextest on default
    members), `ci it` (builds the test images under `tests/it/images/` and runs `rackhand-it`), `ci net` and
    `ci ebpf` (build test binaries as the user, then run them as root inside `vmtest` VMs; kernel images are fetched
    by `xtask kernels fetch` with pinned SHA-256 values in `tests/ebpf/kernels.toml`), `ci win`, `ci perf`,
    `it-images`.
  - One smoke test per tier that checks its environment: Docker answers (`it`), the VM has `CAP_NET_ADMIN` and can
    create a network namespace (`net`), the VM kernel version matches the requested one and BTF exists (`ebpf`).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `xtask::tiers::unknown_tier_fails_with_list_of_tiers` | `ci nope` exits non-zero and names the valid tiers | 14 |
  | `xtask::kernels::checksum_mismatch_is_refused` | a fetched kernel whose hash differs from `kernels.toml` is deleted and the command fails | 14 (eBPF row) |
  | `rackhand-it::smoke::docker_answers` | Docker version query succeeds | 14 (integration) |
  | `rackhand-net-tests::smoke::can_create_netns` | runs as root in the VM; a namespace pair with a veth link pings | 14 (network) |
  | `rackhand-ebpf-tests::smoke::kernel_has_btf` | `/sys/kernel/btf/vmlinux` exists and `uname -r` matches the requested series | 14 (eBPF) |
- **Fails first:** compile errors, the tiers and test crates don't exist.
- **Verification:**
  ```bash
  cargo nextest run -p xtask -E 'test(tiers::) | test(kernels::)' && cargo xtask ci fast && cargo xtask ci it && cargo xtask ci net && cargo xtask ci ebpf
  ```
  Expected: xtask tests 2 passed; each tier exits 0 with its smoke test passing (eBPF: on each of 5.10, 6.1 and the
  current Proxmox kernel series).
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** None.
- **Done when:**
  - [x] New tests observed failing before the implementation
  - [x] Every tier runs locally and its smoke test passes
  - [x] `cargo xtask ci fast` clean
  - [x] Evidence recorded below
- **Risk / rollback:** kernel images for 5.10 and 6.1 with BTF may need building; `xtask kernels build` from pinned
  kernel.org tarballs is the fallback (recorded as a plan deviation). Revert the commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p xtask -E 'test(tiers::) \| test(kernels::)' | compile errors: Tier, verify_sha256, parse_kernels, tiers::run, kernels::fetch_all, vm::build_rootfs missing |
  | 2026-11-19 | cargo nextest run -p xtask -E 'test(tiers::) \| test(kernels::)' | 3 passed, 0 failed (the plan's 2, plus kernels_toml_lists_the_three_series) |
  | 2026-11-19 | cargo xtask ci fast | exit 0: fmt, clippy, arch-check, cargo deny clean; 8 passed |
  | 2026-11-19 | cargo xtask ci it | exit 0: 1 passed (smoke::docker_answers) |
  | 2026-11-19 | cargo xtask ci net | exit 0: 1 passed (smoke::can_create_netns) in a VM on 6.1.192 |
  | 2026-11-19 | cargo xtask ci ebpf | exit 0: smoke::kernel_has_btf passed on 5.10.274, 6.1.192 and 6.17.13 |
  | 2026-11-19 | cargo xtask ci win; cargo xtask ci perf | exit 0 (Windows cross build; no Pester scripts or perf tests yet) |

### T03: CI workflows and the guard test
- **Design refs:** 13 (CI), 5.3, D37, D81, AC44
- **Goal:** `ci.yml` runs every tier on the maintainers' self-hosted runners only for upstream pushes, manual runs and
  same-repository pull requests; `ci-github-hosted.yml` runs only when `RACKHAND_GITHUB_HOSTED` is `true`; a test
  proves both conditions against recorded event payloads.
- **Depends on:** T02
- **Changes:**
  - `.github/workflows/ci.yml`: jobs `fast` (`[self-hosted, sm-linux]`), `it` (`[self-hosted, sm-linux-docker]`),
    `net` and `ebpf` (`[self-hosted, sm-linux-kvm]`), `perf` (nightly schedule, `[self-hosted, sm-linux-kvm]`), `win`
    (`[self-hosted, sm-linux]`). Each job's `if:` is the guard
    `github.repository == 'StrangeMatterStudio/Rackhand' && (github.event_name == 'push' || github.event_name ==
    'workflow_dispatch' || github.event_name == 'schedule' || (github.event_name == 'pull_request' &&
    github.event.pull_request.head.repo.full_name == github.repository))`. Toolchains install under `$HOME` (no sudo
    on these runners); `CARGO_HOME` and `CARGO_TARGET_DIR` use the per-repository `/cache` mount; `CARGO_BUILD_JOBS`
    is capped to fit the profile's memory. Each label set is also gated by a repository variable (`RACKHAND_CI_LINUX`,
    `RACKHAND_CI_DOCKER`, `RACKHAND_CI_KVM`), set to `true` in T04 once that runner exists, so no job queues for a
    runner that isn't there. A small `runners` job per label set prints kernel, CPU, memory, Docker and `/dev/kvm`.
  - `.github/workflows/ci-github-hosted.yml`: the same jobs on `ubuntu-latest`, each with
    `if: vars.RACKHAND_GITHUB_HOSTED == 'true'`.
  - `xtask/src/ci_guard.rs`: parses both workflow files, checks every job carries the expected `if:` text, and
    evaluates it with a small evaluator for exactly this expression grammar against `ci/fixtures/*.json`.
  - `ci/fixtures/`: push to upstream, push in a fork, pull request from the same repository, pull request from a
    fork, `workflow_dispatch`, `schedule`, each with an expected result per workflow and variable value.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `ci_guard::fork_pull_request_does_not_run_self_hosted` | the fork PR fixture evaluates to false for every `ci.yml` job | AC44 |
  | `ci_guard::upstream_push_and_same_repo_pr_run_self_hosted` | both evaluate to true | AC44 |
  | `ci_guard::push_in_a_fork_does_not_run_self_hosted` | `github.repository` differs, so false | AC44 |
  | `ci_guard::hosted_copy_runs_only_with_variable_true` | false with the variable unset or `false`; true with `true` | AC44, D37 |
  | `ci_guard::job_without_guard_is_reported` | a fixture workflow with one unguarded job fails the check | AC44 |
  | `ci_guard::jobs_skip_when_runner_variable_unset` | with `RACKHAND_CI_KVM` unset, the `net`, `ebpf` and `perf` jobs evaluate to false on an upstream push | 13 |
- **Fails first:** compile error, `xtask::ci_guard` doesn't exist.
- **Verification:**
  ```bash
  cargo nextest run -p xtask -E 'test(ci_guard::)' && actionlint && cargo xtask ci-guard
  ```
  Expected: 6 passed, 0 failed; `actionlint` prints nothing; `ci-guard` reports every fixture as expected.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** None (the live runs are checked in T04).
- **Done when:**
  - [x] New tests observed failing before the implementation
  - [x] New tests pass; `actionlint` clean
  - [x] Regression suite passes
  - [x] Evidence recorded below
- **Risk / rollback:** the maintainers' rule against GitHub-hosted labels conflicts with `ci-github-hosted.yml`; it is off by
  default and the conflict is reported to the owner. Revert the commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p xtask -E 'test(ci_guard::)' --no-fail-fast | 5 failed (no workflows or fixtures yet: No such file or directory); job_without_guard_is_reported passed on its first run because the checker was written before the tests were first run |
  | 2026-11-19 | cargo nextest run -p xtask -E 'test(ci_guard::)' && actionlint && cargo xtask ci-guard | 6 passed, 0 failed; actionlint clean; 6 fixtures as expected (9 self-hosted, 5 hosted jobs) |
  | 2026-11-19 | cargo xtask ci fast | exit 0; 14 passed |

### T04: Runner profiles for Rackhand
- **Design refs:** 13 (CI), 14 (tiers), D37, D81
- **Goal:** the maintainers' self-hosted runners pick up every Rackhand CI job: the existing `[self-hosted, sm-linux]` profile
  for the fast and Windows tiers, a Docker profile for the integration tier, and a KVM profile for the network, eBPF
  and performance tiers, and this public repository may use the runner group.
- **Depends on:** T03
- **Changes:**
  - Owner, in the runner service's configuration (not in this repository): profile `linux-docker` with labels
    `[self-hosted, sm-linux-docker]`, `docker: true`, at least 4 CPUs, 8 GB memory and 40 GB disk; profile `linux-kvm`
    with labels `[self-hosted, sm-linux-kvm]`, `/dev/kvm` passed into the runner container, `docker: true` (the net
    and eBPF tiers build their kernels and VM root filesystem in containers), user namespaces allowed (`unshare -r`),
    at least 4 CPUs, 8 GB memory and 40 GB disk; runner time limits of at least 60 minutes for `it`, `net` and `ebpf`. Where a profile needs something the
    runner service doesn't offer yet (for example passing `/dev/kvm` into the container), the owner adjusts the
    service (D108).
  - Owner, in GitHub organization settings: the runner group the runner service uses allows public repositories, limited to
    `StrangeMatterStudio/Rackhand` among public ones. The guard from T03 and the organization's "require approval for
    outside contributors" setting keep fork code off the runners.
  - Then, for each label set that has a working runner: `gh variable set RACKHAND_CI_LINUX --body true` (and
    `RACKHAND_CI_DOCKER`, `RACKHAND_CI_KVM`) on the repository. A manually triggered workflow can't be used for this
    check, because GitHub only runs `workflow_dispatch` for workflows already on the default branch.
- **Tests to write first:** none new; the T03 guard tests already cover which events may reach these runners.
- **Fails first:** before the owner's setup the variables are unset, so a push runs only the guard-free lint job and
  every runner job is skipped; with a variable set but no runner, the job waits and the runner service fails it after
  its queue limit.
- **Verification (from PowerShell, after a push of this branch):**
  ```powershell
  gh run watch --repo StrangeMatterStudio/Rackhand --exit-status $(gh run list --repo StrangeMatterStudio/Rackhand --workflow ci.yml --branch design/0001-architecture --limit 1 --json databaseId --jq '.[0].databaseId')
  ```
  Expected: the run succeeds; the `runners` job for each enabled label set prints its facts (Docker server version on
  `sm-linux-docker`, a writable `/dev/kvm` on `sm-linux-kvm`), and every enabled tier job is green.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** MV1 (the owner creates the profiles and the runner group setting).
- **Done when:**
  - [ ] the `runners` jobs green on all three label sets
  - [ ] `ci.yml` green on a push of this branch for every job whose runner exists
  - [ ] Evidence recorded below
- **Risk / rollback:** a public repository on shared runners widens their exposure; the guard, the outside-contributor
  approval setting and the per-repository allow-list in the runner group are the controls (design 17, "Self-hosted
  runners exposed"). Remove the repository from the runner group to roll back. If a profile isn't ready when
  the run reaches T04, the run carries on with that tier in WSL, leaves its variable unset, and T04 stays `unverified`
  until MV1 is done.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | push of 772eb83; gh run list --repo StrangeMatterStudio/Rackhand --branch design/0001-architecture | runs 44471533915 (ci) and 44471533951 (ci-github-hosted) completed, every job skipped: no runner variables set, RACKHAND_GITHUB_HOSTED unset |
  | 2026-11-19 | gh variable list --repo StrangeMatterStudio/Rackhand; gh api orgs/StrangeMatterStudio/actions/runners | no variables; runner listing needs org admin (403). Waiting for MV1; every tier runs in WSL meanwhile |

### L1: Local lab harness
- **Design refs:** 14 (live tier), D107, D71
- **Goal:** `cargo xtask lab` runs QEMU/KVM virtual machines in WSL as the normal user, on two lab site networks, with
  reset and snapshots, including nested Proxmox VE 8 and 9 nodes that each run an LXC guest, so the spikes and every
  live pass can run on the development machine.
- **Depends on:** T02
- **Changes:**
  - `lab/lab.toml`: the lab's machines and profiles.
    | Machine | Image | vCPU / memory | Site |
    | --- | --- | --- | --- |
    | `hub` | Debian 12 | 2 / 2 GB | A |
    | `target` | Ubuntu 24.04 | 2 / 2 GB | A |
    | `agentless` | Debian 12 | 1 / 1 GB | A |
    | `alpine` | Alpine 3.20 | 1 / 512 MB | A |
    | `pve8` | Debian 12 with Proxmox VE 8, extra 16 GB disk for a ZFS pool | 4 / 4 GB | A |
    | `pve9` | Debian 13 with Proxmox VE 9, extra 16 GB disk for a ZFS pool | 4 / 4 GB | A |
    | `hub-b`, `target-b` | Debian 12 | 2 / 2 GB each | B |
    | `relay` | Debian 12, a NIC on each site, nftables NAT for site B | 1 / 1 GB | A and B |
    | `operator` | Debian 12 with Claude Code (Claude Code runs only on operator hosts, never on a hub) | 2 / 2 GB | A |

    Profiles (memory in brackets): `lab` (`hub`, `target`, `alpine`, `pve8`, `pve9`; 12.5 GB), `spikes` (`pve8`,
    `pve9`; 8 GB), `m1` (`hub`, `target`; 4 GB), `m2` (`hub`, `target`, `agentless`, `alpine`, `pve8`, `pve9`; 13.5 GB),
    `m3` (`hub`, `target`, `pve9`; 8 GB), `m4` (`hub`, `target`, `agentless`, `pve9`; 9 GB), `m5` (`hub`, `target`,
    `operator`; 6 GB), `m6` (`hub`, `target`, `relay`, `hub-b`, `target-b`; 9 GB), `m8` (`hub`, `target`, `alpine`,
    `pve9`, `hub-b`; 10.5 GB). Only one profile runs at a time.
  - `lab/images.toml`: every download with its URL and pinned SHA-256, taken from the publisher's signed checksum file
    when this step runs (the list is under *Environment and tools*).
  - `xtask/src/lab/`: `lab doctor`, `lab fetch`, `lab up <profile>`, `lab down`, `lab reset [machine]` (drops the
    machine's qcow2 overlay over its pristine base), `lab snapshot <machine> <name>` and `lab restore`, `lab ssh
    <machine>`, `lab run <machine> -- <command>`, `lab pause` and `lab resume` (QMP `stop` and `cont`), `lab cut` and
    `lab heal` (QMP `set_link` on the site NIC), `lab status`, `lab destroy` (deletes all lab state). `lab reset` without a machine name skips `operator`, so
    the owner's Claude Code sign-in there survives; only `lab reset operator` or `lab destroy` removes it.
  - Networking without root: each machine has a user-mode NIC (internet, and SSH forwarded to a `127.0.0.1` port) and a
    NIC on its site segment (QEMU socket multicast). Site A is `192.0.2.0/24` and site B is `198.51.100.0/24`, both
    documentation ranges (D71), so lab evidence needs no redaction. Test code in WSL reaches site services through
    forwarded ports; machines reach WSL-side fakes through the user-mode gateway.
  - Cloud-init NoCloud seeds served by `xtask` over HTTP (SMBIOS `ds=nocloud;s=...`), so no ISO tools or sudo are
    needed; a lab SSH key under `~/.cache/rackhand-lab/`, where all lab state lives (Linux filesystem).
  - Proxmox nodes: `lab up` installs Proxmox VE on Debian following Proxmox's "install on Debian" guide with the
    no-subscription repository, creates a ZFS pool on the extra disk, fetches the Alpine LXC template with `pveam`,
    and creates `ct-test` (an unprivileged LXC) and `vm-test` (a small Alpine VM: hardware virtualization if the
    nested CPU offers it, otherwise `kvm: 0` emulation), then snapshots the node as `pristine`.
  - Memory guard: `lab up` refuses a profile whose machines don't fit in available memory minus 12 GB kept for builds;
    `cargo xtask ci live` caps `CARGO_BUILD_JOBS` at 12.
  - `tests/live` (`rackhand-live`, excluded from `default-members`), nextest profile `live`, and `cargo xtask ci live
    --target local|real --milestone <name>|all [--no-deploy]`. With `--target local`, `--milestone <name>` stops any
    other profile, brings up profile `<name>`, deploys the current build (unless `--no-deploy`) and runs that
    milestone's tests; `all` does this for every milestone in order. The live tier runs only in WSL, never in CI (it
    needs the lab).
  - `.gitignore`: `lab/real.env` (the owner's real-lab hosts, used by L9).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `lab::profiles_reference_known_machines` | every profile names machines defined in `lab.toml` | 14 |
  | `lab::image_checksum_mismatch_is_refused` | a fetched image whose SHA-256 differs from `images.toml` is deleted and the command fails | 14 |
  | `lab::profile_over_memory_budget_is_refused` | a profile needing more than available memory minus 12 GB fails before starting anything | 14 |
  | `lab::site_networks_use_documentation_ranges` | every lab address is in `192.0.2.0/24` or `198.51.100.0/24` | D71 |
  | `live::lab::machines_boot_and_answer_ssh` | every machine in profile `lab` answers SSH with the lab key within 5 minutes | 14 |
  | `live::lab::site_a_machines_reach_each_other` | `hub` pings `target` on the site A segment | 14 |
  | `live::lab::reset_restores_the_pristine_disk` | a file written on `target` is gone after `lab reset target` | 14 |
  | `live::lab::pause_and_cut_stop_traffic` | after `lab pause` and after `lab cut`, `target` stops answering; `resume` and `heal` bring it back | 14 |
  | `live::lab::proxmox_nodes_run_an_lxc_guest` | `pveversion` reports 8.x on `pve8` and 9.x on `pve9`; `ct-test` starts on each | 14, D107 |
  | `live::lab::proxmox_vm_guest_boots` | `vm-test` boots on `pve9`; the test records whether it ran with hardware virtualization or emulation | 14 |
- **Fails first:** the `lab::` tests don't compile (no `xtask::lab`); the `live::lab::` tests fail with "lab not
  running".
- **Verification:**
  ```bash
  cargo nextest run -p xtask -E 'test(lab::)' && cargo xtask lab fetch && cargo xtask ci live --target local --milestone lab
  ```
  Expected: 4 passed, 0 failed; every image verified; 6 passed, 0 failed.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** None.
- **Done when:**
  - [x] New tests observed failing before the implementation
  - [x] New tests and the regression suite pass
  - [x] Nested Proxmox result recorded (LXC guests run; VM guests with hardware virtualization or emulation)
  - [x] Evidence recorded below
- **Risk / rollback:** nested Proxmox (three virtualization levels deep under WSL) may not run. If `pve8` or `pve9`
  can't run an LXC guest, the run records a plan-level deviation: T10, T11 and T12 use the owner's real lab as first
  planned (MV2, MV3 and MV4 back to the owner), and the Proxmox tests in L3 to L5 and L8 move to L9. The lab needs
  about 40 GB of disk under `~/.cache/rackhand-lab`. `cargo xtask lab destroy`, then revert the commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p xtask -E 'test(lab::)' | compile errors: unresolved `config` and `images` (run log) |
  | 2026-11-19 | cargo nextest run -p xtask -E 'test(lab::)' | 6 passed, 0 failed (the 4 planned, the seed encoder test, and `provision_stamp_follows_the_inputs`, seen failing first: unresolved `stamp`, `is_provisioned`) |
  | 2026-11-19 | cargo xtask lab fetch | exit 0; alpine-3.20, debian-12, debian-13 and ubuntu-24.04 verified against images.toml |
  | 2026-11-19 first full run | cargo xtask ci live --target local --milestone lab | 5 of 6 passed: `proxmox_nodes_run_an_lxc_guest` failed (pve9 had the arm64 template); `proxmox_vm_guest_boots` passed only after 518 s on a lucky ping, because the bridges learned guest MACs on the uplink port (QEMU's multicast socket NIC hands frames back to their sender) |
  | 2026-11-19 | cargo xtask ci live --target local --milestone lab | 7 passed, 0 failed (`proxmox_guests_answer_every_time` added: 10 of 10 pings to each of the four guests, and learning off on each node's uplink). Proxmox VE 8.4.21 (kernel 6.8.12) and 9.2.31 (kernel 7.0.14); ct-test runs on both; vm-test runs on both with hardware virtualization (nested KVM) |
  | 2026-11-19 | cargo xtask ci fast | exit 0 (111 passed) |
  | 2026-11-19 fix | cargo nextest run -p xtask; cargo xtask lab up lab; cargo xtask ci live --target local --milestone lab | `lab reset` kept a Proxmox node's extra disk (its ZFS pool). It is now `extra-base.qcow2`, written while provisioning, with `extra.qcow2` an overlay that reset replaces; the provision stamp changed, so both nodes were provisioned again. `lab::extra_disk_is_an_overlay_that_reset_replaces` failed first (no `Stage`, `drives`, `reset_files`), then 21 passed. `pve8`'s first attempt lost SSH right after its phase-2 reboot; file copies to a machine are now tried three times, 5 s apart. Live: 7 passed, with `reset_restores_the_pristine_disk` also checking that a dataset made on `pve9`'s pool is gone after a reset (this live check wasn't run against the old layout) |

### Spikes (D87)

Every spike step follows the same rules:
- Throwaway code lives in `spikes/<id>/` while the step runs and is deleted before the commit (`spikes/` is listed in
  `.gitignore` by T01).
- The commit adds `docs/designs/0001-architecture/spikes/<id>.md` (questions, method, measurements, answer, redacted
  per D71) and appends the finding under the spike in design section 17 with a change-log row.
- If the finding contradicts the design, the run stops and asks the owner, and the design is updated (change log)
  before any step that depends on the spike starts.
- **Fails first** for a spike means the threshold check script is written first and run against a stub that reports
  nothing, so it fails with "no measurement".

### T05: Spike S8: time-series encoding
- **Design refs:** 7.4.1 (storage estimate), 5.2 (database at most 2 GB per 50 machines), D43, S8
- **Goal:** the real bytes per value of Gorilla-encoded chunks on recorded data, compared with the estimate's 1.4 bytes
  (tier 0 and tier 1) and 2 bytes (tier 2).
- **Depends on:** T02
- **Changes:** `spikes/s8/` (recorder and encoder, deleted); `docs/designs/0001-architecture/spikes/s8.md`; design 17
  and change log.
- **Method:** record 24 hours of the 7.4.2 Linux metric set at 15 s from the WSL machine and from one lab VM the owner
  names (recorded by a small script reading `/proc` and `/sys`), plus the rollups derived from them; encode in chunks
  of 120 points with a Gorilla encoder (`tsz` or equivalent); compute bytes per value per tier; project the 50-machine
  total with the retention in G1.
- **Verification:**
  ```bash
  cargo run --release --manifest-path spikes/s8/Cargo.toml -- --data spikes/s8/data --report docs/designs/0001-architecture/spikes/s8.md --check
  ```
  Expected: exit 0 when the projected total is at most 2 GB; the report lists bytes per value per tier and the
  projection.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** None (the owner names the lab VM; the run records from it over SSH with an existing key).
- **Done when:**
  - [x] Report committed; finding appended to design 17 with a change-log row
  - [x] Projection at most 2 GB, or the owner has decided the trade-off and the design is updated (7.4.1 says so)
  - [x] Spike code deleted
- **Risk / rollback:** a miss changes retention or the budget; that is the owner's call before T19.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-20 | cargo run --release --manifest-path spikes/s8/Cargo.toml -- --data spikes/s8/data --report docs/designs/0001-architecture/spikes/s8.md --check | exit 1: projected 4.23 GB over the 2 GB budget (5.21, 3.20 and 4.48 bytes per value for tiers 0, 1 and 2; 66 series over 24.0 h on the WSL host) |
  | 2026-11-20 | same with `--quantize`, `--int`, `--grid` and their combinations, and `--tier1-days` / `--tier2-days` | best encoding (integer values at a per-metric step, samples stamped with their 15 s tick) 1.65, 1.60 and 2.66 bytes per value, 2.52 GB with G1 retention; 1.88 GB with tier 1 kept 14 days. Report `spikes/s8.md`. Blocked: the trade-off is the owner's (7.4.1) |
  | 2026-11-20 (review) | the same runs after review, with an adaptive integer coder (delta-of-delta, delta or XOR per chunk, buckets to 64 bits), `--kib`, the 7.4.1 chunk rule (`--t1-chunk`, `--t2-chunk`) and the SQLite row cost measured on the `series_chunks` schema (103 bytes a row plus 31.5% of the blob, not the assumed 80) | Gorilla 5.66 GB; integer + grid + KiB 1.00, 0.98 and 1.62 bytes per value, 2.40 GB with the chunk rule, 1.82 GB with day-long tier 1 chunks, 1.81 GB with 120-point tier 1 chunks and tier 2 kept 1 year. Report rewritten; design 17 finding and change-log row added (owner decision pending). Still blocked |
  | 2026-11-20 (decision) | owner's answer; design updated | owner chose integer columns at a step with tick timestamps, tier 1 and 2 chunks of 120 points and tier 2 kept 1 year (1.81 GB): D109 in design 18, 7.4.1 (chunk encoding, chunk rule, retention, storage estimate), G1, FR-7 and the settings range; change log. A 4-hour sample of the recording kept as `crates/rackhand-store/tests/fixtures/s8-sample.csv.zst` for T19 (the spike measures 1.04 and 0.96 bytes per value for tiers 0 and 1 on it); spike code and the rest of the data deleted. Regression `cargo xtask ci fast`: 241 passed |

### T06: Spike S6: probe footprint
- **Design refs:** 5.2 (probe footprint), 11, D52, S6
- **Goal:** the static musl binary size and steady RSS and CPU of a probe skeleton with iroh, aya and tokio, against
  15 MB, 25 MB and 1% of a core.
- **Depends on:** T02
- **Changes:** `spikes/s6/` (deleted); `spikes/s6.md`; design 17 and change log.
- **Method:** a binary that opens an iroh endpoint to a local listener, loads a trivial aya tracepoint program, runs a
  tokio current-thread runtime, reads `/proc` every 15 s and sends a 1.2 KB zstd frame. Build for
  `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` with `opt-level = "z"`, LTO and `panic = "abort"`;
  measure size with `stat`, RSS from `/proc/<pid>/status` (`VmRSS`) every 10 s for 30 minutes, CPU from
  `/proc/<pid>/stat`. Compare a multi-thread runtime and iroh feature sets.
- **Verification:**
  ```bash
  spikes/s6/measure.sh --minutes 30 --report docs/designs/0001-architecture/spikes/s6.md --check
  ```
  Expected: exit 0 when size is at most 15 MB, steady RSS at most 25 MB and average CPU at most 1%; the report gives
  every configuration measured.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** None.
- **Done when:**
  - [x] Report committed; finding and the chosen runtime and features appended to design 17
  - [x] Budgets met, or the owner has decided and 5.2 is updated
  - [x] Spike code deleted
- **Risk / rollback:** iroh's size may need trimmed features; recorded as the finding.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | spikes/s6/measure.sh --stub --check | no measurement, exit 1 |
  | 2026-11-19 | spikes/s6/measure.sh --minutes 30 (first run) | invalid: the VM's loopback was down, so every probe exited at start; the check was tightened to require frames received and non-zero RSS |
  | 2026-11-19 | spikes/s6/measure.sh --minutes 30 --report docs/designs/0001-architecture/spikes/s6.md --check | exit 0: 5.55 MB static, 4.9 MB steady RSS, 0.019% CPU (ct-minimal); 122 frames received in 30 minutes; aarch64 4.43 MB |

### T07: Spike S7: git mirror library
- **Design refs:** 7.3.13, 5.3, S7
- **Goal:** choose `gix` or `git2` (statically linked) for pushing the library mirror over SSH with a deploy key.
- **Depends on:** T02
- **Changes:** `spikes/s7/` (deleted); `spikes/s7.md`; design 17, 5.3 (library named) and change log.
- **Method:** with each library, commit a tree and push it over SSH to a bare repository in an `sshd` container with an
  Ed25519 deploy key held in memory, then push again after a change; force-push refusal handling; measure binary size
  added and build success for `x86_64-unknown-linux-musl`.
- **Verification:**
  ```bash
  spikes/s7/run.sh --report docs/designs/0001-architecture/spikes/s7.md --check
  ```
  Expected: exit 0 when at least one library pushes twice successfully with an in-memory key and builds static; the
  report names the choice and the size cost.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** None.
- **Done when:**
  - [x] Report committed; library named in design 5.3 and 17 with a change-log row
  - [x] Spike code deleted
- **Risk / rollback:** if neither pushes from memory, shelling out to `git` is a design change for the owner.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | spikes/s7/run.sh --stub --check | no measurement, exit 1 |
  | 2026-11-19 | spikes/s7/run.sh --report docs/designs/0001-architecture/spikes/s7.md --check | exit 0: git2 pushed twice from an in-memory Ed25519 key, refused a non-fast-forward push, pushed from a static musl build (6.14 MB, 5.8 MB over baseline); gix 0.90 has no push |
  | 2026-11-19 | cargo xtask ci fast | exit 0; 19 passed |

### T08: Spike S2: iroh relay admission and limits
- **Design refs:** 7.3.10, FR-20, AC31, E27, S2
- **Goal:** whether an embedded iroh relay can admit by key, limit per endpoint, prioritize keyed endpoints at
  capacity, and which ports it needs.
- **Depends on:** T02
- **Changes:** `spikes/s2/` (deleted); `spikes/s2.md`; design 17 and change log (and 7.3.10, FR-20 and AC31 if priority
  is impossible, per the design's own fallback).
- **Method:** in the network test VM, run an iroh relay with an admission hook; clients with and without a signed key;
  measure throughput with a token-bucket limiter at 1 Mbit/s; fill to a capacity of 5 and try keyed and unkeyed
  joins; list the listening sockets.
- **Verification:**
  ```bash
  cargo xtask ci net --spike s2 -- --report docs/designs/0001-architecture/spikes/s2.md --check
  ```
  Expected: exit 0; the report states for each of admission, rate limit, daily quota, priority and ports either
  "works" with the measured result or "not possible" with the reason.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** None.
- **Done when:**
  - [ ] Report committed; finding in design 17
  - [ ] If priority is impossible: AC31's priority clause and FR-20's priority wording removed per 7.3.10, with the
    owner told (design-level change, owner agrees)
  - [ ] Spike code deleted
- **Risk / rollback:** the relay API differs between iroh versions; pin the version found here in T17.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | s2 report --out <empty dir> --check | no measurement, exit 1 |
  | 2026-11-19 | cargo xtask ci net --spike s2 -- --report docs/designs/0001-architecture/spikes/s2.md --check | exit 0: admission by key works; server-wide rate 1 MB in 8.4 s at 1 Mbit/s; priority at capacity works by eviction; per-key rate and daily quota not possible; ports TCP 80/443, UDP 7842 |
  | 2026-11-19 | design 17 | finding appended; 7.3.10's per-key rate and daily quota left as written until the owner picks an option (spikes/s2.md) |

### T09: Spike S3: iroh path detection
- **Design refs:** 7.3.11 (bulk transfers direct only), E29, S3
- **Goal:** how a connection reports direct versus relayed paths, and how to wait for a direct path.
- **Depends on:** T02
- **Changes:** `spikes/s3/` (deleted); `spikes/s3.md`; design 17 and change log.
- **Method:** in the network VM, two endpoints behind full-cone NAT (direct possible) and behind symmetric NAT with UDP
  blocked (relay only); record the path events and timings; write a `wait_direct(timeout)` prototype.
- **Verification:**
  ```bash
  cargo xtask ci net --spike s3 -- --report docs/designs/0001-architecture/spikes/s3.md --check
  ```
  Expected: exit 0; full cone reports direct within the measured time; the blocked case reports relay only and
  `wait_direct` times out cleanly.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** None.
- **Done when:**
  - [x] Report committed; finding in design 17
  - [x] Spike code deleted
- **Risk / rollback:** none beyond the finding.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | s3 report --out <empty dir> --check | no measurement, exit 1 |
  | 2026-11-19 | cargo xtask ci net --spike s3 -- --report docs/designs/0001-architecture/spikes/s3.md --check | exit 0: full cone direct within 1 ms; UDP blocked stays relayed, wait_direct times out at 15 s; no NAT direct; two masquerade NATs stay relayed (finding) |
  | 2026-11-19 | cargo xtask ci fast | exit 0 |

### T10: Spike S1: aya eBPF
- **Design refs:** FR-4, FR-5, D17, D103, E36, E37, 5.3 (license), S1
- **Goal:** connect, UDP and exec tracing with aya on kernels 5.10, 6.1 and the current Proxmox kernel; memory use;
  executable path and cgroup id resolved in the program; LXC attribution by cgroup from the host; and the license the
  eBPF program must declare for the helpers it uses.
- **Depends on:** T02, L1
- **Changes:** `spikes/s1/` (deleted); `spikes/s1.md`; design 17 and change log.
- **Method:** CO-RE programs on `sock` and `sched_process_exec` tracepoints; in each eBPF VM run `curl`, a UDP send and
  an exec from `/tmp`; read events; measure map memory. On the local lab's `pve9` node (L1), run the same binary
  on the node and check that a connection from inside an unprivileged LXC is attributed to its cgroup. List every BPF
  helper used and whether it is GPL-only.
- **Verification:**
  ```bash
  cargo xtask ci ebpf --spike s1 -- --report docs/designs/0001-architecture/spikes/s1.md --check && cargo xtask lab up spikes && spikes/s1/lxc-check.sh --node pve9 --guest ct-test --report docs/designs/0001-architecture/spikes/s1.md
  ```
  Expected: exit 0 on each kernel: the connect, UDP and exec events are captured with pid, exe path and cgroup id;
  memory measured; on `pve9` a connection from `ct-test` is attributed to its cgroup. MV2 repeats the LXC part on
  a real Proxmox host in L9.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** None here; MV2 (a real Proxmox host kernel) is run in L9.
- **Done when:**
  - [x] Report committed; finding in design 17
  - [x] License finding stated; if GPL-only helpers are needed, the owner decides the eBPF program's license
    (for example a separate `GPL-2.0 OR MIT` crate) before T68
  - [x] LXC attribution on `pve9` recorded
  - [x] Spike code deleted
- **Risk / rollback:** if a kernel lacks a needed hook, that kernel uses sampling (already the design's fallback).
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 | cargo xtask ci ebpf --spike s1 -- --report docs/designs/0001-architecture/spikes/s1.md --check | exit 0: loaded on 5.10.274, 6.1.192 and 7.0.14; connect, UDP and exec captured with pid, exe path (in the program) and cgroup id; map memory 1080, 548 and 1070 KB; the MIT-declared build is refused by the verifier (GPL-only `bpf_probe_read_kernel`) |
  | 2026-11-19 | spikes/s1/lxc-check.sh --node pve9 --guest ct-test --report docs/designs/0001-architecture/spikes/s1.md | exit 0 on the lab's pve9 (Proxmox VE 9.2.31, kernel 7.0.14-30-pve): the container's connect attributed to `/sys/fs/cgroup/lxc/100/ns/.lxc` |
  | 2026-11-19 | report | `spikes/s1.md` and the finding in design 17; the eBPF program's licence is the owner's decision before T68; spike code deleted |

### T11: Spike S11: collectors on current distributions
- **Design refs:** FR-2, FR-6, 7.6.1 (memory rules), S11
- **Goal:** how a static binary reads authentication events on journal-only systems, and which memory reading keeps the
  memory rules quiet on a healthy host whose ZFS cache holds most memory.
- **Depends on:** T02, L1
- **Changes:** `spikes/s11/` (deleted); `spikes/s11.md`; design 17 and change log.
- **Method:** in Debian 12 and Ubuntu 24.04 containers with systemd and no `/var/log/auth.log`: read SSH and sudo events
  by (a) spawning `journalctl -o json --cursor`, (b) parsing journal files with a pure-Rust reader; compare. On the local
  lab's `pve9` node, whose ZFS pool is on its extra disk, read `/proc/meminfo` and `/proc/spl/kstat/zfs/arcstats` and compute
  `mem.available_pct` with and without the shrinkable ARC.
- **Verification:**
  ```bash
  cargo xtask lab up spikes && spikes/s11/run.sh --zfs-node pve9 --report docs/designs/0001-architecture/spikes/s11.md --check
  ```
  Expected: exit 0; at least one method returns every SSH login and sudo event generated in the container; the ZFS
  computation on `pve9` is recorded; MV3 repeats it on a real host in L9.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** None here; MV3 (a real host's ARC under real load) is run in L9.
- **Done when:**
  - [x] Report committed; the chosen method and the memory formula in design 17 (and 7.4.2 if a metric changes)
  - [x] Spike code deleted
- **Risk / rollback:** none beyond the finding.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 | spikes/s11/run.sh --zfs-node pve9 --report docs/designs/0001-architecture/spikes/s11.md --check | measured on Debian 12, Ubuntu 24.04 and pve9; the first report said NOT every event because the spike's own check expected 3 logins where its script makes 5 (3 plain, 2 for the sudo runs); corrected the expectation, not the data |
  | 2026-11-19 | spikes/s11/run.sh --stub --zfs-node pve9 --report ... --check | exit 0: both methods return 5 logins, 1 invalid user and 2 sudo events on both systems; the cursor file returns 0 new lines on a second read. pve9 with a full ARC: 16.4% available from MemAvailable, 53.1% counting the ARC above c_min |
  | 2026-11-19 | report | `spikes/s11.md`, the finding in design 17 and the 7.4.2 note; spike code deleted |

### T12: Spike S4: Proxmox privileges, firewall, upgrade command
- **Design refs:** 7.8.6, 7.5.6, 7.5.3 (steps 7 and 8), E24, E66, S4
- **Goal:** the exact role privileges for snapshot, rollback, guest firewall, conntrack flush, clone and power on PVE 8
  and 9; the datacenter firewall prerequisite; whether each network device's firewall flag must be on for guest rules,
  and saving and restoring it; and the upgrade command Proxmox needs on its own hosts.
- **Depends on:** T02, L1
- **Changes:** `spikes/s4/` (deleted); `spikes/s4.md`; design 7.8.6 (final privilege list), 17 and change log.
- **Method:** on the local lab's `pve8` and `pve9` nodes (L1), with an API token the script creates and deletes itself, a
  script grants the 7.8.6 role, then tries each operation on the lab guests `ct-test` and `vm-test`, removing one privilege at a time to find the minimum; applies and removes the quarantine rule set and
  compares the saved and restored firewall configuration; checks whether conntrack can be flushed through the API.
  Reads Proxmox documentation for the upgrade command.
- **Verification:**
  ```bash
  cargo xtask lab up spikes && spikes/s4/run.sh --nodes pve8,pve9 --report docs/designs/0001-architecture/spikes/s4.md --check
  ```
  Expected: exit 0; every operation listed as working with the minimal privilege set on both versions, the firewall
  round trip identical, and the conntrack and upgrade answers stated.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** None here; MV4 repeats the privilege check on the owner's real nodes in L9.
- **Done when:**
  - [x] Report committed (redacted); 7.8.6 updated; finding in design 17
  - [x] If conntrack can't be flushed through the API, the owner decides how (design-level)
  - [x] Spike code deleted; the script's tokens deleted from the lab nodes
- **Risk / rollback:** lab guests only; the script refuses any node or guest outside the lab.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 first run | spikes/s4/run.sh --nodes pve8,pve9 --report docs/designs/0001-architecture/spikes/s4.md --check | exit 1: `clone` failed even with the full role on both. Diagnosed by hand: the clone and the delete both work with the role; the spike sent `purge=1` in a DELETE body, which the API doesn't take. Moved it to the query string |
  | 2026-11-19 | spikes/s4/run.sh --nodes pve8,pve9 --report docs/designs/0001-architecture/spikes/s4.md --check | exit 0 ("S4 OK"): every operation works with the 7.8.6 role on PVE 8.4.21 and 9.2.31; firewall round trip identical; no conntrack path in the API; the admin guides use a full upgrade |
  | 2026-11-19 | NIC flag measurement (pings from the lab hub to ct-test) | with the guest firewall DROP: answers with `firewall=0`, silent with `firewall=1`, answers after restore; both versions |
  | 2026-11-19 | report | `spikes/s4.md`, 7.8.6, the finding in design 17 and the change log; the spike's users, roles and tokens are gone from both nodes (`pveum user list`: root@pam only); spike code deleted. Conntrack flush: owner decision before T72 |

### T13: Spike S5: Claude Code headless
- **Design refs:** 7.3.5 (Claude Code runner), D38, D39, S5
- **Goal:** the exact flags for a headless run limited to one stdio MCP server, MCP tools only, stream-json events,
  kill at deadline, and a configuration directory that holds only the provider credential.
- **Depends on:** T02
- **Changes:** `spikes/s5/` (deleted); `spikes/s5.md`; design 7.3.5 (flags) and 17, change log.
- **Method:** in WSL, as a separate user with an empty configuration directory into which the owner signs in, run
  `claude -p` against a stub stdio MCP server with two tools, with a user-level MCP server and a project MCP config
  present that must not load; try `--mcp-config`, the flag that limits a run to it, `--allowedTools "mcp__stub__*"`,
  `--output-format stream-json` (and whatever it requires non-interactively), `--max-turns`; send SIGTERM at a deadline
  and confirm the process tree exits.
- **Verification:**
  ```bash
  spikes/s5/run.sh --report docs/designs/0001-architecture/spikes/s5.md --check
  ```
  Expected: exit 0; only the stub's tools are called, the other MCP servers never start, every stream-json line
  parses, and the kill leaves no process.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** MV5 (the owner signs in to Claude Code in the spike's configuration directory).
- **Done when:**
  - [x] Report committed; flags written into 7.3.5; finding in design 17
  - [x] Spike code deleted; the spike user's configuration directory removed
- **Risk / rollback:** none beyond the finding.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-21 | spikes/s5/run.sh --report docs/designs/0001-architecture/spikes/s5.md --check | exit 0. Only the stub's tools were listed and called (`mcp__stub__echo`; a shell request found no tool), the user-level and project decoys didn't start (the control run without `--strict-mcp-config` started both), every stream-json line parsed, and SIGTERM 20 s into a 120 s tool call left no process after 5 s. Flags in 7.3.5, finding in 17. Spike code deleted; the signed-in configuration directory removed (D56) |
  | 2026-11-21 | cargo xtask ci fast | exit 0 (no code changed) |

### T14: Spike S9: TrueNAS API
- **Design refs:** FR-10, 7.4.2 (TrueNAS row), AC11, S9
- **Goal:** which API (REST or JSON-RPC over WebSocket) current TrueNAS releases support for pool, disk and alert
  reads, and recorded responses for the driver's simulator.
- **Depends on:** T02
- **Changes:** `spikes/s9/` (deleted); `spikes/s9.md`; redacted fixtures under `crates/rackhand-drivers/tests/fixtures/truenas/`
  (kept: they become the AC11 simulator data); design 17 and change log.
- **Method:** with a read-only API key the owner creates (environment variable only), call pool, disk, temperature,
  SMART and alert reads over both APIs where available; record responses; replace names, serials and addresses with
  invented values.
- **Verification:**
  ```bash
  spikes/s9/run.sh --report docs/designs/0001-architecture/spikes/s9.md --fixtures crates/rackhand-drivers/tests/fixtures/truenas --check
  ```
  Expected: exit 0; every metric in the 7.4.2 TrueNAS row found in at least one API; fixtures pass the redaction check
  (no address outside the documentation ranges, no serial matching the originals).
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** MV6 (the owner provides the key and revokes it after).
- **Done when:**
  - [x] Report and redacted fixtures committed; finding in design 17
  - [x] Spike code deleted
- **Risk / rollback:** none beyond the finding.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-21 | spikes/s9/run.sh --report docs/designs/0001-architecture/spikes/s9.md --fixtures crates/rackhand-drivers/tests/fixtures/truenas --check | exit 0 on TrueNAS 25.04.2.6 (1 pool, 5 disks): every metric of the 7.4.2 TrueNAS row in both REST and JSON-RPC; redaction check passed (no address outside the documentation ranges, no original serial or pool name, not the NAS's address), and the files were read through by hand for names. Spike code deleted; the owner revokes the key (MV6) |
  | 2026-11-21 | cargo xtask ci fast | exit 0 (no code changed) |

### T15: Spike S10: threat list and GeoIP terms
- **Design refs:** 7.8.5, D19, D65, D75, NG10, S10
- **Goal:** whether the default sources (Feodo Tracker, Spamhaus DROP, DB-IP Lite) may be used by default in an
  open-source product, and whether they still carry enough entries to be worth shipping as defaults.
- **Depends on:** T02
- **Changes:** `spikes/s10.md` (terms with links and short quotes, entry counts, sizes, update cadence); design 7.8.5
  and 17, change log.
- **Method:** read each source's terms page; download each list once; count valid entries and size.
- **Verification:**
  ```bash
  cargo run --release --manifest-path spikes/s10/Cargo.toml -- --report docs/designs/0001-architecture/spikes/s10.md --check
  ```
  Expected: exit 0; each source has a non-zero entry count, a size, and a terms verdict with a link.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** None (the owner reviews the terms verdicts at plan-run review time; any "not allowed" is a
  design-level stop).
- **Done when:**
  - [ ] Report committed; 7.8.5 license notes updated; finding in design 17
  - [ ] Any source unusable as a default: owner decides a replacement (design-level)
  - [ ] Spike code deleted
- **Risk / rollback:** none beyond the finding.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo run --release --manifest-path spikes/s10/Cargo.toml -- --stub --check | every source 0 entries; "a source has no entries (or no measurement)", exit 1 |
  | 2026-11-19 | cargo run --release --manifest-path spikes/s10/Cargo.toml -- --report docs/designs/0001-architecture/spikes/s10.md --check | exit 0: Feodo 1 entry, DROP 1 747, DB-IP country 732 796, ASN 485 292; each with size, cadence, terms link and verdict |

### M1: Single-site monitoring

From here on, every step's **Regression** is `cargo xtask ci fast` (exit 0, `0 failed`) unless the step adds a tier.
**Done when** always includes:
- new tests seen failing first, for the stated reason;
- new tests pass;
- regression passes;
- lint and format clean;
- evidence recorded.

Only additions to that list are written out below.

### T16: Wire format: framing, limits, close codes, messages
- **Design refs:** 7.3 (common rules), 7.3.1 to 7.3.6 and 7.3.11 (message shapes), 7.3.3 (helper JSON), D41, D94, E53
- **Goal:** every contract's messages exist as prost types with ALPN constants, and one framing codec enforces the 4 MB
  frame limit, the 16 MB decompression limit, the close codes and `unsupported` for unknown enum values.
- **Depends on:** T15 (spikes done)
- **Changes:** `crates/rackhand-proto/proto/*.proto` (join, probe, peer, operator, MCP auth line, tunnel, xfer, signed
  payload with version and expiry); `build.rs` (prost-build with the system `protoc`); `src/frame.rs` (u32 big-endian
  length prefix); `src/zstd.rs` (bounded decompression); `src/close.rs` (`0x10` to `0x15`); `src/alpn.rs`;
  `src/helper.rs` (serde types for the helper socket, newline-delimited JSON); `src/signed.rs` (`SignedPayload` signing
  and verification with a version and an expiry, used by the join response, `KeysUpdate` and command-list updates);
  `tests/fixtures/golden/*.bin`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `frame::round_trip_every_message_type` | encode then decode equals the input for one sample of every message | 7.3 |
  | `frame::frame_over_4_mib_is_rejected_before_allocation` | a length prefix of 4 MiB + 1 gives `FrameTooLarge` without reading the body | 7.3 |
  | `zstd::decompression_past_16_mib_fails_with_0x15` | a 4 MB frame of zeros that expands past 16 MiB returns the `0x15` close error | E53, AC62 |
  | `enums::unknown_enum_value_maps_to_unsupported` | an unknown `JoinError` value decodes to `Unsupported`, no panic | 7.3 |
  | `golden::encoded_bytes_match_fixtures` | today's encoding of each sample equals its golden file | 5.2 compatibility |
  | `golden::older_message_without_new_optional_field_decodes` | a fixture missing an optional field decodes with the default | 5.2 compatibility |
  | `helper::request_lines_parse_and_reject_unknown_fields` | each `HelperRequest` round-trips as one JSON line; an unknown field is refused | 7.3.3 |
  | `signed::expired_not_newer_or_wrong_key_refused` | a payload past its expiry, with a version not above the last applied, or signed by another key fails to verify | 7.3.3, D92 |
- **Fails first:** compile errors, the crate is empty.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-proto
  ```
  Expected: 8 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** golden files change only on deliberate schema changes (`cargo xtask golden --update`, reviewed
  in the diff). Revert the commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-proto | compile errors: unresolved crate::frame, zstd, close, helper, signed, join, samples, known_or_unsupported |
  | 2026-11-19 | cargo xtask golden --update; cargo nextest run -p rackhand-proto | 39 golden files written; 8 passed, 0 failed |
  | 2026-11-19 | cargo xtask ci fast | exit 0; 27 passed; clippy, fmt, arch-check, cargo deny clean |

### T17: Net: endpoint, node key, registry, contract harness
- **Design refs:** 7.1 (endpoint ids, registry), 7.3 (registry check per ALPN, close codes), 7.3.10 (own relays first,
  n0 off), D7, D34, D51
- **Goal:** a Rackhand node has a persistent Ed25519 key that is its iroh endpoint id. It accepts connections only from
  ids registered for that ALPN (others are closed with `0x10`) and uses only configured relays. Tests can stand up
  endpoint pairs in-process.
- **Depends on:** T16, T08, T09
- **Changes:** `crates/rackhand-net/src/{key.rs, endpoint.rs, registry.rs, router.rs, relays.rs}`; `src/testing.rs`
  (feature `testing`: an in-process endpoint pair with a local relay, used by every contract suite); the iroh version
  found in T08 pinned.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `key::node_key_persists_with_mode_0600` | created once, reloaded with the same id, file mode 0600 | 7.1 |
  | `router::unregistered_id_is_closed_with_0x10` | `rackhand/probe/1` from an unknown id closes with `UNKNOWN_PEER` | 7.3 |
  | `router::join_alpn_accepts_unregistered` | `rackhand/join/1` accepts any id | 7.3.1 |
  | `router::revoked_id_is_closed_with_0x13` | after revocation the next connection closes with `0x13` | 7.3, 7.3.4 |
  | `router::unknown_alpn_is_refused` | an ALPN that isn't served is refused | 7.3 |
  | `relays::default_config_has_no_n0_services` | no n0 relay or DNS discovery unless enabled | D51, NG10 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-net --features testing
  ```
  Expected: 6 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** the iroh API changes between 1.x minors, so it is pinned. Revert the commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-net --features testing | compile errors: crate::key, relays, testing, close_code missing |
  | 2026-11-19 | cargo nextest run -p rackhand-net --features testing | 6 passed, 0 failed (iroh pinned =1.5.0) |
  | 2026-11-19 | cargo xtask ci fast | exit 0; 33 passed; cargo deny limited to the shipped targets, unmaintained notices for direct dependencies only |

### T18: Store: schema, writer task, read pool
- **Design refs:** 7.4.1 (database, tables), 7.3.8 (`WriteCmd`, `StoreWriter`), 9 (integrity), 11 (one writer, four
  readers), 13 (refuse a newer database)
- **Goal:** the hub database opens in WAL mode with the baseline schema for every table in 7.4.1. All writes go through
  one writer task, reads use a pool of four, and a database newer than the binary is refused.
- **Depends on:** T16
- **Changes:** `crates/rackhand-store/src/{db.rs, schema.sql, writer.rs, reader.rs, ids.rs}` (ULIDs, Unix
  milliseconds); the `WriteCmd` enum from 7.3.8, with each variant's handler stubbed to `Unimplemented` until the step
  that builds its owning system.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `db::opens_in_wal_mode_with_schema_version` | `journal_mode` is `wal`, `user_version` is the baseline | 7.4.1 |
  | `db::newer_database_is_refused` | a higher `user_version` gives `DatabaseTooNew` and no write | 13 |
  | `db::every_table_in_the_design_exists` | the table list equals 7.4.1's | 7.4.1 |
  | `writer::writes_are_serialized_in_send_order` | 1 000 concurrent commands commit in queue order | 7.3.8 |
  | `writer::multi_table_command_is_one_transaction` | a command that fails on its second table leaves the first unchanged | 9 |
  | `reader::pool_has_four_read_only_connections` | a write through a reader fails | 11 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-store -E 'test(db::) | test(writer::) | test(reader::)'
  ```
  Expected: 6 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** the baseline schema is edited in place until the first release (the maintainers' rule). Revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-store -E 'test(db::) \| test(writer::) \| test(reader::)' | compile errors: unresolved crate::db and crate::writer |
  | 2026-11-19 | cargo nextest run -p rackhand-store -E 'test(db::) \| test(writer::) \| test(reader::)' | 6 passed, 0 failed: WAL and user_version 1; newer database refused untouched; 41 tables match 7.4.1; 1000 commands commit in send order; a failing second table rolls back the first; read pool of 4 refuses writes |
  | 2026-11-19 | cargo xtask ci fast | exit 0; 39 passed |

### T19: Time-series encoding and chunks
- **Design refs:** 7.4.1 (`series_chunks`, chunk rule, chunk encoding), D43, D109, S8 finding
- **Goal:** chunks encode and decode the D109 encoding without loss (integer columns at a metric's step, tick
  timestamps, the cheapest of three coders, f64 Gorilla for metrics without a step). Chunk rows are opened, appended to
  and closed by the 120-point rule and, for tier 0, the hour rule.
- **Depends on:** T18, T05
- **Changes:** `crates/rackhand-store/src/series/{mod.rs, codec.rs, step.rs, chunk.rs, query.rs}`;
  `crates/rackhand-store/tests/fixtures/s8-sample.csv.zst` (from T05).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `codec::round_trip_is_lossless` (property, 10 000 cases) | random timestamps with integer columns, and with f64 columns including NaN, infinities and repeats, decode exactly | D43, D109 |
  | `codec::cheapest_coder_is_chosen_per_column` | a constant column, a random walk and a noisy counter each pick a different coder, and each chunk is no larger than its column coded any other way | D109 |
  | `codec::bytes_per_value_on_recorded_data_within_spike_result` | the T05 sample at 15 s ticks encodes within 10% of the spike's figures: tier 0 1.04 and tier 1 (120-point min, max, avg) 0.96 bytes per value | S8, 5.2 |
  | `step::values_round_to_their_unit_step` | % and ratio to 0.01, Celsius to 0.1, `mem.*`/`swap.*`/`disk.*` bytes to whole KiB, other units to 1; a metric with no step stays f64 | D109 |
  | `step::tier0_timestamps_snap_to_tick_later_sample_wins` | samples 14.2 s and 15.4 s apart land on their ticks; two on one tick keep the later | D109 |
  | `chunk::chunk_closes_at_120_points` | the 121st point opens a new row, in every tier | 7.4.1 |
  | `chunk::tier0_chunk_closes_at_hour_boundary` | a tier 0 point in the next hour opens a new row, even at 30 points | 7.4.1 |
  | `chunk::tier1_chunk_spans_the_hour` | tier 1 points across an hour boundary stay in one open row until 120 | 7.4.1, D109 |
  | `chunk::append_to_open_chunk_preserves_points` | appending in two batches equals one batch | 7.4.1 |
  | `chunk::append_older_than_open_chunk_is_refused` | a point at or before the open row's last point is refused with `OutOfOrder` (backfill is T25's) | 7.4.1 |
  | `query::range_query_returns_points_in_order_across_chunks` | a range spanning three chunks returns sorted, deduplicated points | 7.4.1 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-store -E 'test(codec::) | test(step::) | test(chunk::) | test(query::)'
  ```
  Expected: 11 passed, 0 failed.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** None.
- **Done when:**
  - [x] New tests seen failing first
  - [x] New tests and regression suite pass
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-20 | cargo nextest run -p rackhand-store -E 'test(codec::) \| test(step::) \| test(chunk::) \| test(query::)' (before) | compile errors: `crate::series::{chunk, codec, query, step}` and `SeriesError` don't exist |
  | 2026-11-20 | same (after) | 11 passed; the T05 sample measures 1.013 (tier 0) and 0.951 (tier 1) bytes per value against the spike's 1.04 and 0.96 |
  | 2026-11-20 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 252 passed; no violations |

### T20: Audit log with hash chain and checkpoints
- **Design refs:** FR-26, 7.4.1 (`audit_log`, checkpoints), 12 (`rackhand hub audit verify`), AC39
- **Goal:** audit rows form a SHA-256 chain, verify detects any changed or missing row, and retention keeps the chain
  verifiable through checkpoint rows.
- **Depends on:** T18
- **Changes:** `crates/rackhand-hub/src/audit/{mod.rs, chain.rs, verify.rs}`; the `AppendAudit` and
  `AppendAuditCheckpoint` handlers; `rackhand hub audit verify`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `audit::chain_verifies_after_appends` | 100 appends verify | AC39 |
  | `audit::changed_row_fails_verify_naming_seq` | altering one row's data makes verify fail at that seq | AC39 |
  | `audit::deleted_middle_row_fails_verify` | the gap is detected | AC39 |
  | `audit::retention_with_checkpoint_still_verifies` | removing the oldest 50 rows after writing a checkpoint still verifies | AC39, 7.4.1 |
  | `audit::concurrent_appends_keep_one_chain` | 8 tasks appending 100 rows each give one linear chain | FR-26 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(audit::)'
  ```
  Expected: 5 passed, 0 failed.
- **Manual verification:** None.
- **Done when (in addition):** each thing FR-26 says must be audited gets an "is audited" test in the step that builds
  it (T36, T37, T55, T56, T75). AC39 is complete once T75 is done.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub -E 'test(audit::)' | compile error: unresolved super::Audit, VerifyError, verify |
  | 2026-11-19 | cargo nextest run -p rackhand-hub -E 'test(audit::)' | 5 passed, 0 failed: 100 appends verify; a changed row fails at seq 37; a deleted row is a gap 19..21; retention with a checkpoint verifies and without it fails; 8x100 concurrent appends make one chain |
  | 2026-11-19 | cargo xtask ci fast; cargo run -p rackhand -- hub audit verify --db /tmp/av.db | exit 0, 44 passed; the command prints the verified row count |

### T21: Vault
- **Design refs:** 7.4.1 (secrets at rest), 7.1 (master key as a service credential), 10, AC54, E34
- **Goal:** secrets are stored with XChaCha20-Poly1305 under a 256-bit master key kept outside the database, so the
  database file alone reveals nothing.
- **Depends on:** T18
- **Changes:** `crates/rackhand-hub/src/vault/{mod.rs, master_key.rs}` (loaded from `$CREDENTIALS_DIRECTORY`, or a
  path in tests; recovery-code encoding); the `PutSecret` handler.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `vault::put_then_get_returns_secret` | round trip | 7.4.1 |
  | `vault::database_without_master_key_reveals_nothing` | the raw database file contains none of the stored secrets' bytes; a different key fails to decrypt | AC54 |
  | `vault::nonce_is_unique_per_write` | 10 000 writes, no repeated nonce | 7.4.1 |
  | `vault::tampered_ciphertext_is_refused` | a flipped bit fails authentication | 10 |
  | `vault::recovery_code_round_trips_the_master_key` | the code shown on first run restores the same key | 7.7.1, E34 |
  | `vault::secrets_never_appear_in_debug_output` | `Debug` of a secret prints a placeholder | 10 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(vault::)'
  ```
  Expected: 6 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub -E 'test(vault::)' | compile errors: unresolved super::master_key, Secret, Vault, VaultError |
  | 2026-11-19 | cargo nextest run -p rackhand-hub -E 'test(vault::)' | 6 passed, 0 failed: round trip; database and WAL files hold no secret bytes and another key can't decrypt; 10 000 unique nonces; a flipped bit or another name fails; recovery code restores the key and a typo fails its checksum; Debug prints `redacted` |
  | 2026-11-19 | cargo xtask ci fast | exit 0 |

### T22: Probe Linux collectors
- **Design refs:** FR-1, FR-2, 7.4.2 (catalogue, exclusions, 200-series cap), 7.7.3 (`collect --once --json`), S11
  finding (memory), S6 finding (runtime)
- **Goal:** the probe produces every Linux metric in 7.4.2 from `/proc` and `/sys`, applies the exclusions and the
  series cap, and `rackhand-probe collect --once --json` prints one sample set.
- **Depends on:** T16, T06, T11
- **Changes:** `crates/rackhand-probe/src/collect/` (cpu, load, mem, swap, disk, diskio, net, uptime, temp, self use,
  services, catalogue, cap), reading from a root path: the real `/` or a fixture tree. Fixture trees in
  `tests/fixtures/proc/<case>/`: a Debian VM, an Alpine LXC, a Proxmox host with ZFS (from T11), and a host with 300
  mounts.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `collect::every_catalogue_metric_from_debian_fixture` | every Linux metric in 7.4.2 except `temp.c` is present with the right unit and labels | FR-2, AC1 |
  | `collect::rates_from_two_snapshots` | CPU busy, disk and network rates from two snapshots equal hand-computed values | FR-2 |
  | `collect::excluded_mounts_interfaces_and_devices_skipped` | tmpfs, overlay, `/run`, `veth*`, `docker*` and `loop*` are absent; `vmbr0` is present | 7.4.2 |
  | `collect::series_cap_drops_extra_and_raises_event` | the 300-mount fixture gives 200 series and one `series_cap_reached` | 7.4.2 |
  | `collect::zfs_arc_counted_as_available` | the ZFS fixture's `mem.available_pct` follows the T11 formula | S11, 7.6.1 |
  | `collect::failed_units_and_watched_services_reported` | fixture unit states map to `ServiceState` | FR-2 |
  | `collect::once_json_prints_one_sample_set` | the CLI command prints valid JSON with the catalogue names | 7.7.3 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-probe -E 'test(collect::)'
  ```
  Expected: 7 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fixtures | capture from the local lab | `debian-vm` (the Debian 12 hub VM), `alpine-lxc` (ct-test on pve8, with lxcfs), `proxmox-zfs` (pve9 with its ZFS pool): two snapshots 5 s apart of /proc, thermal zones, statvfs per mount and the systemd unit lists. Synthetic `rates` (hand-checkable counters, the exclusion cases, unit states) and `mounts-300` |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-probe -E 'test(collect::)' | compile errors: unresolved `super::{Collection, Config, RootHost, SelfUse, collect}` and `rackhand_proto` |
  | 2026-11-19 | cargo nextest run -p rackhand-probe -E 'test(collect::)' | 7 passed, 0 failed |
  | 2026-11-19 real system | rackhand-probe collect --once --json (WSL) | 130 series of 33 metrics; showed snap mounts (`fuse.snapfuse`) and a CD image (`iso9660`) at 100%. Added both to the synthetic fixture, the exclusion test failed, then they were excluded with the other image filesystems; 7 passed |
  | 2026-11-19 | cargo xtask ci fast | exit 0 (nextest 159 passed) |

### T23: Probe buffer, epochs and label table
- **Design refs:** FR-3, 7.3.2 (epoch and seq, label tables), 7.4.1 (probe buffer), D83, D94, E2, E3
- **Goal:** the probe buffers reports in 4 MB segments up to 64 MB or 24 hours, drops the oldest first and records the
  dropped range, chooses epochs, and keeps each epoch's label table on disk.
- **Depends on:** T16
- **Changes:** `crates/rackhand-probe/src/buffer/{segments.rs, epoch.rs, labels.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `buffer::reports_survive_restart_in_order` | append, reopen, read back in seq order | FR-3 |
  | `buffer::full_buffer_drops_oldest_and_records_range` | past 64 MB the oldest segment is gone and `DataDropped{from,to}` is queued | E2, FR-3 |
  | `buffer::reports_older_than_24h_are_dropped` | the age limit, with an injected clock | FR-3 |
  | `buffer::ack_ranges_delete_only_inside_ranges` | acking `[1..5, 8..9]` keeps 6, 7 and 10 | 7.3.2 |
  | `epoch::empty_buffer_starts_new_random_epoch` | seq restarts at 1 | E3 |
  | `epoch::hub_ahead_starts_new_epoch_even_with_backlog` | `received` covering the next seq starts a new epoch | E3, AC48 |
  | `labels::ids_never_reused_within_epoch` | a label set removed and added again gets a new id | D94 |
  | `labels::table_near_4096_rolls_epoch_when_buffer_empty` | at the limit, a new epoch starts once the buffer drains | D94 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-probe -E 'test(buffer::) | test(epoch::) | test(labels::)'
  ```
  Expected: 8 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-probe -E 'test(buffer::) \| test(epoch::) \| test(labels::)' | compile errors: unresolved super::epoch, labels, segments |
  | 2026-11-19 | cargo nextest run -p rackhand-probe -E 'test(buffer::) \| test(epoch::) \| test(labels::)' | 8 passed, 0 failed |
  | 2026-11-19 | cargo xtask ci fast | exit 0 |

### T24: Bus
- **Design refs:** 7.3.8 (bus delivery), D102
- **Goal:** each consumer has its own bounded queue of 1024. `ReportIngested` notices coalesce per machine and never
  wait. Other events wait for space, except `JobFinished` sent by Actions, which never waits.
- **Depends on:** T18
- **Changes:** `crates/rackhand-hub/src/bus/{mod.rs, coalesce.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `bus::report_notices_coalesce_per_machine` | 10 000 notices for 3 machines leave 3 pending | D102 |
  | `bus::notice_send_never_waits_on_stalled_consumer` | with the consumer stalled, 10 000 sends finish within 50 ms | D102, AC66 |
  | `bus::state_events_are_never_dropped` | with a full queue the sender waits and every event arrives | 7.3.8 |
  | `bus::job_finished_from_actions_does_not_wait` | a full Incidents queue doesn't block Actions; reconciliation picks the event up | 7.3.8 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(bus::)'
  ```
  Expected: 4 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub -E 'test(bus::)' | compile error: unresolved Bus, BusEvent, Delivery, JobOutcome, MachineId |
  | 2026-11-19 | cargo nextest run -p rackhand-hub -E 'test(bus::)' | 4 passed, 0 failed: 10 000 notices leave 3; 10 000 sends to a stalled consumer under 50 ms; 3000 state events with a 1024 queue all arrive; JobFinished never waits and a full queue records it for reconciliation |
  | 2026-11-19 | cargo xtask ci fast | exit 0 |
  | 2026-11-19 correction | cargo xtask ci fast | the run recorded for 208b422 had failed: clippy `field name is never read` (an exit status read from the wrong shell showed 0). Fixed in the next commit; fast tier exit 0, 62 passed |

### T25: Ingest: staging, acks, compaction, recent window, clock
- **Design refs:** 7.3.2 (durability, replay limits, clock), 7.4.1 (recent window, compaction), 7.3.8
  (`Ingest::raise_event`), D100, E1, E4, E32
- **Goal:** Ingest stages each report before acking it and compacts staged points into open chunks every 5 minutes and
  on shutdown. It keeps a 35-minute recent window, corrects sample times by each machine's clock offset, limits replay,
  and is the only writer of `events`.
- **Depends on:** T18, T19, T24
- **Changes:** `crates/rackhand-hub/src/ingest/{staging.rs, compact.rs, window.rs, clock.rs, replay_limits.rs,
  events.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `ingest::ack_follows_commit` | the ack resolves only after the writer reports the staging commit | 7.3.2 |
  | `ingest::compaction_moves_staged_points_into_open_chunks` | the points end up in chunks and staging is empty, in one transaction per machine | 7.3.2, 11 |
  | `ingest::startup_compacts_leftover_staging` | rows left by a crash are compacted on start | E44 |
  | `ingest::recent_window_keeps_35_minutes` | older samples leave the window | D100 |
  | `ingest::window_rebuilt_from_staging_and_tier0_on_start` | after a restart the window holds the last 35 minutes | D100, AC66 |
  | `ingest::clock_offset_is_median_of_last_20_live_reports` | samples from a probe 3 h ahead are placed at receive time | E4 |
  | `ingest::offset_over_30s_raises_clock_skew` | one `clock_skew` warning | E4 |
  | `ingest::replay_over_limits_stops_reading_stream2` | at 2 MB/s per probe, 20 MB/s across the hub or 512 MB of staging, stream 2 reads pause and stream 1 continues | 7.3.2 |
  | `ingest::backfill_into_rolled_up_range_marks_dirty` | a dirty range is recorded | 7.3.2 |
  | `ingest::replayed_sample_older_than_10_min_flagged_history_only` | the sample carries the no-threshold flag | E1, AC2 |
  | `ingest::disk_below_2_percent_stops_replay_and_new_jobs` | at an injected 1.9% free, stream 2 stops, live ingest continues and a critical event is raised | E32 |
  | `ingest::latest_report_facts_kept` | the newest live report's services and containers, and the last update summary sent, are kept; a replayed report changes nothing | 7.3.6, 7.3.2 |
  | `ingest::steady_state_compaction_marks_nothing_dirty` (added after review) | live data compacted after its minute rollup marks nothing dirty, and rows follow the chunk rule | 7.3.2, D109 |

  Carried in from T74:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `mcp::get_machine_facts_from_latest_report` (carried in from T74) | `get_machine`'s services, containers and updates come from the machine's latest report through `Observations` | 7.3.6 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(ingest::)'
  cargo nextest run -p rackhand-hub --test mcp_contract -E 'test(mcp::)'
  ```
  Expected: 12 passed, 0 failed; 1 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-20 | cargo nextest run -p rackhand-hub -E 'test(ingest::)' (before) | compile errors: `Ingest`, `Receipt`, `Stream`, `ReplayLimits`, `SeriesId`, `Tier` not found |
  | 2026-11-20 | same (after) | 12 passed (the clock test's first version expected the window's last sample at receive time, but the one report with a wrong clock is rightly placed 15 minutes on; the test now finds each report's sample by value) |
  | 2026-11-20 | cargo nextest run -p rackhand-hub --test mcp_contract -E 'test(mcp::)' | before `LatestFacts::{services,containers,updates}_json`: compile errors; after: 1 passed (`get_machine` shows the services, containers and updates of the machine's latest report through `Observations`) |
  | 2026-11-20 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 265 passed; no violations |
  | 2026-11-20 (review) | cargo nextest run -p rackhand-hub -E 'test(steady_state)' | a review found compaction marked every point dirty once minute rollups had run (they run ahead of the 5-minute compaction), which would recompute and add rows every hour against the D109 budget; the new test failed with the old marking (2 dirty ranges), and compaction now marks only points that arrived after their minute ended: passes |

### T26: Probe contract `rackhand/probe/1`
- **Design refs:** 7.3.2 (all bullets), FR-3, D83, D94, E3, E5, E52, E53, AC48, AC62
- **Goal:** a contract suite over real endpoints proves the probe client and the hub's probe server agree on Hello,
  Welcome, range acks, `DataDropped`, live and replay streams, label tables, rate limits and error codes.
- **Depends on:** T17, T23, T25
- **Changes:** `crates/rackhand-probe/src/link/` (client); `crates/rackhand-hub/src/ingest/probe_server.rs`;
  `crates/rackhand-hub/tests/probe_contract.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `probe_contract::hello_welcome_ack_round_trip` | a report is acked only after it is committed to staging | 7.3.2 |
  | `probe_contract::duplicate_seq_is_dropped` | resending an acked seq stores nothing new | 7.3.2 |
  | `probe_contract::live_and_replay_streams_interleave` | stream 1 and stream 2 seqs in any order are each stored once | 7.3.2, E1 |
  | `probe_contract::rollback_epoch_accepted_at_once` | when the hub is ahead of the probe's epoch, the probe starts a new epoch and its reports are acked | AC48, E3 |
  | `probe_contract::label_set_first_seen_during_outage_resolves` | after a reconnect, a live report using a label set it defines in `label_sets` stores under the right labels | AC62 |
  | `probe_contract::unknown_label_id_drops_sample_keeps_report` | one bad sample is dropped and counted in `probe.unknown_labels`; the rest are stored | E52, AC62 |
  | `probe_contract::oversized_decompression_closes_0x15` | nothing staged | E53, AC62 |
  | `probe_contract::data_dropped_closes_gap_and_records_event` | `probe.data_gap` names the range | E2, AC3 |
  | `probe_contract::more_than_64_ranges_closes_oldest_gap` | the 65th range closes the oldest gap with `probe.data_gap`; later reports for that gap are dropped | 7.3.2 |
  | `probe_contract::second_probe_with_same_machine_id_gets_0x11` | identity mismatch and a critical `probe.identity_conflict` | E5 |
  | `probe_contract::stream1_over_rate_closes_0x14` | a burst of 10 is allowed; more than 1 a second after it closes | 7.3.2 |
  | `probe_contract::revoked_probe_gets_0x13_and_exits_3` | the probe process exits with code 3 | 7.3.2 |
  | `probe_contract::unsupported_version_keeps_buffering` | on `0x12` the probe keeps its reports and retries hourly (injected clock) | 7.3.2 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub --test probe_contract
  ```
  Expected: 13 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-20 | cargo nextest run -p rackhand-hub --test probe_contract (before) | compile errors: `rackhand_probe::link` and `rackhand_hub::ingest::probe_server` don't exist |
  | 2026-11-20 | same (after) | first run 11 passed, 2 failed: the first `probe.unknown_labels` check overflowed (`i64::MIN` as "never reported"), a bug the ingest unit tests didn't reach; fixed with a saturating subtraction; then 13 passed |
  | 2026-11-20 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 278 passed; no violations |

### T27: Rollups and retention
- **Design refs:** FR-7, 7.4.1 (rollups, retention), AC4, AC69 (series tables), S8 finding
- **Goal:** tier-1 and tier-2 rollups hold the min, max and avg of their source, dirty ranges are recomputed, and
  retention removes data older than each tier's limit in batches of 10 000 rows with 50 ms pauses.
- **Depends on:** T19, T25, T05
- **Changes:** `crates/rackhand-store/src/{rollup.rs, retention.rs}`; the `Rollup`, `RetentionBatch` and
  `MarkRollupDirty` handlers; a retention-rule registry that later tables register into (completed in T98).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `rollup::tier1_equals_min_max_avg_of_minute` | for random data, each tier-1 point equals its source minute's min, max and avg | AC4 |
  | `rollup::tier2_equals_min_max_avg_of_hour_of_tier1` | the same for hours | AC4 |
  | `rollup::dirty_range_is_recomputed` | a backfilled minute changes its tier-1 point | 7.3.2 |
  | `retention::each_tier_removes_only_older_than_limit` | points at the limit minus 1 ms stay; points at the limit plus 1 ms go | AC4 |
  | `retention::deletes_in_batches_with_pauses` | 25 000 old rows take 3 batches with 2 pauses (injected sleeper) | 7.4.1 |
  | `retention::registry_lists_a_rule_for_every_growing_table` | every table created so far has a rule or is listed as fixed-size | AC69 |
  | `rollup::minute_rollups_from_the_window_are_stored` | min, max and avg points handed over from the recent window land in tier 1 under the series' metric key | 7.4.1 |
  | `ingest::minute_rollup_from_window` | a minute of the window becomes one tier 1 point; series reads pick tier 0 with the window for short ranges and tier 1's avg for longer ones | 7.4.1 |

  Carried in from T74:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `mcp::get_vitals_reads_the_series_store` (carried in from T74) | `get_vitals` reads the stored series through `Observations`, choosing the tier for the range, at most 2000 points | 7.3.6 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-store -E 'test(rollup::) | test(retention::)'
  cargo nextest run -p rackhand-hub -E 'test(ingest::minute_rollup) | test(mcp::get_vitals)'
  ```
  Expected: 7 passed, 0 failed; 2 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-20 | cargo nextest run -p rackhand-store -E 'test(rollup::) \| test(retention::)' (before) | compile errors: `crate::rollup::{rollup, put_rollups, recompute_dirty, RollupSeries}` and `crate::retention::{rules, run, Sleeper, ...}` don't exist |
  | 2026-11-20 | same (after) | 7 passed |
  | 2026-11-20 | cargo nextest run -p rackhand-hub -E 'test(ingest::minute_rollup) \| test(mcp::get_vitals)' | before `ingest/series.rs`: compile errors (`rollup_minute`, `series` not found); after: 2 passed (`get_vitals` reads tier 0 and the window for half an hour, tier 1 for ten days and tier 2 for fifty, at most 2000 points) |
  | 2026-11-20 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 287 passed; no violations |

### T28: Detect: threshold rules
- **Design refs:** 7.6.1 (matching, clearing, clear margin, table, example), FR-8, D95, E58, AC65
- **Goal:** threshold rules match and clear by counting samples at the machine's own interval, with the 80% presence
  rule, the 4-interval minimum and the clear margin. The 7.6.1 example gives the stated timeline.
- **Depends on:** T01
- **Changes:** `crates/rackhand-detect/src/{threshold.rs, rules.rs, samples.rs}`. Pure functions; the input is a slice
  of corrected samples plus the interval.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `threshold::worked_example_opens_warning_at_5_and_critical_at_27_and_resolves` | the `/var` example in 7.6.1 | FR-8 |
  | `threshold::needs_80_percent_of_expected_samples` | 79% present doesn't match; 80% does | D95 |
  | `threshold::duration_below_4_intervals_raised_to_4` | at 300 s a 5-minute rule needs 4 matching samples | E58, AC65 |
  | `threshold::clear_needs_2_samples_past_margin` | one sample under 83% doesn't clear; two do | D95, AC65 |
  | `threshold::flapping_between_84_and_86_stays_one_incident` | the AC65 sequence never clears | AC65 |
  | `threshold::no_new_sample_changes_nothing` | two evaluations with no new sample give the same state | D95 |
  | `threshold::same_rule_same_result_at_5_15_and_300_seconds` | table-driven over the default rules | D95 |
  | `threshold::every_default_rule_in_table_present` | the defaults equal the 7.6.1 table | 7.6.1 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-detect -E 'test(threshold::)'
  ```
  Expected: 8 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-detect -E 'test(threshold::)' | compile errors: unresolved imports `crate::rules`, `crate::samples`, `crate::threshold` |
  | 2026-11-19 first run | same | 7 passed, 1 failed: the worked example opened the warning at 3.75 min, because the test had no sample before minute 0 and 16 of 20 samples are enough. Test corrected to the design's example (a normal sample at minute 0, each sample covering the interval that ends at its time); the implementation is unchanged |
  | 2026-11-19 | cargo nextest run -p rackhand-detect -E 'test(threshold::)' | 8 passed, 0 failed. The 80% test uses 15 of 20 (75%) and 16 of 20, since 79% isn't reachable at 20 expected samples |
  | 2026-11-19 | cargo xtask ci fast | exit 0 (fmt, clippy, arch-check, nextest 70 passed) |

### T29: Detect: forecasts
- **Design refs:** 7.6.2, G2, AC6
- **Goal:** the disk-fill, memory-growth and certificate-expiry forecasts give the stated severities, and the 7.6.2
  example gives a warning with an ETA of 62.5 hours.
- **Depends on:** T28
- **Changes:** `crates/rackhand-detect/src/forecast.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `forecast::worked_example_warns_with_eta_62_5_hours` | the 400 of 500 GB example | AC6 |
  | `forecast::fit_below_r2_0_7_is_ignored` | no alert | 7.6.2 |
  | `forecast::shortest_eta_wins_and_critical_under_24h` | of two fits, the shorter ETA decides | 7.6.2 |
  | `forecast::memory_growth_needs_24h_since_boot` | 23 hours of data gives nothing | 7.6.2 |
  | `forecast::memory_growth_warns_over_2_points_per_day_reaching_95_in_7_days` | boundary cases | 7.6.2 |
  | `forecast::cert_expiry_warning_14_critical_3_days` | boundaries | 7.6.2, AC10 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-detect -E 'test(forecast::)'
  ```
  Expected: 6 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-detect -E 'test(forecast::)' | compile error: unresolved import `crate::forecast` |
  | 2026-11-19 | cargo nextest run -p rackhand-detect -E 'test(forecast::)' | 6 passed, 0 failed |
  | 2026-11-19 | cargo xtask ci fast | exit 0 (fmt, clippy, arch-check, nextest 76 passed) |

### T30: Detect: silence
- **Design refs:** 7.6.3, 7.5.1 (Silent), D95, E38, E58, AC8, AC65
- **Goal:** silence rules for machines, `expected_offline` machines, agentless machines, peer hubs and operators give
  the 7.6.3 severities, scaled to the probe interval, with the suppressions listed there.
- **Depends on:** T28
- **Changes:** `crates/rackhand-detect/src/silence.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `silence::machine_warning_at_max_60s_or_4_intervals` | 60 s at a 15 s interval; 20 minutes at 300 s | AC8, AC65, E58 |
  | `silence::machine_critical_at_max_5min_or_20_intervals` | boundaries | 7.6.3 |
  | `silence::expected_offline_gives_info_only` | no warning | E38, AC8 |
  | `silence::agentless_2_and_5_polls` | boundaries | 7.6.3, AC11 |
  | `silence::peer_2_and_10_minutes_and_interval_scaling` | at a 120 s summary interval, silent at 6 minutes | 7.6.3, 7.8.1 |
  | `silence::operator_warning_only_after_10_minutes` | never critical | 7.6.3 |
  | `silence::suppressed_in_maintenance_reboot_job_and_first_3_minutes` | three suppression cases | 7.6.3, E44 |
  | `silence::first_report_clears` | one report resolves | 7.5.2 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-detect -E 'test(silence::)'
  ```
  Expected: 8 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-detect -E 'test(silence::)' | compile error: unresolved import `crate::silence` |
  | 2026-11-19 | cargo nextest run -p rackhand-detect -E 'test(silence::)' | 8 passed, 0 failed |
  | 2026-11-19 | cargo xtask ci fast | exit 0 (fmt, clippy, arch-check, nextest 84 passed) |

### T31: Detect: baselines and counted rules
- **Design refs:** 7.6.4, 7.6.1 (service, restart, check and update rows), AC7
- **Goal:** baseline buckets learn, seed, freeze and fire as 7.6.4 says, and the worked example opens at 14:35. The
  counted rules (watched services, container restarts, failing checks, pending security updates) fire at their counts.
- **Depends on:** T28
- **Changes:** `crates/rackhand-detect/src/{baseline.rs, counted.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `baseline::worked_example_warns_at_14_35_and_freezes` | the `build-vm` example | AC7 |
  | `baseline::first_value_seeds_mean_variance_zero_then_weight_0_1` | the update rule | 7.6.4 |
  | `baseline::hour_of_week_used_when_n_at_least_3_else_hour_of_day` | bucket selection | 7.6.4 |
  | `baseline::std_dev_floor_prevents_noise_alerts` | a flat bucket with small noise doesn't fire | 7.6.4 |
  | `baseline::no_alerts_during_7_day_learning` | silent on day 6; can fire on day 7 | 7.6.4 |
  | `baseline::unfreezes_after_2_hours_without_deviation` | boundary | 7.6.4 |
  | `baseline::never_critical` | a sustained 40-sigma deviation stays a warning | 7.6.4 |
  | `counted::service_not_active_2_and_4_reports` | thresholds | 7.6.1 |
  | `counted::container_restarts_3_and_10_in_10_minutes` | thresholds | 7.6.1 |
  | `counted::check_failing_2_and_4_in_a_row` | thresholds | 7.6.1, AC10 |
  | `counted::security_updates_older_than_7_and_14_days` | thresholds | 7.6.1 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-detect -E 'test(baseline::) | test(counted::)'
  ```
  Expected: 11 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-detect -E 'test(baseline::) \\| test(counted::)' | compile errors: unresolved imports `crate::baseline`, `crate::counted`. Before implementing, three test mistakes were fixed: the Tuesday constant was a Monday in May, `never_critical` sat exactly on the 4-sigma line, and `hourly_update` takes the current time (freezing is checked against now, not the bucket's hour) |
  | 2026-11-19 | cargo nextest run -p rackhand-detect -E 'test(baseline::) \\| test(counted::)' | 11 passed, 0 failed |
  | 2026-11-19 | cargo xtask ci fast | exit 0 (fmt, clippy, arch-check, nextest 95 passed) |

### T32: Incidents: lifecycle and evaluation
- **Design refs:** FR-8, 7.5.2 (states, condition and event incidents, acknowledge, silences), 7.3.8 (reconciliation),
  D95, D100, D102, AC66
- **Goal:** Incidents evaluates the rules every 15 s over the recent window, and opens, updates, reopens and resolves
  incidents per 7.5.2. It merges event incidents for 24 hours, honors silences and acknowledgements, and reconciles
  with finished jobs every minute. Routing beyond `human` comes in T57 and T78.
- **Depends on:** T25, T24, T28 to T31
- **Changes:** `crates/rackhand-hub/src/incidents/{lifecycle.rs, evaluate.rs, dedupe.rs, silences.rs, reconcile.rs}`;
  the `UpsertIncident`, `AppendIncidentEvent` and `PutSilence` handlers.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `incidents::rule_fire_opens_and_clear_resolves` | lifecycle | FR-8 |
  | `incidents::same_dedupe_key_within_30_min_reopens` | reopening keeps the history | 7.5.2 |
  | `incidents::severity_rise_and_fall_without_callout_on_fall` | a fall asks for no callout | 7.5.2 |
  | `incidents::event_incident_merges_for_24_hours` | a second event within 24 hours is appended | 7.5.2 |
  | `incidents::info_events_never_open_incidents` | none opens | 7.5.2 |
  | `incidents::silence_suppresses_new_incident_until_end` | machine and tag silences, at most 30 days | 7.5.2 |
  | `incidents::acknowledge_keeps_state` | the state is unchanged and the ack fields are set | 7.5.2 |
  | `incidents::rule_mid_duration_survives_restart` | 20 minutes into a 30-minute rule, a restart, and the incident still opens at 30 | AC66, D100 |
  | `incidents::reconcile_advances_incident_whose_job_finished` | with no `JobFinished` event, the minute task advances it | 7.3.8 |
  | `incidents::stale_samples_do_not_open_threshold_incidents` | samples flagged as older than 10 minutes feed history only | E1, AC2 |
  | `incidents::condition_resolves_after_restart` (added after review) | an incident open across a restart resolves when its condition clears | 7.5.2, E44 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(incidents::)'
  ```
  Expected: 10 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-20 | cargo nextest run -p rackhand-detect -E 'test(threshold::)' | new `severity_falls_when_only_the_lower_level_matches` failed first (a critical rule never fell back to warning: T28 kept the highest severity seen); detect now follows the highest matching level while active; 34 detect tests pass |
  | 2026-11-20 | cargo nextest run -p rackhand-hub -E 'test(incidents::)' (before) | compile errors: `Incidents`, `Silence`, `SilenceTarget`, `State`, `IncidentsError` not found |
  | 2026-11-20 | same (after) | first run 7 passed, 3 failed: two timing tests assumed a rule fires only after its full duration on a fresh series, but 7.6.1 matches at 80% of the expected samples, so they now start with normal readings; and a second unresolved incident per dedupe key broke the store's unique index (one unresolved incident per key), so event incidents merge while unresolved (below). Then 10 passed |
  | 2026-11-20 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0 (after factoring one tuple into a struct); fast 298 passed; no violations |
  | 2026-11-20 (review) | cargo nextest run -p rackhand-hub -E 'test(condition_resolves_after_restart)' | failed first (rule states start empty after a restart, so an open incident never saw its condition clear); open condition incidents now seed their rule states when Incidents starts: passes. The review also found that forecasts, baselines, machine silence and the counted rules were wired by no step: added as T32b |

### T33: Notify: Discord, SMTP, grouping, retries
- **Design refs:** FR-11, 7.3.9, 7.6.7, E31, AC5 (callout timing), AC52
- **Goal:** callouts go to Discord webhooks and SMTP in the 7.3.9 formats:
  - criticals at once, and warnings grouped per site for 5 minutes;
  - re-sent when severity rises, or every 6 hours while unacknowledged;
  - a resolution message for every incident that was called out;
  - retries at 1, 5 and 15 minutes, after which a failing notifier raises `notifier_failed`.
- **Depends on:** T32
- **Changes:** `crates/rackhand-hub/src/notify/{discord.rs, smtp.rs, grouping.rs, retry.rs}`; test fakes: a `wiremock`
  Discord endpoint and an in-process SMTP receiver (`tests/support/smtp_sink.rs`).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `notify::discord_payload_matches_format` | username, embed fields, colors, a description of at most 2000 characters, the dashboard URL when set | 7.3.9 |
  | `notify::discord_429_retry_after_respected` | the next attempt waits `retry_after` | 7.3.9 |
  | `notify::smtp_subject_and_multipart_body` | subject `[Rackhand] CRITICAL site/machine: title`, with text and HTML parts | 7.3.9 |
  | `notify::critical_sent_immediately_warnings_grouped_5_min` | injected clock: one critical message at t+0 and one grouped warning message at t+5 min | 7.6.7, AC5 |
  | `notify::resent_on_rise_and_every_6h_unacked_and_not_before` | nothing at 5 h 59 min, one at 6 h; acknowledging stops it | AC52 |
  | `notify::resolution_sent_for_called_out_incidents_only` | info incidents get none | 7.6.7 |
  | `notify::retries_1_5_15_then_failed_raises_notifier_failed` | `notifier_failed` is also sent through the other notifier | E31 |
  | `notify::callouts_carry_no_secrets_or_command_output` | a callout built from an incident with job output contains none of it | 7.3.9 |
  | `notify::notify_step_sends_through_every_notifier` | `Notify::send_text` (the runbook step's message) goes through every notifier | 7.8.7 |
  | `notify::smtp_header_injection_stripped` (added after review) | CR and LF in a title (a machine-reported subject) can't start another mail header | 7.3.9, 10 |

  Carried in from T55 (the Executor passes these step kinds to the system that owns them; until then they fail `<kind>_unavailable`):
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::executor::notify_step_sends_message` | a runbook `notify` step sends its message through Notify and the step succeeds; a failed send fails the step | 7.8.7 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(notify::)'
  cargo nextest run -p rackhand-it -E 'test(notify_step)'
  ```
  Expected: 9 passed, 0 failed; 1 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-20 | cargo nextest run -p rackhand-hub -E 'test(notify::)' (before) | compile errors: `Notify`, `Transport`, `Message`, `MessageKind`, `SendError`, `discord`, `smtp` not found |
  | 2026-11-20 | same (after) | first run 7 passed, 1 failed, 1 hung: the ack helper upserted a partial incident row (NOT NULL), now an UPDATE as `acknowledge` does; and the warning group loop held the state lock across its sends (a deadlock the grouping test caught), now taken out first. Then 9 passed |
  | 2026-11-20 | cargo nextest run -p rackhand-it -E 'test(notify_step)' | carried from T55: before, the step failed `notify_unavailable` and the test didn't compile (no `notify` types); after, 1 passed (a `notify` step succeeds through Notify; a failed send fails it) |
  | 2026-11-20 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0 (a test helper's arguments grouped for clippy); fast 307 passed; no violations |
  | 2026-11-20 (review) | cargo nextest run -p rackhand-hub -E 'test(smtp_header_injection)' | failed first (a subject with CR LF added a `Bcc:` header); header values are now kept on one line: passes |
  | 2026-11-20 | cargo deny check; cargo audit; cargo xtask ci it | advisories, bans, licenses, sources ok; 2 allowed warnings; it 22 passed (the new notify step test among them) |

### T32b: Incidents: forecasts, baselines, machine silence and counted rules
- **Design refs:** 7.6.1 (counted rows), 7.6.2 (forecasts), 7.6.3 (silence), 7.6.4 (baselines), 7.5.2 (clearing counts:
  2 recomputations for a forecast or baseline, the first report for silence, the rule's own count for counted rules),
  AC6, AC7, AC8, E38
- **Goal:** Incidents evaluates every rule of 7.6, not only thresholds: disk-fill and memory-growth forecasts from tiers
  1 and 2, baselines from `baseline_buckets` (updated hourly from tier 2), machine silence, and the counted rules
  (watched services, container restarts, security updates). Added after review: no other step wired these.
- **Depends on:** T32, T27, T29 to T31
- **Changes:** `crates/rackhand-hub/src/incidents/{forecasts.rs, baselines.rs, machine_silence.rs, counted.rs}`; Ingest
  keeps per-service and per-container report counts; the `UpdateBaselines` handler.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `incidents::disk_fill_forecast_warns_with_eta` | tier 1 and tier 2 data filling a disk open a warning naming the ETA | 7.6.2, AC6 |
  | `incidents::forecast_clears_after_2_recomputations` | one recomputation under the line isn't enough; two resolve it | 7.5.2 |
  | `incidents::baseline_deviation_opens_and_clears` | a value far outside the learned band opens a warning; 2 samples back inside clear it | 7.6.4, AC7 |
  | `incidents::silent_machine_warns_after_60s_and_clears_on_report` | no report for 60 s (at most 4 intervals) opens `machine.silent`; the first report resolves it | 7.6.3, AC8 |
  | `incidents::expected_offline_is_info_only` | a machine marked expected offline gets no warning | E38 |
  | `incidents::watched_service_not_active_2_and_4_reports` | warning after 2 reports, critical after 4, resolved when active again | 7.6.1 |
  | `incidents::container_restarts_over_3_in_10_min` | 4 restarts in 10 minutes warn; 11 are critical | 7.6.1 |
  | `incidents::security_updates_older_than_7_days` | pending security updates first seen 8 days ago warn; 15 days, critical | 7.6.1 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(incidents::)'
  ```
  Expected: 19 passed, 0 failed.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** None.
- **Done when:**
  - [x] New tests seen failing first
  - [x] New tests and regression suite pass
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-20 | cargo nextest run -p rackhand-hub -E 'test(incidents::)' (before) | compile errors: `evaluate_forecasts`, `evaluate_baselines`, `baseline_hourly`, `set_started` not found |
  | 2026-11-20 | same (after) | first run 18 passed, 1 failed: `event_incident_merges_for_24_hours` runs past the real clock, so machine silence (now evaluated) fired for a machine that never reports; the incident tests now keep silence in its start-up grace unless a test sets the start. Then 19 passed |
  | 2026-11-20 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0 (a row tuple factored into a struct); fast 318 passed; no violations |

### T34: Scheduler and windows
- **Design refs:** 7.2 (Scheduler), 7.5.3 step 1, the `windows` table, E46, AC20 (maintenance window part)
- **Goal:** the Scheduler fires daily and weekly windows in each site's timezone, runs a nonexistent daylight-saving
  time at the next valid minute and a repeated one once, tracks maintenance windows, and drives the periodic tasks
  listed in 7.2.
- **Depends on:** T24
- **Changes:** `crates/rackhand-hub/src/scheduler/{rrule.rs, windows.rs, tasks.rs}`; the `PutScheduleState` and
  `PutWindow` handlers.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `scheduler::daily_window_in_site_timezone` | 04:00 in a non-UTC zone fires at the right instant | 7.5.3 |
  | `scheduler::spring_forward_runs_at_next_valid_minute` | 02:30 on a spring-forward day runs at 03:00 | E46 |
  | `scheduler::fall_back_repeated_time_runs_once` | 01:30 on a fall-back day runs once | E46 |
  | `scheduler::maintenance_window_active_for_machine_and_tag` | membership by machine id and by tag | AC20 |
  | `scheduler::state_survives_restart_without_double_firing` | `schedule_state` prevents a second run | 7.2 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(scheduler::)'
  ```
  Expected: 5 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub -E 'test(scheduler::)' | compile errors: unresolved imports `super::rrule`, `super::tasks`, `super::windows` |
  | 2026-11-19 | cargo nextest run -p rackhand-hub -E 'test(scheduler::)' | 5 passed, 0 failed |
  | 2026-11-19 | cargo xtask ci fast; cargo deny check | exit 0 (nextest 100 passed); advisories, bans, licenses, sources ok (jiff 0.2.46, MIT or Unlicense) |

### T35: Join contract and Registry
- **Design refs:** 7.3.1, 7.3.12 (enrollment, access level change tokens), FR-21, D27, D62, D88, D89, E7, AC36, AC59
- **Goal:** one-time tokens and invites of each kind join machines (managed or monitor, local or remote), devices,
  operators and peers, with the hashing, expiry, single use, kind binding, rate limit and error codes in 7.3.1.
- **Depends on:** T17, T18, T21
- **Changes:** `crates/rackhand-hub/src/registry/{tokens.rs, join_server.rs, machines.rs, devices.rs, operators.rs,
  peers.rs}`; `crates/rackhand-hub/tests/join_contract.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `join_contract::machine_managed_join_returns_managed_setup` | machine id, config, keys, sudoers and the signed command list | 7.3.1 |
  | `join_contract::machine_monitor_join_has_no_managed_setup_or_host_keys` | `managed` is absent | D88, D89 |
  | `join_contract::role_hub_gets_no_assistant_key` | `assistant_pubkey` is absent | D62 |
  | `join_contract::access_mismatch_fails_invalid` | a managed token used with `Monitor` fails with `invalid` | 7.3.1 |
  | `join_contract::used_expired_and_wrong_kind_tokens_refused` | `used`, `expired`, `wrong_kind` | E7, AC36 |
  | `join_contract::device_operator_and_peer_invites_join` | each returns its response and registers the id for its ALPNs | AC36, FR-21 |
  | `join_contract::peer_with_known_site_name_fails` | `site_name_taken` | 7.3.1 |
  | `join_contract::eleven_failures_per_minute_rate_limited` | the 11th failure in a minute gets `rate_limited` | 7.3.1 |
  | `join_contract::level_change_token_keeps_machine_id` | the join keeps the machine's id and history | 7.3.12, AC59 |
  | `registry::tokens_stored_hashed_never_plain` | no token bytes in the database | 7.3.1 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub --test join_contract && cargo nextest run -p rackhand-hub -E 'test(registry::)'
  ```
  Expected: 9 passed, then 1 passed; 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub --test join_contract | compile errors: unresolved imports `rackhand_hub::registry::{Registry, join_server, machines, tokens}` |
  | 2026-11-19 | cargo nextest run -p rackhand-hub --test join_contract && cargo nextest run -p rackhand-hub -E 'test(registry::)' | 9 passed, then 1 passed; 0 failed. The contract runs over real endpoints and a local relay; the rate limit is tested on the handler with explicit times and addresses; a two-join race on one token gives one join and one `used`; the level change keeps the machine's window and tags; the hashed-token test scans `hub.db` and `hub.db-wal` |
  | 2026-11-19 | cargo xtask ci fast | exit 0 (fmt, clippy, arch-check, nextest 111 passed) |
  | 2026-11-19 fix | cargo nextest run -p rackhand-hub --test join_contract | added: a fresh `Registry::load` on the joined tables keeps admission for the machine, device, operator and peer. 9 passed |

### T36: Web foundation and first run
- **Design refs:** 7.7.1 (stack, first-run page), 7.7.2 (sessions, cookies, roles), 10 (CSRF, CSP, escaping), D9, D49
- **Goal:** the dashboard serves HTTPS on 8443 with a generated self-signed certificate, a strict CSP, CSRF tokens and
  auto-escaping templates. It has the first-run page (admin, site, timezone, master-key recovery code, outside sources)
  and a permission layer enforcing the 7.7.2 matrix.
- **Depends on:** T18, T20, T21
- **Changes:** `crates/rackhand-hub/src/web/{server.rs, tls.rs, csrf.rs, csp.rs, perms.rs, pages/first_run.rs}`;
  `templates/`; `static/vendor/` (htmx and uPlot at pinned versions, with `static/vendor/SHA256SUMS`).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `web::first_run_shown_until_admin_exists` | every route redirects to first run before an admin exists, never after | 7.7.1 |
  | `web::first_run_shows_recovery_code_once` | the code appears once and not on reload | 7.7.1 |
  | `web::post_without_csrf_token_is_403` | on every state-changing route | 10 |
  | `web::csp_and_cookie_flags_set` | a `Content-Security-Policy` without `unsafe-inline`; cookies `Secure; HttpOnly; SameSite=Strict` | 10, 7.7.2 |
  | `web::template_output_is_escaped` | a machine named `<script>` renders escaped | 10 |
  | `web::permission_matrix_enforced_for_each_role` | table-driven over the 7.7.2 rows: allowed routes 200, the rest 403 | 7.7.2, AC40 |
  | `web::vendored_assets_match_checksums` | the files match `SHA256SUMS` | D9 |
  | `web::configuration_changes_are_audited` | changing a setting writes an audit row | FR-26 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(web::)'
  ```
  Expected: 8 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub -E 'test(web::)' | compile errors: unresolved `super::perms` and the permission variants |
  | 2026-11-19 first run | same | 6 passed, 3 failed, all in the tests: the session helper reused the name `admin` (unique names now); askama writes `<` as `&#60;` (the test now checks that entity form and that no raw `<script` from data reaches the page); the concurrent first-run case opened its second form after the first had finished (both forms are now opened before either is sent) |
  | 2026-11-19 | cargo nextest run -p rackhand-hub -E 'test(web::)' | 10 passed, 0 failed: the 8 planned, `serves_https_with_generated_certificate` (a TLS client that trusts only the generated certificate gets 200 with the CSP header) and `totp_matches_rfc6238_vectors` (written with the TOTP code, checked against RFC 6238 appendix B) |
  | 2026-11-19 | cargo tree -p rackhand-hub -i aws-lc-rs | no match: rustls, tokio-rustls and rcgen use ring only |
  | 2026-11-19 | cargo xtask ci fast; cargo deny check; cargo audit | exit 0 (nextest 142 passed); deny ok; audit exit 0 with two unmaintained warnings: `chrono` (already present) and `basic-toml` (askama's build-time configuration reader) |

### T37: Sign-in, second factor, step-up and limits
- **Design refs:** FR-14 (step-up), FR-25, 7.7.2 (all bullets), D29, D99, E41, E61, AC40, AC68
- **Goal:** local accounts sign in with an Argon2id password and a mandatory TOTP code that works only once. Step-up
  lasts 5 minutes. Sessions end at 12 hours absolute or 2 hours idle. Sign-in limits apply per source and per account,
  with device cookies and a trusted-proxy list.
- **Depends on:** T36
- **Changes:** `crates/rackhand-hub/src/web/auth/{password.rs, totp.rs, session.rs, step_up.rs, limits.rs,
  devices.rs, client_addr.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `auth::account_without_second_factor_cannot_sign_in` | refused | AC40 |
  | `auth::used_totp_code_refused` | the same code or time step is refused the second time | D99, AC68 |
  | `auth::five_wrong_codes_restart_password_step` | and the failures count toward the limits | 7.7.2 |
  | `auth::source_backoff_after_5_failures_per_15_min` | 1 attempt a minute after that; an IPv6 /64 counts as one source | E41 |
  | `auth::account_never_locked` | the right password from a fresh source still works after a backoff | E41 |
  | `auth::account_flood_limits_new_browsers_not_known_ones` | after 10 failures from 10 addresses, a new browser gets 1 attempt a minute and a known-device browser signs in | E61, AC68 |
  | `auth::forwarded_header_ignored_unless_trusted_proxy` | `X-Forwarded-For` from an address outside `trusted_proxies` is ignored | AC68 |
  | `auth::step_up_valid_5_minutes` | valid at 4:59, prompts at 5:01 | FR-14 |
  | `auth::session_absolute_and_idle_expiry` | 12 h and 2 h | 7.7.2 |
  | `auth::sign_ins_and_failures_are_audited` | audit rows | FR-26 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(auth::)'
  ```
  Expected: 10 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub -E 'test(auth::)' | compile errors: unresolved `client_addr`, `step_up`, `users`, `devices`, `session::touch`, `Web::with_clock`, `WebConfig.trusted_proxies` |
  | 2026-11-19 | cargo nextest run -p rackhand-hub -E 'test(auth::)' | 10 passed, 0 failed (with an injected clock for the 1-minute, 5-minute, 15-minute, 2-hour and 12-hour boundaries, and per-request peer addresses) |
  | 2026-11-19 | cargo nextest run -p rackhand-hub -E 'test(web::)' | 10 passed: the CSRF test now covers every state-changing route except first run (the sign-in forms too), and the matrix test gets its token from the overview so every role is checked on every route |
  | 2026-11-19 | cargo xtask ci fast | exit 0 (nextest 152 passed) |

### T38: Passkeys, OIDC and account settings
- **Design refs:** FR-25, 7.7.2 (passkeys with a trusted certificate, OIDC with a local factor), D49, AC40
- **Goal:** passkeys are offered only when the hub is reached by hostname with a trusted certificate. OIDC users sign in
  through their provider and step up with a local factor they enrolled.
- **Depends on:** T37
- **Changes:** `crates/rackhand-hub/src/web/auth/{passkey.rs, oidc.rs}`; `tests/support/fake_oidc.rs` (an in-process
  OIDC provider with its own signing key, for tests).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `oidc::user_signs_in_through_provider` | the code flow with the fake provider creates a session | AC40 |
  | `oidc::step_up_requires_local_factor` | an OIDC session without a local factor can't approve high risk | AC40, D49 |
  | `oidc::wrong_issuer_or_nonce_refused` | refused | 10 |
  | `passkey::not_offered_with_self_signed_certificate` | no registration options | D49 |
  | `passkey::register_and_assert_with_software_authenticator` | with a trusted-certificate configuration, a software authenticator registers and signs in | FR-25 |
  | `settings::users_and_roles_admin_only` | create, change role, disable; a responder gets 403 | 7.7.1, 7.7.2 |
  | `settings::devices_listed_and_revocable` | a revoked device's next connection gets `0x13` | 7.7.1, 10 |
  | `settings::oidc_client_secret_stored_in_vault` | the settings row holds a `secret:` reference | 7.7.1, 10 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(oidc::) | test(passkey::) | test(settings::users) | test(settings::devices) | test(settings::oidc)'
  ```
  Expected: 8 passed, 0 failed.
- **Manual verification:** a real-browser passkey check is part of MV12.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-store -E 'test(put_user)'; cargo nextest run -p rackhand-hub -E 'test(settings::)' | `Unimplemented("PutUser")`; compile errors: no `Web::with_registry`, `Web::db`, `Registry::allow_device` (the test then used the existing `allow`) |
  | 2026-11-19 | cargo nextest run -p rackhand-store -E 'test(put_user)'; cargo nextest run -p rackhand-hub -E 'test(settings::) \| test(web::)' | 1 passed; 24 passed: `settings::users_and_roles_admin_only`, `settings::last_admin_cannot_be_disabled_or_demoted` (added in the run) and `settings::devices_listed_and_revocable`, whose revoked device's next connection over a local relay is closed with `0x13`, and admission reloaded from the tables still refuses it |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub -E 'test(passkey::)' | compile error: no `Web::with_passkeys` |
  | 2026-11-19 | cargo nextest run -p rackhand-hub -E 'test(passkey::)' | 2 passed. A software authenticator (P-256 with ring, attestation `none`) registers after a step-up, signs in on another browser in place of the code, steps up; a replayed answer and a forged signature are refused (401); without a passkey configuration there are no options (404) and the account page says why. The browser half is `static/passkey.js`, which no test runs: the real-browser check is MV12 |
  | 2026-11-19 | cargo xtask ci fast; cargo deny check | exit 0 (189 passed); ok |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub -E 'test(oidc::) \| test(settings::oidc)' | 4 failed: no `/settings/oidc` or `/sign-in/oidc` routes (404 where 303 was expected) |
  | 2026-11-19 | cargo nextest run -p rackhand-hub -E 'test(oidc::) \| test(passkey::) \| test(settings::users) \| test(settings::devices) \| test(settings::oidc)' | 9 passed (the 8 planned and the last-admin test). Against an in-process provider (`web/auth/fake_oidc.rs`, ES256): the code flow with PKCE signs an OIDC account in and an unknown subject gets nothing; an OIDC admin with no local factor can't step up (`StepUpRequired`) and one with the TOTP their admin issued can; a wrong issuer, nonce or audience, an expired token, a bad signature, an unknown `kid` and `alg: none` are each refused and audited, and a callback works once and only in the browser that started it; the client secret is sealed in the Vault and `config/hub.toml` holds `secret:oidc.client_secret` (not in the audit log either) |
  | 2026-11-19 | cargo xtask ci fast; cargo deny check; cargo audit; cargo xtask arch-check | exit 0 (193 passed); ok; 2 allowed warnings; no violations |

### T39: Dashboard pages for monitoring
- **Design refs:** 7.7.1 (Overview, Site, Machine, Incidents, Audit, Settings: notifiers), G1, 5.2 latency, AC1
- **Goal:** the monitoring pages render with their empty and error states. Charts read the recent window merged with
  chunk rows, and live parts refresh with htmx.
- **Depends on:** T32, T36
- **Changes:** `crates/rackhand-hub/src/web/pages/{overview.rs, site.rs, machine.rs, incidents.rs, audit.rs,
  settings_notifiers.rs}`; `crates/rackhand-hub/src/query/vitals.rs` (merges the window and chunks; at most 2000
  points).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `pages::overview_empty_state_offers_add_machine` | "No machines yet" | 7.7.1 |
  | `pages::machine_page_shows_capture_method_and_access_level` | both fields shown | 7.7.1 |
  | `pages::silent_machine_shows_since` | "Probe silent since" | 7.7.1 |
  | `query::vitals_merge_window_and_chunks_without_duplicates` | a range spanning both returns sorted, unique points | 7.4.1 |
  | `query::vitals_visible_before_compaction` | a sample staged a second ago is returned | 5.2 latency, AC1 |
  | `pages::audit_page_shows_broken_chain_banner` | with a tampered row, a critical banner | 7.7.1 |
  | `pages::notifier_send_test_sends_one_message` | to the fake Discord endpoint | 7.7.1 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(pages::) | test(query::)'
  ```
  Expected: 7 passed, 0 failed.
- **Manual verification:** the M1 page walk, done by the run in L2 against the lab hub; the passkey part of MV12
  stays with the owner.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-20 | cargo nextest run -p rackhand-hub -E 'test(pages::) \| test(query::)' (before) | compile errors: `Web::with_ingest`, `Ingest::set_capabilities`, `query::vitals::{vitals, MAX_POINTS}` not found |
  | 2026-11-20 | same (after) | first run 14 of 15 (the long-range vitals test never compacted its later samples, so only the 35-minute window held them; the test now compacts), then 15 passed with the overview's health and incident summary, the machine page (capture, access, silent since, services, containers, an htmx vitals partial drawing an SVG line per metric), incidents, site, audit (critical banner naming the broken row) and Settings: Notifiers with Send test |
  | 2026-11-20 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 325 passed (the permission matrix covers the 8 new routes); no violations |

### T40: `/metrics` endpoint
- **Design refs:** FR-7, 7.3.14, 12 (hub internals), AC49
- **Goal:** `GET /metrics` returns 401 without the bearer token. With it, it returns the latest value of every series
  plus the hub internals, in Prometheus text format.
- **Depends on:** T25, T36
- **Changes:** `crates/rackhand-hub/src/web/metrics.rs`; internal counters in Ingest, Actions, Notify, Peers and
  Assist.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `metrics::without_token_401` | 401 | AC49 |
  | `metrics::with_token_every_series_latest_value` | for 3 machines with 10 series each, 30 lines with the labels `site`, `machine` and the metric's own | AC49 |
  | `metrics::hub_internals_present` | every name listed in section 12 | 12 |
  | `metrics::output_parses_as_prometheus_text` | a Prometheus text parser accepts it | 7.3.14 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(metrics::)'
  ```
  Expected: 4 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-20 | cargo nextest run -p rackhand-hub -E 'test(metrics::)' (before) | 4 failed: no `/metrics` route (404) |
  | 2026-11-20 | same (after) | 4 passed: 401 without or with a wrong token; 30 series lines with `site`, `machine` and the metric's labels; every hub internal of section 12; the output passes a strict Prometheus text check (which itself rejects malformed text) |
  | 2026-11-20 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 329 passed; no violations |

### T41: Hub composition and `rackhand hub` commands
- **Design refs:** 7.1 (process users, hardened units), 7.2 (composition root), 7.7.3 (`hub init`, `hub run`), 7.8
  (`hub.toml`), 5.2 security, D98, AC67 (hub part)
- **Goal:** `rackhand hub init` creates the node key, the master key, the automation and assistant keys, and
  `hub.toml`. `rackhand hub run` wires every system built so far and serves `/healthz`. The shipped unit file runs the
  hub unprivileged and passes it the master key as a credential.
- **Depends on:** T24 to T40
- **Changes:** `crates/rackhand/src/{main.rs, hub_cmd.rs}`; `packaging/systemd/rackhand-hub.service`
  (`User=rackhand-hub`, `NoNewPrivileges`, `ProtectSystem=strict`, `LoadCredential=master.key:/etc/rackhand/master.key`,
  `AmbientCapabilities=CAP_NET_RAW`); `tests/it/src/hub_start.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `hub_cmd::init_creates_keys_and_config_with_modes` | the files exist with their modes; the master key is 0600 | 7.1 |
  | `hub_cmd::run_refuses_missing_master_key_with_clear_message` | exits non-zero, naming the path | 7.7.3 |
  | `hub_cmd::detect_replay_prints_what_would_have_fired` | `rackhand hub detect replay --machine <id> --from <t> --to <t>` over a seeded database prints the incidents the rules would open, and writes nothing | 12 |
  | `it::hub_start::service_runs_unprivileged_and_healthz_ok` | in a systemd container the hub's uid isn't 0, `/healthz` is ok and first run is reachable | 5.2 security, AC67, AC32 |
  | `it::hub_start::hub_user_cannot_open_master_key_by_path` | `sudo -u rackhand-hub cat /etc/rackhand/master.key` fails | AC67 |

  Carried in from the run's reviews (wiring the systems together is where these land):
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::mirror::push_after_lost_work_tree_builds_on_remote` | push, delete the mirror's work tree, save again: the push succeeds on top of the remote branch | 7.3.13 |
  | `mirror::settings_changes_reach_the_mirror` | a settings change produces a mirror commit | 7.3.13 |
  | `mirror::learned_host_key_is_pinned` | the fingerprint from the first push is stored; a different server key fails the push | 7.3.13 |
  | `hub_cmd::join_and_host_key_events_wired` | `Joined` pins host keys in SSH; `HostKeyAlert` and `MirrorAlert` become events | 7.3.1, E8 |
  | `web::first_run_setup_code_guessing_limited` | first-run attempts count against the source limiter | 7.7.2 |
  | `collect::series_cap_keeps_net_and_diskio_before_extra_mounts` | on a host with 300 mounts, network and disk I/O series survive the cap | 7.4.2 |
  | `it::receive::root_not_owned_by_root_refused` | a transfer root writable by another user is refused | 7.3.11 |

  Carried in from T58:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `hub_cmd::dashboard_decision_publishes_approval_decided` (carried in from T58) | approving or rejecting in the dashboard publishes `ApprovalDecided` on the Bus | 7.3.8 |
  Carried in from T25:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `actions::new_job_refused_while_disk_low` (carried in from T25) | with Ingest's `accepting_jobs()` false, `Actions::run` refuses a new job and records why; live ingest is unaffected | E32 |
  | `hub::observations_wired_from_ingest` (carried in from T25) | the composition's `Observations` gives MCP and the dashboard the latest facts from Ingest and series from the store | 7.3.6 |
  Carried in from T26:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `hub::probe_directory_from_registry` (carried in from T26) | the probe server's `ProbeDirectory` is the Registry's machines (`probe_endpoint_id`), and an enrolled probe's reports reach Ingest | 7.3.2 |
  Carried in from T27:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `hub::rollup_and_retention_ticks_run` (carried in from T27) | the scheduler's `Rollup` tick runs `Ingest::rollup_minute` for the last completed minute and `rollup_hour` on the hour, then `Incidents::baseline_hourly` (T32b), and the `Retention` tick runs `retention::run` hourly | 7.4.1, 7.6.4 |
  Carried in from T33:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `hub::notifiers_built_from_config` (carried in from T33) | `config/notifiers.toml` with `secret:` references builds the Discord and SMTP notifiers (secrets from the Vault), Notify ticks every 15 s, and the Executor's other step kinds reach Notify | 7.3.9, 7.4.3 |
  Carried in from the review after T33:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `hub::notify_state_survives_restart` (carried in from the review) | after a restart, incidents called out before it still get their resolution and their 6-hour re-send (rebuilt from `notifications`) | 7.6.7 |
  | `hub::received_ranges_survive_restart` (carried in from the review) | after a restart, `Welcome.received` still lists the committed ranges, so a rolled-back probe starts a new epoch | 7.3.2, AC48 |
- **Fails first:** compile errors; then the container tests fail because there is no unit file.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand -E 'test(hub_cmd::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(hub_start::)'
  ```
  Expected: 3 passed, then 2 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-20 | cargo nextest run -p rackhand -E 'test(hub_cmd::)' | T41a: 3 passed (`init` writes the keys and `hub.toml` with their modes and the Vault's secrets, and refuses to run twice; `run` names the unreadable master key; `detect replay` prints what would have fired and writes nothing). The tests were written with the code, so each was seen failing with its behaviour removed (hub.toml's mode, the path in the message, the replayed lines), then passing |
  | 2026-11-20 | cargo nextest run --profile it -p rackhand-it -E 'test(hub_start::)' | 2 failed: in a Docker container, systemd 252 leaves the unit's `LoadCredential` directory `root:700`, so the hub's user can't read its master key (tmpfs ACLs do work there; a oneshot unit with only `User=` and `LoadCredential=` shows the same) |
  | 2026-11-20 | the same checks by hand on the local lab's `hub` VM (Debian 12, systemd 252), `packaging/systemd/rackhand-hub.service` and the static build | `/healthz` ok, first run 200, the hub at uid 999, `sudo -u rackhand-hub cat /etc/rackhand/master.key` refused. The two container tests move to the live tier as `m1::hub_service_runs_unprivileged_and_healthz_ok` and `m1::hub_user_cannot_open_master_key_by_path`, run in L2 once the deploy exists (D52) |
  | 2026-11-20 | cargo nextest run -p rackhand-hub -p rackhand -E 'test(new_job_refused_while_disk_low) \| test(hub::)' | carried in: `actions::new_job_refused_while_disk_low` (Actions has a job gate; Ingest is the hub's), `hub::observations_wired_from_ingest`, `hub::notifiers_built_from_config` (`config/notifiers.toml` with `secret:` references), `hub::notify_state_survives_restart` (rebuilt from `notifications`), `hub::received_ranges_survive_restart` (a new `probe_ranges` table written by compaction and loaded with the staged seqs on start): 6 passed; each seen failing with its behaviour removed |
  | 2026-11-20 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 337 passed; no violations |
  | 2026-11-20 | cargo nextest run -p rackhand-hub -p rackhand-probe -p rackhand -E 'test(first_run_setup_code_guessing_limited) \| test(series_cap) \| test(dashboard_decision_publishes) \| test(hub::)' | carried in, each seen failing first: `web::first_run_setup_code_guessing_limited` (failed: no limit; now counted with the sign-in source limiter, 429 after 5 wrong codes until a minute passes; its first version computed the authenticator code from the real clock after moving the hub's, fixed in the test), `collect::series_cap_keeps_net_and_diskio_before_extra_mounts` (failed: mounts sorted ahead; now the cap keeps host-wide series, the root mount, network and disk I/O before other mounts), `pages::dashboard_decision_publishes_approval_decided` (failed: no `Web::with_bus`; the decision is published after its commit), `hub::probe_directory_from_registry` and `hub::rollup_and_retention_ticks_run` (the minute's work as `hub_cmd::every_minute`; both seen failing with their behaviour removed); passed |
  | 2026-11-20 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 342 passed; no violations |
  | 2026-11-20 | cargo nextest run --profile it -p rackhand-it -E 'test(mirror::) \| test(receive::)' | carried in: `it::mirror::push_after_lost_work_tree_builds_on_remote` (a work tree with no commits fetches the remote branch first and builds on it), `it::mirror::learned_host_key_is_pinned` (the first push stores the server's fingerprint in `config/hub.toml` and audits `git_mirror.host_key_pinned`), `it::receive::root_not_owned_by_root_refused` (every directory from the transfer root to the target's parent must be a root-owned directory nobody else can write): 7 passed. Each seen failing with its behaviour removed (no fetch, no pin, no ownership check: 1 failed each), then passing. `web::settings_changes_reach_the_mirror` passes in the fast tier; settings and policy edits now notify the mirror |
  | 2026-11-20 | cargo nextest run -p rackhand -E 'test(hub_cmd::)' | `hub_cmd::join_and_host_key_events_wired` (a managed machine's `Joined` pins its host keys in SSH; `HostKeyAlert` becomes `ssh.host_key_changed` (critical) and `MirrorAlert::Failed` `git_mirror_failed` (warning), a push raises none), `hub_cmd::managed_setup_has_keys_sudoers_and_signed_commands` (the join's managed setup: the automation and assistant keys, no assistant on role hub, the wrapper's sudoers line, the command list signed with the node key), `hub_cmd::join_server_waits_for_first_run_site`: 6 passed. Each seen failing with its behaviour removed (6 mutations, 1 failed each). `hub run` routes `rackhand/join/1`, runs the git mirror from the settings and raises the alerts as events (D53) |
  | 2026-11-20 | local smoke: `rackhand hub init` into a temporary directory, `rackhand hub run`, then interrupt | `/healthz` ok, first run 200, the QUIC port bound, exit 0 |
  | 2026-11-20 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 346 passed; no violations |
  | 2026-11-20 | cargo nextest run -p rackhand -E 'test(hub_cmd::)'; cargo nextest run -p rackhand-hub -E 'test(settings_changes_reach_the_mirror) \| test(policy_changes_reach_the_mirror)' | follow-up after review: `hub_cmd::hub_addrs_from_endpoint_and_names` failed first (a default hub bound to 0.0.0.0 advertised no addresses: `left: []`); joins now hand out the endpoint's direct addresses (a real endpoint bound to 0.0.0.0 reported its interfaces), read when the join server is built (D53 updated). `web::policy_changes_reach_the_mirror` added; both mirror notification tests fail with their `library.changed` call removed, then pass. These assert the `Change` reaching the mirror's channel; that a change becomes a pushed commit is covered by `it::mirror::change_pushed_within_60s_and_planted_secret_blocks`. 7 and 2 passed |
  | 2026-11-20 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 348 passed; no violations |
  | 2026-11-20 | cargo xtask ci it | the whole integration tier with the stricter file-receive check: 25 passed, 0 failed |

### T42: Probe daemon
- **Design refs:** FR-1, FR-3, 7.3.2 (reconnect, state file), 7.3.3 (probe privileges), G1, AC1, AC2, AC3, AC8
- **Goal:** `rackhand-probe run` samples at its interval, reports to its hub, buffers and replays across outages,
  reconnects with backoff and writes `probe.state`. With a real hub, vitals appear within 30 s and outages backfill.
- **Depends on:** T22 to T26, T41
- **Changes:** `crates/rackhand-probe/src/{main.rs, run.rs, state_file.rs}`; `packaging/systemd/rackhand-probe.service`
  (capabilities per 7.3.3); `tests/it/src/probe_hub.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `run::backoff_from_1s_to_60s_with_jitter` | with an injected clock | 7.3.2 |
  | `it::probe_hub::vitals_visible_within_30s` | a Debian container with a probe, Docker and two containers, plus a hub: every 7.4.2 metric except `temp.c` is queryable within 30 s, and services and containers are listed | AC1 |
  | `it::probe_hub::outage_backfills_and_live_stays_fresh` | the hub is stopped for 10 minutes at a 5 s interval; after restart the gap fills within 15 minutes, live samples stay under 30 s old during replay, and old samples open no threshold incident. The 2-hour version runs in T96 | AC2, E1 |
  | `it::probe_hub::buffer_limit_drops_oldest_with_gap_event` | with the buffer cap set to 1 MB for the test, `probe.data_gap` names the range | AC3, E2 |
  | `it::probe_hub::stopped_probe_opens_silent_warning_at_60s` | and `expected_offline` gives info only | AC8, E38 |
  | `it::probe_hub::disk_rule_callouts_and_resolution` | a probe started with a test-only fixture root (the collector's root-path seam from T22) whose `/data` usage the test rewrites: at 96% for 5 minutes a critical goes to the fake Discord endpoint and the SMTP sink within 60 s; at 86% for 5 minutes a warning within 6 minutes; at 70% for two samples a resolution message | AC5 |

  Carried in from T55 (the Executor passes these step kinds to the system that owns them; until then they fail `<kind>_unavailable`):
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::executor::wait_report_step_waits_for_fresh_report` | a `wait_report` step succeeds once the probe's next report arrives after the step started, and fails `timeout` if none does | 7.8.7 |
  | `it::executor::probe_check_step_runs_check_on_probe` | a `probe_check` step asks the probe to run the check and fails when it fails | 7.8.7 |
  | `collect::rate_interval_is_monotonic` (carried in from T38's run: `collect::once_json_prints_one_sample_set` failed once under load and passed in 4 reruns; the interval between snapshots comes from the wall clock, so a clock step back skips the rate series) | rates use a monotonic interval; a wall-clock step back between two snapshots still gives `net.rx_bps` | 7.4.2 |
  Carried in from T26:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `probe::revoked_daemon_exits_3` (carried in from T26) | the probe process exits with code 3 after `0x13` (`Stop::exit_code`) | 7.3.2 |
  | `probe::unsupported_version_retries_hourly` (carried in from T26) | after `0x12` the daemon keeps collecting into its buffer and reconnects after `Stop::retry_after` (injected clock) | 7.3.2 |
  | `probe::new_epoch_defines_every_label_set_again` (carried in from T26) | after a Welcome that starts a new epoch, the next live report's `label_sets` holds every label set it uses | 7.3.2, AC48 |
- **Fails first:** compile errors; then the container tests fail (no daemon).
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-probe -E 'test(run::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(probe_hub::)'
  ```
  Expected: 1 passed, then 5 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-20 | cargo nextest run -p rackhand-probe -E 'test(run::) \| test(collect::)'; cargo nextest run -p rackhand-hub --test probe_daemon | T42a, the daemon (`rackhand-probe run`, `run.rs`, `config.rs`): `collect::rate_interval_is_monotonic` failed first (a wall-clock step back lost `net.rx_bps`: `left: None`), now rates use a monotonic stamp. `run::backoff_from_1s_to_60s_with_jitter` (1, 2, 4 ... 60, 60 s; full jitter takes a quarter off), `run::disconnected_reports_are_buffered`, and against the hub's probe server `probe::revoked_daemon_exits_3`, `probe::unsupported_version_retries_hourly` (an hourly wait while collection fills the buffer, then again after the next `0x12`), `probe::new_epoch_defines_every_label_set_again`, and `probe::live_reports_flow_while_replay_is_held_back` (the hub reads stream 2 at 1 B/s with a 6 MB backlog; live reports still arrive): 11 and 4 passed. Each seen failing with its behaviour removed (no doubling, nothing buffered while away, no exit on `0x13`, nothing buffered during the hour, the Hello's label ids kept after a new epoch, replay inline before live: 1 failed each). The first version of the held-replay test passed with replay inline because its backlog compressed under the 1.25 MB stream window; it now uses values that don't compress (D54) |
  | 2026-11-20 | cargo nextest run -p rackhand -E 'test(hub_cmd::)' | `hub_cmd::probe_welcome_has_design_defaults`: the probe server's Welcome now carries the default probe settings (15 s, 500 tuples, 64 MB) rather than an empty config; passed |
  | 2026-11-20 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 356 passed; no violations |
  | 2026-11-21 | cargo nextest run -p rackhand-probe -E 'test(buffer::) \| test(collect::)'; cargo nextest run -p rackhand -E 'test(hub_cmd::)'; cargo nextest run -p rackhand-hub -E 'test(wait_report_step)' | T42b and T42c unit tests: `buffer::cap_from_hub_drops_oldest_with_ranges` failed first against a stub (2 005 600 bytes kept under a 1 MB cap), now the hub's `buffer_max_mb` shrinks the segments and drops the oldest with their ranges; `collect::fixture_usage_can_change_between_collections` failed with the code before (a fixture's `statvfs.txt` was read once); `hub_cmd::probe_welcome_from_settings` (a `[probe]` section in `config/hub.toml`, its 7.8.1 ranges checked on save, read when the hub starts); `executor::wait_report_step_waits_for_fresh_report` (in the hub's tests: the step only reads Ingest) and `hub_cmd::step_kinds_reach_their_systems` (`notify` to Notify, `wait_report` to Ingest, the rest unavailable). Each seen failing with its behaviour removed (an old report counts, `wait_report` not routed, the settings ignored, the ranges not checked on save: 1 failed each); passed |
  | 2026-11-21 | cargo nextest run --profile it -p rackhand-it -E 'test(probe_hub::) \| test(callouts::)' | the hub binary on the test host, the probe under `packaging/systemd/rackhand-probe.service` in a Debian 12 container (D-Bus added to the image: unprivileged `systemctl` needs the system bus). `probe_hub::vitals_visible_within_30s`: every 7.4.2 metric but `temp.c` and the per-core series on `/metrics` after 15 s, a failed unit on the machine page (services are the watched ones and every failed unit), `probe.state` connected, the probe not root. `probe_hub::outage_backfills_and_live_stays_fresh`: the hub down 10 minutes at a 5 s interval, all 130 seqs held 93 s after the restart, the newest report never over 30 s old during the replay, no threshold incident. `probe_hub::stopped_probe_opens_silent_warning_at_60s`: the warning after the hub's 3-minute grace, not before 55 s, resolved by the next report, and only an info event once the machine's policy expects it offline. `probe_hub::buffer_limit_drops_oldest_with_gap_event` (a 1 MB cap; 1500 failed units make each report large enough to fill it during a 3-minute outage) and `callouts::disk_rule_callouts_and_resolution` (in process, D55). All 6 passed: vitals on /metrics after 15 s; the outage refilled 93 s after the restart; silence at 60 s; the 1 MB buffer filled during the outage and the hub recorded probe.data_gap for the dropped range, holding none of it; the disk rule's critical 4.3 minutes into 96% (Discord and STARTTLS mail), the resolution 30 s after 70%, and a warning callout within 6 minutes of the warning opening (warnings join the site's 5-minute group; a severity that falls sends nothing, 7.6) |

### T43: Helper basics and package-list refresh
- **Design refs:** 7.3.3 (socket, ownership table, version skew, package lists), FR-2 (pending updates), D24, D79, D91
- **Goal:** the root helper serves its socket only to the probe user, directories and files follow the 7.3.3 ownership
  table, probe and helper versions must match, and the helper refreshes package lists every 6 hours with its fixed
  commands.
- **Depends on:** T42
- **Changes:** `crates/rackhand-probe/src/helper/{server.rs, peercred.rs, layout.rs, packages.rs}`;
  `packaging/systemd/rackhand-probe-helper.service`; `packaging/openrc/`; a test image with a fake `apt-get` and `apk`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `helper::unknown_request_is_an_error_not_a_crash` | invalid JSON or an unknown variant returns `Error` | 7.3.3 |
  | `helper::version_mismatch_reported_by_probe` | the probe reports `helper_version_mismatch` and runs without the helper's features | 7.3.3 |
  | `packages::apt_simulation_counts_security_updates` | recorded `apt-get -s upgrade` output gives the total, the security count and reboot-required | FR-2 |
  | `packages::apk_version_output_counts_updates` | from recorded output | FR-2, D54 |
  | `it::helper::socket_refuses_other_users` | a user other than the probe user is rejected by `SO_PEERCRED` | 7.3.3 |
  | `it::helper::layout_matches_ownership_table` | every path in the 7.3.3 table has its owner and mode | D91 |
  | `it::helper::refresh_runs_fixed_commands_at_low_priority` | the fake package manager records `nice 19`, `ionice -c3` and only the fixed commands | D79 |
  Carried in from T42 (containers come from the helper):
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::probe_hub::containers_listed_within_30s` (carried in from T42) | the AC1 container: its two Docker containers are listed on the machine page within 30 s, from the helper's container data | AC1, 7.3.3 |
- **Fails first:** compile errors; the container tests fail (no helper).
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-probe -E 'test(helper::) | test(packages::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(helper::)'
  ```
  Expected: 4 passed, then 3 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-21 | cargo nextest run -p rackhand-probe -p rackhand-proto -E 'test(helper) \| test(packages::)' | `helper::unknown_request_is_an_error_not_a_crash` failed first: `{"op":"ping","path":"/etc/shadow"}` was accepted (serde doesn't refuse unknown fields on a unit variant of a tagged enum); `parse_request` now also requires the line's fields to be exactly the request's (`unit_request_with_extra_field_refused` added in the protocol's tests). `helper::version_mismatch_reported_by_probe` (one `helper_version_mismatch` event, no containers or updates), `helper::matching_helper_gives_updates`, `packages::apt_simulation_counts_security_updates`, `packages::apk_version_output_counts_updates` (no security marker, D54), `packages::fixed_commands_at_low_priority`, `containers::engine_times_parse`, `daemon::refresh_runs_only_the_fixed_commands`, `daemon::probe_user_from_passwd`: 13 passed |
  | 2026-11-21 | cargo xtask it-images; cargo nextest run --profile it -p rackhand-it -E 'test(helper_it::) \| test(containers_listed) \| test(vitals_visible)' | `it::helper::socket_refuses_other_users` (the probe user gets `pong`; a user in the probe's group gets nothing, `SO_PEERCRED`; one outside it can't connect to the `660 root rackhand-probe` socket), `it::helper::layout_matches_ownership_table` (a `probe.toml` left `666 rackhand-probe` is put back to `644 root`; every directory of the table has its owner and mode), `it::helper::refresh_runs_fixed_commands_at_low_priority` (a fake `apt-get` records exactly `19 idle update -q` and `19 idle -s -q upgrade`; `UpdatesStatus` then gives 1 pending, 1 security), and `it::probe_hub::containers_listed_within_30s` (carried in: two containers of the engine whose socket the machine mounts are on its machine page): passed; vitals still pass with the helper running beside the probe |
  | 2026-11-21 | mutation checks | each test seen failing with its behaviour removed: any helper version accepted, the mismatch reported every time, updates dropped, security origins not counted, versions kept in apk names, any peer answered, the layout not enforced, the refresh at full priority (1 failed each) |
  | 2026-11-21 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 370 passed; no violations |
  | 2026-11-21 | cargo xtask ci it | 33 of 34 passed; probe_hub::outage_backfills_and_live_stays_fresh missed its 15 minutes while the tier ran its other containers beside it, and passed alone with the helper running (filled 76 s after the restart). The tests that time a real hub and probe now run one at a time (a nextest test group, .config/nextest.toml); the tier is rerun as T44's regression |

### T44: Linux and Alpine installer and enrollment
- **Design refs:** 7.3.12 (enrollment flow, Linux command, offline variant, access levels), 7.3.7 (accounts, keys,
  sudoers), FR-21, D27, D55, D62, D88, D90, D105, E64, AC35, AC58 (accounts part)
- **Goal:** `install.sh` verifies the probe against the two pinned release keys, then enrolls a Debian or Alpine
  machine:
  - as `managed`: both accounts, keys with `from=`, sudoers checked with `visudo -c`, and the signed command list;
  - or as `monitor`: none of these.

  The hub's SSH test completes the enrollment.
- **Depends on:** T35, T43
- **Changes:** `crates/rackhand-release/` (signature verification against the two pinned public keys, shared later by
  the helper and the updater; T91 adds manifests and reproducible builds); `rackhand-verify`, a small static binary from
  that crate, built for every release (D105): `install.sh` holds the verifier's SHA-256 for its own release, checks
  the downloaded verifier against it, and the verifier then checks every other binary against the two pinned keys,
  because a POSIX shell can't check minisign signatures itself; `packaging/install.sh` (POSIX sh);
  `crates/rackhand-probe/src/enroll.rs` (join client; writes `probe.toml`); test release keys in `tests/keys/` (test
  only, never valid for real releases). The hub's SSH test is a `ssh -o BatchMode=yes` check until T53 replaces it with
  the SSH system.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::install::debian_managed_enrolls_and_reports` | users `rackhand` and `rackhand-ai` exist with keys restricted by `from=`; sudoers has the single wrapper entry and passes `visudo -c`; `commands.json` present; the machine is enrolled and reporting | AC35, FR-21 |
  | `it::install::alpine_managed_enrolls_and_reports` | the same on Alpine with OpenRC; `sudo` and `bash` added | AC35 |
  | `it::install::monitor_has_no_accounts_keys_or_command_list` | no hub users, no hub key, no sudoers file and no `commands.json`; reports arrive | AC58, D88 |
  | `it::install::bad_signature_stops_before_installing` | a tampered binary: non-zero exit, nothing installed | AC35 |
  | `it::install::verifier_hash_mismatch_stops` | a verifier whose SHA-256 differs from the one in `install.sh`: non-zero exit, nothing installed | AC35, D105 |
  | `it::install::standby_key_signature_accepted` | a binary signed with the standby test key installs | E64, AC67 |
  | `it::install::offline_variant_checks_script_hash` | a wrong SHA-256 stops it | 7.3.12 |
  | `it::install::role_hub_machine_gets_no_assistant_account` | no `rackhand-ai` | D62 |
  | `it::runcmd::first_list_arrives_with_join` | after enrollment, `commands.json` equals the one from the join response (moved from T51, D28) | AC61 |
  Carried in from T43:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::install::openrc_services_run_probe_and_helper` (carried in from T43) | on Alpine the installer's `packaging/openrc/` scripts start the helper as root and the probe as `rackhand-probe`, with the 7.3.3 layout | 7.3.3, D54 |
- **Fails first:** the container tests fail (no installer).
- **Verification:**
  ```bash
  cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(install::)'
  ```
  Expected: 8 passed, 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None (the Windows installer is T90).
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-21 | cargo nextest run -p rackhand-release -p rackhand-probe -p rackhand -E 'test(rackhand_release::) \| test(enroll::) \| test(managed_setup)' | `rackhand-release`: minisign signatures (prehashed and legacy) checked against the current and standby pins, a tampered file, a changed trusted comment, an unpinned key and a forged key id refused; the release build pins nothing until the maintainer's keys exist (`keys/*.pub` are placeholders), the `test-keys` feature pins `tests/keys/`. `enroll`: the ticket format, `authorized_keys` limited to the hub's addresses (loopback in remote mode), `probe.toml` from the join, host keys from `/etc/ssh`. The managed setup's sudoers now has the assistant's entry with its sessions logged (7.3.7) and none on role hub. 10 passed |
  | 2026-11-21 | cargo xtask it-images; cargo nextest run --profile it -p rackhand-it -E 'test(install_it::)' | 10 passed: `install::debian_managed_enrolls_and_reports`, `install::alpine_managed_enrolls_and_reports` (OpenRC; sudo and bash added), `install::openrc_services_run_probe_and_helper` (carried in: the helper as root, the probe as `rackhand-probe`), `install::monitor_has_no_accounts_keys_or_command_list`, `install::bad_signature_stops_before_installing`, `install::unpinned_key_signature_refused` (added), `install::verifier_hash_mismatch_stops`, `install::standby_key_signature_accepted`, `install::role_hub_machine_gets_no_assistant_account`, `runcmd::first_list_arrives_with_join` (the join's list, with its version). The first run failed 3: OpenRC services stuck "starting" in a container that hadn't run its default runlevel (the image now runs `openrc default` with `rc_sys=docker`, as a booted machine has it), busybox `command -v` answering for its first name only, and the list compared with its version field (test fixes) |
  | 2026-11-21 | mutation checks | each test seen failing with its behaviour removed: the verifier's hash not checked, signatures not checked (the bad and unpinned signature tests, 2 failed), monitor not passed to the join, sudo and bash not added on Alpine, no command list from the join, an assistant on role hub (1 failed each) |
  | 2026-11-21 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 379 passed; no violations |
  | 2026-11-21 | cargo xtask ci it | 45 tests: 43 passed on the first run; the two failures were races in the tests under the tier's parallel load: probe_hub::stopped_probe_opens_silent_warning_at_60s measured 60 s from the probe's stop rather than its last report (it fired 54.6 s after the stop, correctly 60 s after the last report; now measured from the last report), and executor::ssh_cut_during_detached_step_recovers cut SSH after a fixed 2 s, before a loaded host had started the step (now it waits for the step's process). Both pass alone and the executor group passes together (8 passed) |

### T45: Hub self-watch, integrity and backups
- **Design refs:** 9 (hub backups, restore), 10 (self-watch), D58, E32, E33, E34, AC47
- **Goal:**
  - The hub runs a daily `quick_check`. On corruption it stops writing and refuses jobs, while still alerting from
    memory.
  - It checks its own binary and config daily.
  - It takes nightly encrypted backups (2 kept) that restore together with the node key, so probes reconnect without
    re-enrolling.
- **Depends on:** T41
- **Changes:** `crates/rackhand-hub/src/selfwatch.rs`; `crates/rackhand-hub/src/backup/{take.rs, restore.rs}`;
  `rackhand hub backup` and `rackhand hub restore`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `backup::backup_is_encrypted_and_restores_identically` | the restored database equals the source; the file can't be read without the master key | 9 |
  | `backup::keeps_two_local_copies` | the third backup deletes the oldest | D58 |
  | `selfwatch::quick_check_failure_stops_writes_and_alerts` | an injected failure: no acks, jobs refused, critical incident | E33 |
  | `selfwatch::binary_hash_mismatch_is_critical` | checked against a test manifest | 10 |
  | `it::backup::restore_on_new_machine_probes_reconnect` | restored into a second hub container with the same address, the probe reconnects without re-enrolling | AC47 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(backup::) | test(selfwatch::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(backup::)'
  ```
  Expected: 4 passed, then 1 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** E34 (master key lost) is documented in T99 and tested in L8
  (`live::m8::recovery_procedure_restores_the_master_key`).
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-21 | cargo nextest run -p rackhand-hub -p rackhand -E 'test(backup::) \| test(selfwatch::) \| test(hub_cmd::)' | `backup::backup_is_encrypted_and_restores_identically` (failed first: `VACUUM INTO` refused on the store's read-only pool; now on a connection of its own. Restored rows equal the source, the node key comes back, nothing readable in the file, another master key and a cut file, mid-chunk or at a chunk boundary, are refused and leave nothing), `backup::keeps_two_local_copies`, `selfwatch::quick_check_failure_stops_writes_and_alerts` (reports held: no staging row, no ack, the latest values still in memory; jobs refused; the critical goes straight to the notifiers, no event written), `selfwatch::binary_hash_mismatch_is_critical` (against a manifest signed with the test release key; an unpinned signer proves nothing), `selfwatch::config_writable_by_others_is_exposed`, `hub_cmd::backup_and_restore_commands`, `hub_cmd::nightly_at_two_site_time`, `hub_cmd::site_minute_in_the_sites_time_zone`: passed |
  | 2026-11-21 | mutation checks | each seen failing with its behaviour removed: nothing pruned, no node key restored, writes not stopped, reports staged anyway, the hash not compared, the manifest's signature not checked, the config mode not checked, the backup at 03:00 (1 failed each). Removing the chunk reader's end check alone still refuses a cut file, because zstd's frame check catches the short stream too: two layers |
  | 2026-11-21 | cargo nextest run --profile it -p rackhand-it -E 'test(probe_hub::backup::)' | `probe_hub::backup::restore_on_new_machine_probes_reconnect`: a probe enrolled at hub A; `rackhand hub backup` while A runs; A stopped; `rackhand hub restore` on a new directory with A's master key, on A's address; the restored hub has A's endpoint id and the probe reports to it without re-enrolling (its `probe.toml` unchanged): passed (AC47) |
  | 2026-11-21 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 387 passed; no violations |
  | 2026-11-21 | cargo xtask ci it | 45 tests: 43 passed on the first run; the two failures were races in the tests under the tier's parallel load: probe_hub::stopped_probe_opens_silent_warning_at_60s measured 60 s from the probe's stop rather than its last report (it fired 54.6 s after the stop, correctly 60 s after the last report; now measured from the last report), and executor::ssh_cut_during_detached_step_recovers cut SSH after a fixed 2 s, before a loaded host had started the step (now it waits for the step's process). Both pass alone and the executor group passes together (8 passed) |

### T39b: Settings: add or replace a notifier
- **Design refs:** 7.7.1 (Settings: notifiers), 7.3.9, 7.4.3 (`config/notifiers.toml`, secrets as `secret:<name>`), D113,
  FR-11, FR-26
- **Goal:** an admin adds a Discord or SMTP notifier from Settings: Notifiers. The webhook URL or SMTP password goes into
  the Vault, `config/notifiers.toml` gets a new revision holding only `secret:<name>`, the change is audited without the
  secret and reaches the git mirror. Added before L2 (D60): no step gave the dashboard a way to add a notifier, and
  the live callout test needs one.
- **Depends on:** T39, T41
- **Changes:** `crates/rackhand-hub/src/web/pages/notifiers.rs` (the page, Send test and the save handler, moved out of
  `monitoring.rs`); `POST /settings/notifiers` (Administer); `notify::config::to_toml`; `templates/notifiers.html`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `pages::notifier_added_from_settings_keeps_the_url_in_the_vault` | a Discord and an SMTP notifier saved: the file holds `secret:notifier.<name>.webhook` and `.password`, the Vault the values, the hub can build both; nothing secret in the file, the audit log or the page; two audit rows; the change reaches the mirror; the page lists both as applying when the hub restarts; saving a name again replaces it and an empty secret keeps the stored one; refused with 400 and nothing saved: plain http off this host, a bad name, an unknown security, no recipients, a new notifier without its secret; a viewer gets 403 | 7.7.1, 7.4.3, D113 |
- **Fails first:** 405 (no such route).
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(notifier)'
  ```
  Expected: 4 passed, 0 failed.
- **Risk / rollback:** revert; notifiers can still be written to `config/notifiers.toml` by hand.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-21 | cargo nextest run -p rackhand-hub -E 'test(notifier_added_from_settings)' (before) | failed: 405 for `POST /settings/notifiers` |
  | 2026-11-21 | cargo nextest run -p rackhand-hub -E 'test(notifier)' | 4 passed |
  | 2026-11-21 | mutation checks | each seen failing with its behaviour removed: no replace, the secret written into the file, any webhook URL accepted, no mirror change (1 failed each) |
  | 2026-11-21 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 390 passed, 1 skipped; no violations |

### L2: Live tier and the M1 pass
- **Design refs:** 14 (live tier), D107, 7.3.12, AC1, AC2, AC5, AC8, AC35, AC40, AC47, AC49, AC66
- **Goal:** the M1 build, deployed to the lab's `hub` machine, enrolls `target` with the dashboard's install command,
  watches it, calls out and recovers, all against real machines.
- **Depends on:** T44, T45, L1
- **Changes:**
  - `cargo xtask lab deploy [--hub-on <machine>]`: builds static musl binaries, signs them with the test release keys
    T44's integration tests use (`tests/keys/`), pinned through the `lab-build` feature; serves them from a
    lab release server in WSL; installs the hub with the packaged systemd unit and completes first run with a
    generated admin whose password and TOTP secret stay in `~/.cache/rackhand-lab/creds` (never printed or committed).
  - The `lab-build` feature fails the build when `RACKHAND_RELEASE=1` is set, which T91's release build sets. It also
    adds `rackhand hub lab-token --kind machine --access managed|monitor`, which prints a one-time machine token from
    the Registry, because the Add page that issues tokens arrives only in T49. Release builds don't have the command.
  - `tests/live/src/`: a hub client (sign-in with TOTP, API calls), the dashboard install command runner, and
    WSL-side fakes for a Discord webhook and an SMTP server that record callouts.
  - `--no-deploy` on `ci live`, used to see the tests fail first.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `lab::release_build_with_test_keys_fails` | building with the `lab-build` feature and `RACKHAND_RELEASE=1` fails with a message naming the feature; a build without `lab-build` has no `lab-token` command | D90 |
  | `live::m1::hub_serves_dashboard_and_metrics` | HTTPS answers on the hub; sign-in needs the second factor; `/metrics` is 401 without a token and lists series with one | AC40, AC49 |
  | `live::m1::target_installs_and_reports_within_30s` | the 7.3.12 Linux command with a token from `rackhand hub lab-token`, run on `target`, enrolls it as `managed`; vitals, services and updates appear within 30 s | AC1, AC35 |
  | `live::m1::tampered_probe_stops_the_install` | with the lab release server serving a tampered probe, the install exits non-zero and installs nothing | AC35 |
  | `live::m1::stopped_service_calls_out_and_resolves` | stopping a watched service on `target` opens a critical incident and the fake webhook gets the callout in time; starting it resolves the incident | AC5 |
  | `live::m1::paused_target_raises_silence_warning` | `lab pause target` gives the silence warning at 60 s; `resume` clears it | AC8 |
  | `live::m1::cut_link_backfills_without_stale_incidents` | `lab cut target` for 10 minutes (AC2's 2 hours shortened for the lab), then `heal`: the gap backfills, data is live within 30 s, no stale incident remains | AC2 |
  | `live::m1::hub_reboot_keeps_history_and_rules` | rebooting `hub` keeps history, rules and open incidents; `target` reconnects | AC66 |
  | `live::m1::backup_restores_on_a_fresh_hub` | a backup, `lab reset hub`, deploy and restore: history is back and `target` reconnects | AC47 |
  Carried in from T41:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `m1::hub_service_runs_unprivileged_and_healthz_ok` (carried in from T41) | on the lab's hub, the shipped unit runs the hub as a non-root user, `/healthz` is ok and first run answers | 5.2 security, AC67, AC32 |
  | `m1::hub_user_cannot_open_master_key_by_path` (carried in from T41) | `sudo -u rackhand-hub cat /etc/rackhand/master.key` fails; the key is `600 root` | AC67 |
- **Fails first:** `lab::release_build_with_test_keys_fails` fails (no guard yet); `cargo xtask ci live --target
  local --milestone m1 --no-deploy` (no hub on `hub` yet) fails every `live::m1::` test with "hub not reachable".
- **Verification:**
  ```bash
  cargo nextest run -p xtask -E 'test(lab::)' && cargo xtask ci live --target local --milestone m1
  ```
  Expected: 5 passed, 0 failed; then 8 passed, 0 failed.
- **Regression:** `cargo xtask ci fast`: exit 0; `cargo xtask ci live --target local --milestone lab`: 6 passed.
- **Manual verification:** the page walk of MV12, done by the run: every M1 page in 7.7.1 opened against the lab hub
  in the in-app browser and compared with 7.7.1's contents and empty states; screenshots kept as evidence. It is a
  visual check, so it can't be an automated assertion.
- **Done when:**
  - [x] New tests observed failing before the deploy
  - [x] New tests and the regression suites pass
  - [ ] M1 page walk recorded (waits for the owner: the browser pane refuses the hub's self-signed certificate until the owner continues past the warning)
  - [x] Evidence recorded below
- **Risk / rollback:** `lab reset` returns every machine to its base image. Revert the commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-21 | cargo nextest run -p rackhand -E 'test(metrics_token)' | `hub_cmd::metrics_token_read_with_the_master_key` failed first (`metrics_token` not found), then passed: `rackhand hub metrics-token` prints the token `/metrics` checks, read-only from the Vault with the master key; another master key opens nothing (D61) |
  | 2026-11-21 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 390 passed, 1 skipped; no violations |
  | 2026-11-21 | cargo nextest run -p rackhand-hub -E 'test(machine_page_shows_updates)' | failed first (the machine page had no updates section: "Updates not reported yet" missing), then passed: pending and security counts, reboot required and the package names (design 7.7.1 lists updates on the Machine page; T39 left them out) |
  | 2026-11-21 | cargo nextest run -p rackhand -E 'test(ticket_names)' | `hub_cmd::ticket_names_the_node_key_and_addresses` failed first (`ticket` not found), then passed: `rackhand1:<endpoint id>@<ip>:<quic port>,...` from the node key, refused without an address; `lab-token --addr <ip>` prints `machine=`, `ticket=`, `token=` |
  | 2026-11-21 | cargo xtask lab reset hub; cargo xtask lab reset target; cargo xtask ci live --target local --milestone m1 --no-deploy | 9 of 10 failed: the 8 needing the dashboard at the sign-in form or the health check (no hub answers), the 2 carried from T41 at their SSH commands; `tampered_probe_stops_the_install` passed, since it needs only the release files and install.sh (T44), and was seen failing with the byte flip removed (the install got past verification), then passed after `lab reset hub`. The m1 tier now has 10 tests, not 8: the 8 listed and the 2 carried from T41 |
  | 2026-11-21 | cargo xtask ci live --target local --milestone m1 (pass 1) | 2 of 10 passed (the master-key check and the tampered install); target's install failed: the join's answer never arrived (`read error: connection lost`), which left target registered without a config, and every test that needed it failed waiting for it; the first sign-in failed, first run answered 303 once done, and the hub and probe wrote no logs at all |
  | 2026-11-21 | cargo nextest run -p rackhand -p rackhand-probe -E 'test(json_lines)' | `logging::json_lines_at_info_by_default` in both binaries failed first (`subscriber` not found), then passed: one JSON line per event with level, message, fields and timestamp, debug hidden at the default level, `RACKHAND_LOG=debug` shows it, a bad filter falls back to info |
  | 2026-11-21 | cargo nextest run -p rackhand-net -E 'test(segmentation)' | `endpoint::segmentation_offload_is_off` failed first (`transport` not found), then passed: the endpoint's QUIC config has segmentation offload off; iroh's default has it on |
  | 2026-11-21 | join by hand on the lab, with the logs on | the hub's first segmented send to `target` (2958 bytes, the join's answer) failed with EIO (`halting segmentation offload`): the lab's virtio NICs have no TX checksum offload. A second join against the same hub process, which had stopped segmenting, went through, so the connection that started with segmentation never recovers: iroh keeps the segment count a connection started with (`Sender::max_transmit_segments`) |
  | 2026-11-21 | cargo xtask lab reset hub; lab reset target; cargo xtask ci live --target local --milestone m1 (pass 2) | 3 of 10 passed: target installed and reported (vitals 17.6 s, services 1.1 s, updates 17.7 s after the install command finished); the cut test passed; the backup test failed on its ownership check (`/var/lib/rackhand/backups` root's, mode 700, after `sudo rackhand hub backup`); the reboot test's transient timer fired 9 s late, so the old system still answered and the test ran into the shutdown, and the tests after it found no hub |
  | 2026-11-21 | cargo xtask ci live --target local --milestone m1 (pass 3, on pass 2's machines) | 8 of 10 passed: backup and restore (target reported to the restored hub, probe.toml unchanged), the cut (live 11 s after the heal, the hole filled 12 s after it, live lag at most 10 s during the replay), a critical callout 74 s after the unit failed and the resolution 15 s after it ran again; the reboot test failed (the open critical incident resolved after the restart) and the pause test found no silence warning within 150 s, the hub having just restarted (E44's 3 minutes). Pass 4, on reset machines: 8 of 10 again (install: vitals 17.5 s, services 1.1 s, updates 17.5 s; the cut: live 13 s after the heal, filled 13 s after it, lag at most 6 s); the incident now resolved at the hub's first evaluation, before target reported; the pause test's checks passed (silence warning 71 s after the pause, cleared 62 s after the resume, the clock 67 s behind and set) and it failed only on the reboot test's leftover incident |
  | 2026-11-21 | cargo nextest run -p rackhand-hub -E 'test(counted_incidents_stay_open)' | `incidents::counted_incidents_stay_open_across_a_restart` failed first (a critical `service.not_active` and a warning `updates.security` both resolved at the first report after the restart, while the service was still down and the updates still pending), then, with an evaluation added before that first report, failed again the way the lab did (resolved at the first evaluation), then passed: both stay open at their severity and resolve once the service runs and the updates are installed; the 20 `incidents::` tests pass |
  | 2026-11-21 | cargo xtask ci live --target local --milestone m1 (pass 5, on pass 4's machines) | 10 passed: the install (vitals 17.5 s, services 1.1 s, updates 17.5 s after the install command, managed, the hub's accounts and sudoers in place), `/metrics` (401 without the token, the hub's internals and every listed target series with it), the second factor required, a critical callout 66 s after the unit failed and the resolution 15 s after it ran again, the silence warning 67 s after the pause and cleared 16 s after the resume, the cut (live 7 s after the heal, the hole filled 7 s after it, live lag at most 8 s during the replay), the reboot (the open critical incident, history, the resolved incidents and the notifier kept, target back), the backup restored on a reset hub (target reported 203 s after the restore began, `probe.toml` unchanged), the tampered install stopped with nothing installed, and the two carried from T41 |
  | 2026-11-21 | cargo nextest run -p xtask -E 'test(lab::)' --run-ignored all | 9 passed (the plan's 5 and the lab steps' later tests), `release_build_with_test_keys_fails` among them |
  | 2026-11-21 | cargo xtask ci live --target local --milestone lab | 7 passed (the lab profile has 7 tests now, not 6) |
  | 2026-11-21 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 396 passed, 1 skipped; no violations |
  | 2026-11-21 | MV12 page walk in the in-app browser | not done: the pane refuses `https://127.0.0.1:32101` (the hub's self-signed certificate, ERR_CERT_AUTHORITY_INVALID) and only the owner can continue past the warning; waits for the owner |
  | 2026-11-21 | cargo nextest run -p rackhand-hub -p rackhand-detect -E 'test(incidents::) \| test(silence)' | `incidents::silence_stays_open_across_a_restart` failed first (an open `machine.silent` resolved at the first evaluation after a restart, in the 3-minute start grace, while the machine was still silent), then passed: it stays open until the machine's first report; 29 passed |

### M2: Checks and agentless drivers

### T46: Service checks and network drivers
- **Design refs:** FR-9, FR-10 (ICMP, TCP, HTTP), 7.3.8 (`Driver` trait), 7.4.2 (check metrics), 7.6.1 (check
  failing), 7.6.2 (certificate expiry), AC10
- **Goal:** the hub runs HTTP(S) (status and body match), TCP, DNS, TLS-expiry and ICMP checks from its site at their
  configured intervals, stores the results and series, and failing checks and expiring certificates open incidents.
- **Depends on:** T41
- **Changes:** `crates/rackhand-drivers/src/{trait.rs, icmp.rs, tcp.rs, http.rs, dns.rs, tls.rs}`;
  `crates/rackhand-hub/src/checks/{schedule.rs, results.rs}`; the `PutCheck` and `PutCheckResults` handlers.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `drivers::http_status_and_body_match` | against a local test server: a 200 with a matching body passes; a 500 or a body mismatch fails with detail | FR-9 |
  | `drivers::tcp_connect_and_dns_answer` | an open port passes and a closed one fails; a local DNS stub returns the expected answer | FR-9 |
  | `drivers::tls_days_to_expiry` | a test certificate expiring in 10 days reports 10 | FR-9, AC10 |
  | `drivers::icmp_uses_unprivileged_socket_or_cap_net_raw` | a ping to loopback succeeds without root | 7.1 |
  | `checks::interval_bounds_15s_to_1h` | out-of-range intervals are refused | 7.8.1 |
  | `checks::two_failures_warn_four_critical` | through Incidents | AC10 |
  | `it::checks::http_check_on_stopped_service_and_expiring_cert` | in containers: warning after 2 failed checks; a certificate 10 days from expiry gives a warning | AC10 |

  Carried in from T55 (the Executor passes these step kinds to the system that owns them; until then they fail `<kind>_unavailable`):
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `executor::verify_step_runs_named_checks` | `verify` with `containers_running:{{project}}` evaluates the check for the substituted project; a failing check fails the step with its name | 7.8.7 |
  | `executor::api_step_calls_driver` | an `api` step makes the driver call and records its result | 7.8.7 |
  Carried in from T32b:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `incidents::check_failing_2_and_4_runs` (carried in from T32b) | a check failing 2 runs in a row warns and 4 is critical, through `Incidents::condition`; 2 good runs resolve it | 7.6.1 |
  | `incidents::cert_expiry_warns_at_14_days` (carried in from T32b) | a TLS check's certificate with 14 days left warns, 3 days critical | 7.6.2 |
  Carried in from T42 (`probe_check` as D115 defines it: `RunCheck` and `CheckResult` on stream 0):
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::executor::probe_check_step_runs_check_on_probe` (carried in from T42) | a `probe_check` step with `tcp:` and `http:` checks runs them on the probe (`RunCheck`, `CheckResult`) and fails with the first failing check; a check of an address that isn't loopback or the machine's own is refused by the probe | 7.8.7, D115 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-drivers -E 'test(drivers::)' && cargo nextest run -p rackhand-hub -E 'test(checks::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(checks::)'
  ```
  Expected: 4 passed, then 2 passed, then 1 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-21 | T46a: cargo nextest run -p rackhand-drivers -E 'test(drivers::)' (before) | compile errors: `DriverTarget`, `DriverReading`, `DriverError`, `Http`, `Tcp`, `Dns`, `Tls`, `Icmp` not found |
  | 2026-11-21 | T46a: same (after) | 4 passed: HTTP status and body (a 500, a body mismatch and an unfollowed 302 fail with detail; an unknown setting is a configuration error), TCP open and closed, DNS against a local stub (the expected address, a wrong one, NXDOMAIN), the days to a self-signed certificate's expiry (10), and an unprivileged ping to loopback (WSL's `ping_group_range` allows every group), one to an address nothing answers failing within its timeout |
  | 2026-11-21 | T46a: mutation checks | each seen failing with its behaviour removed: the status not compared, the body not checked, the days computed wrong, unknown settings allowed, the DNS answer not compared, a closed port passing (1 failed each) |
  | 2026-11-21 | T46a: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0 (with `cargo deny check` for the new dependencies); fast 401 passed, 1 skipped; no violations |
  | 2026-11-21 | T46b: cargo nextest run -p rackhand-store -E 'test(checks_and_their)' | `writer::checks_and_their_results_written` failed first (`Unimplemented("PutCheck")`), then passed: a check updated in place, a result written once |
  | 2026-11-21 | T46b: cargo nextest run -p rackhand-hub -E 'test(checks::) \| test(check_failing) \| test(cert_expiry)' (before) | compile errors: `Checks`, `checks::config`, `Ingest::put_points` not found |
  | 2026-11-21 | T46b: same (after) | 4 passed: `checks::interval_bounds_15s_to_1h` (14 and 3601 refused, 15, 3600 and the default 60 taken; an unknown kind, an API driver's kind, a setting the kind lacks, a bad name and a duplicate refused; saving `config/checks` through the Library refuses the same), `checks::two_failures_warn_four_critical` (a TCP check of a closed port from the hub: one failure nothing, a run before it's due adds nothing, 2 warn, 4 critical; across a restart the next failure keeps it critical, since the count comes from the stored results; one good run keeps it open, two resolve it; 7 results and the `check.up` series under `hub`; a check taken out of the file stops), and the carried `incidents::check_failing_2_and_4_runs` and `incidents::cert_expiry_warns_at_14_days` (20 days nothing, 14 warning, 3 critical, renewed resolved) |
  | 2026-11-21 | T46b: cargo xtask it-images; cargo nextest run --profile it -p rackhand-it -E 'test(checks::)' | `checks::http_check_on_stopped_service_and_expiring_cert`: the hub binary checks a container's HTTP service and its HTTPS certificate (10 days from expiry): the certificate warning opens, and the HTTP check's warning 44 s after the service stopped, after 2 failed runs: passed (AC10) |
  | 2026-11-21 | T46b: mutation checks | each seen failing with its behaviour removed: one good run resolving, the interval unbounded, the failures not counted, a check run before it's due; and the integration test with the hub's checks loop removed (1 failed each) |
  | 2026-11-21 | T46b: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 406 passed, 1 skipped; no violations |
  | 2026-11-21 | T46c: cargo nextest run -p rackhand-hub -E 'test(executor::)' (before) | compile errors: `checks::steps` not found, `ContainerState` has no `project` |
  | 2026-11-21 | T46c: same (after) | 2 passed: `executor::verify_step_runs_named_checks` (`containers_running:shop` passes with the project's containers running and fails with its name, naming the exited container, when one stopped; a project with no container fails; `check:<name>` of a check bound to the machine fails on a failed result, on a pass from before the step started, and passes on a newer pass; an unknown name fails at once), `executor::api_step_calls_driver` (the call goes to the machine's driver at its address and its answer is the step's output; a refused call fails with the driver's reason; no driver for the machine's kind fails `no_driver:<kind>`) |
  | 2026-11-21 | T46c: cargo nextest run -p rackhand -E 'test(step_kinds_reach)' | failed first (`verify_unavailable`), then passed: the hub hands `verify` and `api` to Checks |
  | 2026-11-21 | T46c: mutation checks | each seen failing with its behaviour removed: a container's state ignored, a failed result passing, an old pass counting (survived at first; the test gained the pass-before-the-step case), the api output dropped, unknown names passing |
  | 2026-11-21 | T46c: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 408 passed, 1 skipped; no violations |
  | 2026-11-21 | T46d: cargo nextest run -p rackhand-probe -p rackhand-hub -E 'test(probe_check) \| test(own_addresses)' (before) | compile errors: `run_with`, `own` not found (and `Incoming`, `CheckResult`, `probe_checks` for the contract test) |
  | 2026-11-21 | T46d: same (after) | 3 passed: `probe_check::only_this_machines_addresses` (loopback passes; a name resolving to loopback passes, one resolving to 192.0.2.99 is refused, so is a literal; a closed port fails; other kinds and bad syntax fail), `probe_check::own_addresses_are_loopback_or_bindable`, and the contract test `probe_check_round_trip` (no probe: `probe_not_connected`; then each check goes to the probe as `RunCheck` on stream 0 with its timeout, in order, and the step fails with the first failing check, its detail in stderr, the passed ones in stdout) |
  | 2026-11-21 | T46d: cargo nextest run -p rackhand -E 'test(step_kinds_reach)' | failed first (`steps` took no probe server), then passed: the hub hands `probe_check` to the probe server |
  | 2026-11-21 | T46d: cargo nextest run --profile it -p rackhand-it -E 'test(probe_check_step)' | `checks::probe_check_step_runs_check_on_probe` through the real probe daemon: `tcp:` and `http:` checks run on the probe, the step fails with the HTTP check answering 503, passes with the TCP one alone, and a check of 192.0.2.99 is refused by the probe: passed |
  | 2026-11-21 | T46d: mutation checks | each seen failing with its behaviour removed: any address counting as the machine's, the address rule skipped, the answers not delivered to the waiting step, the daemon ignoring `RunCheck` (the integration test alone catches that one, since the contract test drives the link itself) |
  | 2026-11-21 | T46d: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 411 passed, 1 skipped; no violations |
  | 2026-11-21 | cargo xtask ci it (T46 regression, run 1, with the lab profile's 5 machines up) | 46 of 47: `executor_it::executor::ssh_cut_during_detached_step_recovers` failed (`no_exit_status`) |
  | 2026-11-21 | cargo xtask ci it (run 2, the lab down) | 46 of 47: `executor_it::executor::detached_step_timeout_not_killed_machine_locked` failed (its step still `running` 30 s after the job timed out); both pass alone (the first 3 runs of 3) |
  | 2026-11-21 | 16 copies of `ssh_cut_during_detached_step_recovers` at once, the failure message given a post-mortem of the machine's job files | 2 of 16 failed: the job files there with no `exit`, `slow-echo 8` still running. Not load: the SSH cut lost the `job-start` call's answer while the unit ran, and the hub failed the step. After the fix (a start without an exit status asks `job-status` whether it started): 16 of 16 passed |
  | 2026-11-21 | 16 copies of `detached_step_timeout_not_killed_machine_locked` at once | 16 of 16 passed; the failure didn't come back. Its message now carries the same post-mortem, and it is left as seen once (a status poll that connects and then stalls can take the whole 60 s limit, which would explain it; not changed unverified) |
  | 2026-11-21 | cargo xtask ci it (run 3, at f3e1f0d) | 46 of 47: `jobs::detached::job_survives_ssh_disconnect` failed in its set-up (`job-start` didn't return in 20 s); 16 copies alone all passed. The container helper went on after 10 s whether or not the container's systemd had finished booting, so a test could race the boot (`systemd-run` waits for it); it now waits up to 60 s and fails saying so, and the test's message carries the machine's state |
  | 2026-11-21 | cargo xtask ci it (run 4, at 1f55869) | exit 0: 47 passed |
  | 2026-11-21 | D91 (owner B1): cargo nextest run -p rackhand-drivers -E 'test(https_check_pins)' (before) | failed: `unknown setting fingerprint (known: status, body_contains)` |
  | 2026-11-21 | D91: cargo nextest run -p rackhand-drivers (after) | 18 passed: a self-signed HTTPS service fails without `fingerprint` (TLS), passes with its SHA-256 (any case, colons optional), fails with another; a malformed fingerprint, or one on an `http://` URL, is a configuration error |

### T47: Proxmox driver
- **Design refs:** FR-10 (Proxmox VE API), 7.4.2 (Proxmox row), 7.8.6 (role from T12), 7.3.12 (certificate pinning),
  D93, S4 finding
- **Goal:** the Proxmox driver polls node, storage and guest metrics with an API token and a pinned certificate
  fingerprint, and performs the operations later steps need (snapshot, rollback, firewall read and write, power, clone,
  config read), each tested against recorded API responses.
- **Depends on:** T46, T12
- **Changes:** `crates/rackhand-drivers/src/proxmox/{client.rs, poll.rs, ops.rs, sim.rs}` (`sim.rs`: an in-process
  simulator serving responses recorded in T12, redacted, from `tests/fixtures/proxmox/{pve8,pve9}/`).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `proxmox::poll_maps_every_catalogue_metric` | node CPU and memory, storage per datastore, guest status, CPU and memory with labels `node`, `storage`, `vmid`, on PVE 8 and 9 fixtures | FR-10, AC11 |
  | `proxmox::certificate_fingerprint_mismatch_refused` | a different certificate fails before any request | 7.3.12 |
  | `proxmox::snapshot_and_rollback_requests_match_api` | method, path and body equal the recorded calls | 7.5.3 |
  | `proxmox::firewall_config_read_and_restore_round_trip` | options, rules and per-device flags read, written and read back identically | D104, AC72 |
  | `proxmox::task_polling_reports_failure_detail` | a failed task's exit status reaches the caller | 9 |

  Carried in from T55 (the Executor passes these step kinds to the system that owns them; until then they fail `<kind>_unavailable`):
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::executor::snapshot_and_rollback_steps_use_proxmox_driver` | `snapshot` and `rollback` steps call the Proxmox driver for the guest | 7.8.7 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-drivers -E 'test(proxmox::)'
  ```
  Expected: 5 passed, 0 failed.
- **Manual verification:** None here (lab use is in T59, T60, T64 and T72).
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-21 | cargo xtask lab up spikes; cargo xtask lab record-proxmox | the answers of PVE 8.4.21 and 9.2.31 recorded into `tests/fixtures/proxmox/{pve8,pve9}/`: nodes, node status, storage, guests, their status, config, firewall options and rules, the datacenter firewall, snapshots; a snapshot, its rollback and deletion on `ct-test` with their tasks, and a deletion of a missing snapshot, whose task fails (`snapshot 'rackhand-missing' does not exist`). Redacted: the host's CPU model, flags and clock, and the lab's SSH key; only documentation addresses and lab names remain |
  | 2026-11-21 | cargo nextest run -p rackhand-drivers -E 'test(proxmox::)' (before) | compile errors (`proxmox::ops` not there) |
  | 2026-11-21 | same (after) | 5 passed: every 7.4.2 Proxmox reading on both versions (node CPU and memory, `local` and `tank`, guests 100 and 200 up with CPU and memory, labels `node`, `storage`, `vmid`), every request with the API token; a certificate other than the pinned one refused with nothing sent, and no pin refused as a setting; snapshot and rollback as `POST .../lxc/100/snapshot` `snapname=...` and `POST .../snapshot/<name>/rollback`, each waiting for its task; the firewall read, changed by a quarantine (policies, a rule, the device's flag), restored and read back identically; a failed task's exit status as the error |
  | 2026-11-21 | mutation checks | each seen failing with its behaviour removed: any certificate accepted, datastores not read, old rules kept on restore, a failed task passing, the wrong snapshot field, the guest binding not required |
  | 2026-11-21 | cargo nextest run -p rackhand-hub -E 'test(executor::)'; cargo nextest run -p rackhand -E 'test(step_kinds_reach)' | `executor::snapshot_and_rollback_steps_use_proxmox_driver` (carried in from T55) failed first (`Hypervisor` not found), then passed: a proposed binding refused with nothing sent (`guest_binding_unconfirmed`), a confirmed one snapshots the guest on its node as `rackhand-<job id>` and rolls back to it, a machine that isn't a guest refused. The hub hands `snapshot` and `rollback` to it (failed first: `steps` took no Vault) |
  | 2026-11-21 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | first run 416 of 417: `probe_daemon::probe::unsupported_version_retries_hourly` (T42, untouched here) timed out waiting 20 s for 100 fast-clock reports under the tier's load; 12 runs alone and 8 at once all passed; second run exit 0, 417 passed, 1 skipped; no violations |

### T48: TrueNAS, Redfish and SNMP drivers
- **Design refs:** FR-10, 7.4.2 (TrueNAS, Redfish, SNMP rows), 7.6.3 (agentless silence), AC11, S9 finding
- **Goal:** the TrueNAS, Redfish and SNMP v2c and v3 (read-only) drivers record their 7.4.2 metrics from simulators
  that replay recorded responses, and a stopped simulator gives a silent warning after 2 polls.
- **Depends on:** T46, T14
- **Changes:** `crates/rackhand-drivers/src/{truenas.rs, redfish.rs, snmp.rs}`; simulators in `src/sim/`; fixtures
  from T14 (TrueNAS), a public Redfish mockup set (license checked by `cargo deny`'s source review or noted), and
  recorded SNMP walks with invented values.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `truenas::pool_disk_smart_alerts_metrics` | every TrueNAS metric in 7.4.2 from the fixture, over the API chosen in T14 | AC11 |
  | `redfish::power_fans_temps_psu_health` | every Redfish metric in 7.4.2 | AC11 |
  | `snmp::v2c_and_v3_read_interfaces_and_configured_oids` | `ifInOctets`, `ifOutOctets`, `ifOperStatus`, `sysUpTime` and one configured OID; v3 with authPriv | AC11 |
  | `snmp::no_set_requests_ever_sent` | the client has no set operation; the simulator records only get and walk | FR-10 |
  | `it::drivers::form_added_simulators_report_and_silence_after_2_polls` | each simulator added through the dashboard form reports metrics; stopping it gives a silent warning after 2 polls | AC11 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-drivers -E 'test(truenas::) | test(redfish::) | test(snmp::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(drivers::)'
  ```
  Expected: 4 passed, then 1 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-21 | cargo nextest run -p rackhand-drivers -E 'test(truenas::) \| test(redfish::) \| test(snmp::)' (before) | compile errors (each module absent) |
  | 2026-11-21 | same (after) | 6 passed. `truenas::pool_disk_smart_alerts_metrics` over JSON-RPC on the WebSocket and over REST (an agent without `/api/current`), each from its own recording: pool health and use, disk temperatures (none for a disk without a reading), SMART status from the latest test (none for a disk never tested; a failed test 0), alerts not dismissed by level, reads only with the API key; `truenas_certificate_fingerprint_mismatch_refused`. `redfish::power_fans_temps_psu_health`: power state, the health rollup, temperatures (an absent sensor's stale 0 left out), fans, a Critical supply 0, GETs only with Basic authentication, a wrong password the reading's failure. `snmp::v2c_and_v3_read_interfaces_and_configured_oids`: `sysUpTime`, `ifInOctets`, `ifOutOctets`, `ifOperStatus` by `ifName` and a configured OID, over v2c and v3 authPriv (scoped PDUs encrypted); a wrong community or v3 password gets nothing. `snmp::no_set_requests_ever_sent`: the agent saw only GET and GET-NEXT; a `write` setting is refused. `snmp::usm_matches_published_vectors`: RFC 3414's localized key, RFC 2202's HMAC-SHA1, NIST SP 800-38A's AES-128-CFB |
  | 2026-11-21 | mutation checks | each seen failing with its behaviour removed: TrueNAS without its REST fallback, dismissed alerts counted, a no-reading temperature kept, SMART status ignored (survived at first: the recording has only passes; the simulator gained a failed test); Redfish's own health for the rollup, absent sensors read (survived at first: the fixture's absent sensor had no number; it now has a stale 0), supply health ignored; SNMP's IV built wrong, the key not stretched, timeticks not hundredths, a walk leaving its subtree |
  | 2026-11-21 | cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 423 passed, 1 skipped; no violations |

### T49: Add page, agentless enrollment and guest binding
- **Design refs:** 7.3.12 (agentless form, Proxmox token, guest binding), 7.7.1 (Add, Machine page guest binding),
  D93, E50, AC60 (binding part), AC36 (agentless form)
- **Goal:** the Add page issues one-time commands for Linux, Alpine and Windows machines (local or remote, managed or
  monitor, with the offline variant's SHA-256), invites for devices, operators and peers, and the site bootstrap
  command. Admins add appliances and Proxmox clusters through per-driver forms (credentials into the Vault, certificate
  fingerprints accepted). The hub proposes a guest binding by MAC address for an admin to confirm; once confirmed it
  is fixed, and a mismatch raises `machine.guest_binding_mismatch` and marks the binding `mismatch`.
- **Depends on:** T47, T48, T39
- **Changes:** `crates/rackhand-hub/src/registry/{agentless.rs, guest_binding.rs}`; `web/pages/add.rs` (machine
  commands, appliance forms, invites, site bootstrap command), `web/pages/machine.rs` (binding confirm).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `binding::proposes_guest_by_mac` | a probe whose interface MAC matches one guest config gets `proposed` | D93 |
  | `binding::confirm_fixes_binding` | after an admin confirms, later reports don't change `proxmox_ref` | D93 |
  | `binding::reported_mac_of_other_guest_sets_mismatch_and_event` | `mismatch` and one `machine.guest_binding_mismatch` warning; `proxmox_ref` unchanged | E50, AC60 |
  | `binding::confirm_after_mismatch_needs_admin_step_up` | a responder gets 403; an admin without fresh step-up is prompted | 7.7.2, AC60 |
  | `agentless::form_stores_credentials_in_vault_only` | the `machines` row holds a `secret:` reference, never the credential | 10 |
  | `agentless::form_join_completes_and_used_invite_refused` | the agentless form completes; a second use is refused with its reason | AC36 |
  | `add::machine_command_per_os_mode_and_level` | the command holds the ticket and a 60-minute token bound to the chosen level; the offline variant holds the script's SHA-256 | 7.3.12, FR-21 |
  | `add::device_operator_peer_invites_expire_in_24h` | each invite is single use and kind-bound | 7.3.1, FR-21 |
  | `add::admin_only` | a responder gets 403 | 7.7.2 |
  Carried in from T44:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::install::hub_ssh_test_completes_enrollment` (carried in from T44) | after a managed machine's first report the hub logs in as `rackhand` (`true`) and, unless role hub, as `rackhand-ai` (`sudo -n true`) with the pinned host key, and the Add page shows the machine enrolled and healthy; a failed test says which account | 7.3.12, AC35 |
  | `it::install::offline_variant_checks_script_hash` (moved from T44) | the hub serves `install.sh` and the release files it holds; the offline command with a wrong SHA-256 stops before running the script | 7.3.12 |
  Carried in from T48:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::drivers::form_added_simulators_report_and_silence_after_2_polls` (carried in from T48) | each simulator (Proxmox, TrueNAS, Redfish, SNMP) added through the Add page's form reports its 7.4.2 metrics; stopping it gives a silent warning after 2 polls | AC11, 7.6.3 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(binding::) | test(agentless::) | test(add::)'
  ```
  Expected: 9 passed, 0 failed.
- **Manual verification:** None.
- **Done when (in addition):** blocking of hypervisor-side actions on a mismatched binding is tested in T62.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-21 | T49a: cargo nextest run -p rackhand-hub -E 'test(binding::)' (before) | compile errors (`guest_binding` absent, `Web::with_bindings` not found) |
  | 2026-11-21 | T49a: same (after) | 4 passed: `binding::proposes_guest_by_mac` (a MAC in another case and with dashes still matches; none matching proposes nothing; a MAC two guests' configs carry proposes nothing), `binding::confirm_fixes_binding` (confirmed with who confirmed it; later reports change nothing; a guest neither bound nor seen can't be confirmed), `binding::reported_mac_of_other_guest_sets_mismatch_and_event` (another guest's MAC, or none of its own, turns it `mismatch` with one warning naming the guest seen; the binding itself doesn't move; confirming the seen guest rebinds it), `binding::confirm_after_mismatch_needs_admin_step_up` (the Machine page shows the state and both guests; a responder 403, an admin sent to `/step-up`, then confirmed and audited; a stranger guest 409) |
  | 2026-11-21 | T49a: mutation checks | each seen failing with its behaviour removed: confirming without a step-up, no mismatch event, any guest confirmable, an ambiguous MAC proposing (survived at first; the test gained the case) |
  | 2026-11-21 | T49a: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 427 passed, 1 skipped; no violations |
  | 2026-11-21 | T49b: cargo nextest run -p rackhand-hub -E 'test(add::)' (before) | compile errors (`Web::with_ticket`, `Web::with_release_dir` not found) |
  | 2026-11-21 | T49b: same (after) | 3 passed: `add::machine_command_per_os_mode_and_level` (Linux with `--ticket`, `--token`, `--monitor` and `--remote`; the token a machine's, 60 minutes, bound to the level; the pending machine's kind, access and mode; the offline variant checks the hub's own `install.sh` against its SHA-256; Alpine `wget` without sudo; Windows `install.ps1 -Ticket`; a name in use 409, an unknown OS 400), `add::device_operator_peer_invites_expire_in_24h` (each `<ticket>#<secret>` with its join hint, 24 hours, single use and bound to its kind), `add::admin_only` (a responder 403 on the page and both actions) |
  | 2026-11-21 | T49b: mutation checks | each seen failing with its behaviour removed: the level not chosen, the script's hash not taken, no device invites |
  | 2026-11-21 | T49b: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 430 passed, 1 skipped; no violations |
  | 2026-11-21 | T49c: cargo nextest run -p rackhand-hub -E 'test(agentless::)'; cargo nextest run -p rackhand-drivers -E 'test(pinned_tls::)' (before) | compile errors (`Web::with_drivers`, `pinned::presented` not found) |
  | 2026-11-21 | T49c: same (after) | 5 and 1 passed: `agentless::form_stores_credentials_in_vault_only` (the address first: the TrueNAS simulator's fingerprint shown and nothing sent to it; a wrong key, or a fingerprint other than the one shown, refused 422 and the form still usable; then the row `appliance`, `enrolled`, driver `truenas`, `api_key` as `secret:driver.<id>` and the accepted fingerprint; the Vault entry holds the key and fingerprint; no table in the database holds the key), `agentless::form_join_completes_and_used_invite_refused` (sent again with another key: 409 with its reason and the Vault entry unchanged; an expired form 410; a probe machine's install token 400 "another kind"; a probe join can't use a form's token), `agentless::proxmox_token_attaches_to_its_enrolled_host` (no second row; the enrolled host gets driver `proxmox`, its address, and `driver.<host>` with `token` and `fingerprint`, as the snapshot step reads it), `agentless::snmp_form_has_no_certificate_and_keeps_its_community_secret`, `agentless::appliance_forms_admin_only`; `drivers::pinned_tls::presented_is_the_servers_fingerprint_and_nothing_is_sent` |
  | 2026-11-21 | T49c: mutation checks | each seen failing with its behaviour removed: the row given the credentials, any fingerprint accepted, a failed first poll accepted, attaching ignored, a used form not refused before the poll; a control mutation that keeps the behaviour passed |
  | 2026-11-21 | T49c: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 436 passed, 1 skipped; no violations |
  | 2026-11-21 | T49d: cargo nextest run -p rackhand-hub -E 'test(checks::tests::agentless::) | test(probe_machine_with_an_api)' (before) | compile error (`Checks::with_agentless` not found); then, built, all 3 failed: no poll scheduled, no `machine.silent` after 2 failed polls, and a probe machine with an API attached never silent (`machine_silence` read only `driver IS NULL`, a gap T49c's attach opened) |
  | 2026-11-21 | T49d: same (after) | 3 passed: `checks::tests::agentless::polled_every_60s_with_its_vault_settings_and_kept_across_config_syncs` (the TrueNAS simulator polled with the Vault's key, not again for 60 s, its `truenas.pool.used_pct` a series of the machine; a config/checks sync neither stops the poll nor retires its row; revoked, it stops and its row gets `interval_s` 0), `checks::tests::agentless::silent_after_2_failed_polls_critical_after_5` (a revoked key: `machine.silent` warning at 2, critical at 5, no `check.failing`; after a restart it stays open in the start grace; the key put right, the next poll resolves it), `incidents::tests::probe_machine_with_an_api_still_silent_by_report` |
  | 2026-11-21 | T49d: mutation checks | each seen failing with its behaviour removed: no start grace for appliances, `check.failing` for appliances too, probe silence skipped for a machine with an API, the driver readings not stored, the Vault's settings not used, revoked machines still polled, a config sync retiring the polls (survived at first: the test gained the row's `interval_s`) |
  | 2026-11-21 | T49d: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 439 passed, 1 skipped; no violations |
  | 2026-11-21 | T49e: cargo build --workspace --all-targets (before) | compile errors (`proxmox::sim::Sim::fail_config`, `collect::interfaces`, `GuestBindings::reported`, `ProbeServer::with_bindings`, `Checks::with_bindings` not found) |
  | 2026-11-21 | T49e: cargo nextest run --workspace -E 'test(guests_op) | test(interfaces_with) | test(guest_macs::) | test(judged_when) | test(probe_directory_from_registry)' (after) | 6 passed: `proxmox::guests_op_lists_each_guest_with_its_configured_macs` (LXC 100 and VM 200 of the pve8 recording with their MACs; a guest whose configuration doesn't load fails the list), `collect::interfaces_with_their_macs_from_sys_class_net` (eth0 only: no loopback, veth or docker device, no all-zero or missing MAC), `binding::judged_when_either_the_report_or_the_guest_list_arrives` (either order proposes; a probe reporting no MACs, or only zeros, leaves a confirmed binding confirmed; another guest's MAC is still a mismatch), `checks::tests::guest_macs::proxmox_poll_feeds_the_guests_macs_to_guest_binding`, `checks::tests::guest_macs::a_guest_list_that_failed_to_load_is_not_judged`, and `hub_tests::probe_directory_from_registry` (a probe's Hello MACs reach guest binding through the probe server) |
  | 2026-11-21 | T49e: mutation checks | each seen failing with its behaviour removed: a guest whose configuration failed left out of the list, no interfaces excluded, all-zero MACs kept by the probe, an all-zero MAC judged, no MACs judged, polls not feeding guest binding, Hellos not feeding it |
  | 2026-11-21 | T49e: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 444 passed, 1 skipped; no violations |
  | 2026-11-21 | T49f: cargo nextest run -p rackhand-hub -E 'test(hub_serves_its_release_files)' (before) | failed: `/install.sh` 404 |
  | 2026-11-21 | T49f: cargo nextest run -p rackhand-it --profile it -E 'test(offline_variant_checks_script_hash)' (before the installer flag) | failed as expected: the wrong SHA-256 stopped it, and the right one ran the script, whose downloads from the hub failed on its self-signed certificate (curl 60) |
  | 2026-11-21 | T49f: same, and `install::debian_managed_enrolls_and_reports` (after) | 2 passed; `add::hub_serves_its_release_files` passed (no session needed; `install.sh` and a held binary served; a missing name, `..`, a hidden name or a path 404; the offline command passes `--release-url https://<hub>:8443/release --self-signed`; a hub holding no release files serves none) |
  | 2026-11-21 | T49f: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 445 passed, 1 skipped; no violations |
  | 2026-11-21 | T49g: cargo nextest run -p rackhand-hub --test join_contract -E 'test(machine_join_records_direct_address)' (before) | failed: `address` empty, expected `198.51.100.7` |
  | 2026-11-21 | T49g: cargo nextest run -p rackhand-hub --lib -E 'test(ssh::tests::enroll_test::)'; cargo nextest run -p rackhand -E 'test(ssh_test_after_first_report_wired)' (before) | failed to build: no `ssh::enroll_test` module, no `joins::spawn_enroll_tests` |
  | 2026-11-21 | T49g: same (after) | join contract 10 passed (a direct join records its IP; a relayed one none; a machine with a driver keeps its API address); `enroll_test` 3 passed (as `rackhand` `true` and, unless role hub, `rackhand-ai` `sudo -n true`; a failure names the account and keeps the command's error; no address fails naming `rackhand`; monitor machines aren't tested; due until a test passes and again after a join); hub wiring passed (the outcome is a `machine.ssh_test_passed` info or `machine.ssh_test_failed` warning event with the account; a failed machine is tested at its next report, a passed one isn't) |
  | 2026-11-21 | T49g: mutation, the join keeps no API address (driver filter removed) | caught: `the API's address is kept` failed |
  | 2026-11-21 | T49g: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 450 passed, 1 skipped; no violations |
  | 2026-11-21 | T49g: cargo nextest run -p rackhand-hub --lib -E 'test(lists_recently_added_machines_with_ssh_test_result)' (before) | failed: no `Recently added` list on `/add` |
  | 2026-11-21 | T49g: same, and `web::tests::add::` (after) | 5 passed (machines enrolled in the last day, newest first: `Enrolled and healthy` once the SSH test passed, the latest failure as `SSH test failed as rackhand-ai: ...`, `Waiting for the hub's SSH test`, a monitor machine `Waiting for its first report` until it reports; older machines not listed) |
  | 2026-11-21 | T49g: cargo nextest run -p rackhand-it --profile it -E 'test(hub_ssh_test_completes_enrollment)' (new image `debian-install-sshd`) | passed: the address is the container's IP; with sshd stopped the test fails naming `rackhand` and the Add page says so; with sshd started and the probe restarted the next report is tested again and passes, the Add page shows `Enrolled and healthy`, and sshd logged exactly 2 public-key logins (`rackhand`, `rackhand-ai`) |
  | 2026-11-21 | T49g: mutation, the probe server not told of Hellos (`with_greeted` removed) | caught: `not within 60s: the SSH test failed` |
  | 2026-11-21 | T49g: cargo nextest run -p rackhand-it --profile it -E 'test(install_it::) \| test(ssh_it::)' | 16 passed |
  | 2026-11-21 | T49g: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 451 passed, 1 skipped; no violations |
  | 2026-11-21 | T49h: cargo nextest run -p rackhand-it --profile it -E 'test(form_added_simulators_report_and_silence_after_2_polls)' (first run) | failed: `not within 120s: every appliance's readings on /metrics`; every poll had answered (`1 nodes, 2 guests`, `read over JSON-RPC`, `8 readings`, `7 readings`), but `Ingest::put_points` stored driver and check readings in tier 0 without adding them to the recent window, so `/metrics` and the dashboard showed them only after a restart |
  | 2026-11-21 | T49h: cargo nextest run -p rackhand-hub --lib -E 'test(polled_points_in_the_recent_window)' (before, after) | failed: window empty; then passed (both points in the window, the latest in `latest_values`, `last_seen` still none); `ingest::`, `checks::`, `incidents::` 46 passed |
  | 2026-11-21 | T49h: cargo nextest run -p rackhand-it --profile it -E 'test(form_added_simulators_report_and_silence_after_2_polls)' | passed in 210 s (1 slow): Proxmox, TrueNAS, Redfish and SNMP simulators in the test process, each added through the Add page's forms (the certificate shown and accepted, SNMP without one), each machine enrolled, each with its readings on `/metrics` (`rackhand_pve_node_cpu_pct`, `rackhand_truenas_pool_healthy`, `rackhand_redfish_temp_c`, `rackhand_snmp_if_in_octets`); with the simulators stopped every machine has an open `machine.silent` warning with 2 to 4 failed polls |
  | 2026-11-21 | T49h: mutation, a driver's own readings not stored (`reading.points` dropped in Checks) | caught: `pve1: rackhand_pve_node_cpu_pct reported` failed |
  | 2026-11-21 | T49h: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 452 passed, 1 skipped; no violations |
  | 2026-11-21 | D90 (owner): cargo nextest run -p rackhand-hub -p rackhand -E 'test(machine_managed_join) \| test(machine_monitor_join) \| test(pending_machine_is_tested) \| test(lists_recently_added) \| test(ssh_test)' (before, with `EnrollTest::passed` an empty stub) | 4 failed: the join left a managed machine `enrolled`; a pending machine wasn't tested; the Add page didn't list pending machines; the hub's wiring never enrolled it; the monitor join (already `enrolled`) passed |
  | 2026-11-21 | D90: same (after) | 8 passed: a managed machine's first join leaves it `pending`, a monitor's enrolls it; the test runs on a pending machine, a pass enrolls it, a failure leaves it pending, a revoked machine isn't touched; the Add page shows "Pending: SSH test failed as rackhand-ai: ..." and "Pending: waiting for the hub's SSH test" |
  | 2026-11-21 | D90: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(install::) \| test(join) \| test(enroll)' (first run) | 4 failed: `not within 60s: the machine's reports on /metrics`, every managed install: the hub's probe directory admitted only `enrolled` machines, so a pending machine's reports were dropped |
  | 2026-11-21 | D90: cargo nextest run -p rackhand -E 'test(probe_directory_from_registry)' (before; after) | failed `pending` (no machine for the endpoint); passed once the directory admits `pending` and `enrolled` |
  | 2026-11-21 | D90: the integration run again | 12 passed: `hub_ssh_test_completes_enrollment` sees the machine `pending` after the failed test and `enrolled` after the pass |
  | 2026-11-21 | D90: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 477 passed, 1 skipped; no violations |
  | 2026-11-21 | cargo xtask ci it (started at 4de695a, with later edits in the working tree while it ran) | 51 tests: 49 passed, 2 failed. `probe_hub::outage_backfills_and_live_stays_fresh`: `machine.ssh_test_failed` was open; since T49g the fixture's managed machine, which has no sshd or accounts, rightly fails its SSH test; the integration tier had not been run whole since T46 (1f55869). `install_it::install::hub_ssh_test_completes_enrollment`: 1 login in the journal, 2 expected; the run first put this down to the journal being read before it was flushed, which the rerun below refuted |
  | 2026-11-21 | D94: cargo nextest run -p rackhand -E 'test(ssh_test_after_first_report)' (before) | failed `retried while the machine reports`: a pending machine's test ran only when its probe connected, so one whose SSH was fixed stayed pending until a reconnect |
  | 2026-11-21 | D94: same, with `test(enroll_test::)` (after) | 5 passed, and the wiring test 10 of 10: tried again every minute while the machine reports and not while it doesn't, one test at a time, an unchanged failure recorded once, enrolled without a reconnect, no test after a pass |
  | 2026-11-21 | D94: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 494 passed, 1 skipped; no violations; the integration tier is run again on the commit |
  | 2026-11-21 | cargo xtask ci it on a clean clone of 25216cc (with other builds on the machine while it ran) | 51 tests: 48 passed, 3 failed. `install_it::install::hub_ssh_test_completes_enrollment` again, with the journal flushed: one login under `-u ssh`, its session closed, no second one, while the hub recorded a pass (open: cause not established). `probe_hub::stopped_probe_opens_silent_warning_at_60s`: no newest report, since the test reads `report_staging`, which compaction empties every 5 minutes. `mirror_it::mirror::change_pushed_within_60s_and_planted_secret_blocks`: the push passed its 60 s (load suspected, not established) |
  | 2026-11-21 | the 11 `install::` tests with two busy loops per CPU | 11 passed: the enrollment failure wasn't reproduced; the passing run's unfiltered journal has both logins and the `sudo` line. Its failure message now carries the unfiltered sshd and sudo journal and the hub's events; what it asserts is unchanged |
  | 2026-11-21 | cargo nextest run -p rackhand-it --profile it -E 'test(stopped_probe_opens_silent)' with the last report's time taken under 1 s before the stop | 1 passed; its 59 s and 80 s bounds are unchanged. cargo xtask ci fast: 502 passed, 1 skipped |
  | 2026-11-22 | cargo xtask ci it on a clean clone of c99d22f, nothing else building or testing | exit 0: 51 passed, 0 skipped. Open: `hub_ssh_test_completes_enrollment` failed its login count in 2 of the 3 full runs on 2026-11-21 and 22, both with other builds running, cause not established; the hub records a pass only after both logins exit 0 (`logs_in_as_both_accounts_unless_role_hub`), and the test's message now shows the unfiltered journal |

### L3: Live pass for M2: agentless and Proxmox
- **Design refs:** 14, D107, FR-10, AC10, AC11, AC35, AC36, AC60
- **Goal:** agentless machines, service checks and the Proxmox driver work against real machines and real Proxmox VE 8
  and 9 APIs.
- **Depends on:** T49, L2
- **Changes:** live tests only; `lab` gains a test HTTPS service on `target` with a certificate that expires in 10 days,
  and `snmpd` on `agentless` (an SNMP appliance with no probe).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `live::m2::snmp_appliance_added_by_form_reports` | `agentless`, added through the Add page's SNMP form with no probe, reports its interface metrics; a second use of the form's invite is refused | AC36, AC11 |
  | `live::m2::alpine_installs_and_reports` | the Add page's Alpine command enrolls `alpine` (OpenRC) and it reports | AC35 |
  | `live::m2::service_checks_and_certificate_warning` | HTTP and TCP checks against `target` pass; the 10-day certificate gives the certificate warning | AC10 |
  | `live::m2::proxmox8_driver_reports_node_and_guests` | the driver, with a token the test creates on `pve8`, reports the node and its two guests | AC11 |
  | `live::m2::proxmox9_driver_reports_node_and_guests` | the same on `pve9` | AC11 |
  | `live::m2::silent_proxmox_node_after_two_polls` | `lab pause pve8` makes it silent after 2 polls | AC11 |
  | `live::m2::probe_in_lxc_is_bound_to_its_guest` | a probe installed in `ct-test` on `pve9` is bound to that guest | AC60 |
- **Fails first:** `cargo xtask ci live --target local --milestone m2 --no-deploy` with the M1 build still deployed
  from L2: the SNMP, Alpine, Proxmox and binding tests fail (no drivers or Add page yet); then the M2 build is deployed.
- **Verification:**
  ```bash
  cargo xtask ci live --target local --milestone m2
  ```
  Expected: 7 passed, 0 failed.
- **Regression:** `cargo xtask ci fast`: exit 0; `cargo xtask ci live --target local --milestone m1`: 8 passed.
- **Manual verification:** the M2 page walk (Add page, machine and driver pages), done by the run as in L2.
- **Done when:**
  - [ ] New tests observed failing before the M2 deploy
  - [ ] New tests and the regression suites pass
  - [ ] M2 page walk recorded
  - [ ] Evidence recorded below
- **Risk / rollback:** if nested Proxmox didn't work in L1, the three Proxmox tests move to L9 (deviation). Revert the
  commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-21 | L3: cargo nextest run -p xtask -E 'test(machine_script_is_part_of_the_stamp)' (before, after) | failed to build: no `machine_script`; then 9 lab tests passed (`lab/provision/<name>.sh` runs at first boot and counts in the stamp; `agentless.sh` installs `snmpd` with v2c community `rackhand-lab`) |
  | 2026-11-21 | L3: cargo xtask lab up m2 | `agentless` provisioned (snmpd active); `ct-test` on `pve9` reaches the hub (`https://192.0.2.10:8443/healthz` ok) but not the release server, and has `wget` but no `curl` |
  | 2026-11-21 | L3: cargo nextest run -p rackhand-hub --lib -E 'test(machine_command_per_os_mode_and_level)' (before, after) | failed: the Alpine offline command used `curl`, which a stock Alpine machine lacks; then passed: `wget -q --no-check-certificate -O /tmp/rackhand-install.sh https://<hub>:8443/install.sh && ... && sh ...`, no `curl` on Alpine |
  | 2026-11-21 | L3: cargo xtask ci live --target local --milestone m2 --no-deploy (the L2 build still on `hub`) | 0 passed, 7 failed: `no form on /add` (no Add page forms in that build) and the checks never configured |
  | 2026-11-21 | L3: cargo xtask lab reset hub; lab reset target; cargo xtask ci live --target local --milestone m2 (pass 1) | 4 of 7 passed (SNMP form, Alpine install with the SSH test, Proxmox 8 and 9 node and guests); the silence test saw its incident but compared an escaped title; the LXC test's release copy ran `cd` outside `sudo`; the service checks found no way to edit `config/checks.toml` from the dashboard (the Library page edited runbooks and playbooks only) |
  | 2026-11-21 | L3: cargo nextest run -p rackhand-hub --lib -E 'test(library_edits_configuration_files)' (before, after) | failed: no editor at `/library/config/checks`; then passed: config files listed and edited on the Library page with their validation (`gopher` refused with the reason), admins only |
  | 2026-11-21 | L3: cargo xtask ci live --target local --milestone m2 (pass 2, fresh deploy) and the LXC test again | 6 of 7, then 7: `ct-test` (LXC 100 on `pve9`, reaching only the hub) installed from the hub's own release files with the Add page's offline Alpine command, reported, was proposed as its guest and confirmed after a step-up |
  | 2026-11-21 | L3: cargo xtask ci live --target local --milestone m1 --no-deploy (on the M2 hub) | 8 of 10: the cut counted the M2 certificate warning on `target` as stale (now only incidents opened after the cut count), and the tampered release server wasn't listening yet after 1 s (now waited for) |
  | 2026-11-21 | L3: cargo nextest run -p rackhand-hub --lib -E 'test(no_mirror_configured_raises_nothing)' (before, after) | failed to build: no `MirrorAlert::Off`; then passed, with `mirror` and the hub's event wiring 8 passed: a hub with no git mirror pushes nothing and raises nothing (it raised `git_mirror_failed` at every library change and retried hourly; seen on the lab hub) |
  | 2026-11-21 | L3: the cut test again | failed: `systemd-networkd-wait-online.service not active` (critical) on `target`: unattended-upgrades upgraded libc at 18:07 and needrestart restarted networking during the cut, so the unit really failed; the lab's `target` now has `lab/provision/target.sh` (no unattended upgrades), and the lab test checks it (seen failing without the script) |
  | 2026-11-21 | L3: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 455 passed, 1 skipped; no violations |
  | 2026-11-21 | L3: cargo xtask lab reset hub; lab reset pve9; lab reset alpine (target provisioned again); cargo xtask ci live --target local --milestone m2 | 7 passed: target installed (vitals 17.5 s, services 1.1 s, updates 17.5 s), pve8 silent 98 s after the pause and resolved after the resume |
  | 2026-11-21 | L3: cargo xtask ci live --target local --milestone m1 --no-deploy (regression, same hub) | 10 passed: the gap filled 18 s after the heal, live lag at most 1 s during the replay |
  | 2026-11-21 | M2 page walk in the in-app browser | not done: as MV12, the pane refuses the hub's self-signed certificate and only the owner can continue past the warning; the Add page, appliance forms, machine pages (guest binding) and Library were exercised over HTTPS by the live tests |

### M3: Actions

### T50: Runbook and playbook model
- **Design refs:** 7.8.7 (runbook format, step kinds, retries, resumable, detached, leading dash), 7.8.8 (playbook
  format), 7.3.7 (parameter rules), 12 (`rackhand hub runbook check`), D92, E51
- **Goal:** runbooks and playbooks parse and validate as 7.8.7 and 7.8.8 say, parameters are checked against their type
  and whole-value pattern with leading dashes refused, and the model generates the command-list templates the wrapper
  matches.
- **Depends on:** T01
- **Changes:** `crates/rackhand-runbook/src/{runbook.rs, playbook.rs, params.rs, validate.rs, templates.rs}`;
  `crates/rackhand-runbook/builtin/` (built-in runbooks and playbooks, filled in by the steps that build them);
  `rackhand hub runbook check <file>`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `runbook::compose_restart_example_parses` | the 7.8.7 example | 7.8.7 |
  | `runbook::unknown_step_kind_or_field_is_an_error_with_location` | the error names the line | 12 |
  | `runbook::retries_without_idempotent_refused` | validation error | 7.8.7 |
  | `runbook::detached_step_is_resumable` | the flag is implied | 7.8.7 |
  | `params::pattern_must_match_whole_value` | `^[a-z]+` against `abc;rm` fails because the pattern is anchored at both ends | 7.3.7 |
  | `params::leading_dash_refused_unless_allowed` | `-f` refused; accepted with `allow_leading_dash = true` | E51, AC61 |
  | `templates::commands_json_generated_from_enabled_runbooks` | one argument template per `sudo /usr/local/lib/rackhand/run` step with one regex per parameter | D92 |
  | `playbook::front_matter_and_sections_parse` | the 7.8.8 example, including `tools` and `hosts` | 7.8.8 |
  | `check_cmd::reports_sudo_coverage` | a root step with no matching template is reported | 12 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-runbook
  ```
  Expected: 9 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-runbook | compile errors: unresolved imports `crate::runbook`, `params`, `playbook`, `templates`, `check_cmd` |
  | 2026-11-19 | cargo nextest run -p rackhand-runbook | 9 passed, 0 failed |
  | 2026-11-19 | rackhand hub runbook check <file> | a step running `sudo /usr/bin/docker` directly: exit 1 naming the step and the wrapper form; through `sudo /usr/local/lib/rackhand/run`: exit 0, "1 root step, all allowed by sudo" |
  | 2026-11-19 | cargo xtask ci fast | exit 0 (fmt, clippy, arch-check: `rackhand-runbook` depends on nothing of ours; nextest 120 passed) |
  | 2026-11-19 fix | cargo nextest run -p rackhand-runbook | review found a pattern like `a)\|(.*` escaped the `^(?:...)$` wrapping and accepted `x; rm -rf /`; new assertions failed first (`Ok(())`), then: the raw pattern must compile on its own, and `check_value` always matches the same anchored regex as commands.json (an `int` with `allow_leading_dash` no longer passes `-1` where the wrapper wouldn't). 9 passed |
  | 2026-11-19 fix | cargo nextest run -p rackhand-runbook | review: step ids now follow the wrapper's job-step format (`a-z`, `0-9`, `-`); five bad ids failed first. 9 passed |

### T51: Command wrapper and signed command lists
- **Design refs:** 7.3.7 (command wrapper, command list updates), 7.3.3 (signed payload rules), D84, D92, E51, E60,
  AC57, AC61
- **Goal:** `rackhand-probe run-cmd` (installed as `/usr/local/lib/rackhand/run`) executes only commands matching the
  hub-signed `commands.json` exactly, without a shell. `run install-commands` installs a newer list only if it is signed
  by the pinned hub, is newer than the installed one, and hasn't expired.
- **Depends on:** T50, T16
- **Changes:** `crates/rackhand-probe/src/runcmd/{mod.rs, matcher.rs, install.rs}`, using the signed-payload checks
  from T16.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `runcmd::exact_template_match_executes_without_shell` | arguments with spaces and quotes reach the process as single arguments | 7.3.7 |
  | `runcmd::one_argument_different_from_every_template_refused` | refused, and nothing runs (a canary file is not created) | AC57 |
  | `runcmd::leading_dash_value_refused` | `-f` in a parameter slot is refused | E51, AC61 |
  | `install::unsigned_expired_or_not_newer_list_refused` | each case leaves `commands.json` byte-identical | E60, AC61 |
  | `install::list_signed_by_other_key_refused` | a key other than the one pinned in `probe.toml` is refused | D92 |
  | `it::runcmd::sudo_entry_runs_wrapper_only` | in a container, `rackhand` can `sudo /usr/local/lib/rackhand/run <allowed>` and can't `sudo` anything else | AC57 |
  | `it::runcmd::first_list_arrives_with_join` | after enrollment, `commands.json` equals the one from the join response | AC61 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-probe -E 'test(runcmd::) | test(install::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(runcmd::)'
  ```
  Expected: 5 passed, then 2 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-probe -E 'test(runcmd::) \\| test(install::)' | compile errors: unresolved `super::{install, matcher, spawn_capture}` and the new dependencies |
  | 2026-11-19 | cargo nextest run -p rackhand-probe -E 'test(runcmd::) \\| test(install::)' | 5 passed, 0 failed (arguments with spaces, quotes, `$(...)` and backticks reach printf as single arguments; each refused install leaves commands.json byte-identical) |
  | 2026-11-19 | cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(runcmd::)' | 1 passed: in a Debian 12 container, `rackhand` runs `sudo -n /usr/local/lib/rackhand/run /usr/bin/id -u` as root (prints 0); a request outside the list exits 126 and creates nothing; `sudo -n` of anything else fails; an unsigned `install-commands` payload is refused and the list's SHA-256 is unchanged |
  | 2026-11-19 | cargo xtask ci it; cargo xtask ci fast | exit 0 (2 passed); exit 0 (164 passed) |
  | 2026-11-19 fix | cargo nextest run -p rackhand-probe -E 'test(runcmd::)' | review: the wrapper trusted the list's anchoring; a list regex `[a-z]+` let `web;rm` through. New cases failed first; the wrapper now anchors every regex itself and refuses one that doesn't compile alone. 7 passed |

### T52: Wrapper detached steps and file receive
- **Design refs:** 7.3.7 (detached steps), 7.3.11 (`run receive`, `transfer_roots`), D97, E54, E55
- **Goal:** `run job-start` starts a matched command in its own unit (systemd or OpenRC) and returns at once;
  `job-status`, `job-clean` and `job-stop` manage it by hub-generated ids. `run receive` writes only under
  `transfer_roots` through a temporary file with a hash check.
- **Depends on:** T51
- **Changes:** `crates/rackhand-probe/src/runcmd/{detached.rs, receive.rs}`; test images: Debian with systemd as PID 1,
  Alpine with OpenRC.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `detached::ids_must_be_hub_format` | an id with `/..` or shell characters is refused | 7.3.7 |
  | `it::detached::job_survives_ssh_disconnect` | start a 30 s command, drop the SSH session; `job-status` later shows exit 0 and the full output | E54, D97 |
  | `it::detached::status_offsets_return_only_new_output` | polling at an offset returns the rest | 7.3.7 |
  | `it::detached::job_stop_ends_unit` | the unit is gone and the status is `stopped` | 7.3.7 |
  | `it::detached::openrc_variant_same_behaviour` | the first test on Alpine | 7.3.7 |
  | `it::receive::outside_transfer_roots_refused` | `/etc/passwd` as a destination is refused | 7.3.11 |
  | `it::receive::hash_mismatch_keeps_temp_and_no_rename` | the destination is untouched and the partial file is kept for resume | 7.3.11, E30 |
- **Fails first:** compile errors; the container tests fail.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-probe -E 'test(detached::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(detached::) | test(receive::)'
  ```
  Expected: 1 passed, then 6 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** systemd as PID 1 in Docker needs `--cgroupns=host` and a tmpfs on `/run`; if Docker Desktop
  refuses it, the systemd cases run in the network-tier VM instead (plan deviation). Revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-probe -E 'test(detached::)' | compile errors: unresolved `super::detached` and `super::receive` |
  | 2026-11-19 | cargo nextest run -p rackhand-probe -E 'test(detached::) \\| test(receive::)' | 2 passed (the planned ids test, and a lexical check of receive destinations added beside it) |
  | 2026-11-19 first container run | cargo nextest run -p rackhand-it -E 'test(detached::) \\| test(receive::)' | 3 passed, 3 failed: two in the tests (pgrep matched its own shell; dash's `kill` refuses `--` before a negative pid), one in the code: job-stop ran an external `kill`, which a minimal Debian doesn't have; now rustix's `kill_process`. On Alpine the test container needed `--init` so the killed session doesn't linger as zombies |
  | 2026-11-19 | cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(detached::) \\| test(receive::)' | 6 passed, 0 failed: a 10-line job survives killing its session's process group on systemd (own unit) and OpenRC (start-stop-daemon), status offsets return only new output, job-stop leaves no unit or process, /etc/passwd as a destination exits 126 and is unchanged, a part with a non-matching BLAKE3 keeps the partial file, a wrong resume offset is refused and the right one renames into place as root 0640 |
  | 2026-11-19 | cargo xtask ci it; cargo xtask ci fast | exit 0 (8 passed); exit 0 (166 passed) |
  | 2026-11-19 fix | cargo nextest run -p rackhand-it -E 'test(detached::)' | review: `job-supervise` could be replayed through sudo to run a finished step again (the new check failed first); it now claims the step once. The supervisor is started by the wrapper's fixed path (not `current_exe`, which a symlinked install would break), a failed start removes the step, and a recorded step with no process yet reads `starting`. 4 passed |

### T53: SSH system
- **Design refs:** 7.3.7 (identities, keys, host keys, command execution, quoting), FR-12 (output limits), E8
- **Goal:** the hub runs commands over SSH as the automation or assistant identity with keys from the Vault, pins host
  keys from the join (a changed key blocks actions and opens a critical incident), quotes arguments POSIX-style, and
  caps stdout and stderr at 1 MB per step with a marker.
- **Depends on:** T21, T35
- **Changes:** `crates/rackhand-hub/src/ssh/{client.rs, quote.rs, hostkeys.rs, pool.rs}`; the `PutHostKey` handler;
  T44's installer SSH check switched to this client.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `quote::posix_quoting_round_trips_hostile_strings` | property test: `sh -c 'printf %s\\n "$@"'` with quoted arguments prints them unchanged (quotes, `$()`, newlines, `*`) | 7.3.7 |
  | `hostkeys::changed_key_blocks_and_raises_critical` | `ssh.host_key_changed` critical; the connection is refused | E8 |
  | `it::ssh::runs_as_automation_and_assistant_identities` | `id -un` gives `rackhand` and `rackhand-ai` | 7.3.7 |
  | `it::ssh::output_capped_at_1mb_with_marker` | a 2 MB print gives exactly 1 MB plus the marker | FR-12, AC12 |
  | `it::ssh::from_restriction_refuses_other_source` | a connection from an address outside `from=` fails | 7.3.7 |
  | `it::ssh::accepting_new_key_needs_admin_step_up` | through the dashboard route; then actions run again | E8 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(quote::) | test(hostkeys::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(ssh::)'
  ```
  Expected: 2 passed, then 4 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub -E 'test(quote::) \\| test(hostkeys::)' | compile errors: unresolved `super::{hostkeys, keys, quote}` |
  | 2026-11-19 | cargo nextest run -p rackhand-hub -E 'test(quote::) \\| test(hostkeys::)' | 2 passed (300 random argument lists of quotes, `$()`, backticks, newlines, globs and Unicode round-trip through a real sh; a changed key is refused with one critical `ssh.host_key_changed` alert and stays refused until accepted; pins survive a reload) |
  | 2026-11-19 | cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(ssh::)' | 4 passed, 0 failed against OpenSSH in Debian 12: `id -un` gives rackhand and rackhand-ai; a 2 MB print gives 1 MiB plus the marker; a key limited to another address is refused; after the server's host keys are regenerated, actions fail, the dashboard route sends an admin without a fresh step-up to /step-up, and after a step-up accepts the key (audited) and actions run again |
  | 2026-11-19 | cargo tree -p rackhand-hub -i aws-lc-rs; -i rsa | neither is in the tree (russh 0.65 with only `ring`) |
  | 2026-11-19 | cargo xtask ci it; cargo xtask ci fast; cargo deny check | exit 0 (12 passed); exit 0 (168 passed); ok |
  | 2026-11-19 fix | cargo nextest run -p rackhand-hub -E 'test(hostkeys::)'; cargo nextest run -p rackhand-it -E 'test(ssh::)' | review: accepting a host key now names the fingerprint the admin was shown; another one gets 409 and nothing changes. 1 passed; 4 passed |

### T54: Policy: decisions and approvals
- **Design refs:** 7.6.8 (levels, risk, exceptions, step-up patterns), 7.7.2 (who approves), 7.3.6 (approval binding),
  FR-14, D20, D21, D45, D61, D74, D85, D89, D101, E22, E42
- **Goal:** `decide()` returns `Allow`, `NeedsApproval{risk, step_up}` or `Deny` exactly as 7.6.8 and 7.3.12 say.
  Approvals bind the requester, tool, target, arguments and runbook revision by hash, expire, are used once, and the
  first decision wins.
- **Depends on:** T18
- **Changes:** `crates/rackhand-hub/src/policy/{decide.rs, risk.rs, approvals.rs, exclusions.rs, exec_patterns.rs}`;
  the `PutPolicy`, `CreateApproval`, `DecideApproval`, `UseApproval`, `PutQuarantineRule` handlers.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `decide::table_levels_by_risk_by_requester` | a table of at least 60 rows covering levels 0 to 3 x low, normal, high x local, peer, personal key, assistant job | 7.6.8, FR-14 |
  | `decide::high_risk_always_approval_with_step_up` | including assistant `exec` on roles operator, relay, hypervisor | 7.6.8 |
  | `decide::monitor_machine_always_needs_approval_and_no_auto_policy` | auto-quarantine and auto-rollback give `NeedsApproval` | D89, AC58 |
  | `decide::personal_key_always_level_1` | `run_runbook` and the sensitive diagnostics need approval; `df` doesn't | D85, AC70 |
  | `decide::peer_request_auto_only_when_policy_says_and_never_high` | `peer_requests = "auto"` for normal; high still needs approval | 7.6.8 |
  | `decide::exec_step_up_patterns` | each pattern in 7.6.8 needs step-up; `zfs destroy pool/rackhand-patch-x` doesn't | 7.6.8 |
  | `exclusions::never_quarantined_roles_and_tag` | hub, operator, relay, hypervisor and `no-quarantine` are excluded before any rule | E22, D57 |
  | `approvals::hash_binds_requester_tool_target_args_revision` | changing any one field gives `approval_mismatch` | D101, E20 |
  | `approvals::used_once_and_expired_refused` | second use and expired | 7.3.6 |
  | `approvals::first_decision_wins` | two concurrent decisions: one succeeds, the other gets "already decided" | E42 |
  | `approvals::self_approval_allowed_viewer_cannot_responder_not_high` | the 7.7.2 rules | D74, AC40 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(decide::) | test(exclusions::) | test(approvals::)'
  ```
  Expected: 11 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub -E 'test(decide::) \\| test(exclusions::) \\| test(approvals::)' | compile errors: the policy items (`decide`, `Requester`, `Role`, `Approvals` and the rest) don't exist |
  | 2026-11-19 | cargo nextest run -p rackhand-hub -E 'test(decide::) \\| test(exclusions::) \\| test(approvals::)' | 11 passed, 0 failed (the decision table has 62 rows; the concurrent decision gives one success and one `AlreadyDecided`) |
  | 2026-11-19 | cargo nextest run -p rackhand-store -E 'test(put_policy)' | added for the `PutPolicy` and `PutQuarantineRule` upserts: failed with the handler stashed (unimplemented), 1 passed with it |
  | 2026-11-19 | cargo xtask ci fast | exit 0 (nextest 132 passed) |
  | 2026-11-19 fix | cargo nextest run -p rackhand-hub -E 'test(decide::)' | review found `sudo -u root shutdown` and `bash -c 'mkfs ...'` slipped through (only the first word was matched); four new cases failed first, then every word position is tried as a command start. 6 passed |

### T55: Actions and Executor
- **Design refs:** FR-12, 7.2 (Actions single coordinator), 7.3.7, 7.3.8 (`JobFinished`), 7.8.7 (step kinds), 9 (each
  step recorded before it runs), D97, E44, E49, E54, E55, AC12, AC50
- **Goal:** Actions runs every job with one job per machine (a second waits up to 60 s, then `machine_busy`), records
  each step before it runs, and executes `ssh`, `verify`, `wait_report`, `probe_check`, `reboot_if_required`, `api` and
  `notify` steps with timeouts. Detached steps are polled, monitor machines refuse account steps with `monitor_only`,
  and `JobFinished` is published.
- **Depends on:** T52, T53, T54, T24
- **Changes:** `crates/rackhand-hub/src/actions/{coordinator.rs, locks.rs, jobs.rs}`;
  `crates/rackhand-hub/src/executor/{steps/*.rs, detached.rs, verify.rs}`; the `CreateJob`, `UpdateJobStep`, `FinishJob`
  handlers.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `actions::second_job_waits_60s_then_machine_busy` | injected clock | AC50 |
  | `actions::step_recorded_before_it_runs` | a crash injected inside the step leaves a `running` step row | 9 |
  | `actions::monitor_machine_ssh_step_fails_monitor_only_before_sending` | no SSH connection attempted | E49, AC58 |
  | `actions::jobs_and_approvals_are_audited` | audit rows for start, finish and approval use | FR-26 |
  | `it::executor::step_timeout_fails_with_timeout` | a `sleep 600` with a 5 s timeout | AC12 |
  | `it::executor::output_over_1mb_cut_with_marker_in_job_log` | the job log shows command, exit code and output | AC12 |
  | `it::executor::detached_step_timeout_not_killed_machine_locked` | job `timed_out`, incident open, the machine stays locked until the unit exits and its result is recorded | E55 |
  | `it::executor::ssh_cut_during_detached_step_recovers` | the connection is dropped; polling resumes and the result is recorded | E54 |
  | `it::executor::second_job_of_any_kind_waits_then_machine_busy` | an assistant-exec job submitted to Actions while a runbook runs waits 60 s, then fails `machine_busy` | AC50 |
  | `actions::concurrent_execs_of_one_job_keep_their_own_rows` (added in the run) | two execs of one assistant job on two machines leave two step rows | 9 |
  | `tests::writer::job_rows_created_stepped_and_finished_once` (store, added in the run) | a step row recorded before it runs keeps its command when the result fills in; the first `FinishJob` wins | 9 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(actions::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(executor::)'
  ```
  Expected: 4 passed, then 5 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-store -E 'test(job_rows)' | `Unimplemented("CreateJob")` |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub -E 'test(actions::)' | compile errors: unresolved `super::runner`, `super::Actions`, `DEFAULT_LOCK_WAIT` |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-it -E 'test(executor::)' | compile errors: unresolved `rackhand_hub::executor::Executor`, `executor::commands` |
  | 2026-11-19 | cargo nextest run -p rackhand-hub -E 'test(actions::)' | 5 passed (the 4 planned and the concurrent-exec test) |
  | 2026-11-19 | cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(executor::)' | 5 passed, against systemd, sshd and the wrapper in a container: the runbooks become a signed command list installed by `run install-commands`, then plain and detached steps run through it. The first run failed the cut test because `pkill -f` matched its own shell; fixed in the test |
  | 2026-11-19 review | same two commands | review: a busy machine now leaves a `failed`/`machine_busy` job row with `JobFinished`; a timed-out plain step is stopped on the machine (with the old code the test's new check failed: `sleep 600` was still running after `timed_out`); concurrent execs of one job no longer share a row (the new test failed with the old ids); a refused `job-status` ends the step; a store error still finishes the job. 5 passed; 5 passed |
  | 2026-11-19 | cargo xtask ci fast; cargo xtask ci it; cargo xtask arch-check; cargo deny check; cargo audit | exit 0 (183 passed); exit 0 (19 passed); no violations; ok; 2 allowed warnings (chrono, basic-toml unmaintained) |
  | 2026-11-19 review | cargo nextest run -p rackhand-it -E 'test(executor::)' | `executor::wrapped_step_timeout_stops_root_command` (added): a timed-out `sudo <wrapper> /bin/sleep 601` step is stopped on the machine as well; without the D33 prefix it failed (still running after 15 s). 6 passed |
  | 2026-11-19 scope | - | Only `ssh` steps (plain and detached) and assistant `exec` execute in T55. `wait_report`, `verify`, `probe_check`, `reboot_if_required`, `api` and `notify` fail `<kind>_unavailable` until their systems exist; their tests are carried into T33, T42, T46, T47 and T59, and E55's incident into T57 (D32) |

### T56: Library and git mirror
- **Design refs:** FR-24, 7.3.13 (layout, pre-push scan, debounce, restore), D33, E40, AC38, S7 finding
- **Goal:** runbooks, playbooks and configuration are stored with revisions and drafts, built-ins are loaded, and every
  change is pushed to the configured git repository within 60 s with no secret values. A planted secret blocks the push
  and raises a critical audit event.
- **Depends on:** T50, T21, T07
- **Changes:** `crates/rackhand-hub/src/library/{items.rs, revisions.rs, drafts.rs, builtins.rs, mirror.rs, scan.rs}`
  using the library chosen in T07; `rackhand hub restore-library <repo>`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `library::edit_creates_revision_and_keeps_history` | rev increments; old content readable | FR-24 |
  | `library::invalid_runbook_refused_on_save_with_errors` | the T50 validation errors are returned | 12 |
  | `scan::refuses_each_secret_kind` | Vault values, PEM and OpenSSH private keys, Discord webhook URLs, AWS keys, `password = "..."` | E40, AC38 |
  | `scan::allows_secret_references` | `secret:name` passes | 7.3.13 |
  | `mirror::layout_matches_design` | the files in 7.3.13 with a generated README | 7.3.13 |
  | `mirror::debounced_30s_commit_message_user_summary` | two changes 10 s apart give one commit | 7.3.13 |
  | `it::mirror::change_pushed_within_60s_and_planted_secret_blocks` | against a bare repository in an `sshd` container | AC38 |
  | `it::mirror::failed_push_raises_warning_and_retries_hourly` | `git_mirror_failed` | 7.3.13 |
  | `library::changes_are_audited` | audit rows | FR-26 |
  | `settings::git_mirror_url_and_deploy_key_in_vault` | the deploy key is generated into the Vault and its public half shown | 7.7.1, 7.3.13 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(library::) | test(scan::) | test(mirror::) | test(settings::git_mirror)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(mirror::)'
  ```
  Expected: 8 passed, then 2 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub -E 'test(library::)' | compile error: unresolved `super::items` |
  | 2026-11-19 | cargo nextest run -p rackhand-hub -E 'test(library::) \\| test(scan::) \\| test(mirror::) \\| test(settings::git_mirror)' | 9 passed, 0 failed (the 8 planned and `restore_reads_the_layout_back`, seen failing first: no `restore`) |
  | 2026-11-19 | cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(mirror::)' | 2 passed: against a git server over SSH (git-shell, non-fast-forward refused), a saved runbook is pushed in under 60 s with message `admin: add runbook/compose-restart` and a README; a planted AWS key blocks the next push (nothing pushed, `git_mirror.secret_blocked` audited as critical); a push to a closed port gives `git_mirror_failed` (warning) with the retry an hour later. These two were written after the mirror code, so they weren't seen failing first |
  | 2026-11-19 | cargo xtask ci it; cargo xtask ci fast; cargo deny check | exit 0 (14 passed); exit 0 (177 passed); ok |

### T57: Incident routing to runbooks and attempt limits
- **Design refs:** 7.5.2 (routing precedence, job success isn't the end, attempt limits), 7.6.8 (level 0 tell), D96,
  E56, E57, AC64
- **Goal:** an open incident starts the most specific matching runbook through `StartJob` (machine, then tag, then
  kind, then general; ties by name). A succeeded job waits up to 10 minutes for the condition to clear. Automatic starts
  are limited to 2 per incident per 24 hours, and past the limit the incident goes to a person with "attempt limit
  reached".
- **Depends on:** T32, T55
- **Changes:** `crates/rackhand-hub/src/incidents/{routing.rs, attempts.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `routing::most_specific_runbook_wins_ties_by_name` | table of precedence cases | 7.5.2 |
  | `routing::level_0_tells_a_person_without_running` | state `human`, note names the runbook | 7.6.8 |
  | `routing::level_1_creates_approval_and_waits` | job `waiting_approval` | 7.6.8 |
  | `routing::success_waits_for_clear_then_failed_after_10_min` | condition never clears: routed as failed | E57, AC64 |
  | `attempts::two_automatic_starts_per_24h_then_human` | the third reopen goes to a person with the note | E56, AC64 |
  | `attempts::person_started_jobs_not_counted` | a dashboard start doesn't count | 7.5.2 |
  | `attempts::limits_count_across_reopens` | reopen keeps the count | 7.5.2 |

  Carried in from T55 (E55's incident; T55 checks the `JobFinished(TimedOut)` it opens from):
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `incidents::timed_out_detached_step_opens_incident` | `JobFinished(TimedOut)` for a job whose detached step is still running opens an incident; the machine stays locked until the step's result is recorded | E55 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(routing::) | test(attempts::)'
  ```
  Expected: 7 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-21 | T57: cargo nextest run -p rackhand-runbook -p rackhand-hub -E 'test(targets_name_machines) \| test(routing::) \| test(attempts::) \| test(timed_out_detached_step_opens_incident)' (before) | failed to build: no `targets.machines`, no `incidents::routing` |
  | 2026-11-21 | T57: same (after) | 10 passed: precedence machine, tag or role, kind, general, ties by name, targets that leave the machine out and non-automatic or other-kind triggers not candidates; level 0 tells a person with the runbook named; level 1 asks for an approval bound to `incident:<id>` and starts with it once approved (a rejection goes to a person); a succeeded job's incident waits 10 minutes, then a person has it ("persists"), one cleared in time stays resolved; a failed job goes to a person; 2 automatic starts per 24 hours across reopens, then "attempt limit reached"; a person's job not counted; a timed-out job opens `job.timed_out` on its machine |
  | 2026-11-21 | T57: mutation, no attempt limit | caught: `two_automatic_starts_per_24h_then_human` failed |
  | 2026-11-21 | T57: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 465 passed, 1 skipped; no violations (Incidents uses only `actions::StartJob`) |

### T58: Dashboard: approvals, jobs, library, patching
- **Design refs:** 7.7.1 (Approvals, Jobs, Library, Patching pages), 7.7.2, FR-14, AC40, E42
- **Goal:** people approve and reject in the dashboard with the exact action, target, arguments, risk, requester and
  reason shown, with step-up for high risk. They see job runs, steps and output, edit library items with diffs and
  validation, and see patch windows and results.
- **Depends on:** T55, T56, T37
- **Changes:** `crates/rackhand-hub/src/web/pages/{approvals.rs, jobs.rs, library.rs, patching.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `pages::approval_shows_exact_arguments_and_hash` | every bound field rendered | 7.7.1 |
  | `pages::high_risk_approve_prompts_step_up` | without fresh step-up, a prompt; with it, approved | FR-14 |
  | `pages::viewer_cannot_approve_responder_cannot_approve_high` | 403 for both | AC40 |
  | `pages::second_decision_shows_already_decided` | E42 surface | E42 |
  | `pages::job_page_shows_commands_exit_codes_output` | with the 1 MB marker | AC12 |
  | `pages::library_diff_and_validation_errors` | rendered | 7.7.1 |
  | `pages::nothing_waiting_empty_state` | "Nothing waiting" | 7.7.1 |
  | `pages::policy_and_window_editing_admin_only_revisioned` | an admin edits a policy and a maintenance window; a revision is stored and mirrored; a responder gets 403 | 7.7.1, 7.8, D33 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(pages::approval) | test(pages::high_risk) | test(pages::viewer) | test(pages::second_decision) | test(pages::job_page) | test(pages::library) | test(pages::nothing_waiting) | test(pages::policy_and_window)'
  ```
  Expected: 8 passed, 0 failed.
- **Manual verification:** the M3 page walk, done by the run in L4.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub -E 'test(pages::)' | 8 failed: no such routes (404 where the pages were expected) |
  | 2026-11-19 | cargo nextest run -p rackhand-hub -E 'test(pages::approval) \| test(pages::high_risk) \| test(pages::viewer) \| test(pages::second_decision) \| test(pages::job_page) \| test(pages::library) \| test(pages::nothing_waiting) \| test(pages::policy_and_window)' | 8 passed: an approval shows its id, tool, target, every argument, runbook revision, risk, requester, reason and SHA-256; a high-risk approve without a fresh step-up goes to `/step-up` and stays pending, then approves (audited); a viewer and a responder deciding high risk get 403, and a viewer sees no buttons; the second decision gets 409 "already decided"; a job page shows the command, `exit code 3`, the 1 MiB marker, and escapes the output; the library shows a line diff between revisions, a change that doesn't validate is refused (400) with its text kept, and an assistant's draft is applied by an admin (a responder gets 403); "Nothing waiting" when empty; an admin's policy and window are rows and a revision of `config/policies.toml` that the mirror renders, a bad window rule is 400, and a responder gets 403 |
  | 2026-11-19 | cargo xtask ci fast; cargo xtask arch-check | exit 0 (230 passed); no violations |

### T59: Patching
- **Design refs:** FR-13, G4, 7.5.3 (steps 1 to 6 and 9), D28, D45, D54, D66, D67, E9, E10, E11, E12, AC19, AC20, AC63,
  S4 finding
- **Goal:** each window selects managed `auto` machines with pending updates that aren't in a maintenance window or
  quarantined, with at most 3 per site and hypervisors and the hub last. `patch-debian` and `patch-alpine` run:
  1. precheck;
  2. snapshot, keeping 3;
  3. record services, containers and mounts;
  4. detached update and install;
  5. reboot if required;
  6. wait for a report;
  7. verify.

  A failure opens `patch_failed`, and auto-rollback applies only under D45.
- **Depends on:** T55, T34, T47, T12
- **Changes:** `crates/rackhand-hub/src/actions/patching/{select.rs, approve_only.rs, verify.rs, rollback.rs}`;
  `crates/rackhand-runbook/builtin/{patch-debian.toml, patch-alpine.toml}`; a fake package manager image for tests
  (`tests/it/images/fakepkg/`) whose update takes 60 s and can be told to fail, hold a lock, or need a reboot.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `select::auto_pending_not_maintenance_not_quarantined_managed_only` | table cases, including a monitor machine skipped | FR-13, AC58 |
  | `select::max_3_per_site_hypervisors_and_hub_last_one_at_a_time` | ordering | 7.5.3 |
  | `select::hold_never_patched` | `hold` machines never selected; pending updates still reported | E10, AC20 |
  | `select::approve_only_approval_expires_at_window_end_late_approval_waits` | next window picks it up | AC20 |
  | `select::offline_machine_retried_every_15_min_until_window_end` | injected clock | 7.5.3 |
  | `select::alpine_only_in_full_window` | not selected in the security window | D54 |
  | `precheck::snapshot_unsupported_fails_unless_optional` | `snapshot_unsupported` | E12 |
  | `precheck::unconfirmed_guest_binding_fails_unless_optional` | `guest_binding_unconfirmed` | 7.3.12 |
  | `rollback::only_when_no_report_15_min_auto_rollback_on_not_hub` | all four conditions in D45 | E11, D45 |
  | `rollback::defaults_auto_rollback_off_no_reboot_windows_desktop` | defaults from 7.5.3 step 9 | D67 |
  | `it::patch::debian_full_flow_with_fake_package_manager` | precheck, record, update, install, reboot, wait, verify; job log shows each step | AC19 |
  | `it::patch::apt_lock_waits_10_min_then_fails_without_changes` | with a shortened wait for the test, the job fails before any change | E9 |
  | `it::patch::verify_fails_on_missing_required_mount` | `patch_failed` opens | D66, AC21 |
  | `it::patch::ssh_cut_during_install_finishes_and_verifies` | same, with the connection cut | AC63 |
  | `it::patch::no_patch_or_silence_alert_during_maintenance_window` | nothing patches and no silence incident opens | AC20 |

  Carried in from T55 (the Executor passes these step kinds to the system that owns them; until then they fail `<kind>_unavailable`):
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::executor::reboot_if_required_reboots_only_when_flagged` | the step reboots when the latest report has `reboot_required` and waits for the next report; otherwise it does nothing | 7.8.7 |

  Carried in from T58:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `pages::patching_shows_pending_updates_per_machine` (carried in from T58) | the patching page lists each machine's pending updates from its latest report, and the holds | 7.7.1 |
  Carried in from T32b:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `incidents::no_silence_during_maintenance_or_reboot_wait` (carried in from T32b) | machine silence's context gets the maintenance window and the reboot job's wait from the scheduler and Actions, so neither raises `machine.silent` | 7.6.3, AC20 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(select::) | test(precheck::) | test(rollback::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(patch::)'
  ```
  Expected: 10 passed, then 5 passed; 0 failed. (The hub-restart half of AC63 is tested in T65, after restart
  recovery exists.)
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** first in the local lab (L4); then on real hardware MV7 (AC19 on a real Proxmox guest: snapshot `rackhand-patch-*` taken, pruned to 3, updates
  installed, reboot, verify; E11 reboot loop with `auto_rollback` on a test guest).
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-21 | T59a: cargo nextest run -p rackhand-hub --lib -E 'test(select::)' (before) | failed to build: no `Candidate`, `eligible`, `How`, `Order`, `Run` |
  | 2026-11-21 | T59a: same (after) | 6 passed: managed `auto` machines with updates pending for the window, outside maintenance and quarantine (monitor, maintenance, quarantine and nothing pending each left out); `hold` never; approve-only asks once with the approval expiring at the window's end, starts when approved in the window, a decision after the end starts nothing until the next window, which runs a machine carrying it; 3 per site at once, the hypervisor after every other machine at its site, alone, the hub last; offline at its turn, tried every 15 minutes until the window ends; Alpine only in the full window (one fix to the test's own sequence: it marked a machine finished that hadn't started) |
  | 2026-11-21 | T59a: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 471 passed, 1 skipped; no violations |
  | 2026-11-21 | T59b: cargo nextest run -p rackhand-hub --lib -E 'test(precheck::) \| test(rollback::)' (before) | failed to build: no `Facts`, `Guest`, `precheck`, `Failure`, `Defaults`, `defaults` |
  | 2026-11-21 | T59b: same, with `select::` (after) | 11 passed: on any machine 1 GB free on `/`, a report, no package lock, no other job and no open critical incident, whatever the snapshot policy; on a guest an unconfirmed binding (`guest_binding_unconfirmed`), storage that can't snapshot (`snapshot_unsupported`) or a datastore under 10% or 5 GB free (`datastore_low`) stop it under `required` and become a "patched without a snapshot" note under `optional`; rollback only with no report 15 min after the reboot, `auto_rollback`, not the hub and a snapshot taken; defaults `snapshot` required, `auto_rollback` off, `auto_reboot` off for `windows`, `desktop`, `hypervisor` and `hub` |
  | 2026-11-21 | T59b: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 476 passed, 1 skipped; no violations |
  | 2026-11-21 | T59c1: cargo nextest run -p rackhand-runbook -p rackhand-hub -E 'test(builtin) \| test(patch_tests::)' (before) | failed to build: no `crate::builtin`; with the module and an empty `Library::seed`: 7 failed (`unknown_check:patch_precheck`, `unknown_check:record_state`, nothing seeded, ...) |
  | 2026-11-21 | T59c1: same, with `test(verify_step)` (after) | 10 passed: `patch-debian` and `patch-alpine` have precheck, snapshot, record, update and install (detached, through the wrapper, apt `-o DPkg::Lock::Timeout=600` with `DEBIAN_FRONTEND=noninteractive` by `/usr/bin/env`, `upgrade --with-new-pkgs` keeping changed config files; apk `--wait 600`), reboot if required, wait for a report, verify; seeded with origin `builtin`, a newer built-in replacing an unedited one and an admin's edit kept; `patch_precheck` judged once (`no_report`, `root_disk_low`, `open_critical_incident`, not for the security-updates incident); `record_state` then `as_recorded` naming a stopped service or container, and failing without a record; `required_mounts` from the policy; `bound_checks` only with a result from after the step started (one fix on the way: a vanished mount looked present in the recent window when two reports fell on one tick, so the latest report now keeps its mounts) |
  | 2026-11-21 | T59c1: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 489 passed, 1 skipped; no violations |
  | 2026-11-21 | T59c2: cargo nextest run -p rackhand-drivers -p rackhand-hub --features rackhand-drivers/sim -E 'test(snapshots_op) \| test(snapshot_room) \| test(patch_snapshot::)' (before) | failed to build: no `Sim::set_storage` (and no `snapshots` or `snapshot_room` operation) |
  | 2026-11-21 | T59c2: cargo nextest run -p rackhand-hub -E 'test(patch_snapshot::)' with the runner and precheck changes held back | 2 failed: a patch job's snapshot on a machine that isn't a guest failed `not_a_proxmox_guest`; no `rackhand-patch-*` name |
  | 2026-11-21 | T59c2: cargo nextest run -p rackhand-drivers --features sim -E 'test(proxmox::)'; cargo nextest run -p rackhand-hub -E 'test(patch_snapshot::) | test(snapshot_and_rollback) | test(precheck::)' (after) | 8 passed; 6 passed: `snapshots` lists a guest's snapshots without `current`; `snapshot_room` names each storage the disks use (the cloud-init CD left out) with type, free and total and whether it can snapshot (ZFS yes; a directory only for a VM's qcow2); a patch job's snapshot passes with a note on a machine that isn't a guest, fails `guest_binding_unconfirmed`, `snapshot_unsupported` or `datastore_low` under `required` and goes on without a snapshot under `optional`, without any write to the hypervisor; it is `rackhand-patch-<YYYYMMDD-HHMM>`, the oldest of 4 patch snapshots pruned and the admin's own kept, and the job's rollback goes back to it |
  | 2026-11-21 | T59c2: cargo nextest run -p rackhand-store -E 'test(policy_defaults)' (before; after) | failed `("optional", 0)`; passed: a policy's `snapshot` defaults to `required` (7.5.3 step 9; the baseline schema had `optional`) |
  | 2026-11-21 | T59c2: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 494 passed, 1 skipped; no violations |
  | 2026-11-21 | T59c3: cargo nextest run -p rackhand-hub --lib -E 'test(driver::tests) \| test(scheduler::patching) \| test(other_runs)' (before, with stubs) | 8 failed on behaviour: no job started, no approval asked for, no window open, the other runs' jobs not counted |
  | 2026-11-21 | T59c3: cargo nextest run -p rackhand-hub --lib -E 'test(driver::tests) \| test(scheduler::) \| test(select::)' (after) | 19 passed: the windows open now by policy and site timezone with the defaults; each kind's runbook started, leaving out hold, maintenance, quarantine, pending machines and kinds and roles without a runbook yet; 3 at once per site across policies; once per window, also after a hub restart; offline tried again after 15 min; approve-only asked once, started with an approval Actions accepts; a late approval starts nothing until the next window, which doesn't ask again (one expectation fixed on the way: a policy with an unreadable security time still has its default full window) |
  | 2026-11-21 | T59c3: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 502 passed, 1 skipped; no violations |
  | 2026-11-22 | T59d: cargo nextest run -p rackhand-runbook -E 'test(reboot_step_adds)'; cargo nextest run -p rackhand-it --profile it -E 'test(reboot_if_required)' (before) | failed: no `/sbin/reboot` in the command list; failed `reboot_if_required_unavailable` |
  | 2026-11-22 | T59d: cargo nextest run -p rackhand-it --profile it -E 'test(executor::)' (after) | 9 passed: no flag, no reboot; a flag and a policy without `auto_reboot` goes on without one and the log says so; with it, once as root through the wrapper, ending when the machine is back; not back in time fails `no_report_after_reboot` |
  | 2026-11-22 | T59d: a machine that goes on reporting after the reboot command (before; after) | failed `no_report_after_reboot`, the reason a guest is rolled back for; then `did_not_reboot`, 1 passed |
  | 2026-11-22 | T59d: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 503 passed, 1 skipped; no violations. The facts behind the step (the policy, and whether the machine started again) aren't wired in the hub yet |
  | 2026-11-22 | T59c3: cargo nextest run -p rackhand-runbook -p rackhand-hub --lib -E 'test(failed_patch_opens) \| test(rolls_back_only) \| test(rollback_job_uses) \| test(rollback_runbook)' (before) | 4 failed: no `patch_failed`, no rollback job, the rollback of another job's id went to a made-up snapshot name, no `rollback` runbook |
  | 2026-11-22 | T59c3: cargo nextest run -p rackhand-runbook -p rackhand-hub --lib -E 'test(failed_patch_opens) \| test(rolls_back_only) \| test(rollback) \| test(routing::) \| test(driver::tests)' (after) | 23 passed: a patch job that fails opens one `patch_failed` per machine and a later success resolves it, a cancelled one opens none; rolled back only after `no_report_after_reboot` with `auto_rollback` and a snapshot, once, the machine kept busy until it ends; the `rollback` runbook goes back to the named job's snapshot and fails `no_snapshot` when that job took none or was another machine's |
  | 2026-11-22 | T59c3: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 507 passed, 1 skipped; no violations |
  | 2026-11-22 | cargo xtask ci it on a clean clone of 388c641, nothing else building or testing | exit 0: 52 passed, 0 skipped |
  | 2026-11-22 | T59d: cargo nextest run -p rackhand -E 'test(hub_cmd::patching)' (before, with a stub; after) | 2 failed; 2 passed: heard from within 60 s or 4 intervals, pending from the last summary, maintenance by tag; `auto_reboot` from the policy or the 7.5.3 defaults; back only with a report from a machine that started after the reboot was asked for, by its uptime |
  | 2026-11-22 | T59d: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 509 passed, 1 skipped; no violations. The hub runs the reboot step now (15 min to report again); the window loop is still off |
  | 2026-11-22 | T59d: real apt and apk with a lock held (`tests/it/images/fakepkg`, the OpenRC image) | `apt-get -o DPkg::Lock::Timeout=20 update` with the lists' lock held: exit 100 at once, no wait (T59c1 had said it waits; the probe's own 6-hourly refresh holds that lock); `upgrade` with dpkg's frontend lock held: waits its timeout, then fails with nothing changed, or goes on; `apk --wait 20` waits for the lock |
  | 2026-11-22 | T59d: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(patch::)' (before the update step waited) | 3 passed, 1 failed: `/var/lib/apt/lists/lock: waited 3.3 s` |
  | 2026-11-22 | T59d: same (after) | 4 passed: every step in order with real apt, a reboot asked for and made once, no snapshot on a machine that isn't a guest; either of apt's locks held for the whole wait fails the job with nothing changed, the lists' lock held for less goes on; a missing required mount fails the verify and opens `patch_failed`; SSH cut during the install, its output and exit code recorded and the verify reached |
  | 2026-11-22 | T59d: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 509 passed, 1 skipped; no violations |
  | 2026-11-22 | cargo xtask ci it on a clean clone of 5dff0bd, nothing else building or testing | 56 tests: 53 passed, 3 failed (the four `patch::` tests passed). `standby_key_signature_accepted` and `debian_managed_enrolls_and_reports`: systemd hadn't booted in 60 s, its journal still flushing, while a dozen unrelated tests ended within seconds of each other; `callouts::disk_rule_callouts_and_resolution`: no critical on Discord in 390 s |
  | 2026-11-22 | The machine's clock, measured: WSL's monotonic clock counts 22.14 s in 20.13 s of Windows time (kernel tick 11000, normally 10000), and its wall clock is stepped forward 1.8 s and back 4.5 s about every 30 s by the time service, which says it is 4.5 s off; journald in the test containers logged `Time jumped backwards, rotating`, 11 of them during the run on 25216cc and none during the two green runs | The environment isn't fit for timed tests until it is fixed. Every timed figure taken here since it began is up to 10% off. It is the likely cause of the failures above and of the missing sshd journal lines (D94), the mirror's 60 s and the OpenSSL build's `modification time in the future`; none is proven until the tier runs on a sound clock |
  | 2026-11-22 | T59e: cargo nextest run -p rackhand-hub -p rackhand -E 'test(no_silence) ...' (before) | compile errors (no `Quiet`, `awaiting_reboot`, `Expected`, window loop); `driver::maintenance_after_selection_holds_the_machine_back` failed on its assertion (4 jobs started, not 3) |
  | 2026-11-22 | T59e: same (after) | 34 patching tests passed, among them `incidents::no_silence_during_maintenance_or_reboot_wait`, `silence_open_before_maintenance_stays_until_a_report`, `no_silence_event_or_agentless_silence_in_maintenance`, `actions::awaiting_reboot_until_the_wait_step_ends`, `pages::patching_shows_pending_updates_per_machine`, `hub_cmd::patching::no_patch_or_silence_alert_during_maintenance_window` and `window_loop_starts_the_patch_job` |
  | 2026-11-22 | T59e: each behaviour broken in turn in a copy of the tree | unchanged: 8 passed; maintenance ignored, reboot wait ignored, an open incident resolved by the suppression, the wait held to the job's end, a rollback not counted, maintenance not asked at a machine's turn, the loop telling the driver nothing, revoked machines listed: each made at least one of the 8 fail |
  | 2026-11-22 | T59e: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 518 passed, 1 skipped; no violations (first stopped by RUSTSEC-2026-0592, published today: url 2.5.8 to 2.5.9, with form_urlencoded 1.2.3) |
  | 2026-11-22 | The clock again after a WSL restart | the rate is right: 64.26 s counted in 64.22 s of Windows time, kernel tick 10000. The wall clock is still stepped 5.2 s forward and back every few seconds: the Windows host's clock is 5.22 s ahead of two internet time servers (its time service is stopped; last event 2026-11-16), and the virtual machine's host time sync and systemd-timesyncd each set their own time. The row above on the clock judged the host's clock by its rate only. Timed and integration work waits until the host's clock is set |
  | 2026-11-22 | cargo xtask ci it on a clean clone of ebdd86f, the host's clock set (both clocks sound before and after, no jumps) | 56 tests: 51 passed, 5 failed, all `systemd didn't finish booting in 60 s` with `systemd-journal-flush` running; groups of unrelated tests ended within 0.03 s of each other. So the clock wasn't the cause of those, as the rows above supposed; `callouts::` passed |
  | 2026-11-22 | The same containers' tests again with the disk sampled every 2 s (33 tests, 4 failed) | up to 4.4 GB waiting to be written within seconds of the start; the host's SSD then wrote 85 MB/s, and 13 MB/s at 1 s a write for a minute; every sync waited behind it. The writes are the unstripped probe (267 MB; 37 MB stripped) copied or downloaded into each of two dozen containers |
  | 2026-11-22 | The same with stripped binaries in the containers | 33 passed, most in 8 to 30 s (before: 75 to 258 s); at most 150 MB waiting to be written |
  | 2026-11-22 | cargo xtask ci it on a clean clone of da8df7a, the disk sampled every 2 s | 56 tests in 1662 s (before: 2316 s): 55 passed, every container booted; at most 363 MB waiting to be written and no sample over 60% blocked. 1 failed: `callouts::disk_rule_callouts_and_resolution`, the critical after 225 s where the test asks for 240 s (D101) |
  | 2026-11-22 | cargo xtask ci it on a clean clone of 14520f2, the disk sampled every 2 s | exit 0: 56 tests, 56 passed (2267 s; the callout test ran to its end, 841 s). No sample over 60% blocked; at most 1.1 GB waiting to be written with containers running. The boot waits, the login count (D94) and the mirror passed in this run and in the one before, after the binaries were stripped (D100); the login count isn't shown to have had that cause. Live: L4 |

### T60: Hypervisor and hub-host patching
- **Design refs:** 7.5.3 (steps 7 and 8), E13, E14, E62, AC73, S4 finding (upgrade command)
- **Goal:** `patch-proxmox-host` installs without rebooting and asks for a high-risk approval listing every guest when
  a reboot is needed (never two hosts of one cluster in one window). `patch-hub-host`, and a reboot of the hypervisor
  hosting the hub, schedule the reboot 60 s out and resume at verify after the hub restarts.
- **Depends on:** T59
- **Changes:** `crates/rackhand-runbook/builtin/{patch-proxmox-host.toml, patch-hub-host.toml}`;
  `crates/rackhand-hub/src/actions/patching/hypervisor.rs`; resume logic in `actions/coordinator.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `hypervisor::reboot_needs_high_risk_approval_listing_guests` | the approval lists every guest from the simulated API | E13 |
  | `hypervisor::approval_names_hub_when_hub_is_a_guest` | from the confirmed binding | E62, AC73 |
  | `hypervisor::two_cluster_members_never_rebooted_same_window` | the second waits | 7.5.3 |
  | `hypervisor::uses_upgrade_command_from_spike` | the command recorded in T12 | S4 |
  | `it::hubhost::reboot_scheduled_60s_job_resumes_at_verify` | in a systemd container that is restarted: job ends `succeeded` after verify | E14 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(hypervisor::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(hubhost::)'
  ```
  Expected: 4 passed, then 1 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** first in the local lab (L4); then, if the owner names a hypervisor hosting a test
  hub, MV8 (AC73 and E62: the owner approves a reboot of the hypervisor hosting a test hub; the
  job finishes at verify).
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-22 | T60a: cargo nextest run -p rackhand-runbook -p rackhand-hub -E 'test(host_runbooks) | test(hypervisors_and_the_hub_host)' (before) | 2 failed: `patch-proxmox-host is built in`; no job for the hypervisor |
  | 2026-11-22 | T60a: cargo nextest run -p rackhand-runbook -p rackhand-hub -p rackhand -E 'test(builtin) | test(driver) | test(select) | test(patching) | test(library)' (after) | 48 passed, among them `host_runbooks_follow_the_designed_steps`, `driver::hypervisors_go_last_with_their_own_runbook` and the hypervisor lines of `reboot_facts_from_the_policy_and_uptime` |
  | 2026-11-22 | T60a: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 520 passed, 1 skipped; no violations |
  | 2026-11-22 | T60b: the new tests (before) | compile errors (`Sim::set_nodes`, the `hypervisor` module, `Driver::with_hosts`); `reboot-host` not built in. `driver::hypervisor_two_cluster_members_never_rebooted_same_window` then failed on its assertion until a host got one try per window |
  | 2026-11-22 | T60b: cargo nextest run -p rackhand-drivers -p rackhand-runbook -p rackhand-hub -p rackhand -E 'test(host) | test(hypervisor) | test(driver) | test(reboot) | test(patching) | test(builtin) | test(approved)' (after) | 61 passed |
  | 2026-11-22 | T60b: each behaviour broken in turn in a copy of the tree | clusters never recognised, a lone host taken for a cluster, asked without need, an unconfirmed binding naming the hub, no limit per window, two reboots at once, any approval rebooting a hypervisor, a patch job's approval rebooting it, stopped guests said to run: each failed one of the 11 tests |
  | 2026-11-22 | T60b: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(hypervisor_rebooted) | test(reboot_if_required)' | 2 passed (the kernel comparison in a real shell: none installed, the newest running, a newer one, pinned, flagged, approved) |
  | 2026-11-22 | T60b: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 529 passed, 1 skipped; no violations |
  | 2026-11-22 | T60c: the new tests (before) | compile errors (`REBOOT_IN_60S`, `StepRunner::rebooted`, `Actions::resume`, `hosts_hub`) |
  | 2026-11-22 | T60c: cargo nextest run -p rackhand-store -p rackhand-runbook -p rackhand-hub -p rackhand -E 'test(host) | test(hypervisor) | test(driver) | test(reboot) | test(patching) | test(builtin) | test(resum) | test(templates) | test(hub_runs_on) | test(writer) | test(actions)' (after) | 81 passed |
  | 2026-11-22 | T60c: each behaviour broken in turn in a copy of the tree | ten faults. Nine failed a test at once (never marked, going on at once, resuming at the next step instead of verify, not waiting for the machine, taking up any job, the silence hold kept after it, an unconfirmed binding, the hub's host not asked about, the command list without the scheduled reboot); a job taken up twice did once the test asked while it was still waiting |
  | 2026-11-22 | T60c: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(hubhost::) | test(hypervisor_rebooted) | test(reboot_if_required)' | 3 passed; `hubhost::reboot_scheduled_60s_job_resumes_at_verify` with the machine's own timer, its restart 60 s later and a new hub over the same database (79 s) |
  | 2026-11-22 | T60c: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | first run, with another build filling the disk (load 22, 2.5 GB waiting to be written): 532 passed, 2 failed, both probe tests with 60 s limits (backoff_from_1s_to_60s_with_jitter, unsupported_version_retries_hourly); on a calm disk the whole tier again: exit 0; fast 534 passed, 1 skipped; no violations |
  | 2026-11-22 | cargo xtask ci it on a clean clone of ac88ee9, on a calm machine | exit 0: 58 tests, 58 passed (2294 s), `hubhost::reboot_scheduled_60s_job_resumes_at_verify` among them. Live: L4; a real hypervisor hosting the hub: MV8 |

### T61: Remaining built-in runbooks and key rotation
- **Design refs:** 7.8.7 (built-in list), 7.3.3 (`ApplyKeys`), 7.3.7 (`sudoers-refresh`), 7.3.12 (unenroll), D73, D92
- **Goal:** the built-in runbooks `reboot`, `rollback`, `snapshot`, `service-restart`, `compose-restart`,
  `compose-update`, `sudoers-refresh`, `keys-rotate` and `unenroll` exist with their risks. Key updates go through the
  helper with a version and an expiry, and a replayed or expired payload is refused.
- **Depends on:** T55, T43
- **Changes:** `crates/rackhand-runbook/builtin/*.toml` (the nine runbooks); `crates/rackhand-probe/src/helper/keys.rs`
  (`ApplyKeys`); `crates/rackhand-hub/src/actions/keys.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `builtins::all_parse_and_have_design_risk` | high: `sudoers-refresh`, `unenroll`, `keys-rotate`, `rollback`; low: restarts | 7.6.8 |
  | `keys::older_equal_or_expired_payload_refused` | each refused; `authorized_keys` unchanged | 7.3.3 |
  | `keys::payload_can_only_touch_hub_users_key_lines_and_from` | a payload naming another user is refused | 7.3.3 |
  | `keys::monitor_machine_refuses_apply_keys` | `Error` | D89 |
  | `it::builtins::compose_restart_restarts_project` | in a Docker-in-Docker test machine | 7.8.7 |
  | `it::builtins::sudoers_refresh_installs_newer_list` | via the wrapper's `install-commands` | D92 |
  | `it::builtins::keys_rotate_new_key_works_old_refused` | after rotation | 7.3.3 |
  | `it::builtins::unenroll_removes_users_keys_sudoers_list_and_revokes` | nothing left; the endpoint id is revoked | 7.3.12 |
  | `it::builtins::probe_uninstall_locally_on_monitor_machine` | `rackhand-probe uninstall` as root removes the services and files; as the probe user it fails | 7.3.12, 7.7.3 |
  Carried in from T41:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::builtins::sudoers_refresh_after_join_list` (carried in from T41) | a machine that got its first command list with its join (version = the signing time in ms) accepts the list `sudoers-refresh` sends: the refresh versions its lists the same way, so the wrapper never refuses it as not newer | D92, 7.3.7 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-runbook -E 'test(builtins::)' && cargo nextest run -p rackhand-probe -E 'test(keys::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(builtins::)'
  ```
  Expected: 1 passed, then 3 passed, then 5 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-22 | T61a: the new tests (before) | compile errors (`Step::always`); five runbooks not built in |
  | 2026-11-22 | T61a: cargo nextest run -p rackhand-runbook -p rackhand-hub -E 'test(builtin) | test(always) | test(reboot) | test(templates) | test(library) | test(diagnostics)' (after) | 41 passed, among them `builtin::all_parse_and_have_design_risk` and `restart_runbooks_judge_a_fresh_report` |
  | 2026-11-22 | T61a: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(reboot_asked_for) | test(hypervisor_rebooted) | test(reboot_if_required)' | 3 passed |
  | 2026-11-22 | T61a: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 537 passed, 1 skipped; no violations |
  | 2026-11-22 | T61b: the key-update tests were written together with the code, so they weren't seen failing first; `concurrent_updates_leave_the_newest` and the hard link in `links_are_not_followed` were (2 failed), before their fixes | `cargo nextest run -p rackhand-probe --lib -E 'test(keys::)'`: 9 passed after |
  | 2026-11-22 | T61b: each rule broken in turn in a copy of the tree | twelve faults (version not stored, valid for a day, any user, any key text, monitor machines, an unreadable version, unknown fields, the `.ssh` link, the file link, comments dropped, restrictions left out, not one at a time): each failed at least one of the 9 tests |
  | 2026-11-22 | T61b: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | first run 545 passed, 1 failed (`executor::verify_step_runs_named_checks`: it stamps a check result, writes it and only then starts the step, so a write slower than 1 ms failed it; with a 20 ms delay put in, the old test fails on the same line and the new one, whose result arrives while the step waits, passes); then exit 0; fast 546 passed, 1 skipped; no violations |
  | 2026-11-22 | T61c1: the new tests (before) | compile errors (`StepKind::Hub`, `Step::needs_account`, `Executor::with_hub`, `HubSide`) |
  | 2026-11-22 | T61c1: cargo nextest run -p rackhand-runbook -p rackhand-hub -p rackhand -E 'test(hub_steps) | test(sudoers_refresh) | test(hub_step) | test(refresh_sends) | test(all_parse) | test(monitor_machine_hub)' (after) | 6 passed |
  | 2026-11-22 | T61c1: each rule broken in turn in a copy of the tree | six faults (revoking needing an account, any call accepted, a command in a hub step, the list versioned 1, valid for a day, no hub side wired): each failed one of the 6 |
  | 2026-11-22 | T61c1: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(commands::) | test(hubhost::) | test(reboot_if_required)' | 4 passed: `commands::sudoers_refresh_after_join_list` (a join's list versioned by its signing time, then the refresh's newer one), `sudoers_refresh_installs_newer_list` (a runbook the first list lacked fails, then runs after the refresh; what the new list lacks is gone; an old version is refused and the machine keeps its list) |
  | 2026-11-22 | T61c1: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 551 passed, 1 skipped; no violations |
  | 2026-11-22 | T61c2: the new tests (before) | compile errors (`keys::load_for`, `next_for`, `commit_next`, `HubSide::signed_keys`) |
  | 2026-11-22 | T61c2: cargo nextest run -p rackhand-runbook -p rackhand-hub -p rackhand-probe -p rackhand -E 'test(keys_rotate) | test(machine_key) | test(key_updates_name) | test(all_parse) | test(keys::) | test(refresh_sends)' (after) | 16 passed |
  | 2026-11-22 | T61c2: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(rotation::) | test(commands::)' | 4 passed: `rotation::keys_rotate_new_key_works_old_refused` (the new key works and the old one is refused, the line is the new key alone from the hub's address with no forwarding, the assistant's account is untouched, the log names the key and never gives it, runbooks go on working with it, a second rotation does the same) and `keys_rotate_refused_without_the_pinned_hubs_signature` (nothing changes on the machine or in the Vault; an honest retry goes through) |
  | 2026-11-22 | T61c2/c3: each rule broken in turn in a copy of the tree | fifteen faults: a pending key replacing the machine's at once, a new key every time, a commit that keeps the old key, the old key not dropped, the hub never keeping the new key (twice: in both the rotation and the unenroll runs), the machine's own key not used, `from=` left empty; anyone may uninstall, an extra path removed, the binary not last, users before the way in, a revoke that leaves the endpoint admitted or the state unchanged, a revoke without seeing the key refused: each failed at least one test |
  | 2026-11-22 | T61c3: cargo nextest run -p rackhand-runbook -p rackhand-hub -p rackhand-probe -p rackhand -E 'test(uninstall) | test(unenroll) | test(revoking_a_machine) | test(the_hub_revokes) | test(all_parse)' | 9 passed |
  | 2026-11-22 | T61c3: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(unenroll::) | test(rotation::) | test(probe_uninstall_locally)' | 5 passed: `unenroll::unenroll_removes_users_keys_sudoers_list_and_revokes` (the users, home, sudoers file, command list and Rackhand's files gone; a file beside them and another user stay; sshd goes on; the machine is revoked only after it refused the hub's key), `unenroll_that_fails_on_the_machine_revokes_nothing`, and `install_it::probe_uninstall_locally_on_monitor_machine` (a real installer's machine: the probe's own user can't, root removes the services and files) |
  | 2026-11-22 | T61c: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check; cargo deny check | first run 560 passed, 1 failed and 1 timed out (probe_daemon::unsupported_version_retries_hourly, uffer::cap_from_hub_drops_oldest_with_ranges: both have 60 s limits and another session was compiling, load 11 to 16); on a calm machine the whole tier again: exit 0; fast 562 passed, 1 skipped; arch-check no violations; cargo deny: advisories, bans, licenses and sources ok |

### T62: Access levels and monitor enforcement
- **Design refs:** 7.3.12 (access level, changing it, hypervisor-side actions on monitor guests), 7.3.7 (monitor
  machines), D88, D89, D93, E49, E50, AC58, AC59, AC60
- **Goal:** the one-time level-change command moves a machine between `monitor` and `managed` in place (adding or
  removing users, keys, sudoers and the command list, keeping its id and history), and nothing the hub does alone
  changes the level. Hypervisor-side actions on a monitor guest always need an approval, and a mismatched guest binding
  blocks them. (That automatic quarantine rules don't apply to monitor machines is tested in T72, with the rules.)
- **Depends on:** T44, T55, T49
- **Changes:** `packaging/install.sh` (`--change-level`); `crates/rackhand-hub/src/policy/monitor.rs`;
  `crates/rackhand-hub/src/actions/hypervisor_guard.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `guard::mismatched_binding_refuses_snapshot_rollback_firewall_power` | each refused before any API call | E50, AC60 |
  | `guard::other_guest_never_touched` | the simulated API records no call on the other vmid | AC60 |
  | `guard::monitor_guest_hypervisor_action_needs_approval` | a snapshot, rollback, power or firewall action on a monitor guest creates an approval whatever the runbook's level | AC58, D89 |
  | `it::level::monitor_to_managed_keeps_id_and_history` | users, keys, sudoers and list added; same machine id; old series still queryable | AC59 |
  | `it::level::managed_to_monitor_removes_everything` | users, keys, sudoers file and list gone | AC59 |
  | `it::level::hub_cannot_change_level_alone` | no hub route or MCP tool changes `access`; a direct registry write is refused | AC59, D89 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(guard::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(level::)'
  ```
  Expected: 3 passed, then 3 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** first in the local lab (L4, L5); then MV9 (AC58's Proxmox part: on a monitor guest, a hypervisor quarantine runs only after an
  approval and an enabled auto rule does nothing).
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T62: the new tests (before) | store: `level::a_write_without_a_token_cannot_change_the_level` failed with the guard off (the write went through); hub: compile errors (`actions::hypervisor_guard`, `Hypervisor::guest_call`); IT: `level::managed_to_monitor_removes_everything` failed (the hub's users, home, sudoers file and command list were still there) |
  | 2026-11-23 | T62: cargo nextest run -p rackhand-store -p rackhand-hub -E 'test(level::) | test(guard::)' (after) | 7 passed: `level::a_write_without_a_token_cannot_change_the_level`, `level::a_join_that_uses_a_token_changes_it_and_a_write_of_the_same_level_is_fine`, `guard::mismatched_binding_refuses_snapshot_rollback_firewall_power` (no request reaches the API, for all four actions), `guard::other_guest_never_touched` (only vmid 200 is addressed), `guard::monitor_guest_hypervisor_action_needs_approval` (passed at once: the rules were in `decide()`; it pins them for every requester and level), and the web tests `level::level_command_binds_a_token_to_the_machine_and_changes_nothing`, `level::only_an_admin_asks_and_only_for_a_change` |
  | 2026-11-23 | T62: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(install_it::level::) | test(install_it::install::)' | 15 passed: `level::monitor_to_managed_keeps_id_and_history` (same machine id and endpoint, the hub's users, keys, sudoers and list added, history kept, a used command refused), `level::managed_to_monitor_removes_everything` (users, homes, sudoers file and list gone; another user, a file beside them and sshd stay), `level::a_level_command_is_bound_to_its_machine_and_level`, and the 12 installer tests as before |
  | 2026-11-23 | T62: planted fault: the store's guard switched off | `level::a_write_without_a_token_cannot_change_the_level` failed (the level changed) |
  | 2026-11-23 | T62: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 618 passed, 1 skipped (a 60 s-limit probe test failed once under load from another build and passed on a calm machine) |

### T63: Diagnostics allow-list
- **Design refs:** 7.8.3, 7.3.6 (`run_diagnostic`), D69, D101
- **Goal:** every diagnostic in 7.8.3 exists as a built-in, read-only template run as the automation identity, with
  limits on its parameters, its output capped at 256 KB, `journal` and `docker_logs` marked sensitive, and output
  wrapped as untrusted.
- **Depends on:** T55
- **Changes:** `crates/rackhand-runbook/builtin/diagnostics.toml`; `crates/rackhand-hub/src/actions/diagnostics.rs`;
  the templates are added to `commands.json` generation.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `diagnostics::every_name_in_design_exists` | the list equals 7.8.3 | 7.8.3 |
  | `diagnostics::parameter_limits_enforced` | `lines` over 2000 and `depth` over 3 refused; a `ping` target outside the site refused | 7.8.3 |
  | `diagnostics::sensitive_flag_on_journal_and_docker_logs_only` | flags | 7.8.3 |
  | `diagnostics::leading_dash_unit_refused` | `-f` as a unit name refused | E51 |
  | `it::diagnostics::each_linux_diagnostic_runs_read_only` | each runs in a container and returns output under 256 KB | 7.8.3 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(diagnostics::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(diagnostics::)'
  ```
  Expected: 4 passed, then 1 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub -E 'test(diagnostics::)' | compile errors: unresolved `super::prepare`, `OUTPUT_LIMIT`, `untrusted`, no `ActionsError::UnknownDiagnostic` |
  | 2026-11-19 | cargo nextest run -p rackhand-hub -E 'test(diagnostics::)' | 4 passed: the 19 names equal 7.8.3; `lines` 2001 and `depth` 4 refused (2000 and 3 accepted; the patterns hold the limits, so the wrapper enforces them too); `ping` only to a machine of the same site by name or address; `http_head` only to a URL of the machine's checks; `journal` and `docker_logs` alone are sensitive; `-f`, `--all` and `-x` refused |
  | 2026-11-19 | cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(diagnostics::)' | 1 passed: all 19 run over SSH on a systemd machine (the root ones through the wrapper, from a command list signed with the diagnostics' templates in it), each exit 0 and at most 256 KB, and nothing under `/etc`, `/usr`, `/opt` or `/home` changed. This test was written after the hub code, so it wasn't seen failing first; its first runs failed for real reasons: `systemctl` as a non-root user needs D-Bus (added to the image, as on real hosts) |
  | 2026-11-19 | cargo xtask ci fast; cargo xtask ci it; cargo xtask arch-check | exit 0 (197 passed); exit 0 (21 passed); no violations |

### T64: Provisioning VMs and LXCs
- **Design refs:** FR-23, G7, 7.3.12 (binding set by the runbook), AC33, S4 finding
- **Goal:** `provision-vm` and `provision-lxc` clone from a template with cloud-init (or LXC setup), start the guest,
  enroll it with a fresh token, and record its guest binding as confirmed.
- **Depends on:** T59, T49
- **Changes:** `crates/rackhand-runbook/builtin/{provision-vm.toml, provision-lxc.toml}`;
  `crates/rackhand-hub/src/actions/provision.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `provision::vm_clone_cloudinit_start_calls_match_recorded_api` | the simulated API sees clone, config, start with the cloud-init user data containing the enrollment command | FR-23 |
  | `provision::binding_confirmed_by_runbook` | `proxmox_ref_state = confirmed` | 7.3.12 |
  | `provision::lxc_variant` | create and start calls | FR-23 |
  | `provision::token_single_use_and_expires_60_min` | tokens bound to the job | 7.3.1 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(provision::)'
  ```
  Expected: 4 passed, 0 failed.
- **Manual verification:** first in the local lab (L4); then MV10 (AC33: on the owner's Proxmox, `provision-vm` with a template and cloud-init gives a
  VM that boots, enrolls and is healthy).
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T64: the new tests (before) | the runbook, driver and hub tests were written beside their code and first run with it (the driver's `provisioning_operations_make_and_start_guests` did fail first: no such operation); the later planted faults below stand in for the rest |
  | 2026-11-23 | T64: cargo nextest run -p rackhand-drivers --features sim -E 'test(proxmox::)'; cargo nextest run -p rackhand-runbook; cargo nextest run -p rackhand-hub -E 'test(provision::)' (after) | 11 passed; 25 passed; 6 passed: clone, `config_set` (cloud-init keys only: never a hook script, raw arguments or LXC key), start and `create_lxc` each wait for their task and show in the host's list; the runbooks' steps and parameters; `provision::vm_clone_cloudinit_start_calls_match_recorded_api` (clone, config, start in that order with the hypervisor's credentials from the Vault), `provision::lxc_variant`, `provision::binding_confirmed_by_runbook` (confirmed, by `job:<id>`, fixed afterwards, nothing else bindable), `provision::token_single_use_and_expires_60_min` (the host's site, pending, managed, 60 minutes, bound to the machine), `provision::await_machine_sees_enrolled_by_name_on_the_hosts_site` |
  | 2026-11-23 | T64: cargo nextest run -p rackhand-probe -E 'test(guest::)'; cargo nextest run -p rackhand -E 'test(provisioning_gives)' (after) | 5 passed; 1 passed: `run install-guest` writes a VM's user data (only `rackhand-<vmid>.yml`) and answers with its `cicustom`, waits for a container and runs the installer in it, takes only a payload of its own kind from the pinned hub (not expired, not valid for more than 10 minutes, newer, not on a monitor machine) and builds the installer line from a fixed shape (http, a quote, a space, `;`, `$(...)`, a backtick, a pipe, a newline, a backslash and an unknown field refused); the hub's side makes the machine and token, gives the ticket and the installer's address (the release's, or the hub's own with `--self-signed` when it holds a release), signs the request with the node key, binds on the node the hypervisor names |
  | 2026-11-23 | T64: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(provision::)' | 3 passed: `provision::send_guest_writes_the_vms_user_data_and_answers_with_its_cicustom`, `provision::send_guest_runs_the_installer_inside_the_container` (a recording `pct`), `provision::a_request_the_pinned_hub_didnt_sign_does_nothing` |
  | 2026-11-23 | T64: planted faults, each in a copy of the tree | six: `config_set` taking any key, a guest installer from plain http, an unverified signature, a bound guest bound again, a token that lives a day, a monitor machine taking a guest request: each failed at least one test |
  | 2026-11-23 | T64: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 633 passed, 1 skipped |

### T65: Hub restart recovery for jobs
- **Design refs:** 7.5.3 step 8 (resumable), 7.3.7 (detached pickup), E44, 7.6.3 (silence suppressed 3 minutes)
- **Goal:** when the hub restarts, jobs with a `resumable_step` or in a detached step resume, other running jobs become
  `interrupted` with an incident, silence is suppressed for 3 minutes, staging is compacted, and the recent window is
  rebuilt before rules run.
- **Depends on:** T55, T59
- **Changes:** `crates/rackhand-hub/src/actions/recovery.rs`; start-up ordering in `crates/rackhand/src/hub_cmd.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `recovery::startup_order_window_before_rules` | rules don't evaluate until the window is rebuilt | E44 |
  | `recovery::non_resumable_running_job_interrupted_with_incident` | state and incident | E44 |
  | `it::recovery::hub_killed_mid_jobs_resumes_detached_and_resumable` | kill -9 during two jobs; after start, one resumes at its step, the detached one is picked up by polling, a third is `interrupted` | E44 |
  | `it::recovery::no_silence_incident_in_first_3_minutes` | probes reconnect late; no silence incident | E44 |
  | `it::recovery::hub_restart_during_patch_install_finishes_and_verifies` | the package manager finishes; output and exit code recorded; the job goes on to verify | AC63, E54 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(recovery::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(recovery::)'
  ```
  Expected: 2 passed, then 3 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T65: the new tests (before) | not seen failing alone: the unit tests were written with the code and first run together (compile errors, then green); the planted faults below stand in |
  | 2026-11-23 | T65: cargo nextest run -p rackhand-hub -E 'test(recovery::)' (after) | 4 passed: `recovery::startup_order_window_before_rules` (no rule runs before the window is rebuilt: a hub that judged first would open a critical silence on every machine), `recovery::non_resumable_running_job_interrupted_with_incident` (a runbook job and an assistant job end `interrupted` with `hub_restarted`, their running step too, a `job.interrupted` warning on the machine opens an incident, queued and waiting jobs are left alone, a second start does nothing), `recovery::a_job_in_a_detached_step_is_picked_up_by_polling_and_goes_on` (the step is adopted, not started again, its output recorded, only the step after it runs), `recovery::an_adopted_step_that_fails_fails_the_job_and_one_that_cannot_be_taken_up_is_interrupted` |
  | 2026-11-23 | T65: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(recovery::) | test(hub_restart_during_patch)' | 3 passed, the hub's tasks all stopped where they were (a runtime shut down) and a new Actions and Executor started on the same database: `recovery::hub_killed_mid_jobs_resumes_detached_and_resumable` (the detached step finishes on the machine and the new hub records all eight lines and exit 0, started once), `recovery::a_job_in_a_plain_step_is_interrupted_with_an_incident`, `patch::hub_restart_during_patch_install_finishes_and_verifies` (AC63, E54: the package manager finishes, the install step's output and exit code are recorded, the job goes on to verify and succeeds) |
  | 2026-11-23 | T65: planted faults, each in a copy of the tree | five: rules running before the window is rebuilt, a detached step interrupted instead of adopted, an interruption with no event, an adopted step started again, a queued job interrupted too: each failed at least one test |
  | 2026-11-23 | T65: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 637 passed, 1 skipped |

### L4: Live pass for M3: actions and patching
- **Design refs:** 14, D107, 7.5, FR-23, AC19, AC33, AC58, AC63, AC64, AC73, E11, E62
- **Goal:** runbooks, approvals, patching with snapshots and rollback, hypervisor actions and provisioning work on real
  machines and on the nested Proxmox node.
- **Depends on:** T65, L3
- **Changes:** live tests; `lab` gains an apt repository on `hub` that offers `rackhand-lab-dummy` 2.0 over the 1.0
  installed on `target` and in `ct-test`, and a 2.0-broken variant whose postinst stops the probe; `lab deploy
  --hub-on pve9` installs a second lab hub in an LXC `ct-hub` on `pve9` for the hypervisor-hosting-the-hub test.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `live::m3::failed_service_runbook_after_approval` | a stopped service routes to its runbook; after approval the service restarts and the job log is complete; a second failure inside the window stops at the attempt limit | 7.5, AC64 |
  | `live::m3::patch_target_from_lab_repository` | a patch job on `target` installs `rackhand-lab-dummy` 2.0, verify passes, the job log lists every step | AC19 |
  | `live::m3::lxc_patch_snapshots_and_prunes_to_three` | four `auto` patch runs on `ct-test` leave exactly three `rackhand-patch-*` snapshots | AC19 |
  | `live::m3::broken_guest_rolls_back_after_15_minutes` | the broken variant on `ct-test` with `auto_rollback` on: no report for 15 minutes, then the guest is rolled back and reports again | E11 |
  | `live::m3::hypervisor_hosting_the_hub_finishes_at_verify` | with the hub in `ct-hub`, the approval for rebooting `pve9` names the hub; after the reboot the job finishes at verify | AC73, E62 |
  | `live::m3::monitor_guest_hypervisor_action_needs_approval` | with `ct-test` enrolled as `monitor`, a hypervisor action on it waits for approval and nothing runs inside the guest | AC58 |
  | `live::m3::provision_vm_boots_enrolls_and_is_healthy` | `provision-vm` on `pve9` from an Alpine template with cloud-init boots, enrolls and is healthy | AC33, FR-23 |
  | `live::m3::install_step_survives_hub_restart_and_ssh_cut` | a patch install step on `target` survives a hub restart and an SSH cut and finishes | AC63 |
- **Fails first:** `cargo xtask ci live --target local --milestone m3 --no-deploy` with the M2 build still deployed:
  every test fails (no actions or patching yet); then the M3 build is deployed.
- **Verification:**
  ```bash
  cargo xtask ci live --target local --milestone m3
  ```
  Expected: 8 passed, 0 failed (the rollback test takes about 20 minutes).
- **Regression:** `cargo xtask ci fast`: exit 0; `cargo xtask ci live --target local --milestone m1`: 8 passed.
- **Manual verification:** the M3 page walk (approvals, jobs, library, patching), done by the run as in L2. The
  real-hardware confirmations are MV7 to MV10, run in L9.
- **Done when:**
  - [ ] New tests observed failing before the M3 deploy
  - [ ] New tests and the regression suites pass
  - [ ] M3 page walk recorded
  - [ ] Evidence recorded below
- **Risk / rollback:** an emulated `vm-test` may be too slow for the provisioning test's timeout; the test then uses an
  LXC template and the VM case moves to L9 (deviation). Revert the commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

### M4: Security watch

### T66: Helper security scans
- **Design refs:** FR-6, 7.3.3 (`HashFiles`, `AuthEventsSince`, `Containers`, `SocketOwners`, `ContainerOf`,
  `ProcessScan`), 7.8.4 (critical file list), D64, D91, S11 finding
- **Goal:** the helper hashes the critical file list every 5 minutes and on inotify change, tails authentication events
  by the method chosen in T11, and answers container, socket-owner, cgroup and process-scan requests. It never returns
  file contents, and never takes a path from the socket.
- **Depends on:** T43, T11
- **Changes:** `crates/rackhand-probe/src/helper/{hash.rs, auth.rs, containers.rs, sockets.rs, procscan.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `hash::list_is_compiled_in_plus_root_owned_extras_max_500` | the 501st extra path is ignored with a warning; an extras file not owned by root is ignored | 7.8.4, D91 |
  | `hash::response_has_metadata_never_contents` | fields: path, exists, sha256, mode, uid, gid, mtime | FR-6 |
  | `auth::parses_ssh_sudo_su_user_and_group_events` | from recorded journal and auth-log fixtures | FR-6, S11 |
  | `procscan::finds_exe_in_tmp_vartmp_devshm_and_deleted` | from a fixture `/proc` | FR-5 |
  | `it::helper_scan::inotify_change_reported_within_seconds` | editing `/etc/sudoers.d/x` shows a new hash without waiting 5 minutes | FR-6 |
  | `it::helper_scan::containers_read_only_calls` | Docker and Podman socket calls are only GETs | D64 |
  | `it::helper_scan::socket_owner_and_cgroup_to_container_name` | a container's socket maps to its name | D103 |
  | `it::helper_scan::journal_only_system_auth_events` | a Debian container without `auth.log` reports SSH logins | S11 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-probe -E 'test(hash::) | test(auth::) | test(procscan::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(helper_scan::)'
  ```
  Expected: 4 passed, then 4 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T66: cargo nextest run -p rackhand-probe -E 'test(hash::) | test(auth::) | test(procscan::) | test(sockets::)' | 12 passed (written beside the code; a deadlock and two bugs the tests found are fixed: the month read once per name, a cursor that passed for an option): `hash::list_is_compiled_in_plus_root_owned_extras_max_500` (the 501st path ignored with a warning, an extras file another user owns or others can write ignored), `hash::authorized_keys_file_directive_names_more_files`, `hash::response_has_metadata_never_contents` (exactly path, exists, sha256, mode, uid, gid, mtime_ms), `auth::parses_ssh_sudo_su_user_and_group_events` (and no command line carried), `auth::auth_log_lines_parse_too`, `auth::journal_only_system_auth_events` (journalctl only, with a cursor of journald's own form), `auth::a_log_file_is_read_from_the_cursor_and_survives_rotation`, `procscan::finds_exe_in_tmp_vartmp_devshm_and_deleted`, `sockets::socket_owner_and_cgroup_to_container_name`, `sockets::container_ids_are_found_in_every_cgroup_layout` (the innermost id wins) |
  | 2026-11-23 | T66: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(helper_scan::)' | 4 passed: `helper_scan::inotify_change_reported_within_seconds` (a new and then a changed `/etc/sudoers.d/x` is hashed within seconds, no byte of it in the answer, another user gets none), `helper_scan::containers_read_only_calls` (a fake engine's log has GET lines only), `helper_scan::socket_owner_and_cgroup_to_container_name` (a listener in a unit named like a container is mapped by its inode and its cgroup id to the name the engine gives), `helper_scan::journal_only_system_auth_events` (a Debian container with no auth.log: an SSH login, a failure and a sudo come from the journal, each once; the first run lost the first entry to `journalctl`'s own skipping of the cursor's neighbour when a match is given, so the programs are picked out in Rust) |
  | 2026-11-23 | T66: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 649 passed, 1 skipped |

### T67: Probe sampling capture and security signals
- **Design refs:** FR-4 (sampling), FR-5, 7.3.2 (connection tuples, overflow), D17, D103, E36, E59, AC13 (sampling
  part), AC71 (sampling part)
- **Goal:** without eBPF the probe reads the connection table every 5 seconds and gets process and container
  attribution from the helper. It aggregates tuples per `(container, exe, dest_ip, dest_port, proto)` with at most 500
  per report, folding the rest, and reports new listeners and exec-from-temp processes. The Machine page shows
  "sampling".
- **Depends on:** T66, T42
- **Carried in (D91, 2026-11-21):** probe security events are stored with a known `kind` only (an unknown one is counted and dropped) and their fields in `data`, so `list_security_events` and `get_incident` return them inside `untrusted_output`.
- **Changes:** `crates/rackhand-probe/src/security/{conntable.rs, aggregate.rs, listeners.rs, capability.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `conntable::parses_proc_net_tcp_udp_v4_v6` | fixture rows to tuples | FR-4 |
  | `aggregate::over_500_tuples_keeps_most_bytes_folds_rest` | 600 tuples give 500 plus folded records per container and exe, and one `conn.overflow` | E59 |
  | `listeners::new_listener_event_once` | a new socket gives one `port.new_listener` | FR-5 |
  | `capability::no_ebpf_reports_sampling` | a kernel without BTF gives `sampling` in `Hello.capabilities` | E36 |
  | `it::sampling::connection_open_across_poll_attributed_to_container` | two containers running the same `curl`; the record names the right container | AC71, D103 |
  | `it::sampling::exec_from_tmp_and_new_port_reported` | both events reach the hub | FR-5 |
  Carried in from the review after T33:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `ingest::probe_events_stored_before_compaction` (carried in from the review) | a report's `events` become `events` rows (through `raise_event`) and its `connections` reach connection storage before compaction deletes the frame | 7.3.2, 7.6.5 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-probe -E 'test(conntable::) | test(aggregate::) | test(listeners::) | test(capability::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(sampling::)'
  ```
  Expected: 4 passed, then 2 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T67: cargo nextest run -p rackhand-probe -E 'test(conntable::) | test(aggregate::) | test(listeners::) | test(capability::)'; cargo nextest run -p rackhand-hub -E 'test(probe_events_stored_before_compaction)' | passed (written beside the code): `conntable::parses_proc_net_tcp_udp_v4_v6` (IPv4 and IPv6 as the kernel prints them, a dual-stack IPv4 peer, listeners and outbound told apart), `aggregate::over_500_tuples_keeps_most_bytes_folds_rest` (500 kept by most bytes, one folded record per container and executable carrying every socket and byte past the cap, one `conn.overflow`), `listeners::new_listener_event_once`, `listeners::a_process_from_tmp_is_reported_once_until_it_ends`, `capability::no_ebpf_reports_sampling`, and the carried-in `ingest::probe_events_stored_before_compaction` (known kinds stored as the hub's events with the hub's severity before compaction, an unknown kind counted and dropped, `conn.overflow` once an hour) |
  | 2026-11-23 | T67: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(sampling::)' | 2 passed: `sampling::connection_open_across_poll_attributed_to_container` (two units named like containers run the same `socat`; each connection is attributed to its own container, with the helper's answers), `sampling::exec_from_tmp_and_new_port_reported` (`/tmp/evil` once; only the port that appeared after the first look). The first run of the first test was wrong in the test: its listener closed each connection at once |
  | 2026-11-23 | T67: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 687 passed, 1 skipped |

### T68: eBPF capture
- **Design refs:** FR-4, FR-5, 7.3.3 (probe capabilities), 11 (per-CPU maps), D17, D103, E36, AC13 (eBPF part), AC71
  (eBPF part), S1 finding, S6 finding
- **Goal:** on systemd Linux with kernel 5.8 or later and BTF, the probe records every outbound TCP connect and UDP
  flow and every exec with pid, exe path, cgroup id (mapped to a container by the helper), user and destination,
  through aya CO-RE programs with `CAP_BPF` and `CAP_PERFMON` only. It falls back to sampling when loading fails.
- **Depends on:** T67, T10, T06
- **Changes:** `crates/rackhand-probe-ebpf/` (the eBPF programs, with the license the owner chose after T10);
  `crates/rackhand-probe/src/security/ebpf.rs` (loader, map draining every interval); `tests/ebpf/src/capture.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `ebpf_tests::capture::short_connect_seen` | a 10 ms TCP connection that sampling would miss is recorded with pid, exe and destination | FR-4, AC13 |
  | `ebpf_tests::capture::udp_flow_seen` | one UDP send recorded | FR-4 |
  | `ebpf_tests::capture::exec_from_tmp_seen` | `sched_process_exec` from `/tmp` recorded | FR-5 |
  | `ebpf_tests::capture::two_containers_same_exe_attributed` | records name each container | AC71 |
  | `ebpf_tests::capture::runs_with_only_cap_bpf_and_cap_perfmon` | as a non-root user with those capabilities | 7.3.3 |
  | `ebpf_tests::capture::load_failure_falls_back_to_sampling` | with BTF hidden, the probe reports `sampling` and still captures long connections | E36 |
- **Fails first:** compile errors; the eBPF crate doesn't exist.
- **Verification:**
  ```bash
  cargo xtask ci ebpf -- -E 'test(capture::)'
  ```
  Expected: 6 passed, 0 failed on each of 5.10, 6.1 and the current Proxmox kernel series.
- **Regression (in addition):** none beyond the fast tier.
- **Manual verification:** LXC attribution from the Proxmox host (E37) is tested in L5 on `pve9`, then on a real
  host as MV2 in L9.
- **Risk / rollback:** a kernel where loading fails uses sampling. Revert the commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

### T69: Threat intel and outside sources
- **Design refs:** 7.8.5, 7.3.10 (relay list fetch rules apply the same parsing discipline), 10 (fetched lists), D19,
  D65, D75, NG10, S10 finding
- **Goal:** the hub downloads the default threat lists and GeoIP/ASN data over HTTPS on their schedules with strict
  parsing and size caps, looks up IPs, lets each source be turned off, and has an air-gapped mode that turns them all
  off. Optional sources stay off unless enabled.
- **Depends on:** T41, T15
- **Changes:** `crates/rackhand-hub/src/intel/{sources.rs, feodo.rs, drop.rs, dbip.rs, lookup.rs, airgap.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `intel::parsers_accept_fixtures_reject_garbage` | each fixture parses; HTML, binary and oversized inputs are refused without replacing the loaded list | 10 |
  | `intel::lookup_ip_in_lists_and_asn_country` | known entries match | 7.6.5 |
  | `intel::air_gapped_mode_makes_no_requests` | a request-recording fake sees nothing | D65, NG10 |
  | `intel::optional_sources_off_by_default` | MaxMind, reputation lookups, relay lists and n0 off | NG10 |
  | `intel::freshness_reported_for_security_page` | last success time per source | 7.7.1 |
  | `intel::db_ip_attribution_present` | the Security page shows the CC BY 4.0 attribution | 7.8.5 |
  | `intel::settings_toggle_each_source_and_air_gapped_mode` | the Settings page turns each source and air-gapped mode on and off; changes are audited | 7.7.1, D65 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(intel::)'
  ```
  Expected: 7 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T69: cargo nextest run -p rackhand-hub -E 'test(intel::)' | 8 passed (written beside the code): `intel::parsers_accept_fixtures_reject_garbage` (Feodo, DROP v4 and v6, DB-IP country and ASN parse; HTML, binary, oversized, mostly-unreadable, empty and non-gzip downloads and a gzip that expands past its cap are refused and the loaded list stays), `intel::lookup_ip_in_lists_and_asn_country`, `intel::air_gapped_mode_makes_no_requests` (a recording fake sees nothing; a source turned off is not asked; nothing twice while fresh; the daily lists again after a day), `intel::optional_sources_off_by_default` (and a config written before the new fields reads the same), `intel::freshness_reported_for_security_page` (last success, last try and error per source; not retried within the hour after a failure), `intel::db_ip_attribution_present`, `intel::the_last_good_lists_are_kept_across_a_restart`, and `web::tests::intel::settings_toggle_each_source_and_air_gapped_mode` (each source and air-gapped mode on and off on the Settings page, audited, the optional ones kept off); a CSV field in quotes with a comma (`"Cloudflare, Inc."`) is one field |
  | 2026-11-23 | T69: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 687 passed, 1 skipped |

### T70: Connection scoring and connection storage
- **Design refs:** 7.6.5, 7.4.1 (`conn_records`, `conn_baseline`, per-day cap), 10 (desktop privacy), D56, D103, E59,
  AC13, AC14, AC55, AC69 (connection part), AC71
- **Goal:** connection records are scored as 7.6.5 says (threat list, ASN and country, learning, new destination with
  raises, large egress, exclusions) and stored in 5-minute buckets. Storage is capped at 20 000 rows per machine per day
  with summary rows past the cap, and machines whose policy says `summary` or `off` store only counts or nothing, while
  threat-list checks still run on every tuple.
- **Depends on:** T67, T69
- **Changes:** `crates/rackhand-hub/src/ingest/{conn_score.rs, conn_store.rs}`; the `PutConnRecords` and
  `PutConnBaseline` handlers.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `conn_score::private_destinations_skipped_unless_watch_internal` | table | 7.6.5 |
  | `conn_score::threat_list_hit_is_critical_conn_known_bad` | critical | AC14 |
  | `conn_score::learning_adds_to_baseline_without_events` | first 7 days | 7.6.5 |
  | `conn_score::new_asn_new_country_port_4444_is_warning_naming_container` | the 7.6.5 example | AC13, AC71 |
  | `conn_score::server_process_high_port_raises_to_warning` | above 49151 from a server process | 7.6.5 |
  | `conn_score::large_egress_over_1gb_per_hour` | `conn.large_egress` warning | 7.6.5 |
  | `conn_score::rackhand_and_patch_job_package_manager_excluded` | no events | 7.6.5 |
  | `conn_score::folded_records_counted_not_scored` | no destination scoring | 7.6.5 |
  | `conn_store::daily_cap_20000_then_summary_rows_and_overflow` | 100 000 distinct destinations: at most 20 000 rows plus summary rows; a threat-listed one among them still gives a critical | AC69, E59 |
  | `conn_store::summary_mode_stores_country_asn_counts_only_known_bad_still_named` | desktop default | AC55, D56 |
  | `conn_store::off_mode_stores_nothing` | no rows | AC55 |
  | `it::conn::threat_listed_destination_critical_within_60s` | end to end from a probe container | AC14 |
  | `it::conn::desktop_summary_and_off_modes_end_to_end` | a probe container with role `desktop`: only per-country and per-ASN counts stored; a threat-listed destination still opens a critical naming it; with `off`, nothing stored | AC55 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(conn_score::) | test(conn_store::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(conn::)'
  ```
  Expected: 11 passed, then 2 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T70: cargo nextest run -p rackhand-hub -E 'test(conn_score::) | test(conn_store::) | test(connections_scored_and_stored_by_policy)'; cargo nextest run -p rackhand-store -E 'test(connection_rows_accumulate)' | passed (written beside the code): the eight `conn_score::` tests (private destinations skipped unless `watch_internal`, a listed destination critical `conn.known_bad` naming the container and not learned, 7 days of learning with no event, the 7.6.5 example as a warning with its reasons, a container's or root's process on a high port, `conn.large_egress` once an hour, Rackhand's own processes and a patch job's package manager left out, folded records counted and not scored), the three `conn_store::` tests (100 000 destinations: 20 000 rows and summary rows that count the rest, `summary` stores only ASN and country counts with no address or program, `off` nothing), and an ingest test through three policies (every machine is told of the listed destination; full rows, counts only, none; the baseline learned only where full) |
  | 2026-11-23 | T70: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(install_it::conn::)' | 2 passed: `conn::threat_listed_destination_critical_within_60s` (a container really connects to a listed address: a critical `conn.known_bad` names the destination and the program, a row says `known_bad`), `conn::desktop_summary_and_off_modes_end_to_end` (a desktop's rows hold only counts per ASN, the listed destination is still named; with `off` nothing is stored) |
  | 2026-11-23 | T70: planted faults, each in a copy of the tree | the threat check skipped, a summary row that keeps the address, a failed burst at 20: each failed a test (see T71) |
  | 2026-11-23 | T70: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 687 passed, 1 skipped |

### T71: Security events, severities and exemptions
- **Design refs:** 7.6.6 (severities, exemptions), 7.5.2 (event incidents), FR-5, FR-6, G3, D76, E48, AC15, AC16
- **Goal:** helper and probe signals become security events with the 7.6.6 severities: logins from new sources, failed
  bursts, root logins, users added, key changes, file changes, new listeners, exec from temp. The exemptions apply
  exactly as written, scoped to the named jobs and users, and the events open event incidents.
- **Depends on:** T70, T61
- **Changes:** `crates/rackhand-hub/src/ingest/{security_events.rs, exemptions.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `security_events::severity_table_matches_design` | each row in 7.6.6 | 7.6.6 |
  | `exemptions::memfd_runc_child_exempt` | no event | E48 |
  | `exemptions::patch_job_package_owned_file_change_is_info_with_job_id` | `dpkg -S` match recorded | 7.6.6 |
  | `exemptions::key_change_exempt_only_for_hub_users_in_named_jobs` | another user's keys during `keys-rotate` are still critical | 7.6.6 |
  | `exemptions::commands_json_exempt_only_when_hash_matches_sent_list` | a different hash is critical | 7.6.6 |
  | `exemptions::probe_toml_exempt_only_during_enrollment_and_level_change` | otherwise critical | 7.6.6 |
  | `security_events::failed_burst_over_20_in_5_min` | boundary | 7.6.6 |
  | `it::security::exec_from_tmp_critical_new_port_warning_container_start_nothing` | end to end | AC15 |
  | `it::security::authorized_keys_added_outside_job_critical_new_ip_login_warning` | and the probe never received file contents (socket traffic checked) | AC16 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(security_events::) | test(exemptions::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(security::)'
  ```
  Expected: 7 passed, then 2 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T71: cargo nextest run -p rackhand-hub -E 'test(security_events::) | test(exemptions::)'; cargo nextest run -p rackhand-probe -E 'test(signals::)' | 9 passed (written beside the code): `security_events::severity_table_matches_design` (every row of 7.6.6), `security_events::a_login_from_a_new_source_or_as_root_is_a_warning`, `security_events::failed_burst_over_20_in_5_min` (the 21st, once; 15 in 5 minutes never), `exemptions::memfd_runc_child_exempt`, `exemptions::patch_job_package_owned_file_change_is_info_with_job_id`, `exemptions::key_change_exempt_only_for_hub_users_in_named_jobs` (another user's keys during `keys-rotate` are still critical), `exemptions::commands_json_exempt_only_when_hash_matches_sent_list`, `exemptions::probe_toml_exempt_only_during_enrollment_and_level_change`, and the probe's `signals::` (a changed critical file is one event, a changed keys file two, never a file's content) |
  | 2026-11-23 | T71: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(install_it::security::)' | 2 passed: `security::exec_from_tmp_critical_container_start_nothing`, `security::authorized_keys_added_outside_job_critical_new_ip_login_warning` (a key added to a person's file is a critical `auth.keys_changed` with no content in the events; a login from a second source is a warning, the first source being learned) |
  | 2026-11-23 | T71: planted faults, each in a copy of the tree | nine across T66, T70 and T71: another user's keys exempt, a failed burst at 20, the threat check skipped, a summary row that keeps the address, an extras file of any owner, no per-report cap: each failed at least one test; two (a redundant early return in the off mode, and in air-gapped fetching, each also checked a second time) change nothing |
  | 2026-11-23 | T71: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 687 passed, 1 skipped |

### T72: Quarantine
- **Design refs:** FR-15, 7.5.6 (states, applying, releasing, exclusions), 7.8.2 (auto rules), 7.6.8 (exceptions),
  D18, D57, D61, D77, D80, D104, E22, E23, E24, E66, AC17, AC18, AC72, S4 finding
- **Goal:** quarantine follows the 7.5.6 state machine:
  - Proxmox guests are isolated with the guest firewall after saving the whole prior configuration (the datacenter
    firewall is never turned on by Rackhand). Managed Linux uses the nftables table through the wrapper.
  - A forensic snapshot follows isolation.
  - Release restores the saved configuration exactly, or stops with `quarantine_config_changed` if someone changed it.
  - Auto rules need step-up to enable, and exclusions apply first.
  - Remote-mode machines and appliances are unsupported.
- **Depends on:** T71, T55, T47
- **Changes:** `crates/rackhand-hub/src/policy/quarantine.rs` (state machine, rules);
  `crates/rackhand-runbook/builtin/{quarantine.toml, quarantine-release.toml}`;
  `crates/rackhand-probe/src/runcmd/quarantine.rs` (`quarantine on|off <hub-addresses>`, nftables table
  `rackhand_quarantine`, conntrack flush).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `quarantine::state_machine_transitions` | every arrow in 7.5.6, and nothing else | 7.5.6 |
  | `quarantine::auto_rule_matches_tag_quarantines_without_approval` | `dmz` tag with `conn.known_bad` goes to `applying` | AC18 |
  | `quarantine::hypervisor_with_same_finding_not_quarantined` | exclusion wins; incident only | E22, AC18 |
  | `quarantine::enabling_rule_requires_step_up` | without fresh step-up refused | AC18 |
  | `quarantine::release_always_needs_approval_with_step_up` | never automatic | D61 |
  | `quarantine::pve_firewall_off_fails_with_instructions_never_enables` | the simulated API sees no datacenter write | E24 |
  | `quarantine::guest_rules_exact_set` | DROP policies; DHCP 67/68, guest to hub QUIC port, hub to guest 22 and ICMP echo, nothing else | D104, AC72 |
  | `quarantine::release_restores_identical_configuration` | saved and restored configurations compare equal | AC72 |
  | `quarantine::changed_config_stops_release` | `quarantine_config_changed` | E66, AC72 |
  | `quarantine::isolation_failure_sets_failed_and_critical` | state `failed`, critical incident | E23 |
  | `quarantine::remote_mode_and_appliance_unsupported_stay_with_person` | incident note | D80 |
  | `quarantine::auto_rule_matching_monitor_machine_does_nothing` | logged; no state change; an approval is needed instead | AC58, D89 |
  | `it::quarantine::nftables_only_hub_paths_and_dhcp_then_removed` | in a container with nftables: allowed paths work, others fail; `off` restores traffic and touches no other table | AC17 (in-guest part) |
  | `it::quarantine::auto_rule_dmz_known_bad_quarantines_end_to_end` | a probe container tagged `dmz` connects to a threat-listed test address; the enabled rule quarantines it in-guest without an approval | AC18 |

  Carried in from T75:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `actions::quarantined_machine_refuses_runbooks_but_release` | the quarantine block is in Actions, so Incidents, the dashboard and the Scheduler can't run a runbook other than `quarantine-release` (or a diagnostic) on a quarantined machine either; MCP checks it today | 7.5.6, AC72 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(quarantine::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(quarantine::)'
  ```
  Expected: 12 passed, then 2 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** first in the local lab (L5); then MV11 (AC17, AC72 and E66 on the owner's Proxmox with the datacenter firewall on: a test
  guest with its own rules is quarantined after an approval with step-up, reaches only DHCP and the hub, the hub still
  runs diagnostics, the forensic snapshot exists, release restores identical configuration; a change during quarantine
  stops release; E24 with the datacenter firewall off).
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T72: cargo nextest run -p rackhand-hub -E 'test(quarantine) | test(quarantined_machine)'; cargo nextest run -p rackhand-drivers -E 'test(quarantine::)'; cargo nextest run -p rackhand-probe -E 'test(runcmd::quarantine::)'; cargo nextest run -p rackhand-runbook | 35 + 6 + 5 + 27 passed (written beside the code): the pure `policy::quarantine::` tests (`state_machine_transitions`: every arrow of 7.5.6 and no other; `auto_rule_matches_tag_quarantines_without_approval`; `hypervisor_with_same_finding_not_quarantined`: hub, operator, relay, hypervisor and `no-quarantine`; `enabling_rule_requires_step_up`: saved off needs none, enabled or changed while enabled needs one, a changed rule keeps who enabled it only if unchanged; `release_always_needs_approval_with_step_up`; `remote_mode_and_appliance_unsupported_stay_with_person`; `auto_rule_matching_monitor_machine_does_nothing`), the Proxmox driver's (`pve_firewall_off_fails_with_instructions_never_enables`: no write at all; `guest_rules_exact_set`: DROP policies, DHCP, the guest to the hub's port, the hub's SSH and ping, for v4 and v6, the guest's own rules gone and the device flag on; `release_restores_identical_configuration`: the guest's own rules and options and its device line identical; `changed_config_stops_release`; `a_failed_isolation_puts_the_saved_configuration_back`; `isolate_needs_the_hubs_addresses_and_port`), the executor's (`executor::tests::quarantine::`: the three hub calls against the simulated API, the record a retry takes up, `unconfirmed_binding_is_refused_before_any_call`, the in-guest path needing an account, a supported system and the hub's addresses, the conntrack commands and why a flush wasn't done), Actions' (`actions::quarantine::`: `quarantined_machine_refuses_runbooks_but_release` for every requester, the states a job moves through, `isolation_failure_sets_failed_and_critical`, a failed snapshot, a failed release staying `active` with a critical event, a busy machine changing nothing), routing's (`routing::tests::quarantine::`: the rule starting `quarantine` as `rule:<id>` with no approval; a hypervisor, a remote-mode machine and an appliance staying with a person; a critical finding proposing it for an approval with step-up and the machine `pending`; rejected and expired proposals clearing `pending`; policy `never`; a monitor machine asking for an approval), the probe's wrapper (`runcmd::quarantine::`: addresses are ip and port only, the exact ruleset, only the `rackhand_quarantine` table touched) and the runbooks (`quarantine_runbooks_isolate_snapshot_and_release`, `conntrack_flush_takes_one_address_for_the_hypervisor`) |
  | 2026-11-23 | T72: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(quarantine::)' | 2 passed: `quarantine::nftables_only_hub_paths_and_dhcp_then_removed` (in privileged containers with real nftables: before `on` everything reaches everything; while on, only the hub's SSH and ping reach the machine, only the probe's UDP port goes out, another machine's SSH and ping, the guest's own traffic to another machine and to the hub on another port are all cut, DHCP is in the table, and the machine's own nftables table is untouched; after `off` it is all back, and `off` again is not an error), `install_it::quarantine::auto_rule_dmz_known_bad_quarantines_end_to_end` (a managed machine tagged `dmz` in a container, a hub with a threat list, an enabled rule: the container really connects to the listed address, the hub quarantines it with no approval through its own SSH and the wrapper, the job ran as `rule:dmz`, `quarantine.active` is recorded, the table is in the machine and a new connection to the listed address is cut) |
  | 2026-11-23 | T72: planted faults, each in a copy of the tree | twelve, each failed at least one test: a runbook allowed on a quarantined machine, a failed quarantine without its critical event, a failed release leaving the machine released, the exclusions skipped in routing, policy `never` ignored, a monitor machine started by a rule, a retry saving the isolated configuration again, the datacenter firewall not checked, the changed-configuration check skipped, the device flag not set, the guest's own rules kept, a policy that isn't DROP, and in the policy tests the exclusion, the step-up check and a release straight from `active` |
  | 2026-11-23 | T72: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 731 passed, 1 skipped |

### T73: Dashboard: security pages
- **Design refs:** 7.7.1 (Security page, Machine page connections, capture method, quarantine state), 7.8.2, D77
- **Goal:** the Security page shows the event feed, baseline status per machine, threat-list and GeoIP freshness, and
  quarantine rules. The Machine page shows connections with verdicts by container, the capture method, and the
  quarantine state with whether it is enforced (hypervisor) or advisory (in-guest).
- **Depends on:** T71, T72
- **Changes:** `crates/rackhand-hub/src/web/pages/{security.rs, machine_connections.rs, quarantine_rules.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `pages::security_lists_not_downloaded_empty_state` | "Lists not downloaded yet" | 7.7.1 |
  | `pages::machine_connections_grouped_by_container_with_verdicts` | rendered | 7.7.1, D103 |
  | `pages::quarantine_kind_enforced_or_advisory_shown` | both kinds | D77 |
  | `pages::quarantine_rule_edit_admin_only_with_step_up` | responder 403 | 7.7.2 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(pages::security) | test(pages::machine_connections) | test(pages::quarantine)'
  ```
  Expected: 4 passed, 0 failed.
- **Manual verification:** the M4 page walk, done by the run in L5.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T73: cargo nextest run -p rackhand-hub -E 'test(pages::security)' | 4 passed (written beside the code; the plan's filter `test(pages::security) | test(pages::machine_connections) | test(pages::quarantine)` names the four tests by module paths that differ here, so the one filter above runs all four, in `web::tests::pages::security`): `security_lists_not_downloaded_empty_state` ("Lists not downloaded yet" and "No security events yet" while nothing is there; once a list is loaded each source shows its name and what it holds; the feed shows only security events, with their severity and machine; a machine learning for two days says "Learning, 5 days left"), `machine_connections_grouped_by_container_with_verdicts` (the machine's own connections first, then each container by name, each connection with its program, destination, country and verdict), `quarantine_kind_enforced_or_advisory_shown` (a quarantine recorded by the hypervisor's firewall says "Enforced by the hypervisor's firewall", an in-guest one "Advisory: an attacker with root on the machine can undo it", a machine that isn't quarantined says neither), `quarantine_rule_edit_admin_only_with_step_up` (a viewer and a responder get 403; an admin saves a rule that stays off with no step-up; turning it on without a fresh one is sent to the step-up and nothing changes; with one it is saved with who turned it on, audited; the edit button is shown to the admin only) |
  | 2026-11-23 | T73: planted faults, each in a copy of the tree | four, each failed one test: the step-up taken as fresh, the feed listing every event, an in-guest quarantine shown as enforced, connections not grouped by container |
  | 2026-11-23 | T73: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 735 passed, 1 skipped |

### L5: Live pass for M4: security watch and quarantine
- **Design refs:** 14, D107, AC15, AC16, AC17, AC58, AC72, E24, E37, E66
- **Goal:** security signals fire on real machines and kernels, and quarantine works on a real Proxmox guest firewall.
- **Depends on:** T73, L4
- **Changes:** live tests only.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `live::m4::new_ssh_key_is_critical` | a key added to a user on `target` raises a critical event, with no file contents stored | AC16 |
  | `live::m4::login_from_new_address_is_a_warning` | an SSH login to `target` from `agentless`, a new address, is a warning | AC16 |
  | `live::m4::exec_from_tmp_and_new_port_flagged` | on `target` (Ubuntu 24.04 kernel, eBPF), a program run from `/tmp` that opens a new listening port raises both events | AC15 |
  | `live::m4::lxc_connection_attributed_to_its_cgroup` | the probe on the `pve9` host attributes a connection made inside `ct-test` to that guest | E37 |
  | `live::m4::quarantine_lxc_guest_and_release` | after approval with step-up, `ct-test` reaches only DHCP and the hub; diagnostics still work; release restores the firewall configuration exactly | AC17, AC72 |
  | `live::m4::changed_firewall_during_quarantine_stops_release` | a firewall change during quarantine stops the release with the reason | E66 |
  | `live::m4::datacenter_firewall_off_fails_with_instructions` | with the datacenter firewall off, quarantine fails with instructions and never turns it on | E24 |
  | `live::m4::monitor_guest_auto_rule_does_nothing` | an auto rule matching a `monitor` guest takes no action | AC58 |
- **Fails first:** `cargo xtask ci live --target local --milestone m4 --no-deploy` with the M3 build still deployed:
  every test fails (no security watch yet); then the M4 build is deployed.
- **Verification:**
  ```bash
  cargo xtask ci live --target local --milestone m4
  ```
  Expected: 8 passed, 0 failed.
- **Regression:** `cargo xtask ci fast`: exit 0; `cargo xtask ci live --target local --milestone m1`: 8 passed.
- **Manual verification:** the M4 page walk (security pages), done by the run as in L2. Real-hardware confirmations
  are MV2, MV9 and MV11, run in L9.
- **Done when:**
  - [ ] New tests observed failing before the M4 deploy
  - [ ] New tests and the regression suites pass
  - [ ] M4 page walk recorded
  - [ ] Evidence recorded below
- **Risk / rollback:** quarantine tests run only on lab guests. Revert the commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

### M5: Assistant

### T74: MCP server and read tools
- **Design refs:** FR-17, 7.3.6 (framing, callers, read tools, errors, untrusted output, rate limit), 7.7.2 (MCP
  keys), D50, D101, AC26
- **Goal:** the hub serves MCP over `rackhand/mcp/1` (one stream per session, JSON-RPC 2.0 lines, an auth line first)
  to job tokens and to personal keys bound to a device. The read tools work, machine output comes back as
  `untrusted_output`, a key's scope is capped by its user's role, and calls are limited to 60 a minute per token.
- **Depends on:** T17, T54
- **Changes:** `crates/rackhand-hub/src/mcp/{server.rs, auth.rs, tools_read.rs, keys.rs}` (rmcp server over the QUIC
  stream); the `PutMcpKey` handler.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `mcp_contract::auth_line_required_first` | any other first line closes the session | 7.3.6 |
  | `mcp_contract::read_tools_return_expected_shapes` | `list_machines`, `get_machine`, `get_vitals` (at most 2000 points), `list_incidents`, `get_incident`, `list_security_events`, `get_connections`, `list_runbooks`, `get_runbook`, `list_playbooks`, `get_playbook`, `get_approval` | 7.3.6 |
  | `mcp_contract::machine_output_wrapped_untrusted` | `get_incident` job output is inside `untrusted_output` | 7.3.6 |
  | `mcp_contract::read_key_refused_for_diagnostic_and_runbook` | `tool_not_allowed` | AC26 |
  | `mcp_contract::expired_key_refused` | refused | AC26 |
  | `mcp_contract::read_request_key_on_viewer_works_as_read` | cannot run a diagnostic | D101, AC70 |
  | `mcp_contract::over_60_calls_per_minute_rate_limited` | `rate_limited` | 7.3.6 |
  | `mcp_contract::every_call_audited` | audit rows | FR-26 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub --test mcp_contract
  ```
  Expected: 8 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub --test mcp_contract; cargo nextest run -p rackhand-store -E 'test(mcp_keys)' | compile errors: unresolved `rackhand_hub::mcp::{Mcp, Observations, Facts, SeriesQuery, keys}`; `Unimplemented("PutMcpKey")` |
  | 2026-11-19 | cargo nextest run -p rackhand-hub --test mcp_contract | 8 passed, over a QUIC stream through a local relay with the Registry's admission: a first line other than the auth line, a wrong token and a key used from another device each get one error line and a closed stream; the 12 read tools return their shapes (`get_vitals` cut to at most 2000 points; machines by id or `site/name`); job output only inside `untrusted_output`; a `read` key gets `tool_not_allowed` for `run_diagnostic` and `run_runbook`; an expired key is refused and a key over a year isn't issued; `read_request` on a viewer lists only the read tools; call 61 in a minute is `rate_limited`, shared by sessions of the token; every call (refusals too) is an `mcp.call` audit row, for a key and for a job token used from its operator. The first full run overflowed the test thread's stack (one large future); the test session now boxes each request |
  | 2026-11-19 | cargo xtask ci fast; cargo xtask arch-check; cargo deny check | exit 0 (206 passed); no violations; ok |
  | 2026-11-21 | D91 (owner B3): cargo nextest run -p rackhand-hub --test mcp_contract -E 'test(machine_reported_text)' (before) | failed: `list_machines: machine text outside untrusted_output at .machines[0].os` |
  | 2026-11-21 | D91: cargo nextest run -p rackhand-hub --test mcp_contract (after) | passed: text a machine planted reaches no tool outside `untrusted_output` (`list_machines`, `get_machine` OS and facts, `list_incidents` and `get_incident` titles and timeline, `list_security_events` subject and data, `get_connections` container and exe); `get_machine_facts_from_latest_report` reads the facts inside the wrapper |

### T75: MCP gated tools and approval binding
- **Design refs:** FR-14, FR-17, 7.3.6 (gating, enforcement), 7.5.6 (no `exec` on quarantined machines), 7.6.8, D21,
  D85, D101, D104, E18, E19, E20, AC22, AC23, AC24, AC26, AC70, AC72 (exec part)
- **Goal:** `run_diagnostic`, `exec` and `run_runbook` go through `decide()`, with these rules:
  - Calls that need an approval return `needs_approval {approval_id}`.
  - Repeating the exact call with the id runs it once, and only for the same caller.
  - Scope, allowed tools, job hosts, quarantine and monitor rules are enforced on every call.
  - No MCP tool changes an approval.
- **Depends on:** T74, T55, T63
- **Changes:** `crates/rackhand-hub/src/mcp/{tools_act.rs, gate.rs}`; `propose_library_change`, `add_incident_note`
  and `finish_job` tools.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `mcp_contract::exec_outside_job_hosts_out_of_scope_and_audited` | `out_of_scope` plus an audit row | AC22, E18 |
  | `mcp_contract::tool_not_in_playbook_refused_and_audited` | `tool_not_allowed` | AC22, E18 |
  | `mcp_contract::level_1_run_runbook_needs_approval_then_runs_once` | `needs_approval`; after a dashboard approval the same call with the id runs once; a third call is refused | AC23 |
  | `mcp_contract::different_arguments_give_approval_mismatch` | | AC23, E20 |
  | `mcp_contract::approval_from_other_caller_or_after_edit_refused` | another token, or a runbook edited since | AC70, D101 |
  | `mcp_contract::no_tool_changes_an_approval` | the tool list contains none; every tool called with hostile arguments leaves approvals unchanged | AC23, AC24, E19 |
  | `mcp_contract::injected_output_does_not_change_approvals` | a diagnostic printing "approve the pending request" leaves the approval pending | AC24, E19 |
  | `mcp_contract::personal_key_journal_needs_approval_df_does_not` | | AC70, D85 |
  | `mcp_contract::read_request_key_same_gating` | `run_runbook` from a device always needs approval | AC26, D85 |
  | `mcp_contract::exec_on_quarantined_machine_refused` | `machine_quarantined` | AC72, D104 |
  | `mcp_contract::exec_on_monitor_machine_refused` | `monitor_only` | E49 |
  | `mcp_contract::propose_library_change_creates_draft_only` | nothing applied until the dashboard applies it | 7.3.6 |
  | `mcp_contract::exec_on_busy_machine_waits_then_machine_busy` | an `exec` while a runbook runs on the machine fails with `machine_busy` after 60 s (injected clock) | AC50 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub --test mcp_contract
  ```
  Expected: 21 passed (8 from T74 and these 13), 0 failed.
- **Manual verification:** None.
- **Done when (in addition):** AC39's list (actions, approvals, configuration changes, sign-ins, MCP calls) all audited.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub --test mcp_contract | compile error: no `Mcp::with_actions` |
  | 2026-11-19 | cargo nextest run -p rackhand-hub --test mcp_contract | 21 passed (T74's 8 and these 13): `exec` and `run_diagnostic` off the job's hosts are `out_of_scope` and audited; a tool outside the playbook is `tool_not_allowed`; at level 1 `run_runbook` gets `needs_approval`, the same call with the id still needs it until a person approves, then runs once and a third call is `approval_mismatch`; other arguments, another job's token and a runbook edited since all give `approval_mismatch`; no tool approves, and every tool called with hostile arguments leaves a pending approval pending, as does a diagnostic printing an instruction; a personal key's `journal` needs an approval and `df` doesn't; from a device `run_runbook` always needs one; `exec` on a quarantined machine is `machine_quarantined` (diagnostics still run) and on a monitor machine `monitor_only`; `propose_library_change` makes a draft only; `add_incident_note` adds a note; an `exec` while a runbook holds the machine waits (500 ms here) then `machine_busy`, and `finish_job` ends the job. Two T74 assertions follow the shared fixture, which now has four machines and two playbooks |
  | 2026-11-19 | cargo xtask ci fast; cargo deny check; cargo xtask arch-check | exit 0 (219 passed); ok; no violations |
  | 2026-11-19 review | cargo nextest run -p rackhand-hub --test mcp_contract; cargo nextest run -p rackhand-hub -E 'test(actions::)' | review fixes, each with a test that failed first: the caller is checked again on every request (`caller_checked_on_every_call`: after `finish_job` a call gets `deadline_exceeded`, and a key revoked mid-session ends the session); a quarantine in state `failed` is refused like any other; `quarantine` and `quarantine-release` are judged as quarantine (`quarantine_runbook_always_high_risk`: a level-2 job gets an approval at high risk with step-up); approvals asked for and used over MCP are audited (`approval.requested`, `approval.used`); a job token from another endpoint than its operator is refused (AC70); `run_runbook` uses the lower of the job's level and the runbook's own; and Actions checks an approval first but uses it only once it holds the machine (`actions::busy_machine_doesnt_spend_the_approval`). 23 passed; 6 passed |
  | 2026-11-19 review | cargo xtask ci fast; cargo xtask arch-check | exit 0 (222 passed); no violations |
  | 2026-11-21 | D91 (owner B4): cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(exec_timeout_stops)' (before) | failed: `the exec still runs on the machine` 15 s after its 3 s timeout |
  | 2026-11-21 | D91: cargo nextest run -p rackhand-it --profile it -E 'test(executor::)' (after) | 8 passed: a timed-out exec's `sleep 602` is gone from the machine; an exec in time keeps its output and exit code and records `timeout -k 5 30 sh -c ...` |
  | 2026-11-21 | D91: cargo nextest run -p rackhand-hub -E 'test(exec_approval_shows)' (before, with the page change held back; after) | failed (no "Runs as"); passed: an exec approval shows `timeout -k 5 600 sh -c 'journalctl -u nginx \| tail'`, a runbook approval no line |
  | 2026-11-21 | D91: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | exit 0; fast 480 passed, 1 skipped; no violations |

### T76: Operator contract and Assist
- **Design refs:** FR-16, 7.3.5 (offers, declines, tokens, disconnects, transcripts), 7.5.4 (deadline with a pending
  approval, Resume job), D39, D63, D68, D70, D101, E15, E16, E17, E21, E47, AC51, AC70
- **Goal:** Assist offers assistant jobs to invited operators in their configured order. A decline moves to the next
  operator, and no operator or 3 declines send the incident to a person. Tokens work only from the accepting operator,
  and hub restarts reattach jobs. Transcripts are stored up to 5 MB per job, the daily cap is enforced, and a deadline
  reached with an approval pending ends `needs_human` with Resume job offered.
- **Depends on:** T75
- **Changes:** `crates/rackhand-hub/src/assist/{offers.rs, tokens.rs, transcripts.rs, cap.rs, resume.rs}`;
  `crates/rackhand-hub/tests/operator_contract.rs` with a scripted fake operator.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `operator_contract::offer_accept_events_done` | events stored through Actions; `JobFinished` published | FR-16 |
  | `operator_contract::decline_tries_next_three_declines_go_human` | callout says so | E15 |
  | `operator_contract::no_operator_goes_human` | state `human` | E15 |
  | `operator_contract::token_from_other_endpoint_refused` | `out_of_scope` | AC70, D101 |
  | `operator_contract::disconnect_fails_tools_then_failed_after_5_min` | `hub_unreachable`, then `failed` on reconnect | E16 |
  | `operator_contract::hub_restart_reattaches_running_jobs` | via `OperatorHello.running` | E17 |
  | `operator_contract::transcript_capped_5mb_later_events_counted` | | 7.3.5 |
  | `assist::daily_cap_routes_to_person_with_note` | the 21st incident of the day | AC51, E47 |
  | `assist::deadline_with_pending_approval_needs_human_and_resume` | Resume starts a new job with the approved call first | E21 |
  | `assist::offer_has_scoped_token_hosts_tools_deadline` | fields per 7.3.5 | FR-16 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub --test operator_contract && cargo nextest run -p rackhand-hub -E 'test(assist::)'
  ```
  Expected: 7 passed, then 3 passed; 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-19 fails first | cargo nextest run -p rackhand-hub --test operator_contract | compile errors: unresolved `rackhand_hub::assist::{Assist, AssistRequest, AssistResult}` |
  | 2026-11-19 | cargo nextest run -p rackhand-hub --test operator_contract && cargo nextest run -p rackhand-hub -E 'test(assist::)' | 10 passed (7, then the 3 `assist::` tests, which live in the same file to share the fake operator), over QUIC through a local relay: an accepted offer's events are stored through Actions and its `JobDone` ends the job with `JobFinished`; three operators decline in their configured order and the job ends `declined`, and with no operator `no_operator`; the job token from another operator's endpoint gets `out_of_scope` and from its own works with the playbook's tools; after a dropped connection the job waits for the operator, which reports `failed` on reconnect; a restarted hub reattaches the job from `OperatorHello.running` and takes its events and end; six 1 MB events keep five and count one; the 21st assistant job of the day goes to a person with a note; the offer carries the incident, playbook and revision, brief, tools, level, hosts, a 30-minute deadline (at most 2 hours), 60 turns, and a token bound to the operator, hosts, tools and deadline; a deadline with an approval open ends `needs_human`, and Resume runs the approved runbook first with its approval and offers a new job whose brief says so. The first run failed on test ids that weren't valid ULIDs |
  | 2026-11-19 | cargo xtask ci fast; cargo xtask arch-check; cargo deny check | exit 0 (240 passed); no violations; ok |

### T77: Operator binary and runners
- **Design refs:** 7.3.5 (operator, Runner interface, Claude Code runner), 7.1 (operator user), D38, D39, D50, D62,
  AC21, AC25, AC34, S5 finding
- **Goal:** `rackhand operator join` and `rackhand operator run` connect an operator host to several hubs and run jobs
  through a `Runner`. The `mcp-bridge` keeps the job token inside the bridge. The Claude Code runner uses exactly the
  flags and configuration directory found in T13, and a scripted fake runner drives the integration tests.
- **Depends on:** T76, T13
- **Changes:** `crates/rackhand-operator/src/{main.rs, join.rs, run.rs, bridge.rs, runner.rs, claude_code.rs,
  fake.rs}`; `packaging/systemd/rackhand-operator.service`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `claude_code::command_line_matches_spike_flags` | the exact argument vector from T13, MCP config with only the bridge | S5 |
  | `claude_code::stream_json_lines_map_to_job_events` | recorded lines from T13 | 7.3.5 |
  | `claude_code::killed_at_deadline_no_process_left` | with a stub binary that ignores SIGTERM | 7.3.5 |
  | `bridge::token_not_in_runner_environment_or_args` | the runner process sees no token | 7.3.5 |
  | `it::operator::patch_failure_offer_within_60s` | verify fails for a missing mount, then `patch-failure` is offered to the operator within 60 s | AC21 |
  | `it::operator::guided_install_each_change_approved_in_order` | the fake runner follows a script; each change waits for an approval | AC34 |
  | `it::operator::one_operator_two_hubs` | jobs from both hubs; neither hub reaches the other through it | D63 |

  Carried in from T76:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `operator::tools_fail_hub_unreachable_then_runner_killed_after_5_min` (carried in from T76) | while the hub is unreachable tool calls fail `hub_unreachable`; after 5 minutes the runner is killed and `failed` is reported on reconnect | E16 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-operator && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(operator::)'
  ```
  Expected: 4 passed, then 3 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** run in L6 on the lab's `operator` machine with the owner's sign-in, as MV14 (AC25: a real Claude Code operator and a stopped Compose project; within 30 minutes the
  assistant calls `run_diagnostic`, requests `compose-restart`, and after approval the containers run and the incident
  resolves, in at least 2 of 3 runs).
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T77: cargo nextest run -p rackhand-operator | 11 passed (written beside the code): `claude_code::command_line_matches_spike_flags` (the vector spike S5 ran, ending with the brief; an MCP configuration with one server, the bridge), `claude_code::stream_json_lines_map_to_job_events` (messages, tool calls with the `mcp__rackhand__` prefix removed, tool results and errors, the final result, output that isn't JSON, a long result cut), `claude_code::killed_at_deadline_no_process_left` (a stand-in that ignores SIGTERM and starts a child that does too: stopped at the deadline, killed after the grace, neither process left; the run's directory holds its brief and its one-server config and no token), a run that ends by itself and one that fails, `bridge::token_not_in_runner_environment_or_args` (the command the runner starts has no token in its program, arguments or environment; the hub still gets `{"auth": <token>}` as its first line from the operator's side; the socket is 0600 in a 0700 directory), `bridge::an_unreachable_hub_fails_tool_calls_and_the_next_one_tries_again` (a tool call is answered `hub_unreachable`, another method with a plain error, and the same session works when the hub is back; a stream the hub drops fails that call only), notifications and the socket going with the job, `run::operator::tools_fail_hub_unreachable_then_runner_killed_after_5_min` (paused clock: kept for 4 minutes, a hub that came back resets the wait, stopped after 5 and reported `failed` with the reason), messages kept for an unreachable hub, and the hubs file |
  | 2026-11-23 | T77: cargo nextest run -p rackhand-it --profile it -E 'test(operator::)' | 3 passed: `operator::join_registers_the_host_with_the_hub` (a real hub: an invite, `rackhand operator join`, the hub's operator row has the endpoint id of the host's node key, the host remembers the hub, the invite works once), `operator::one_operator_two_hubs` (one operator process, two hubs in this process: each offers a job, the scripted runner works through the real bridge and MCP, both finish, each hub's transcript names only its own machine), `operator::guided_install_each_change_approved_in_order` (AC34: the second change isn't asked for until the first is decided and has run; nothing runs before its approval; the approvals are used once each, in order) |
  | 2026-11-23 | T77: planted faults, each in a copy of the tree | four, each failed a test: `--strict-mcp-config` dropped, no kill after the grace (the deadline test then never ends), no auth line sent to the hub, and a hub that came back not resetting the 5-minute wait |
  | 2026-11-23 | T77: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 746 passed, 1 skipped |

### T78: Incident routing to playbooks and briefs
- **Design refs:** 7.5.2 (routing to playbooks, `on_failure`, attempt limits, event incidents resolved by assistants),
  7.5.4 (brief contents), D76, D96, AC21
- **Goal:** incidents route to the most specific playbook when no runbook matches or the runbook failed (or to the
  playbook named by `on_failure`), at most one assistant job per incident per 24 hours. The brief holds what 7.5.4
  lists with machine output marked untrusted. Assistants resolve event incidents only at level 2 or 3, and only for
  warning kinds.
- **Depends on:** T77, T57
- **Carried in (D91, 2026-11-21):** a brief's machine-reported text (titles, timeline, events, facts) is wrapped as `untrusted_output`, as the MCP read tools return it.
- **Changes:** `crates/rackhand-hub/src/incidents/{playbook_routing.rs, brief.rs}`; built-in playbooks
  `crates/rackhand-runbook/builtin/playbooks/*.md` (the seven in 7.8.8).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `playbook_routing::precedence_and_on_failure_override` | table | 7.5.2 |
  | `playbook_routing::one_assistant_job_per_incident_per_24h` | the second goes to a person | D96 |
  | `playbook_routing::assistant_resolves_event_incident_only_level_2_3_warning` | critical stays with a person | D76 |
  | `brief::contains_required_sections_and_untrusted_markers` | incident, timeline, machine facts, recent vitals, failed steps (marked untrusted), playbook, level, hosts, deadline, the data-not-instructions rule | 7.5.4 |
  | `builtins::seven_playbooks_parse` | `patch-failure`, `service-down`, `disk-filling`, `security-finding`, `machine-silent`, `backup-stale`, `guided-install` | 7.8.8 |

  Carried in from T76:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `incidents::no_operator_or_declines_go_human_with_callout` (carried in from T76) | `JobFinished` for an assistant job ended `no_operator` or `declined` moves the incident to `human`, and a callout says so | E15 |
  | `incidents::assistant_job_without_report_ends_after_deadline` (carried in from T76) | an assistant job whose operator never reports ends `timed_out` a while after its deadline | 7.3.5 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(playbook_routing::) | test(brief::)' && cargo nextest run -p rackhand-runbook -E 'test(builtins::seven_playbooks_parse)'
  ```
  Expected: 4 passed, then 1 passed; 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T78: cargo nextest run -p rackhand-hub -E 'test(playbook_routing::) | test(brief::)'; cargo nextest run -p rackhand-runbook -E 'test(seven_playbooks_parse)' | 12 + 1 passed (written beside the code): `playbook_routing::precedence_and_on_failure_override` (the kind's playbook, ties to the name that sorts first; a failed step's `on_failure` wins and skips the kinds; a name that doesn't exist matches nothing), `playbook_routing::one_assistant_job_per_incident_per_24h` (the second, across a reopen, goes to a person with "attempt limit reached"; allowed again a day after the first), `playbook_routing::assistant_resolves_event_incident_only_level_2_3_warning` (the pure rule, and through routing for four level and severity pairs: only level 2 or 3 with a warning is closed by the assistant, every other end goes to a person), `brief::contains_required_sections_and_untrusted_markers` (the rule, incident, timeline, machine, vitals, failed steps, playbook, level, hosts, deadline; every machine-reported string, the title, the timeline data and the step output, is wrapped as `untrusted_output` and a hostile sentence is never outside a wrapper), a long output cut, and the seven playbooks parse with real tool names, `finish_job`, a runtime of at most 30 minutes, and kinds for the six an incident starts; in routing: a playbook takes an incident no runbook does with a brief and its hosts, a failed runbook step goes to the playbook it names, `no_operator_or_declines_go_human_with_callout` (carried in from T76: a note and a `human` event with a callout, and the job's own end changes nothing more), level 0, a condition incident waiting 10 minutes after `resolved` and then going to a person, and an assistant that hands over, times out or fails |
  | 2026-11-23 | T78: cargo nextest run -p rackhand-hub -E 'test(assistant_job_without_report_ends_after_deadline)' | 1 passed (carried in from T76): an assistant job whose token's deadline passed more than 5 minutes ago ends `timed_out`; one inside its deadline or its grace is left alone |
  | 2026-11-23 | T78: cargo xtask it-images; cargo nextest run -p rackhand-it --profile it -E 'test(operator::)' | 4 passed, the three of T77 and `operator::patch_failure_offer_within_60s` (AC21: a patch job fails its verify step, the incident routes to `patch-failure`, and the operator process is offered the job and starts it, in the real operator over the real transport, about 5 seconds after the failure) |
  | 2026-11-23 | T78: planted faults, each in a copy of the tree | four, each failed a test: `on_failure` ignored, no limit per incident, an assistant closing any event incident, and the brief's text not wrapped |
  | 2026-11-23 | T78: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 760 passed, 1 skipped |

### T79: Dashboard: assistant pages and settings
- **Design refs:** 7.7.1 (Incidents detail with transcript and Resume job; Settings: MCP keys, assistant daily cap;
  Peers and relays: operators), 7.7.2 (MCP keys), 10 (AI provider data notice)
- **Goal:** people see assistant transcripts on incidents, use Resume job, create and revoke personal MCP keys (scope
  capped by role), set the assistant daily cap, see operators, and the operator setup page states what the AI provider
  receives.
- **Depends on:** T78
- **Changes:** `crates/rackhand-hub/src/web/pages/{incident_transcript.rs, mcp_keys.rs, operators.rs,
  settings_assistant.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `pages::transcript_rendered_escaped` | tool output escaped | 10 |
  | `pages::resume_job_shown_after_late_approval` | E21 surface | E21 |
  | `pages::mcp_key_scope_capped_by_role_and_expiry_max_1_year` | a viewer can't create `read_request`; 366 days refused | 7.7.2 |
  | `pages::operator_setup_states_provider_data_use` | the notice text present | 10 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(pages::transcript) | test(pages::resume) | test(pages::mcp_key) | test(pages::operator_setup)'
  ```
  Expected: 4 passed, 0 failed.
- **Manual verification:** the M5 page walk, done by the run in L6.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T79: cargo nextest run -p rackhand-hub -E 'test(pages::assistant)' | 4 passed (written beside the code; the plan's filter names the four by module paths that differ here, so the one filter above runs all four, in `web::tests::pages::assistant`): `transcript_rendered_escaped` (an incident shows its assistant jobs and their transcripts; a transcript line with markup, quotes and an ampersand is escaped, never drawn as markup), `resume_job_shown_after_late_approval` (E21: a job that ended `needs_human` shows Resume job once an approval its call asked for is still valid, to a responder and not to a viewer, and never for a job that resolved), `mcp_key_scope_capped_by_role_and_expiry_max_1_year` (a viewer can't make a `read_request` key and isn't offered it; 366, 0, negative and non-numeric days are refused; a 90-day read key is made with its token shown once and never again; a responder may ask for changes up to 365 days; nobody makes a key for another user's device or revokes another user's key), `operator_setup_states_provider_data_use` (the notice that an assistant job sends the brief and every tool result to the AI provider; the operators with their runners; an invite gives the `rackhand operator join` command; a daily cap of 1 to 1000 is saved and audited; only an admin sees it) |
  | 2026-11-23 | T79: planted faults, each in a copy of the tree | four: the transcript not escaped, a viewer allowed to ask for changes, the resume button always shown (each failed its test), and the key's maximum raised to 400 days (not caught by the page test, since the key store refuses it too; that check is the store's own test) |
  | 2026-11-23 | T79: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 764 passed, 1 skipped |

### L6: Live pass for M5: a real Claude Code operator
- **Design refs:** 14, D107, 7.3.5, AC22, AC24, AC25
- **Goal:** a real Claude Code operator, signed in with the owner's account, connects to the lab hub, fixes a stopped
  Compose project after approval, and ignores injected text.
- **Depends on:** T79, L5
- **Changes:** live tests; `lab` stages a Compose project on `target` (Docker installed there by cloud-init) and
  installs Claude Code and the operator on `operator`, which joins `hub` with an operator invite.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `live::m5::operator_connects_and_lists_its_tools` | the operator on `operator` connects to `hub` and lists only the tools its key allows | 7.3.5 |
  | `live::m5::stopped_compose_project_fixed_in_2_of_3_runs` | three runs: in at least two the assistant calls `run_diagnostic`, requests `compose-restart`, and after approval the incident resolves within 30 minutes | AC25 |
  | `live::m5::injected_approve_text_changes_nothing` | a container log line telling the assistant to approve itself changes nothing; the job still waits for a person | AC24 |
  | `live::m5::out_of_scope_tool_is_refused_and_audited` | a request outside the operator's scope is refused and audited | AC22 |
- **Fails first:** `RACKHAND_LIVE_ASSISTANT=1 cargo xtask ci live --target local --milestone m5 --no-deploy` with the
  M4 build still deployed: every test fails (no operator yet); then the M5 build is deployed.
- **Verification:**
  ```bash
  RACKHAND_LIVE_ASSISTANT=1 cargo xtask ci live --target local --milestone m5
  ```
  Expected: 4 passed, 0 failed.
- **Regression:** `cargo xtask ci fast`: exit 0; `cargo xtask ci live --target local --milestone m1`: 8 passed.
- **Manual verification:** MV14: the owner signs in to Claude Code once in the operator's configuration directory on
  `operator` (the run can't hold the owner's credentials); the run then does the three runs. The M5 page walk is done by
  the run as in L2. The runs use the owner's Claude Code usage.
- **Done when:**
  - [ ] New tests observed failing before the M5 deploy
  - [ ] New tests and the regression suites pass
  - [ ] M5 page walk recorded
  - [ ] Evidence recorded below
- **Risk / rollback:** the run waits here until the owner has signed in; without `RACKHAND_LIVE_ASSISTANT=1` the tests
  skip and the step stays `blocked`. only `lab reset operator` or `lab destroy` removes the sign-in. Revert the commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

### M6: Multi-site

### T80: Peer contract
- **Design refs:** FR-18, 7.3.4 (hello, summaries, queries, allow-list, requests, unlink), 7.5.5 step 1, D30, D32, D69,
  E45, AC28
- **Goal:** linked hubs exchange `SiteSummary` every 30 seconds, answer only the queries allowed for that peer (with
  `JobLog` denied by default) at no more than 10 a second, and forward `ActionRequest`s idempotently with status
  updates. The owning hub always requires an approval unless its policy says `auto` for a runbook that isn't high
  risk. Either side can unlink.
- **Depends on:** T35, T41
- **Changes:** `crates/rackhand-hub/src/peers/{link.rs, summary.rs, queries.rs, requests.rs, unlink.rs}`;
  `crates/rackhand-hub/tests/peer_contract.rs`; the `PutPeerSummary` handler (latest summary per peer only).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `peer_contract::invite_links_pairwise_only` | A to B and B to C don't link A and C | 7.3.4 |
  | `peer_contract::summary_every_interval_with_audit_head` | contents per 7.3.4; one row per peer kept | FR-18, AC69 |
  | `peer_contract::joblog_denied_by_default` | `Denied("not allowed")` | E45, AC28 |
  | `peer_contract::query_rate_over_10_per_second_limited` | | 7.3.4 |
  | `peer_contract::action_request_needs_owner_approval` | status `NeedsApproval`, then `Running`, then `Done` after an approval on the owner | AC28 |
  | `peer_contract::request_retry_same_id_idempotent` | one job only | 7.3.4 |
  | `peer_contract::requested_by_not_trusted_as_user` | it never satisfies a role check | 7.3.4 |
  | `peer_contract::unlinked_peer_gets_0x13` | | 7.3.4 |
  | `peer_contract::sensitive_diagnostic_output_never_sent` | `journal` output isn't in any peer answer | 7.8.3 |
  | `it::peers::responder_on_a_requests_compose_restart_on_b` | two hub containers: hub B runs it only after a hub B approval; A's `JobLog` query is denied | AC28 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub --test peer_contract && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(peers::)'
  ```
  Expected: 9 passed, then 1 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T80: cargo nextest run -p rackhand-hub --test peer_contract | 10 passed (written beside the code, a scripted peer over real endpoints and a local relay): `invite_links_pairwise_only` (a linked peer is answered; a stranger is closed with `unknown peer`), `summary_every_interval_with_audit_head` (the summary holds the machines with health, the open incidents, the hub's health and version, the peers seen, and the 32-byte audit head; two summaries from a peer leave one row, the latest, and the peer's last-seen time), `joblog_denied_by_default` (E45, AC28: `Denied("not allowed")`; once the admin allows it the log comes in chunks and the output of a sensitive diagnostic is withheld), `sensitive_diagnostic_output_never_sent`, `query_rate_over_10_per_second_limited` (ten served, the rest told `rate limited`), `action_request_needs_owner_approval` (AC28: `NeedsApproval`, no job; after the owner's approval a job runs and the status ends `Done`), `request_retry_same_id_idempotent` (a retry on a new stream takes up the same request: one approval, one job; a finished request says so again), `requested_by_not_trusted_as_user` (the approval is the peer's, never the user the peer named), a policy's `peer_requests = auto` runs a low-risk runbook without an approval, and `unlinked_peer_gets_0x13` (the peer unlinks itself; its next connect is closed with the revoked code) |
  | 2026-11-23 | T80: planted faults, each in a copy of the tree | five, each failed a test: the allow-list not checked, no rate limit, sensitive output sent, a retry making a second request, and every peer request taken as auto |
  | 2026-11-23 | T80: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 775 passed, 1 skipped |

### T81: Peer watch and callout election
- **Design refs:** 7.5.5 steps 2 to 4, 7.6.3 (peer silence), D47, E25, AC9
- **Goal:** a peer is silent after 2 minutes without a summary and down after 10. Among the healthy hubs that see it
  down, only the one whose site name sorts first calls out. A hub with no peers can call a dead-man URL every 5
  minutes.
- **Depends on:** T80
- **Changes:** `crates/rackhand-hub/src/peers/{watch.rs, election.rs, deadman.rs}`; `tests/net/src/peer_watch.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `election::first_sorted_healthy_reporter_calls_out` | table cases | D47 |
  | `election::unhealthy_hub_never_elected` | | 7.5.5 |
  | `deadman::requests_every_5_minutes` | injected clock | 7.5.5 |
  | `deadman::url_set_in_settings_admin_only` | saved and audited; a responder gets 403 | 7.7.1 |
  | `net_tests::peer_watch::three_hubs_one_cut_exactly_one_callout` | in network namespaces: silent within 2 minutes, down within 10, one callout received by the fake webhook; local monitoring continues on the cut hub | AC9, E25 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(election::) | test(deadman::)' && cargo xtask ci net -- -E 'test(peer_watch::)'
  ```
  Expected: 4 passed, then 1 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci net`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T81: cargo nextest run -p rackhand-hub -E 'test(election::) | test(deadman::) | test(peers::watch)'; cargo nextest run -p rackhand-hub --test peer_contract | 6 + 12 passed (written beside the code): `election::first_sorted_healthy_reporter_calls_out` (the table: first of three, not first, a hub that doesn't see it down isn't a reporter, alone, a same name), `election::unhealthy_hub_never_elected` (an unhealthy hub never calls out, and an unhealthy other is not a candidate), `deadman::requests_every_5_minutes` (an injected clock: at once, then every 5 minutes; nothing without a URL or for a hub that has peers), `deadman::url_set_in_settings_admin_only` (a responder gets 403; only an https address without spaces; saved, shown on the page and audited as set or cleared without the URL itself in the log; empty turns it off), the states by age (silent at 2 minutes, down at 10), and in the contract test: a silent peer is a warning and a down one critical, each a callout from the only hub, and hearing from it again resolves both; a hub that isn't first among the healthy hubs seeing a peer down opens nothing, and takes over when the first one is not well |
  | 2026-11-23 | T81: planted faults, each in a copy of the tree | five, each failed a test: every hub calling out, an unhealthy hub elected, down after 5 minutes, incidents never resolved, and a hub with peers calling the dead-man URL |
  | 2026-11-23 | T81: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 782 passed, 1 skipped |

### T82: Relay
- **Design refs:** FR-20, 7.3.10 (modes, keys, unkeyed defaults, relay lists), D34, E27, E28, AC31, S2 finding
- **Goal:** `rackhand relay run` embeds the iroh relay with private and public modes, keys issued by `relay key create`
  (bound to their first endpoints), unkeyed limits of 1 Mbit/s and 2 GB a day, and priority at capacity if T08 found it
  possible. Hubs subscribe to relay lists (at most 100 valid entries, invalid ones skipped).
- **Depends on:** T17, T08
- **Changes:** `crates/rackhand-relay/src/{main.rs, admission.rs, keys.rs, limits.rs, acme.rs}`;
  `crates/rackhand-hub/src/peers/relay_lists.rs`; `packaging/systemd/rackhand-relay.service`
  (`CAP_NET_BIND_SERVICE`, unprivileged user).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `relay_keys::token_signed_by_relay_and_bound_to_max_endpoints` | the third endpoint on a 2-endpoint key is refused | 7.3.10 |
  | `relay_lists::garbage_and_10000_entries_keep_first_100_valid` | status shows the error | E28, AC31 |
  | `relay_lists::listed_relays_after_own_and_never_get_keys` | ordering; no key sent | 7.3.10 |
  | `net_tests::relay::private_refuses_unkeyed_admits_keyed` | | AC31 |
  | `net_tests::relay::public_unkeyed_limited_to_1_mbit` | measured throughput within 10% of 1 Mbit/s | AC31 |
  | `net_tests::relay::priority_admission_at_capacity` | only if T08 found it possible; otherwise this test is not written and the plan records the design change | AC31, E27 |
  | `net_tests::relay::refused_client_sees_reason` | | E27 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-relay && cargo nextest run -p rackhand-hub -E 'test(relay_lists::)' && cargo xtask ci net -- -E 'test(relay::)'
  ```
  Expected: 1 passed, then 2 passed, then 4 passed (or 3 if priority was ruled out in T08); 0 failed.
- **Regression (in addition):** `cargo xtask ci net`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T82: cargo nextest run -p rackhand-relay | 10 passed (written beside the code, and a real relay on loopback in `tests/relay.rs`): `keys::a_token_is_signed_by_the_relay_and_says_what_it_was_made_to_say` (another relay's key, a changed body, a cut token and plain text are refused; an expired key says so), `admission::token_signed_by_relay_and_bound_to_max_endpoints` (the third endpoint on a 2-endpoint key is refused; a reconnect of a bound endpoint is not), `admission::private_refuses_unkeyed_admits_keyed`, `admission::priority_admission_at_capacity`, `admission::bindings_survive_a_restart`, `run::one_rate_for_every_connection_set_by_the_operator` (public 125 000 bytes a second unless set, private none unless set), and over the real server with a client that speaks the relay protocol: `relay::private_refuses_unkeyed_admits_keyed` (a forged key and a third endpoint on a 1-endpoint key are refused), `relay::refused_client_sees_reason` (no key, a forged key and an expired key each get `the relay denied our authentication` with the reason), `relay::public_admits_anyone_but_not_a_forged_key`, `relay::priority_admission_at_capacity` (capacity 2: a third unkeyed endpoint is refused with `the relay is full`, a high key closes exactly one unkeyed connection through `Clients::disconnect`, a normal key takes the last unkeyed place, and a second normal key finds none left) |
  | 2026-11-23 | T82: cargo nextest run -p rackhand --bin rackhand -E 'test(relay_cmd::)'; cargo nextest run -p rackhand-net -E 'test(relays::)' | 2 + 2 passed: the `relay run` options and their defaults and every refusal (`--mode`, `--rate 0`, a bad address, `--cert` without `--key`, `--acme-domain` without a contact or beside `--cert`, a missing value, a repeated or unknown option), `relay key create` (a token the relay's own key verifies and another relay's does not, normal for one endpoint by default, an expiry date that lasts through its own day in UTC, and every refusal), and `relays::listed_relays_come_after_own_and_never_get_the_key` |
  | 2026-11-23 | T82: cargo nextest run -p rackhand-hub -E 'test(relay_lists::)' | 3 passed: `relay_lists::garbage_and_10000_entries_keep_first_100_valid` (10 000 entries, a third plain HTTP and a third without a URL, keep exactly the first 100 valid in order, with the skipped and ignored counts in the status; a list that is not TOML shows `not TOML` and the last good list stays in use; no `[[relay]]`, a `relay` that is not a list, an over-long name and a wrong type are each refused or skipped), `relay_lists::a_list_is_fetched_daily` (not at a day less one millisecond, then at a day), `relay_lists::listed_relays_after_own_and_never_get_keys` (own first, then the listed ones in order; a listed relay that is also ours is ours once; only our own relays carry the key) |
  | 2026-11-23 | T82: planted faults, each applied to the file and undone | ten, each failed a test: a private relay admitting an unkeyed endpoint, one endpoint too many bound to a key, equal priority evicting, key bindings not saved, key expiry ignored, a listed relay sent the key, listed relays before own, 1000 entries kept (first missed because the test compared with the constant; the test now says 100), plain HTTP accepted, and a failed list dropping the last good one |
  | 2026-11-23 | T82: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 798 passed, 1 skipped |

### T83: Hole punching and relay fallback
- **Design refs:** G6, FR-18, 14 (network tier), E26, AC27, S3 finding
- **Goal:** two hubs behind NAT link with an invite, connect directly when the NAT allows and through the relay when it
  doesn't, exchange summaries, and query each other's vitals. With hard NAT on both sides and no relay, the dashboard
  explains that a relay is needed.
- **Depends on:** T82, T09
- **Changes:** `tests/net/src/{topology.rs, holepunch.rs}` (full-cone, symmetric and UDP-blocked NAT with nftables);
  `crates/rackhand-hub/src/peers/path_status.rs` (path shown on the dashboard).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `net_tests::holepunch::full_cone_connects_direct` | path reported direct; summaries every 30 s; a vitals query works | AC27 |
  | `net_tests::holepunch::symmetric_connects_via_relay` | path reported relayed | AC27 |
  | `net_tests::holepunch::hard_nat_no_relay_unreachable_with_explanation` | `unreachable: no path`, and the dashboard text says a relay is needed | E26 |
- **Fails first:** the topology exists but the hub has no path status; the tests fail on the missing status.
- **Verification:**
  ```bash
  cargo xtask ci net -- -E 'test(holepunch::)'
  ```
  Expected: 3 passed, 0 failed.
- **Regression (in addition):** `cargo xtask ci net`: exit 0.
- **Manual verification:** first across the lab's two sites in L7; then MV15 (AC27 across the real internet between two of the owner's sites).
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T83: cargo nextest run -p rackhand-net -E 'test(paths::)'; cargo nextest run -p rackhand-hub -E 'test(path_status::)'; cargo nextest run -p rackhand-hub --test peer_contract -E 'test(a_peer_link_reports_the_path_it_uses)' | 2 + 3 + 1 passed (written beside the code): `paths::two_endpoints_on_one_machine_reach_a_direct_path` (`wait_direct`, then the selected path is direct), `paths::a_closed_connection_has_no_path_and_never_gets_a_direct_one` (the first version of this test failed: a closed connection keeps its last snapshot, which still said direct; `kind` and `wait_direct` now look at whether the connection is closed), `path_status::a_direct_path_needs_no_explanation`, `a_relayed_path_says_bulk_transfers_wait`, `hard_nat_no_relay_unreachable_with_explanation` (the label `unreachable: no path`, the words `a relay is needed` and `Add one under Peers and relays`; with a relay configured the advice is about the relay instead), and `a_peer_link_reports_the_path_it_uses` (a real peer link over a local relay moves to a direct path and says `direct` with nothing to explain) |
  | 2026-11-23 | T83: cargo xtask ci net | exit 0: 5 passed in the VM (kernel 6.1.192, 55 s): `holepunch::full_cone_connects_direct` (a hub behind masquerade dials a hub whose UDP port is forwarded, knowing only its relay: `wait_direct` succeeds, the selected path is direct, and a request and answer cross it), `holepunch::symmetric_connects_via_relay` (both behind masquerade: no direct path within 10 s, the selected path is the relay, and a request and answer cross it), `holepunch::hard_nat_no_relay_unreachable_with_explanation` (both behind masquerade, no relay, given only each other's private addresses: no connection in 20 s, and the status is `unreachable: no path` with the relay-needed explanation), `holepunch::public_unkeyed_limited_to_1_mbit` (a public relay with its default rate: 1 MiB relayed between two NATed hubs at a measured rate within 10% of 125 000 bytes a second), and the earlier `smoke::can_create_netns`. The first run failed on the nftables rule syntax in the topology (rules in a chain need a newline or a semicolon), fixed in the topology |
  | 2026-11-23 | T83: planted faults on the network tier, each applied to the file and undone | two, each failed its test: a full-cone NAT without its port forward (`full_cone_connects_direct`), and a public relay whose default rate is a thousand times higher (`public_unkeyed_limited_to_1_mbit`, which printed a rate of 11 537 939 bytes a second) |
  | 2026-11-23 | T83: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 804 passed, 1 skipped |

### T84: Tunnels and remote mode
- **Design refs:** FR-19, FR-21 (remote), 7.3.2 (remote mode), 7.3.11 (who may open, tunnel, CLI), 7.3.7 (remote-mode
  SSH with `from=` localhost), D59, D60, D80, AC30, AC46
- **Goal:** devices with a responder or admin account on the owning hub, runbook jobs, and hubs reaching their
  remote-mode probes open tunnels on ports the target's policy allows. A remote-mode probe splices tunnel streams only
  from its pinned hub and only to `127.0.0.1:22`, and a monitor remote-mode probe accepts none.
- **Depends on:** T83, T55
- **Changes:** `crates/rackhand-hub/src/peers/tunnel.rs` (server); `crates/rackhand-probe/src/remote.rs` (remote-mode
  splice); `crates/rackhand-hub/src/executor/steps/tunnel.rs`; `crates/rackhand-hub/tests/tunnel_contract.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `tunnel_contract::viewer_device_refused_responder_allowed` | `out_of_scope` for a viewer | 7.3.11 |
  | `tunnel_contract::port_not_in_policy_refused` | `port_not_allowed` | 7.3.11 |
  | `tunnel_contract::remote_probe_splices_only_to_local_22_from_pinned_hub` | another hub id is refused; another port is never opened | D60 |
  | `tunnel_contract::monitor_remote_probe_accepts_no_tunnels` | refused | 7.3.2 |
  | `net_tests::tunnel::ssh_through_connect_as_proxycommand` | `ssh -o ProxyCommand='rackhand-cli connect siteb/vm1 22'` works from another namespace; without a device enrollment on hub B it is refused | AC30 |
  | `net_tests::tunnel::runbook_on_remote_mode_machine_through_tunnel` | a remote-mode probe at a site without a hub reports over the mesh and a runbook runs on it; `from=` is localhost | AC46, D80 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub --test tunnel_contract && cargo xtask ci net -- -E 'test(tunnel::)'
  ```
  Expected: 4 passed, then 2 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci net`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T84: cargo nextest run -p rackhand-hub --test tunnel_contract | 6 passed (written beside the code, over real endpoints and a local relay): `tunnel_contract::viewer_device_refused_responder_allowed` (a viewer's device gets `OutOfScope`, a responder's gets its bytes back; a machine of another site and one that doesn't exist are `OutOfScope`; every refusal and the open tunnel are audit rows naming the user), `port_not_in_policy_refused` (the policy's ports only, 22 by default, and a port past 65 535), `remote_probe_splices_only_to_local_22_from_pinned_hub` (the pinned hub reaches the machine's SSH port; another port is `PortNotAllowed` and a listener there is never connected to; another machine's id is `OutOfScope`; another endpoint, even a registered device, is closed), `monitor_remote_probe_accepts_no_tunnels` (the hub says `Unsupported` without dialing, and the probe, asked directly, doesn't speak the protocol), `a_device_reaches_a_remote_machine_through_the_hub_and_the_probe` (two hops), and `the_hubs_own_ssh_to_a_remote_machine_goes_through_the_probe` (a loopback address for a remote-mode machine only, the same one each time) |
  | 2026-11-23 | T84: cargo nextest run -p rackhand-probe -E 'test(remote::)'; cargo nextest run -p rackhand-hub -E 'test(tunnel_step::)' | 3 + 1 passed: only this machine's SSH port, a monitor or local probe listening for no tunnel, only the pinned hub admitted, and `tunnel_step_checks_policy_and_reachability` (a port the policy allows and that opens; the policy's ports only, 22 by default, refused before anything opens; `machine_unreachable`, `tunnel_needs_port` and `out_of_scope`) |
  | 2026-11-23 | T84: cargo nextest run -p rackhand-it --profile it -E 'test(executor_it::executor::)' | 18 passed: with the new `runbook_on_remote_mode_machine_through_the_probes_tunnel` (AC46, D60: a machine in remote mode, whose own address is a documentation address nothing answers on, has a runbook run on it over SSH as the automation account, through the hub's loopback forward, a tunnel to the probe and the probe's splice to a real sshd; the first run timed out because the lab's site was not marked as the hub's own, so the hub did not reach the machine through the probe) and the 17 existing executor tests unchanged |
  | 2026-11-23 | T84: planted faults, each applied to the file and undone | nine, each failed a test: a viewer allowed to open tunnels, the policy's ports ignored, a machine of another site reachable, a monitor machine's probe dialed, local machines reached through a probe, the probe splicing any port, the probe serving any hub, a monitor probe listening for tunnels, and the probe serving other machines |
  | 2026-11-23 | T84: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 814 passed, 1 skipped |

### T85: Transfers and backup streams
- **Design refs:** FR-19, 7.3.11 (transfer, streams for backup tools, direct paths only), 9 (peer backups, export),
  D31, D58, E29, E30, AC29, S3 finding
- **Goal:**
  - `rackhand-cli send` and the runbook `transfer` step move files in content-addressed, BLAKE3-verified 1 MiB chunks
    that resume from the last verified chunk.
  - The `zfs-replicate`, `pbs-sync` and `restic-backup` runbooks stream through `rackhand/xfer/1` or a tunnel.
  - Bulk transfers wait for a direct path unless `allow_relay` is set.
  - Hubs send backups to peers that granted a quota, and `peer-backup export` gets one back out.
- **Depends on:** T84, T09, T45
- **Changes:** `crates/rackhand-hub/src/peers/xfer.rs`; `crates/rackhand-cli/src/send.rs`;
  `crates/rackhand-runbook/builtin/{zfs-replicate.toml, pbs-sync.toml, restic-backup.toml}`;
  `crates/rackhand-hub/src/backup/peer.rs`; `rackhand hub peer-backup export`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `xfer_contract::chunk_hash_mismatch_rejected_and_resent` | a corrupted chunk is not accepted | 7.3.11 |
  | `xfer_contract::resume_from_last_verified_chunk` | after an interruption, only the missing chunks are sent | E30 |
  | `xfer_contract::bulk_waits_for_direct_and_raises_info_after_10_min` | `bulk_waiting_direct_path` (injected clock) | E29 |
  | `peer_backup::sent_only_to_peers_with_quota_one_copy_kept` | quota 0 sends nothing | D58 |
  | `peer_backup::export_writes_restorable_file` | `hub restore` accepts it | 9 |
  | `net_tests::xfer::send_5gb_interrupted_at_60_percent_resumes_hash_matches` | a sparse 5 GB file in the VM; interrupted at 60%; BLAKE3 matches at the end | AC29 |
  | `net_tests::xfer::zfs_style_stream_pipes_between_hubs` | a fake `zfs-send` and `zfs-recv` pair through the wrapper; bytes equal | 7.3.11 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub --test xfer_contract && cargo nextest run -p rackhand-hub -E 'test(peer_backup::)' && cargo xtask ci net -- -E 'test(xfer::)'
  ```
  Expected: 3 passed, then 2 passed, then 2 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci net`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T85: cargo nextest run -p rackhand-hub --test xfer_contract | 5 passed (written beside the code, over real endpoints and a local relay, with a receiving sink in memory): `xfer_contract::chunk_hash_mismatch_rejected_and_resent` (a chunk with a damaged byte, one under the wrong index, one ahead of its turn and one of the wrong length are each not written and asked for again; then the right ones are taken, and the answer to the last is `done`), `resume_from_last_verified_chunk` (the sink breaks at chunk 3; the next attempt of the same file is told to go on from chunk 3 and only chunks 3 and 4 are sent; a finished file is only completed), `a_whole_file_arrives_and_matches` (and an empty file), `refusals_say_why_and_a_wrong_whole_file_is_not_accepted` (a refused destination says why; chunks that are each fine but don't make the offered file end in a refusal; another chunk size isn't taken), and `a_stream_arrives_whole_with_no_resume` |
  | 2026-11-23 | T85: cargo nextest run -p rackhand-net -E 'test(xfer::)' | 2 passed: `xfer::tests::bulk_waits_for_direct_and_raises_info_after_10_min` (an injected clock: the notice comes once, at 10 minutes, and the wait goes on until the path is direct; no notice for a direct path or before 10 minutes; no wait when a relay is allowed) and the chunk count of a file |
  | 2026-11-23 | T85: cargo nextest run -p rackhand-hub --test peer_backup; cargo nextest run -p rackhand-hub -E 'test(xfer_machine::)'; cargo nextest run -p rackhand-probe -E 'test(zfs::)'; cargo nextest run -p rackhand-runbook | 3 + 4 + 1 + 29 passed: `peer_backup::sent_only_to_peers_with_quota_one_copy_kept` (a peer with no space and a hub that isn't a peer are refused and nothing is kept; a peer with space has its backup kept byte for byte; a newer one replaces it, so one copy; a hub with nothing says so; the offers are audited), `a_backup_larger_than_the_space_given_is_refused_and_a_file_that_isnt_a_backup_too`, `export_writes_restorable_file` (the exported file restores with the master key to the same database and node key, and `export` refuses an unknown site, a path and a file that isn't a backup); the machine sink's destination, stream-command, partial-size and quoting rules; the wrapper's `zfs-send` and `zfs-recv` taking one plain dataset and nothing else; and `backup_runbooks_stream_or_run_through_the_wrapper` |
  | 2026-11-23 | T85: cargo nextest run -p rackhand-it --profile it -E 'test(executor_it::executor::transfers::) or test(remote_mode_machine_through)' | 9 passed against a real sshd (every one of these tests runs the machine in remote mode, so the transfer also goes through its probe): a file arrives with its hash, as root, mode 0640, no partial left; a send cut at chunk 2 goes on from the machine's partial file; a partial file that ends inside a chunk is continued, not repeated; a partial file of other content fails its hash and the next try starts over; a viewer, a path outside the roots and a stream to anything but `zfs-recv` are refused and nothing is written outside; the `zfs-replicate` runbook pipes the wrapper's `zfs-send` into `zfs-recv` on another machine of this hub, byte for byte, and names a machine that isn't there; a peer's stream is refused with `needs_approval` until the machine's policy takes peer requests, and a peer sends no file to a machine; a stream is piped through the wrapper into `zfs recv -u`; and the T84 runbook through the tunnel still passes. The first run of the interrupted send kept less than two chunks: dropping the SSH session on abandon discarded written data, so the sink now closes the input and lets `receive` finish |
  | 2026-11-23 | T85: cargo xtask ci net | exit 0: 6 passed in the VM (266 s): the five of T83 and `xfer::send_5gb_interrupted_at_60_percent_resumes_hash_matches` (a sparse 5 GiB backup-shaped file from a hub behind masquerade to a forwarded hub, cut at 60% of its chunks, goes on at the cut and not from the start, and the file kept has the same size and BLAKE3) |
  | 2026-11-23 | T85: planted faults, each applied to the file and undone | fifteen, each failed a test: a damaged chunk accepted, a chunk of any length accepted, an out-of-order chunk accepted (the first test lacked the right bytes under the wrong index, added), resume ignored, no quota check, no size check, more than one backup kept, a file that isn't a backup accepted, export given a path, any destination written, any stream command, flags passed to zfs, no wait for a direct path, and a peer's stream taken without the policy (found by the integration test) |
  | 2026-11-23 | T85: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 831 passed, 1 skipped |

### T86: `rackhand-cli`
- **Design refs:** 7.7.3 (`login`, `connect`, `forward`, `send`, `mcp`, `status`), 7.3.6 (`rackhand-cli mcp`), D42,
  D50, D59
- **Goal:** `rackhand-cli` builds for Linux, Windows and macOS, keeps a device key per hub, and its `login`, `status`,
  `connect`, `forward` and `mcp` commands work. `forward` binds 127.0.0.1 only, and `mcp` is a stdio MCP server that
  dials the owning hub with the device key and a personal MCP key.
- **Depends on:** T84, T75
- **Changes:** `crates/rackhand-cli/src/{main.rs, login.rs, status.rs, connect.rs, forward.rs, mcp.rs, config.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `cli::device_keys_per_hub_mode_0600` | two hubs give two keys | D59 |
  | `cli::forward_binds_loopback_only` | the listener address is 127.0.0.1 | 7.3.11 |
  | `cli::every_command_has_help_and_nonzero_exit_on_error` | | 7.7.3 |
  | `it::cli::mcp_stdio_lists_tools_and_calls_get_machine` | a stdio MCP client session through the CLI to a hub | 7.3.6 |
  | `it::cli::login_with_invite_then_status` | | 7.7.3 |
  | `cross::cli_builds_for_windows_and_macos_targets` | `cargo build -p rackhand-cli --target x86_64-pc-windows-gnu` succeeds; macOS is built in the release workflow (T91) | D42 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-cli && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(cli::)' && cargo build -p rackhand-cli --target x86_64-pc-windows-gnu
  ```
  Expected: 3 passed, then 2 passed; the Windows build exits 0.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T86: cargo nextest run -p rackhand-cli | 9 passed (written beside the code): `config::device_keys_per_hub_mode_0600` (two hubs give two keys, the same hub the same key again, mode 0600, and a key others can read is refused), `commands::forward_binds_loopback_only` (127.0.0.1), `tests::every_command_has_help_and_a_usage_error_when_misused`, `tests::the_words_of_each_command`, the hubs file (a hub enrolled again replaces its entry; an unknown site names the sites there are), the invite and machine-name rules, the MCP auth line, and the binary's own `cli::every_command_has_help_and_nonzero_exit_on_error` (each command's `--help` exits 0; a mistake in the command line exits 2 and a failure exits 1, naming what failed) |
  | 2026-11-23 | T86: cargo nextest run -p rackhand-hub --test cli_contract | 4 passed against a real hub over a local relay: `login_with_invite_then_status` (an invite used once enrolls the device and status says `enrolled and reachable`; a second login with the same invite is refused with the hub's reason; a computer the hub doesn't know is told so), `connect_and_forward_reach_a_machine_by_its_name` (`connect` with standard input and output as the tunnel, and `forward` on a loopback port, by `home/web`; a machine of another site, a machine that isn't there, a port the policy doesn't allow and a hub the computer isn't enrolled to each fail with what was wrong; each tunnel is an audit row), `send_puts_a_file_where_the_hub_takes_it` (2.5 MB, hash checked), and `mcp_stdio_lists_tools_and_calls_get_machine` (a stdio MCP session through the CLI with a personal key: `initialize`, `tools/list` with `get_machine`, `get_machine` by `home/web`; an unknown key gets no session) |
  | 2026-11-23 | T86: planted faults, each applied to the file and undone | five failed a test: `forward` listening on every address, one key for every hub, keys made world-readable, no MCP auth line, and an unknown hub taken for the first one; a sixth, a machine name resolved at any site, is shadowed by the tunnel server's own site check (a machine of another site is refused either way, which the test asserts) |
  | 2026-11-23 | T86: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 845 passed, 1 skipped (earlier runs on a loaded machine timed out on heavy hub tests that each pass alone in under a second) |

### T87: Address changes, `set-hub` and identity conflicts
- **Design refs:** 7.3.2 (errors), 7.3.3 (`KeysUpdate`), 7.7.3 (`set-hub`), E6, E35, E43
- **Goal:**
  - When the hub's address changes, probes still reach it by endpoint id through a relay and receive `ConfigUpdate`
    and a `KeysUpdate` with the new `from=`; at a LAN-only site, `rackhand-probe set-hub <ticket>` fixes a probe.
  - A cloned VM (one endpoint id from two boot ids) is refused until one re-enrolls.
  - A renamed or re-addressed machine keeps its identity, and its SSH host key is still checked.
- **Depends on:** T42, T61
- **Changes:** `crates/rackhand-probe/src/set_hub.rs`; `crates/rackhand-hub/src/registry/identity.rs`;
  `crates/rackhand-hub/src/actions/address_change.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `identity::same_endpoint_two_boot_ids_both_refused` | `identity_conflict`; both refused until re-enrollment | E6 |
  | `identity::rename_and_new_address_keep_machine_and_host_key_check` | | E43 |
  | `it::address::hub_address_change_config_and_keys_update` | probes get the new addresses and `from=`; SSH works from the new address | E35 |
  | `it::address::set_hub_requires_root_and_rewrites_probe_toml` | as the probe user it fails | E35, D91 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(identity::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(address::)'
  ```
  Expected: 2 passed, then 2 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T87: cargo nextest run -p rackhand-hub -E 'test(identity::)' | 3 passed (written beside the code): `identity::same_endpoint_two_boot_ids_both_refused` (a second boot id on an endpoint id whose first session reported 5 s ago is a conflict: the first session is closed, neither is let back in, another endpoint id is not affected, and a re-enrollment clears it), `a_reboot_is_not_a_clone` (an old session silent for longer than 20 s is replaced by the new boot's, the same boot reconnecting is never a conflict, a probe that doesn't say its boot id is never part of one), and `rename_and_new_address_keep_machine_and_host_key_check` (a machine renamed and moved to another address is the same machine id and endpoint id, the pinned SSH host key still verifies and another host's key is refused) |
  | 2026-11-23 | T87: cargo nextest run -p rackhand-hub --test address_change; cargo nextest run -p rackhand-probe -E 'test(set_hub::)' | 3 + 1 passed, with the probe's own `Link` and helper code over real endpoints: `address_change::hub_address_change_config_and_keys_update` (after the hub says its new addresses a connected probe gets a `ConfigUpdate` with them and a `KeysUpdate` that its helper's `apply` accepts, signed by the hub it pins: both hub users' `authorized_keys` take the SSH `from="198.51.100.5"` and lose the old address; a probe that connects afterwards is told in its Welcome), `a_machine_that_isnt_managed_gets_the_addresses_and_no_keys`, `same_endpoint_two_boot_ids_both_refused` (one node key, two boot ids, both reporting: the clone is refused with `IdentityMismatch`, the original is closed with the same code, one critical `probe.identity_conflict` event, and neither gets back in), and `set_hub::set_hub_requires_root_and_rewrites_probe_toml` (not root: nothing changes; root: the hub, its addresses and relays are the ticket's and the machine section is kept; a bad ticket or file changes nothing, no half-written file is left) |
  | 2026-11-23 | T87: planted faults, each applied to the file and undone | eleven failed a test: a silent old session still counting as a clone, an active one never counting, a conflict forgotten, no key update, monitor machines given keys, the old address kept in the key lines, a Welcome without the addresses, set-hub without root, and the probe ignoring the new addresses (the others were shadowed or the same test) |
  | 2026-11-23 | T87: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 852 passed, 1 skipped (a first run of the new tests found a race in one of them, fixed) |

### T88: Dashboard: peers, relays and peer sites
- **Design refs:** 7.7.1 (Overview site tiles, Site page for peers, Peers and relays page), 7.3.4
- **Goal:** the Overview shows a tile per site, local and peers. Peer site pages render from summaries and allowed
  queries, and actions on a peer's machine create an `ActionRequest`. The Peers and relays page shows peer state,
  allowed queries, backup quota, relays and relay lists.
- **Depends on:** T81, T82
- **Changes:** `crates/rackhand-hub/src/web/pages/{peers.rs, peer_site.rs, relays.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `pages::peer_offline_shows_last_summary_time` | | 7.7.1 |
  | `pages::peer_machine_action_creates_action_request` | no local job | 7.7.1 |
  | `pages::peer_allowed_queries_and_quota_editable_by_admin` | responder 403 | 7.7.2 |
  | `pages::relay_list_status_shows_errors` | | 7.3.10 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(pages::peer) | test(pages::relay)'
  ```
  Expected: 4 passed, 0 failed.
- **Manual verification:** the M6 page walk, done by the run in L7.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T88: cargo nextest run -p rackhand-hub -E 'test(pages::peer) | test(pages::relay)' | the four tests named in the plan are in `web::tests::pages::peers` and were written first against code that didn't compile (no `with_peer_reach`, no `with_relay_lists`, no `/peers` routes): `peer_offline_shows_last_summary_time` (a peer last heard 45 minutes ago is Down on its own page, on the peers list and on the overview, each saying how long ago; its machines, health and open incident are the last summary's; a fresh peer is Up; an address that is neither a site nor a peer is 404), `peer_machine_action_creates_action_request` (a viewer is refused, a responder's request reaches the peers system as an `ActionRequest` with the machine's id, runbook, reason, a fresh 16-byte request id and `requested_by` naming the user and this site; the page says it needs an approval on the peer; local `jobs` and `approvals` are unchanged; an unlisted machine, no runbook, no reason and an unknown peer all ask nothing), `peer_allowed_queries_and_quota_editable_by_admin` (a responder gets 403 and nothing changes; an admin's choice is stored as the queries ticked and the space in bytes and is audited; a quota that isn't a whole number from 0 to 100000 is 400; join and unlink are admin only and go to the peers system) and `relay_list_status_shows_errors` (a list with a skipped entry shows `1 relay kept, 1 skipped`, a list that can't be read shows its error, relay lists are off by default, only an admin saves https addresses, and a refused list changes nothing); the module has the four, which are the 4 the filter selects |
  | 2026-11-23 | T88: cargo nextest run -p rackhand-hub --test peer_link; cargo nextest run -p rackhand-store -E 'test(db::)'; cargo nextest run -p rackhand-hub -E 'test(follow_tests::)' | 7 + 6 + 1 passed, the parts T88 needed under the pages: joining with an invite makes both hubs list and admit each other and survive a restart (the inviter keeps the joiner's relays), summaries flow both ways and a peer that can't be reached doesn't hold up the others, a used invite, a site name either side knows and a stranger link nothing, unlinking tells the peer and both forget, a request for a peer's machine gets the owner's answer on a real connection, and the path to a connected peer is known; a version-1 database is upgraded keeping its rows and an upgraded one opens unchanged; relay lists are fetched only when on and not air-gapped and follow the setting |
  | 2026-11-23 | T88: planted faults, each applied to the file and undone | the link code: five failed a test (the joiner never admits the inviter, the inviter drops the joiner's relays, a known site is linked anyway, the joiner forgets the relays it was given, an unreachable peer reported as fine); a connection that is never reused changes nothing anyone can see; the pages: all seven failed a test (a responder editing a peer's queries, a machine the peer never listed being asked for, a down peer shown up, the quota not saved, a plain-http relay list accepted, a list's error not shown, the last summary time not shown, the last found by adding the assertion on the peers list) |
  | 2026-11-23 | T88: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 867 passed, 1 skipped (two runs under heavy disk load timed out on unrelated tests that pass alone in 0.3 s; the run on a quiet disk passed in 42 s) |

### L7: Live pass for M6: two sites
- **Design refs:** 14, D107, AC27, AC28, AC29, AC30, AC46
- **Goal:** two lab sites link through the lab relay and NAT, share summaries, transfer, tunnel and proxy, with real
  machines.
- **Depends on:** T88, L6
- **Changes:** live tests; `lab deploy` installs the relay on `relay` and a second hub on `hub-b`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `live::m6::sites_link_and_exchange_summaries` | `hub` and `hub-b` link (site B behind the relay's NAT) and each shows the other's machines | AC27 |
  | `live::m6::cross_hub_request_needs_owner_approval` | a runbook requested from `hub` on `target-b` waits for approval on `hub-b` | AC28 |
  | `live::m6::cli_connect_works_as_proxycommand` | `ssh -o ProxyCommand='rackhand-cli connect %h'` reaches `target-b` from WSL | AC30 |
  | `live::m6::transfer_resumes_after_a_cut` | a 500 MB transfer (AC29's 5 GB shortened for the lab) cut halfway with `lab cut hub-b` resumes and the hash matches | AC29 |
  | `live::m6::remote_mode_probe_runs_a_runbook` | `target-b` in remote mode reports to `hub` and runs a runbook through the tunnel | AC46 |
- **Fails first:** `cargo xtask ci live --target local --milestone m6 --no-deploy` with the M5 build still deployed:
  every test fails (no peers yet); then the M6 build is deployed.
- **Verification:**
  ```bash
  cargo xtask ci live --target local --milestone m6
  ```
  Expected: 5 passed, 0 failed.
- **Regression:** `cargo xtask ci fast`: exit 0; `cargo xtask ci live --target local --milestone m1`: 8 passed.
- **Manual verification:** the M6 page walk (peers, relays, peer sites), done by the run as in L2. The internet link is
  MV15, run in L9 if the owner provides two sites.
- **Done when:**
  - [ ] New tests observed failing before the M6 deploy
  - [ ] New tests and the regression suites pass
  - [ ] M6 page walk recorded
  - [ ] Evidence recorded below
- **Risk / rollback:** revert the commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

### M7: Windows

### T89: Windows probe and helper
- **Design refs:** FR-4, FR-5, FR-2, 7.3.3 (named pipe, Windows layout, logon types), D11, D53, D81, AC56
- **Goal:** the Windows probe collects vitals, services, connections (GetExtendedTcpTable and GetExtendedUdpTable
  every 5 seconds), processes from `%TEMP%` and Downloads, listening ports and logon events, and talks to its helper
  over a named pipe whose ACL allows only `NT SERVICE\RackhandProbe`. The parsing logic is tested in CI on recorded
  outputs, and the services run as a manual checklist on a real Windows machine.
- **Depends on:** T22, T23, T26, T66, T67
- **Changes:** `crates/rackhand-probe/src/windows/{collect.rs, conntable.rs, procs.rs, logon.rs, pipe.rs,
  service.rs}`, with platform-neutral parsing in `src/windows/parse/` compiled on every platform; recorded outputs in
  `tests/fixtures/windows/` (invented names).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `windows_parse::tcp_udp_table_records_to_tuples` | recorded table bytes to tuples with pid | FR-4, AC56 |
  | `windows_parse::process_in_temp_or_downloads_is_warning` | warning severity | 7.6.6, AC56 |
  | `windows_parse::logon_types_2_3_10_only` | other types ignored | 7.3.3 |
  | `windows_parse::vitals_and_services_from_recorded_wmi` | catalogue names | FR-2 |
  | `windows_parse::pipe_acl_sddl_allows_only_probe_service` | the SDDL string | 7.3.3 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-probe -E 'test(windows_parse::)' && cargo xtask ci win
  ```
  Expected: 5 passed, 0 failed; `ci win` builds `rackhand-probe` for `x86_64-pc-windows-gnu` and exits 0.
- **Regression (in addition):** `cargo xtask ci win`: exit 0.
- **Manual verification:** MV16 (Windows checklist: services start, pipe ACL, AC56 connections, a process from
  `%TEMP%` and a new listening port reported).
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T89: cargo nextest run -p rackhand-probe -E 'test(windows_parse::)' | 5 passed (written first against modules that didn't exist), on recorded outputs in `tests/fixtures/windows/` (invented names, documentation addresses): `windows_parse::tcp_udp_table_records_to_tuples` (the bytes of `MIB_TCPTABLE_OWNER_PID`, `MIB_TCP6TABLE_OWNER_PID`, `MIB_UDPTABLE_OWNER_PID` and `MIB_UDP6TABLE_OWNER_PID` become the sockets the Linux capture reads, with the pid where Linux has an inode: an established connection is outbound with its owner and state 1, a listener on 3389 listens, TIME_WAIT belongs to no process, bound UDP sockets are listeners, and a table that says more rows than it holds, or that is cut short, gives the rows it holds), `windows_parse::process_in_temp_or_downloads_is_warning` (of eight processes the user's Temp, a Downloads folder, the system Temp and another drive in other letter case are flagged, and System32, Program Files and a folder with `Downloads` only in its name are not; the events are `proc.exec_from_tmp` with a drive-letter path, which the hub's severity table, extended in this step, makes a warning while a Linux path stays critical), `windows_parse::logon_types_2_3_10_only` (4624 and 4625 of types 2, 3 and 10 become `logon` and `auth.failed` events with the method and the source address; service, batch, unlock, cached and other types, machine accounts, anonymous logons and other event ids are left out), `windows_parse::vitals_and_services_from_recorded_wmi` (the catalogue's names with the values the recorded CIM output gives, fixed disks by drive without the optical one, interfaces without tunnels and the loopback, physical disks without the total, per-core CPU only when asked for, watched services whatever their state and automatic ones that stopped with their own error but not exit code 1077, and one object where PowerShell writes a list of one) and `windows_parse::pipe_acl_sddl_allows_only_probe_service` (the service SID derived from the name matches the documented `NT SERVICE\TrustedInstaller` one, and the descriptor is a protected DACL of SYSTEM and the probe's service account and nothing else) |
  | 2026-11-23 | T89: cargo nextest run -p rackhand-hub -E 'test(security_events::)' | 3 passed: the severity table has the Windows rows (a path with a drive letter is a warning, a Linux path or an odd `c:` inside one stays critical) |
  | 2026-11-23 | T89: planted faults, each applied to the file and undone | ten failed a test (ports read in the wrong byte order, ESTABLISHED mapped to SYN_SENT, Downloads not looked at, paths compared with their case, service logons reported, machine accounts reported, optical drives reported, a service waiting for its trigger counted as failed, Everyone allowed to read the pipe, the service SID taking no upper-casing); three survived the first time and the test and fixtures were tightened (the state number, a service logon by an account that isn't SYSTEM, an optical drive with media) |
  | 2026-11-23 | T89: cargo xtask ci win | exit 0: `rackhand-probe` and `rackhand-cli` build for `x86_64-pc-windows-gnu` (the first time since T49f; the dependencies' cdylib no longer stops the link); no Pester scripts exist until T90 |
  | 2026-11-23 | T89: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 874 passed, 1 skipped |

### T90: Windows installer, SSH setup, dispatcher and scripts
- **Design refs:** 7.3.7 (Windows), 7.3.12 (Windows installer, monitor on Windows), 7.5.6 (Windows quarantine), 7.5.3
  (`patch-windows`), D53, D67, AC35 (Windows part)
- **Goal:**
  - `install.ps1` verifies signatures and enrolls a Windows machine.
  - For managed machines it also installs OpenSSH Server, puts the `Match User rackhand,rackhand-ai` block before the
    administrators block, and sets transcription for `rackhand-ai`.
  - `dispatch.ps1` accepts only `<script-name> <json-args>` for shipped scripts, validated against each script's
    parameter schema.
  - `patch-windows` and the Windows quarantine script work through the dispatcher.
- **Depends on:** T89, T61, T72
- **Carried in (D91, 2026-11-21):** a Windows `exec` runs through the dispatcher, not `timeout -k 5 <s> sh -c`, which is the Linux line (D91).
- **Changes:** `packaging/windows/{install.ps1, dispatch.ps1, scripts/*.ps1, schemas/*.json}`;
  `crates/rackhand-runbook/builtin/patch-windows.toml`; `packaging/windows/tests/*.Tests.ps1` (Pester).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `Dispatch.Tests: refuses unknown script and extra arguments` | non-zero exit, nothing run | 7.3.7 |
  | `Dispatch.Tests: validates args against schema` | wrong type or pattern refused; a leading dash refused | 7.3.7, E51 |
  | `Install.Tests: sshd_config Match block placed before administrators block` | text order in a sample config | 7.3.7 |
  | `Install.Tests: bad signature stops before installing` | with mocked downloads | AC35 |
  | `Install.Tests: monitor installs no OpenSSH and no accounts` | mocked calls not made | 7.3.12 |
  | `Quarantine.Tests: rules allow only hub paths and DHCP` | generated rule set | 7.5.6 |

  Carried in from T63:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::windows::diagnostics_run_through_dispatcher` | each 7.8.3 diagnostic's Windows form runs through the dispatcher with the same parameter limits | 7.8.3 |
- **Fails first:** Pester reports the scripts don't exist.
- **Verification:**
  ```bash
  cargo xtask ci win
  ```
  Expected: Pester `Passed: 6, Failed: 0`, and the Windows cross builds succeed.
- **Regression (in addition):** `cargo xtask ci win`: exit 0.
- **Manual verification:** MV16 (Windows checklist: enrollment managed and monitor, SSH as both identities, the
  dispatcher, `patch-windows` dry run, quarantine and release).
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T90: cargo xtask ci win | exit 0, with Pester `Passed: 12, Failed: 0` (the six tests of the plan and six more) and the Windows cross build of `rackhand-probe` and `rackhand-cli`: `Dispatch.Tests` (`refuses unknown script and extra arguments`: unknown scripts, names that aren't names, a script with no schema, `..\x`, `x;calc`, an empty command and `x && calc` all refuse with nothing run, an extra or a missing argument is 2 and the script's own exit code comes back; `validates args against schema`: a wrong type, a number past the limit, negative or fractional numbers, a bool as text, a leading dash, a control character, a value past the pattern and a null all refused with nothing run, and a non-object or truncated JSON is not a request; a job reference that isn't the hub's own is refused and a job nobody started is `unknown`), `Install.Tests` (`sshd_config Match block placed before administrators block`, once and idempotent, forced command for `rackhand` only, passwords off, the rest of the file kept, removed again for a monitor machine; `bad signature stops before installing` and a verifier that isn't this installer's stops it before anything else, with no OpenSSH, files, join, account, service or sshd_config touched; `monitor installs no OpenSSH and no accounts`; a managed machine does everything in 7.3.7's order; no assistant key, no `rackhand-ai`), `Quarantine.Tests` (`rules allow only hub paths and DHCP`: exactly DHCP both ways, the probe's QUIC out to the hub, the hub's SSH in and the hub's ping in, and nothing else with a remote address of Any; both directions blocked by default and the release restores what was saved) and `Diagnostics.Tests` (every schema has its script and the other way round, and for each of the nineteen diagnostics and the patch and quarantine scripts the dispatcher runs the script with its parameters and refuses a leading dash, a semicolon and an extra argument; the carried-in `it::windows::diagnostics_run_through_dispatcher`) |
  | 2026-11-23 | T90: cargo nextest run -p rackhand-runbook -p rackhand-hub -E 'test(windows) | test(builtin) | test(a_windows_machine)' | passed, written first and failing to compile or assert: `windows::every_diagnostic_has_a_windows_script_and_a_schema_of_its_own_limits` (the same parameters, patterns and types as `diagnostics.toml`), `windows::the_shipped_scripts_and_schemas_are_the_same_set`, `windows::patch_windows_arguments_are_what_its_script_takes`, `runbook::windows_arguments_take_declared_parameters_whole` (declared whole parameters only), `builtin::patch_windows_has_the_shape_of_the_others_through_the_dispatcher` (the eight steps of 7.5.3, the update and install steps detached `windows_script` steps with phases `scan` and `install`, targets Windows), `executor::windows::` (the dispatcher line is the script and compact JSON of strings in name order, quotes and backslashes stay in their JSON string, nothing the dispatcher wouldn't take is sent, and the `job-start`, `job-status` and `job-clean` lines for a detached step), `coordinator::windows_tests::parameters_fill_a_windows_steps_arguments_whole` and `diagnostics::tests::a_windows_machine_runs_the_dispatcher_script_under_the_same_limits` (a Windows machine gets `diag-<name>` with the same limits and bindings, and a Linux machine is unchanged) |
  | 2026-11-23 | T90: planted faults, each applied to the file and undone | nine failed a test: parameters not put into a Windows step's arguments, an undeclared parameter in a Windows argument accepted, a Windows diagnostic's parameters not checked, a script name allowed to hold a semicolon, the dispatcher accepting a leading dash and accepting an extra argument, the SSH block placed after the administrators block, a bad signature not looked at, a monitor machine getting OpenSSH, and the quarantine leaving a port open |
  | 2026-11-23 | T90: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check clean; fast tier 886 passed, 1 skipped; ci win exit 0 with Pester 12 passed |

### M8: Lifecycle, release and performance

### T91: Release signing, manifests and reproducible builds
- **Design refs:** 5.2 (supply chain), 13 (release signing, D90), D36, D55, AC43, AC67 (standby key), E64
- **Goal:** CI builds static release artifacts and an unsigned manifest; rebuilding a tag elsewhere gives identical
  hashes; the verification crate from T44 also checks manifests. No CI job or run step ever holds a signing key.
- **Depends on:** T44
- **Changes:** `crates/rackhand-release/` (adds the manifest format and manifest checks); `xtask release build`
  (deterministic flags, `SOURCE_DATE_EPOCH`, path remapping, and `RACKHAND_RELEASE=1`, which makes the lab's
  `lab-build` feature fail the build) and `xtask release repro` (builds twice in different
  directories and compares); `.github/workflows/release.yml` (self-hosted, builds artifacts for every target in 5.2 and
  uploads them unsigned as workflow artifacts; no secrets); `docs/maintainers/signing.md` (the offline procedure for the
  maintainer).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `release::verify_accepts_current_and_standby_keys` | test keys | E64, AC67 |
  | `release::verify_rejects_other_key_and_tampered_file` | | 5.2 |
  | `release::manifest_lists_every_artifact_hash` | | 5.2 |
  | `xtask::repro::two_builds_identical_hashes` | for `rackhand-probe` and `rackhand` musl x86_64 | AC43 |
  | `xtask::release::artifacts_are_static` | `file` reports statically linked; no `PT_INTERP` | AC43 |
  | `ci_guard::release_workflow_uses_no_secrets` | the workflow file references no `secrets.` | D90 |
  Carried in from T44 and T45:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `release::release_build_pins_only_the_release_keys` (carried in from T44) | the release build of `rackhand-verify`, the helper and the hub refuses a file signed with a test key of `tests/keys/` (the `test-keys` feature is a dev-dependency feature; a build with `--all-targets` would unify it in) | 13, D90 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-release && cargo nextest run -p xtask -E 'test(repro::) | test(release::) | test(ci_guard::)' && cargo xtask release repro
  ```
  Expected: 3 passed, then 3 passed plus the earlier `ci_guard` tests; `release repro` prints identical hashes.
- **Manual verification:** MV17 (the maintainer follows `signing.md` once with a throwaway key pair to confirm the
  procedure; real signing happens only at release time and isn't part of this run).
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T91: cargo nextest run -p rackhand-release | 12 passed, written first and failing to compile (no manifest module): `release::verify_accepts_current_and_standby_keys` and `release::verify_rejects_other_key_and_tampered_file` are T44's `current_and_standby_signatures_verify` and `tampered_file_or_comment_or_other_key_refused` (a file signed with the standby key is accepted, E64; another key, a changed file or comment and a key id with the wrong key behind it are refused), `release::manifest_lists_every_artifact_hash` (every artifact's SHA-256 and size, sorted by name, the same text from the same files in any order, parsed back equal), `manifest::a_changed_missing_or_extra_file_is_found` (a changed file, also one of the same length, a missing one and a stray one in a release directory, with signatures and the manifest beside the artifacts not counting), `manifest::a_manifest_that_isnt_one_is_refused`, `manifest::a_signed_manifest_is_checked_against_the_pinned_keys` (signed by the current or the standby key; a third key or a manifest changed after signing is refused), and in `tests/release_build.rs` `release_build_pins_only_the_release_keys` (the carried-in test: a build made as a release is made, `RACKHAND_RELEASE=1` and no `test-keys`, refuses a file signed with a test key while a lab build accepts it), `a_release_build_with_the_test_keys_cannot_be_made` and `verify_checks_a_release_directory_against_its_signed_manifest` (`rackhand-verify --manifest <dir>` takes a signed directory whole) |
  | 2026-11-23 | T91: cargo nextest run -p xtask -E 'not test(release::slow_tests::)' | 28 passed: `ci_guard::release_workflow_uses_no_secrets` (the real `release.yml` has no finding, and each way of breaking it has one: a secret, a pull request trigger, write permission, no fork guard, a push without tags, a signing tool), `release::tests::` (the ELF check finds an interpreter or a needed library, the zip is the same bytes for the same files with the standard CRC check value, the flags that name the source, the registry and the toolchain, and unknown targets refused) |
  | 2026-11-23 | T91: cargo xtask ci release | exit 0 in 563 s: `release::slow_tests::artifacts_are_static` (the hub, probe, CLI and verifier for musl x86_64 have no interpreter and need no library, the manifest lists exactly what is there, and the installer is rendered) and `release::slow_tests::repro::two_builds_identical_hashes` (the hub and the probe of one commit, built from two copies in two directories, have the same SHA-256 each: `d3faa8d5...` and `f998e759...`); the first run of the second test failed on a real difference, OpenSSL's compiled-in modules path, which holds the build's target directory, and release builds now run in the fixed `/tmp/rackhand-release-target` |
  | 2026-11-23 | T91: cargo xtask release build --out /tmp/relwin --targets x86_64-unknown-linux-musl,x86_64-pc-windows-gnu | exit 0: sixteen files and an unsigned `manifest.json` (hub, probe, CLI and verifier for Linux; probe, CLI and verifier for Windows; `install.sh` and `install.ps1` with their versions and verifier hashes filled in; `rackhand-windows-scripts.zip`; the unit and OpenRC files); the hub and probe hashes are those of the repro test |
  | 2026-11-23 | T91: planted faults, each applied to the file and undone | six failed a test: a changed file passing the manifest's check (found only after a same-length change was added to the test), a stray file allowed in a release directory, `rackhand-verify --manifest` not checking the files, a release build with the test keys going through, an interpreter not making a binary dynamic, and the guard not looking for secrets |
  | 2026-11-23 | T91: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo deny check; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check and cargo deny clean; fast tier 898 passed, 3 skipped (the first run in the same pass hit disk-pressure timeouts in unrelated hub_cmd tests; the rerun on a quiet disk passed); release tier 2 passed |

### T92: Probe self-update
- **Design refs:** FR-22, 7.3.2 (`UpdateAvailable`), 7.3.3 (updates, guard, slots), 13 (channels, canary), D73, D86,
  D91, E39, E65, AC37, AC45 (offer)
- **Goal:**
  - When the hub says so, the probe downloads the release into its spool (at most 64 MB).
  - The helper copies it into the inactive slot, refuses downgrades, and verifies the hash and signature.
  - A guard running the old binary switches back if the new probe doesn't report `connected` within 2 minutes.
  - One canary per site updates first, the rest an hour later if the canary opened no new incidents.
  - A machine that can't reach the URL stays on its version and reports `update_unreachable`.
- **Depends on:** T91, T43
- **Changes:** `crates/rackhand-probe/src/update/{download.rs, apply.rs, guard.rs}`;
  `crates/rackhand-hub/src/actions/probe_rollout.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `apply::reads_only_fixed_spool_file_without_following_links` | a symlink in the spool is refused | D91 |
  | `apply::downgrade_refused` | | D73 |
  | `apply::bad_hash_or_signature_deletes_slot_copy` | | FR-22 |
  | `rollout::canary_first_then_rest_after_1h_without_incidents` | injected clock; a canary incident holds the rest | 13, AC37 |
  | `rollout::beta_channel_offered_beta_stable_not` | a hub on `stable` never offers a beta release; on `beta` it does | 13 |
  | `download::unreachable_url_reports_info_and_keeps_version` | `update_unreachable` | E65 |
  | `it::update::good_release_switches_slot` | probe reconnects with the new version | FR-22 |
  | `it::update::broken_release_restored_within_3_minutes` | a release that never connects; the guard switches back | E39, AC37 |
  | `it::update::lying_state_file_only_keeps_or_loses_signed_version` | the probe user writes `connected` falsely; no unsigned code runs | 7.3.3 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-probe -E 'test(apply::) | test(download::)' && cargo nextest run -p rackhand-hub -E 'test(rollout::) | test(download::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(update::)'
  ```
  Expected: 4 passed, then 2 passed, then 3 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |
  | 2026-11-23 | T92: cargo nextest run -p rackhand-probe -E 'test(update::)' | 27 passed, written first (each failing on `todo!()` or a missing item): `apply::reads_only_fixed_spool_file_without_following_links` (a link as the spool file or as its directory, a directory, a FIFO and a file over 64 MB are refused and nothing reaches a slot), `apply::downgrade_refused` (an older release that was really signed and is asked for as a newer one, the same version, and 0.1.10 over 0.1.9 as numbers), `apply::bad_hash_or_signature_deletes_slot_copy` (a wrong hash, another key, a signature for other bytes or for another file, junk, and the copy left in the slot is gone), `apply::a_good_release_goes_to_the_inactive_slot_and_nothing_else_changes`, `apply::a_plain_file_from_the_installer_becomes_slot_a`, `apply::a_release_over_the_limit_is_refused_without_being_copied`, `guard::broken_release_restored_within_two_minutes`, `guard::only_connected_with_the_new_version_counts`, `guard::a_probe_that_connects_with_the_new_version_is_kept`, `guard::a_switch_that_cannot_be_made_changes_nothing_and_restarts_nothing`, `guard::the_slots_are_named_by_the_helper_and_nothing_else_is_accepted`, `helper::update::` (5: the guard starts from a copy of the running binary, a refused release starts none, a second update while the guard runs is refused, a guard that can't start leaves the machine as it was, a build with no keys installs nothing), `download::unreachable_url_reports_info_and_keeps_version` and five more of `download::`, `offers::` (4), `probe_and_helper_agree_on_the_spool`, `run::tests::the_hello_names_the_architecture` |
  | 2026-11-23 | T92: cargo nextest run -p rackhand-drivers -E 'test(fetch::)' && cargo nextest run -p rackhand-release | 5 passed, then 16 passed: `fetch::` (a file written as it arrives, the limit counted on what arrives and not on what the server says, a status other than 200 and a redirect refused, no answer or no route is an error and not a hang, a self-signed https certificate taken); in the release crate `binary::version_is_read_from_the_signed_comment`, `binary::a_signature_for_another_file_or_without_a_version_is_refused`, `binary::versions_compare_as_numbers` and `manifest::a_beta_manifest_says_so_and_a_stable_one_is_unchanged` |
  | 2026-11-23 | T92: cargo nextest run -p rackhand-hub -E 'test(rollout) | test(exemptions::) | test(security_events::) | test(probe_build) | test(an_offered_update) | test(release_channel) | test(selfwatch::)' | 38 passed: `rollout::canary_first_then_rest_after_1h_without_incidents` (two sites, an injected clock: one canary each, the rest only after the hour, offered again after ten minutes, a late machine too), `rollout::a_canary_incident_holds_the_rest`, `rollout::beta_channel_offered_beta_stable_not`, `rollout::a_canary_that_does_not_come_up_on_the_new_version_holds_the_rest`, `rollout::a_restarted_hub_goes_on_where_it_was` (canary, started rest and hold survive a restart), `rollout::a_canary_that_stays_away_is_replaced_after_six_hours`, `rollout::only_machines_the_release_has_a_file_for_and_that_are_behind_are_offered_it`, `rollout::what_a_machine_is_offered_is_saved_so_its_files_changing_to_it_are_not_an_event`, nine `rollout_service` tests (the signed manifest and the probe files read with their signatures, a manifest not signed by a pinned key or a file that isn't the listed one offers nothing, the service sends offers and saves rows, a restarted service goes on, the machines that update and incidents by machine and time), `exemptions::a_probe_update_the_hub_offered_is_exempt_for_its_own_files_and_hash_only`, `ingest::an_offered_update_is_found_by_machine_hash_and_time`, `ingest::the_probe_build_from_the_hello_is_kept_per_machine`, `library::the_release_channel_is_stable_unless_the_hub_setting_says_beta`, the severity table rows for `update_unreachable` (info) and `update_refused` (warning), and `selfwatch::binary_hash_mismatch_is_critical` with the manifest in the format T91 writes (it was written for an older one and failed first) |
  | 2026-11-23 | T92: cargo nextest run --profile it -p rackhand-it -E 'test(update::)' | 3 passed in a Debian container with systemd and a hub built with the test keys (`lab-build`): `update::probe::good_release_switches_slot` (174 s: the hub offers 0.1.1 within a minute, the probe downloads it, the helper copies it into slot B, the guard switches, the probe reconnects as 0.1.1 from slot B with slot A and the wrapper as they should be, and nothing the update did is an event or an incident), `update::probe::broken_release_restored_within_3_minutes` (236 s: a signed file that isn't a working probe; the guard switches and goes back to slot A, connected as 0.1.0, within 3 minutes of the switch), `update::probe::lying_state_file_only_keeps_or_loses_signed_version` (266 s: the probe user writes `connected` for 0.1.1 over and over; the guard keeps the signed release, which is exactly the signed file, and the probe user can't write a slot, the link or the wrapper). The runs found three things the unit tests couldn't: the Hello carried no architecture (so the hub could name no file for the machine), the probe wrote its download under `buffer/update` where the helper reads `update`, and `/run` is `noexec` in the container (the guard's copy now lives in `/var/lib/rackhand-helper`) |
  | 2026-11-23 | T92: planted faults, each applied to the file and undone | fifteen failed a test: a release that isn't newer accepted, the version asked for taken for the signed one, a link as the spool file followed, the copy's hash unchecked, the guard not needing `connected`, the guard taking any version, the guard never waiting, a second update starting a second guard, the download's size unlimited, a canary incident not holding the rest, a stable hub offering a beta release, the rest offered at once and not after the hour, any hash exempt on the probe's files, and a signature for another file accepted |
  | 2026-11-23 | T92: cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo deny check; cargo check -p rackhand-probe --target x86_64-pc-windows-gnu; cargo xtask ci fast; cargo xtask arch-check | fmt, clippy, arch-check and cargo deny clean; Windows check of the probe passes; fast tier 957 passed, 3 skipped |
  | 2026-11-24 | T92, Windows (owner, 2026-11-24): cargo test --no-run --lib -p rackhand-release -p rackhand-probe --target x86_64-pc-windows-gnu, the test binaries run on a Windows 11 host | `slots::windows_tests` 4 passed (the installer's `rackhand-probe.exe` becomes slot A and the release goes to slot B, a junction as the spool directory or above it is not followed, a directory or a file over the limit is refused, the guard switches the services and goes back) and the probe's `update::` and `windows::update::` 18 passed (the binary path read from `sc.exe qc`, the active slot the one both services run, the command line a service is pointed at, the slots named by the helper on Windows); a planted fault (the reparse check on the spool's directories taken out) failed `a_junction_in_the_spool_is_not_followed`; clippy for the Windows target, tests included, clean |
  | 2026-11-24 | T92: cargo nextest run -p rackhand-release -E 'test(slots::)' && cargo nextest run -p rackhand-hub -E 'test(rollout)' | 11 passed (the apply and guard tests, moved from `rackhand-probe` into `rackhand-release` when the slots became shared with the hub's updater, with a hub layout of their own), then 19 passed with `rollout::a_windows_machine_is_offered_the_windows_file` and `rollout_service::probes_are_offered_only_the_hubs_own_version` (FR-22: a release newer than the hub waits for the hub); the three `update::probe::` integration tests passed again (227 s, 238 s, 265 s) with the hub built as 0.1.1 (`RACKHAND_LAB_VERSION`) |

### T93: Hub, relay and operator updater
- **Design refs:** 7.5.7, 7.1 (updater), D78, D86, D98, E63, AC67
- **Goal:**
  - An admin's Update click makes the hub take a backup, download the release and write a request.
  - The root updater trusts only the version in that request: it copies the fixed file to the inactive slot, refuses
    a lower version, and verifies the signature with its own pinned keys.
  - A guard switches back, restoring the backup if migrations ran, when `/healthz` isn't healthy within 2 minutes.
  - The first audit entry after a rollback records it.
  - Relays and operators update the same way.
- **Depends on:** T91, T45
- **Changes:** `crates/rackhand/src/update/{request.rs, apply.rs, guard.rs}`;
  `packaging/systemd/{rackhand-updater.path, rackhand-updater.service}`; `rackhand self-update`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `update::request_only_version_trusted` | extra fields ignored; paths never read from it | 7.5.7 |
  | `update::unsigned_or_lower_version_refused_no_slot_change_audited` | | E63, AC67 |
  | `update::standby_key_release_accepted` | | AC67, E64 |
  | `it::updater::good_update_switches_and_healthz_ok` | in a systemd container | 7.5.7 |
  | `it::updater::bad_update_rolls_back_and_restores_backup_when_migrated` | the dashboard shows the rollback and the lost window | 7.5.7 |
  | `it::updater::hub_user_cannot_write_its_binary` | permission denied | D98, AC67 |
  | `it::updater::relay_and_operator_not_root` | process uids not 0 | AC67 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand -E 'test(update::)' && cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(updater::)'
  ```
  Expected: 3 passed, then 4 passed; 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

### T94: Site bootstrap and LXC script
- **Design refs:** G7, G8, 7.7.4, FR-21 (site bootstrap), D35, D36, AC32
- **Goal:** `install.sh --hub` turns a fresh Debian 12 or later machine into a hub that prints the dashboard URL and a
  one-time setup code, and `rackhand-lxc.sh` on a Proxmox host creates a Debian LXC (2 vCPU, 1 GB RAM, 20 GB disk)
  and runs the hub installer inside it.
- **Depends on:** T93, T44
- **Changes:** `packaging/install.sh` (`--hub`); `packaging/rackhand-lxc.sh`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::bootstrap::fresh_debian_becomes_hub_and_links_to_existing` | first run reachable with the setup code; an invite from it links to a second hub | AC32 |
  | `it::bootstrap::lxc_script_pct_calls_match_spec` | with a fake `pct`, the recorded calls create 2 vCPU, 1 GB, 20 GB Debian and run the installer | AC32 |
  | `it::bootstrap::refuses_debian_11` | clear message | 7.7.4 |
- **Fails first:** the container tests fail (no `--hub`).
- **Verification:**
  ```bash
  cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(bootstrap::)'
  ```
  Expected: 3 passed, 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** first in the local lab (L8: the LXC script on `pve9`, and E34 recovery); then MV13 (the
  LXC script on a real Proxmox host, in L9).
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

### T95: Version compatibility
- **Design refs:** 5.2 (compatibility), 13 (versions), AC45, AC53
- **Goal:** a hub accepts probes, operators, relays and CLIs of its own minor version and one minor older, and refuses
  older ones with `0x12`. Peers of different minors interoperate on summaries and requests.
- **Depends on:** T42, T77, T82, T86
- **Changes:** `crates/rackhand-hub/src/version.rs` (acceptance rules); `tests/compat/` and `xtask compat`. Once a
  previous minor release exists, `xtask compat` builds that tag's binaries and runs the main flows of each contract
  against the current hub. Until then it runs the current binaries with their reported version forced to the previous
  minor. That proves the version rules but not schema drift between real releases, so AC45 and AC53 stay `unverified`
  until the first two minor releases exist (this reclassification is put to the owner at plan review).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `compat::older_probe_connects_reports_and_is_offered_update` | with the forced previous-minor version | AC45 |
  | `compat::older_operator_relay_and_cli_connect_and_work` | each completes its main flow | AC53 |
  | `compat::two_minors_older_refused_with_0x12` | | 5.2 |
  | `compat::peer_of_other_minor_exchanges_summary_and_request` | | 5.2 |
- **Fails first:** compile errors; then the version rules refuse the forced older version until they're implemented.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub --test compat && cargo xtask compat
  ```
  Expected: 4 passed, 0 failed; `xtask compat` reports which mode it ran in (previous release or forced version).
- **Manual verification:** None.
- **Done when (in addition):** AC45 and AC53 are marked `unverified (needs a previous minor release)` in the matrix.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

### T96: Performance tier
- **Design refs:** 5.2 (probe and hub footprint, latency), 11, AC2 (2-hour version), AC42, AC66 (load part), AC69
  (performance part), S6 and S8 findings
- **Goal:** the nightly performance tier asserts the budgets:
  - a 1-hour probe soak (RSS, CPU, bytes sent, binary size);
  - a hub load test of 200 simulated probes for 1 hour (p99 ingest-to-visible under 2 s, RSS under 300 MB, CPU under
    10% of a core, live acks under 2 s while rule evaluation is stalled 60 s);
  - a 2-hour hub outage replay;
  - a synthetic 2-year fill for 50 machines (database under 2 GB, retention and rollups within schedule).
- **Depends on:** T42, T68, T05, T06
- **Changes:** `tests/perf/src/{probe_soak.rs, hub_load.rs, outage_replay.rs, fill.rs, sim_probe.rs}`; the `perf` job
  in `ci.yml` (nightly).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `perf::probe_soak_1h_within_budget` | RSS at most 25 MB, CPU at most 1%, at most 2 KB/s, binary at most 15 MB, helper RSS at most 8 MB | AC42 |
  | `perf::hub_load_200_probes_1h` | p99 under 2 s, RSS under 300 MB, CPU under 10% | AC42 |
  | `perf::stalled_rules_60s_acks_still_under_2s` | | AC66 |
  | `perf::outage_2h_backfills_in_15_min_live_under_30s` | | AC2 |
  | `perf::fill_2y_50_machines_under_2gb_retention_on_schedule` | including 100 000 destinations a day on one machine | AC42, AC69 |
- **Fails first:** the tier's crate is empty; the tests don't exist.
- **Verification:**
  ```bash
  cargo xtask ci perf
  ```
  Expected: 5 passed, 0 failed.
- **Regression (in addition):** none beyond the fast tier (perf is nightly).
- **Manual verification:** None.
- **Risk / rollback:** a missed budget is reported to the owner with the numbers (design 17 says the owner decides
  trade-offs). Revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

### T97: Offline operation
- **Design refs:** 5.2 (availability), AC41, NG10
- **Goal:** with no internet, no peers and no operator, the hub keeps collecting, alerts by email through a LAN SMTP
  server, and runs runbooks.
- **Depends on:** T59
- **Changes:** `tests/it/src/offline.rs` (a Docker network with no outside route, a LAN SMTP sink container).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::offline::collects_alerts_by_lan_smtp_and_runs_runbooks` | a disk rule fires an email to the LAN sink; a `service-restart` runbook runs; no outbound connection attempts reach the outside | AC41 |
- **Fails first:** if any system blocks on an outside call, the test fails on a timeout (expected to pass once the
  air-gapped and no-peer paths are right; the test is first run with outside sources enabled to see the failure mode).
- **Verification:**
  ```bash
  cargo xtask it-images && cargo nextest run -p rackhand-it -E 'test(offline::)'
  ```
  Expected: 1 passed, 0 failed.
- **Regression (in addition):** `cargo xtask ci it`: exit 0.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

### T98: Retention for every table and settings ranges
- **Design refs:** 7.4.1 (retention rules for every table, the two caps), D100, AC69
- **Goal:** every table in 7.4.1 that grows has a retention rule, job output and transcripts share a 100 MB budget
  trimmed oldest first (metadata kept), and `peer_summaries` holds one row per peer.
- **Depends on:** T85, T76, T70
- **Changes:** registrations in `crates/rackhand-store/src/retention.rs` for every table; the shared output budget in
  `crates/rackhand-hub/src/actions/output_budget.rs`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `retention::every_table_rule_from_design` | the table of rules equals 7.4.1 (events 90 d, connection records 30 d, check results 30 d, notifications 90 d, incidents and approvals 1 y, audit 1 y with checkpoint, tokens 30 d after expiry, sessions on expiry, known devices 1 y, baseline entries 180 d unseen, label tables 48 h after a newer epoch) | AC69 |
  | `retention::run_leaves_nothing_older_than_rule` | seeded old rows in every table are gone; boundary rows stay | AC69 |
  | `output_budget::oldest_trimmed_first_metadata_kept` | at 100 MB the oldest output goes; job and step rows stay | AC69 |
  | `retention::peer_summaries_one_row_per_peer` | | AC69 |
  | `settings::every_setting_in_7_8_1_has_default_and_range` | table-driven over every row of 7.8.1: the default applies, the bounds are accepted, one past each bound is refused | 7.8.1 |
  Carried in from T42:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `probe::settings_edit_pushes_config_update` (carried in from T42) | saving `config/hub.toml` with a new `[probe] interval_s` sends `ConfigUpdate` to every connected probe, which reports at the new interval without reconnecting | 7.8.1, D114 |
  Carried in from T39b:
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `hub::saved_notifier_applies_without_a_restart` (carried in from T39b) | a notifier saved from Settings sends the next callout without restarting the hub; one removed stops | 7.3.9, 7.7.1 |
  | `incidents::counted_rules_escalate_on_time_after_a_restart` (carried in from L2) | a service down across a hub restart reaches critical at its 4th report counted from before the restart, and pending security updates reach critical 14 days after they were first seen, not 14 days after the restart (the counts and first-seen times are kept) | 7.6.1, AC66 |
  | `incidents::container_restarts_incident_kept_across_a_restart` (carried in from L2) | a container-restarts incident open across a hub restart isn't resolved by the empty restart window the hub starts with: the restart times are kept, or the incident waits for 10 minutes of reports | 7.6.1 |
- **Fails first:** the rule table assertion fails for tables registered as fixed-size placeholders.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-store -E 'test(retention::)' && cargo nextest run -p rackhand-hub -E 'test(output_budget::) | test(settings::every_setting)'
  ```
  Expected: 3 passed (plus the T27 retention tests), then 2 passed; 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

### T99: Documentation and command check
- **Design refs:** G8 (documented for strangers), 7.7.3 (every command has `--help`), 10 (AI provider data, hardening
  guide), 13 (rollout), E34 (documented)
- **Goal:** the repository has user documentation for installing a hub and machines, operators (including what the AI
  provider receives), relays, the hardening guide, the Windows and lab checklists, master-key recovery, and the
  maintainer's signing procedure. A check confirms every command the docs mention exists and answers `--help`.
- **Depends on:** T94
- **Changes:** `README.md` (status, quick start); `docs/{install.md, machines.md, operators.md, relays.md,
  hardening.md, recovery.md, windows-checklist.md, lab-checklist.md}`; `xtask docs-check`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `xtask::docs::every_documented_command_exists` | each `rackhand ...`, `rackhand-probe ...` and `rackhand-cli ...` command in a code block runs `--help` with exit 0 | 7.7.3, G8 |
  | `xtask::docs::no_lab_addresses_in_docs` | only documentation IP ranges appear | D71 |
- **Fails first:** compile errors; then commands from the design that don't exist yet fail the check.
- **Verification:**
  ```bash
  cargo nextest run -p xtask -E 'test(docs::)' && cargo xtask docs-check
  ```
  Expected: 2 passed; `docs-check` reports every command found.
- **Manual verification:** None.
- **Done when (in addition):** pages in the maintainers' documentation space are a follow-up (out of this repository).
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

### L8: Final local pass for M8
- **Design refs:** 14, D107, AC32, AC37, AC41, AC67, E34
- **Goal:** updates, site bootstrap, the LXC script, offline operation and master-key recovery work on real machines,
  and every earlier live pass still passes on the final build.
- **Depends on:** T99, L7
- **Changes:** live tests; `lab deploy --release <version>` builds lab releases with `-lab.N` pre-release versions
  (for example `0.1.0-lab.1` then `0.1.0-lab.2`) so update order can be tested without changing the workspace version
  (D106).
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `live::m8::probe_self_update_canary_first` | publishing `-lab.2` updates the canary (`target`) first, then `alpine`; a broken `-lab.3` is restored within 3 minutes | AC37 |
  | `live::m8::hub_updater_upgrades_and_refuses_lower` | the hub updates to `-lab.2` and refuses `-lab.1` and an unsigned build | AC67 |
  | `live::m8::lxc_script_creates_a_hub_on_proxmox` | `rackhand-lxc.sh` on `pve9` creates an LXC hub that starts and links to `hub` | AC32 |
  | `live::m8::bootstrap_turns_fresh_debian_into_a_linked_hub` | site bootstrap on a reset `hub-b` gives a hub that links to `hub` | AC32 |
  | `live::m8::recovery_procedure_restores_the_master_key` | following `docs/recovery.md` on a lab hub with its key file removed brings it back with its vault readable | E34 |
  | `live::m8::lab_without_internet_keeps_working` | with every user-mode NIC cut, monitoring, callouts to the WSL-side fakes and runbooks keep working | AC41 |
- **Fails first:** `cargo xtask ci live --target local --milestone m8 --no-deploy` with the M6 build still deployed:
  every test fails (no updater, bootstrap or LXC script yet); then the M8 build is deployed.
- **Verification:**
  ```bash
  cargo xtask ci live --target local --milestone m8 && cargo xtask ci live --target local --milestone all
  ```
  Expected: 6 passed, 0 failed; then every live test from L1 to L8 passes (`all`, 52 tests; the M5 tests run when
  `RACKHAND_LIVE_ASSISTANT=1` is set and are otherwise reported as skipped).
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** a final page walk of every page in 7.7.1, done by the run as in L2.
- **Done when:**
  - [ ] New tests observed failing before the M8 deploy
  - [ ] New tests and the full live suite pass
  - [ ] Final page walk recorded
  - [ ] Evidence recorded below
- **Risk / rollback:** revert the commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

### L9: Real-lab pass
- **Design refs:** 14 (real lab), D107, AC17, AC19, AC27, AC32, AC33, AC58, AC72, AC73, E11, E37, E62, E66
- **Goal:** the same build, deployed to the owner's hub VM or LXC, manages one real VM, and the checks that need real
  hardware pass on the owner's Proxmox and TrueNAS.
- **Depends on:** L8
- **Changes:**
  - `lab/real.env.example` (committed, no values): `RACKHAND_REAL_HUB`, `RACKHAND_REAL_TARGET`, `RACKHAND_REAL_SSH_KEY`,
    `RACKHAND_REAL_PVE8`, `RACKHAND_REAL_PVE9`, `RACKHAND_REAL_PVE_TOKEN_FILE`, `RACKHAND_REAL_GUEST`,
    `RACKHAND_REAL_ZFS_HOST`, `RACKHAND_REAL_TRUENAS`, `RACKHAND_REAL_TRUENAS_KEY_FILE`, `RACKHAND_REAL_SITE_B`.
  - `--target real` for `ci live` and `lab deploy`: reads the untracked `lab/real.env`; refuses any host or guest not
    named there. The hub and one managed VM are required: without `RACKHAND_REAL_HUB`, `RACKHAND_REAL_TARGET` and
    `RACKHAND_REAL_SSH_KEY` the first five tests fail and L9 is `blocked`. Any other test whose variables are missing
    is skipped with "not configured", and its MV stays open.
  - `live::real::*` tests, mostly the local tests' bodies run against the real hosts.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `live::real::refuses_unnamed_hosts` | `--target real` with a guest not in `real.env` fails before connecting | D107 |
  | `live::real::hub_deploys_and_signs_in` | the hub installs on `RACKHAND_REAL_HUB` and sign-in with the second factor works | AC40 |
  | `live::real::target_installs_and_reports` | `RACKHAND_REAL_TARGET` enrolls and reports within 30 s | AC1, AC35 |
  | `live::real::service_stop_calls_out_and_resolves` | as `live::m1::stopped_service_calls_out_and_resolves` | AC5 |
  | `live::real::probe_stop_raises_silence` | stopping the probe service gives the silence warning at 60 s | AC8 |
  | `live::real::lxc_attribution_on_a_real_host` | MV2 | E37 |
  | `live::real::zfs_memory_reading` | MV3 | 7.6.1 |
  | `live::real::proxmox_minimal_privileges` | MV4: the S4 script on both real nodes with the owner's token and named guest | 7.8.6 |
  | `live::real::patch_named_guest_with_snapshot_and_rollback` | MV7 | AC19, E11 |
  | `live::real::quarantine_named_guest_and_release` | MV9 and MV11 | AC17, AC58, AC72, E66 |
  | `live::real::provision_vm_on_a_named_node` | MV10 | AC33 |
  | `live::real::lxc_script_on_a_real_node` | MV13 | AC32 |
  | `live::real::truenas_driver_reports` | the TrueNAS driver reports every 7.4.2 TrueNAS metric with the owner's read-only key | AC11 |
- **Fails first:** with `lab/real.env` present, `cargo xtask ci live --target real --milestone real --no-deploy` (no
  hub on the owner's host yet) fails every test except the first with "hub not reachable"; `refuses_unnamed_hosts`
  fails until the guard exists.
- **Verification:**
  ```bash
  cargo xtask ci live --target real --milestone real
  ```
  Expected: the five required tests and every other configured test pass, 0 failed; skipped tests are listed with
  their open MV.
- **Regression:** `cargo xtask ci fast`: exit 0.
- **Manual verification:** the owner provides `lab/real.env` and the access it names (MV18). MV8 (a hypervisor
  hosting a test hub) and MV15 (two sites over the internet) run here only if the owner names those hosts.
- **Done when:**
  - [ ] New tests observed failing before the deploy
  - [ ] Every configured test passes; every skipped test has its MV listed as open
  - [ ] MV rows updated with the results
  - [ ] Evidence recorded below (redacted per D71; no real host names or addresses)
- **Risk / rollback:** the run touches only the hosts and guests named in `real.env`; destructive tests (patch,
  rollback, quarantine, provisioning) run only on the named test guest and node. The documented uninstall steps for the
  hub and the probe remove the lab build afterward. Revert the commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

## Traceability matrix

Every acceptance criterion, functional requirement, contract, edge case and non-functional row in the design, with
the steps and tests that prove it. "MV" marks a manual check (see *Manual verifications*). Status starts at `todo`.

### Acceptance criteria

| Target | Description | Step(s) | Test(s) / check | Status |
| --- | --- | --- | --- | --- |
| AC1 | Vitals, services, containers, updates within 30 s | T22, T39, T42, L2, L9 | `collect::every_catalogue_metric_from_debian_fixture`, `query::vitals_visible_before_compaction`, `it::probe_hub::vitals_visible_within_30s`; `live::m1::target_installs_and_reports_within_30s`, `live::real::target_installs_and_reports` | todo |
| AC2 | 2-hour outage backfills, live under 30 s, no stale incidents | T25, T32, T42, T96, L2 | `ingest::replayed_sample_older_than_10_min_flagged_history_only`, `incidents::stale_samples_do_not_open_threshold_incidents`, `it::probe_hub::outage_backfills_and_live_stays_fresh`, `perf::outage_2h_backfills_in_15_min_live_under_30s`; `live::m1::cut_link_backfills_without_stale_incidents` | todo |
| AC3 | Buffer limit drops oldest, `probe.data_gap` | T26, T42 | `probe_contract::data_dropped_closes_gap_and_records_event`, `it::probe_hub::buffer_limit_drops_oldest_with_gap_event` | todo |
| AC4 | Retention and rollups correct | T27 | `rollup::tier1_equals_min_max_avg_of_minute`, `rollup::tier2_...`, `retention::each_tier_removes_only_older_than_limit` | todo |
| AC5 | Critical and warning callouts in time, resolution | T28, T33, T42, L2, L9 | `threshold::worked_example_...`, `notify::critical_sent_immediately_warnings_grouped_5_min`, `it::probe_hub::disk_rule_callouts_and_resolution`; `live::m1::stopped_service_calls_out_and_resolves`, `live::real::service_stop_calls_out_and_resolves` | todo |
| AC6 | Forecast example ETA 62.5 h | T29 | `forecast::worked_example_warns_with_eta_62_5_hours` | todo |
| AC7 | Baseline example at 14:35, frozen | T31 | `baseline::worked_example_warns_at_14_35_and_freezes` | todo |
| AC8 | Silent warning at 60 s; `expected_offline` info only | T30, T42, L2, L9 | `silence::machine_warning_at_max_60s_or_4_intervals`, `it::probe_hub::stopped_probe_opens_silent_warning_at_60s`; `live::m1::paused_target_raises_silence_warning`, `live::real::probe_stop_raises_silence` | todo |
| AC9 | Three hubs, one cut, one callout | T81 | `net_tests::peer_watch::three_hubs_one_cut_exactly_one_callout` | todo |
| AC10 | HTTP check and certificate warnings | T29, T31, T46, L3 | `it::checks::http_check_on_stopped_service_and_expiring_cert`; `live::m2::service_checks_and_certificate_warning` | todo |
| AC11 | Driver metrics from simulators; silent after 2 polls | T47, T48, T30, L3, L9 | `proxmox::poll_maps_every_catalogue_metric`, `it::drivers::form_added_simulators_report_and_silence_after_2_polls`; `live::m2::proxmox8_driver_reports_node_and_guests`, `live::m2::proxmox9_driver_reports_node_and_guests`, `live::m2::silent_proxmox_node_after_two_polls`, `live::m2::snmp_appliance_added_by_form_reports`, `live::real::truenas_driver_reports` | todo |
| AC12 | Step timeout and 1 MB output cap | T53, T55, T58 | `it::executor::step_timeout_fails_with_timeout`, `it::executor::output_over_1mb_cut_with_marker_in_job_log` | todo |
| AC13 | New ASN and country on 4444 is a warning; sampling shown | T67, T68, T70 | `conn_score::new_asn_new_country_port_4444_is_warning_naming_container`, `ebpf_tests::capture::short_connect_seen`, `capability::no_ebpf_reports_sampling` | todo |
| AC14 | Threat-listed IP critical within 60 s | T70 | `it::conn::threat_listed_destination_critical_within_60s` | todo |
| AC15 | Exec from /tmp and new port; container start quiet | T71, L5 | `it::security::exec_from_tmp_critical_new_port_warning_container_start_nothing`; `live::m4::exec_from_tmp_and_new_port_flagged` | todo |
| AC16 | Key added critical; new-IP login warning; no file contents | T71, L5 | `it::security::authorized_keys_added_outside_job_critical_new_ip_login_warning`; `live::m4::new_ssh_key_is_critical`, `live::m4::login_from_new_address_is_a_warning` | todo |
| AC17 | Approved guest quarantine and release | T72, L5, L9 | `it::quarantine::nftables_only_hub_paths_and_dhcp_then_removed`; `live::m4::quarantine_lxc_guest_and_release`, `live::real::quarantine_named_guest_and_release`; MV11 | todo |
| AC18 | Auto rule for `dmz`; hypervisor excluded; step-up to enable | T72 | `it::quarantine::auto_rule_dmz_known_bad_quarantines_end_to_end`, `quarantine::auto_rule_matches_tag_quarantines_without_approval`, `quarantine::hypervisor_with_same_finding_not_quarantined`, `quarantine::enabling_rule_requires_step_up` | todo |
| AC19 | Patch flow with snapshot, verify, job log | T59, L4, L9 | `it::patch::debian_full_flow_with_fake_package_manager`; `live::m3::patch_target_from_lab_repository`, `live::m3::lxc_patch_snapshots_and_prunes_to_three`, `live::real::patch_named_guest_with_snapshot_and_rollback`; MV7 | todo |
| AC20 | Hold, approve-only, maintenance windows | T34, T59 | `select::hold_never_patched`, `select::approve_only_...`, `hub_cmd::patching::no_patch_or_silence_alert_during_maintenance_window` (D99), `driver::maintenance_after_selection_holds_the_machine_back` | done |
| AC21 | Failed verify routes to `patch-failure`, offer within 60 s | T59, T77 | `it::patch::verify_fails_on_missing_required_mount`, `it::operator::patch_failure_offer_within_60s` | todo |
| AC22 | Out of scope and tool not allowed, audited | T75, L6 | `mcp_contract::exec_outside_job_hosts_out_of_scope_and_audited`, `mcp_contract::tool_not_in_playbook_refused_and_audited`; `live::m5::out_of_scope_tool_is_refused_and_audited` | todo |
| AC23 | Level-1 approval flow, mismatch, no MCP approval | T75 | `mcp_contract::level_1_run_runbook_needs_approval_then_runs_once`, `mcp_contract::different_arguments_give_approval_mismatch`, `mcp_contract::no_tool_changes_an_approval` | todo |
| AC24 | Injected "approve" text changes nothing | T75, L6 | `mcp_contract::injected_output_does_not_change_approvals`; `live::m5::injected_approve_text_changes_nothing` | todo |
| AC25 | Real Claude Code fixes a stopped Compose project, 2 of 3 runs | T77, L6 | `live::m5::stopped_compose_project_fixed_in_2_of_3_runs`; MV14 | todo |
| AC26 | Personal `read` vs `read_request` keys, expiry | T74, T75 | `mcp_contract::read_key_refused_for_diagnostic_and_runbook`, `mcp_contract::expired_key_refused`, `mcp_contract::read_request_key_same_gating` | todo |
| AC27 | Two hubs behind NAT link and exchange summaries | T83, L7 | `net_tests::holepunch::full_cone_connects_direct`, `net_tests::holepunch::symmetric_connects_via_relay`; `live::m6::sites_link_and_exchange_summaries`; MV15 | todo |
| AC28 | Cross-hub request needs owner approval; `JobLog` denied | T80, L7 | `it::peers::responder_on_a_requests_compose_restart_on_b`, `peer_contract::action_request_needs_owner_approval`, `peer_contract::joblog_denied_by_default`; `live::m6::cross_hub_request_needs_owner_approval` | todo |
| AC29 | 5 GB transfer resumes, hash matches | T85, L7 | `net_tests::xfer::send_5gb_interrupted_at_60_percent_resumes_hash_matches`; `live::m6::transfer_resumes_after_a_cut` | todo |
| AC30 | `connect` as `ProxyCommand`; refused without device | T84, L7 | `net_tests::tunnel::ssh_through_connect_as_proxycommand`; `live::m6::cli_connect_works_as_proxycommand` | todo |
| AC31 | Relay modes, limits, lists, priority if S2 allows | T08, T82 | `net_tests::relay::*`, `relay_lists::garbage_and_10000_entries_keep_first_100_valid` | todo |
| AC32 | Site bootstrap and LXC script | T41, T94, L8, L9 | `it::bootstrap::fresh_debian_becomes_hub_and_links_to_existing`, `it::bootstrap::lxc_script_pct_calls_match_spec`; `live::m8::lxc_script_creates_a_hub_on_proxmox`, `live::m8::bootstrap_turns_fresh_debian_into_a_linked_hub`, `live::real::lxc_script_on_a_real_node`; MV13 | todo |
| AC33 | `provision-vm` boots, enrolls, healthy | T64, L4, L9 | `provision::vm_clone_cloudinit_start_calls_match_recorded_api`; `live::m3::provision_vm_boots_enrolls_and_is_healthy`, `live::real::provision_vm_on_a_named_node`; MV10 | todo |
| AC34 | `guided-install` steps approved in order | T77 | `it::operator::guided_install_each_change_approved_in_order` | todo |
| AC35 | Linux, Alpine, Windows install; bad signature stops | T44, T90, L2, L3 | `it::install::debian_managed_enrolls_and_reports`, `it::install::alpine_managed_enrolls_and_reports`, `it::install::bad_signature_stops_before_installing`, `Install.Tests`; `live::m1::target_installs_and_reports_within_30s`, `live::m1::tampered_probe_stops_the_install`, `live::m2::alpine_installs_and_reports`; MV16 | todo |
| AC36 | Agentless, operator, device joins; used or expired refused | T35, T49, L3 | `join_contract::device_operator_and_peer_invites_join`, `join_contract::used_expired_and_wrong_kind_tokens_refused`, `agentless::form_join_completes_and_used_invite_refused`; `live::m2::snmp_appliance_added_by_form_reports` | todo |
| AC37 | Canary first; broken release restored within 3 min | T92, L8 | `rollout::canary_first_then_rest_after_1h_without_incidents`, `it::update::broken_release_restored_within_3_minutes`; `live::m8::probe_self_update_canary_first` | todo |
| AC38 | Library revision pushed within 60 s; secret blocks push | T56 | `it::mirror::change_pushed_within_60s_and_planted_secret_blocks`, `scan::refuses_each_secret_kind` | todo |
| AC39 | Audit for every kind; tamper detected; retention verifiable | T20, T36, T37, T55, T56, T74, T75 | `audit::*`, `web::configuration_changes_are_audited`, `auth::sign_ins_and_failures_are_audited`, `actions::jobs_and_approvals_are_audited`, `library::changes_are_audited`, `mcp_contract::every_call_audited` | todo |
| AC40 | Second factor mandatory; OIDC with local step-up; role limits | T36, T37, T38, T54, T58, L2, L9 | `auth::account_without_second_factor_cannot_sign_in`, `oidc::*`, `pages::viewer_cannot_approve_responder_cannot_approve_high`; `live::m1::hub_serves_dashboard_and_metrics`, `live::real::hub_deploys_and_signs_in` | todo |
| AC41 | Works with no internet, peers or operator | T97, L8 | `it::offline::collects_alerts_by_lan_smtp_and_runs_runbooks`; `live::m8::lab_without_internet_keeps_working` | todo |
| AC42 | Soak, load, fill within budgets | T96 | `perf::*` | todo |
| AC43 | Static, signed, reproducible artifacts | T91 | `xtask::repro::two_builds_identical_hashes`, `xtask::release::artifacts_are_static` | todo |
| AC44 | Workflow guards on recorded payloads | T03, T04 | `ci_guard::*` | todo |
| AC45 | Older probe connects and is offered the update | T95, T92 | `compat::older_probe_connects_reports_and_is_offered_update` (version rules only until a previous minor release exists) | todo |
| AC46 | Remote-mode probe reports and runs a runbook through the tunnel | T84, L7 | `net_tests::tunnel::runbook_on_remote_mode_machine_through_tunnel`; `live::m6::remote_mode_probe_runs_a_runbook` | todo |
| AC47 | Restored backup; probes reconnect | T45, L2 | `it::backup::restore_on_new_machine_probes_reconnect`; `live::m1::backup_restores_on_a_fresh_hub` | todo |
| AC48 | Rolled-back guest starts new epoch, accepted at once | T23, T26 | `epoch::hub_ahead_starts_new_epoch_even_with_backlog`, `probe_contract::rollback_epoch_accepted_at_once` | todo |
| AC49 | `/metrics` 401 without token, every series with | T40, L2 | `metrics::without_token_401`, `metrics::with_token_every_series_latest_value`; `live::m1::hub_serves_dashboard_and_metrics` | todo |
| AC50 | Second job waits 60 s then `machine_busy` | T55, T75 | `actions::second_job_waits_60s_then_machine_busy`, `it::executor::second_job_of_any_kind_waits_then_machine_busy`, `mcp_contract::exec_on_busy_machine_waits_then_machine_busy` | todo |
| AC51 | Daily cap routes to a person | T76 | `assist::daily_cap_routes_to_person_with_note` | todo |
| AC52 | Re-notify at 6 h, ack stops it | T33 | `notify::resent_on_rise_and_every_6h_unacked_and_not_before` | todo |
| AC53 | Older operator, relay, CLI work | T95 | `compat::older_operator_relay_and_cli_connect_and_work` (version rules only until a previous minor release exists) | todo |
| AC54 | Database without master key reveals nothing | T21 | `vault::database_without_master_key_reveals_nothing` | todo |
| AC55 | Desktop summary mode; known-bad still named; off stores nothing | T70 | `it::conn::desktop_summary_and_off_modes_end_to_end`, `conn_store::summary_mode_stores_country_asn_counts_only_known_bad_still_named`, `conn_store::off_mode_stores_nothing` | todo |
| AC56 | Windows connections, `%TEMP%` process, new port | T89 | `windows_parse::*`; MV16 | todo |
| AC57 | Wrapper refuses one-argument difference | T51 | `runcmd::one_argument_different_from_every_template_refused`, `it::runcmd::sudo_entry_runs_wrapper_only` | todo |
| AC58 | Monitor machine: reports, no accounts, skipped, `monitor_only`; hypervisor actions approved only | T44, T54, T55, T59, T62, T72, L4, L5 | `it::install::monitor_has_no_accounts_keys_or_command_list`, `decide::monitor_machine_always_needs_approval_and_no_auto_policy`, `actions::monitor_machine_ssh_step_fails_monitor_only_before_sending`, `select::auto_pending_not_maintenance_not_quarantined_managed_only`, `guard::monitor_guest_hypervisor_action_needs_approval`, `quarantine::auto_rule_matching_monitor_machine_does_nothing`; `live::m3::monitor_guest_hypervisor_action_needs_approval`, `live::m4::monitor_guest_auto_rule_does_nothing`; MV9 | todo |
| AC59 | Level change on the machine keeps id; hub can't change it alone | T35, T62 | `join_contract::level_change_token_keeps_machine_id`, `it::level::*` | todo |
| AC60 | Guest binding mismatch blocks hypervisor actions | T49, T62, L3 | `binding::reported_mac_of_other_guest_sets_mismatch_and_event`, `guard::mismatched_binding_refuses_snapshot_rollback_firewall_power`, `guard::other_guest_never_touched`; `live::m2::probe_in_lxc_is_bound_to_its_guest` | todo |
| AC61 | Leading dash refused; command list install rules; first list with join | T50, T51 | `params::leading_dash_refused_unless_allowed`, `install::unsigned_expired_or_not_newer_list_refused`, `it::runcmd::first_list_arrives_with_join` | todo |
| AC62 | Labels during outage, unknown label dropped, 16 MB cap | T16, T26 | `zstd::decompression_past_16_mib_fails_with_0x15`, `probe_contract::label_set_first_seen_during_outage_resolves`, `probe_contract::unknown_label_id_drops_sample_keeps_report`, `probe_contract::oversized_decompression_closes_0x15` | todo |
| AC63 | Install step survives hub restart and SSH cut | T59, T65, L4 | `it::recovery::hub_restart_during_patch_install_finishes_and_verifies`, `it::patch::ssh_cut_during_install_finishes_and_verifies`; `live::m3::install_step_survives_hub_restart_and_ssh_cut` | todo |
| AC64 | Attempt limit and wait-for-clear | T57, L4 | `attempts::two_automatic_starts_per_24h_then_human`, `routing::success_waits_for_clear_then_failed_after_10_min`; `live::m3::failed_service_runbook_after_approval` | todo |
| AC65 | 300 s interval rules, silence, clear margin, flapping | T28, T30 | `threshold::duration_below_4_intervals_raised_to_4`, `threshold::flapping_between_84_and_86_stays_one_incident`, `silence::machine_warning_at_max_60s_or_4_intervals` | todo |
| AC66 | Rule survives restart; acks under 2 s with stalled rules | T25, T24, T32, T96, L2 | `incidents::rule_mid_duration_survives_restart`, `bus::notice_send_never_waits_on_stalled_consumer`, `perf::stalled_rules_60s_acks_still_under_2s`; `live::m1::hub_reboot_keeps_history_and_rules` | todo |
| AC67 | Nothing root; updater refuses unsigned or lower; standby key accepted | T41, T44, T91, T93, L8 | `it::hub_start::*`, `it::install::standby_key_signature_accepted`, `release::verify_accepts_current_and_standby_keys`, `update::unsigned_or_lower_version_refused_no_slot_change_audited`, `it::updater::relay_and_operator_not_root`; `live::m8::hub_updater_upgrades_and_refuses_lower` | todo |
| AC68 | Account flood, used TOTP, untrusted forwarding header | T37 | `auth::account_flood_limits_new_browsers_not_known_ones`, `auth::used_totp_code_refused`, `auth::forwarded_header_ignored_unless_trusted_proxy` | todo |
| AC69 | Retention for every table, output budget, connection cap | T27, T70, T80, T96, T98 | `retention::every_table_rule_from_design`, `output_budget::oldest_trimmed_first_metadata_kept`, `conn_store::daily_cap_20000_then_summary_rows_and_overflow`, `perf::fill_2y_50_machines_under_2gb_retention_on_schedule` | todo |
| AC70 | Token bound to operator; key capped by role; approval bound; personal key diagnostics | T54, T74, T75, T76 | `operator_contract::token_from_other_endpoint_refused`, `mcp_contract::read_request_key_on_viewer_works_as_read`, `mcp_contract::approval_from_other_caller_or_after_edit_refused`, `mcp_contract::personal_key_journal_needs_approval_df_does_not` | todo |
| AC71 | Container named on new destination, eBPF and sampling | T67, T68, T70 | `it::sampling::connection_open_across_poll_attributed_to_container`, `ebpf_tests::capture::two_containers_same_exe_attributed` | todo |
| AC72 | Firewall restored identically; only DHCP and hub; no `exec`; changed config stops release | T47, T72, T75, L5, L9 | `proxmox::firewall_config_read_and_restore_round_trip`, `quarantine::guest_rules_exact_set`, `quarantine::release_restores_identical_configuration`, `quarantine::changed_config_stops_release`, `mcp_contract::exec_on_quarantined_machine_refused`; `live::m4::quarantine_lxc_guest_and_release`, `live::real::quarantine_named_guest_and_release`; MV11 | todo |
| AC73 | Hypervisor hosting the hub: approval lists it; job finishes at verify | T60, L4 | `hypervisor::approval_names_hub_when_hub_is_a_guest`; `live::m3::hypervisor_hosting_the_hub_finishes_at_verify`; MV8 | todo |

### Functional requirements

| Target | Step(s) | Test(s) / check | Status |
| --- | --- | --- | --- |
| FR-1 | T22, T42 | `collect::*`, `it::probe_hub::vitals_visible_within_30s` | todo |
| FR-2 | T22, T43 | `collect::every_catalogue_metric_from_debian_fixture`, `packages::*` | todo |
| FR-3 | T23, T26, T42 | `buffer::*`, `probe_contract::*`, `it::probe_hub::outage_backfills_and_live_stays_fresh` | todo |
| FR-4 | T67, T68, T89 | `conntable::*`, `ebpf_tests::capture::*`, `windows_parse::tcp_udp_table_records_to_tuples` | todo |
| FR-5 | T66, T67, T68, T71, T89 | `procscan::*`, `listeners::*`, `ebpf_tests::capture::exec_from_tmp_seen` | todo |
| FR-6 | T66, T71 | `hash::*`, `auth::*` (helper), `it::helper_scan::*` | todo |
| FR-7 | T27, T40, T98 | `rollup::*`, `retention::*`, `metrics::*` | todo |
| FR-8 | T28 to T32, T57 | Detect and Incidents tests | todo |
| FR-9 | T46 | `drivers::*`, `it::checks::*` | todo |
| FR-10 | T46, T47, T48 | driver tests, `it::drivers::*` | todo |
| FR-11 | T33 | `notify::*` | todo |
| FR-12 | T52, T53, T55 | `it::executor::*`, `it::detached::*` | todo |
| FR-13 | T59, T60 | `select::*`, `it::patch::*`, `hypervisor::*` | todo |
| FR-14 | T37, T54, T58, T75 | `auth::step_up_valid_5_minutes`, `decide::*`, `pages::high_risk_approve_prompts_step_up` | todo |
| FR-15 | T72 | `quarantine::*` | todo |
| FR-16 | T76, T77 | `operator_contract::*`, `it::operator::*` | todo |
| FR-17 | T74, T75 | `mcp_contract::*` | todo |
| FR-18 | T80, T81, T83 | `peer_contract::*`, `net_tests::peer_watch::*`, `net_tests::holepunch::*` | todo |
| FR-19 | T84, T85, T86 | `tunnel_contract::*`, `xfer_contract::*`, `net_tests::tunnel::*`, `net_tests::xfer::*` | todo |
| FR-20 | T82 | `relay_keys::*`, `net_tests::relay::*` | todo |
| FR-21 | T35, T44, T49, T62, T94 | `join_contract::*`, `it::install::*`, `it::level::*`, `it::bootstrap::*` | todo |
| FR-22 | T92 | `apply::*`, `it::update::*` | todo |
| FR-23 | T64, L4 | `provision::*`; `live::m3::provision_vm_boots_enrolls_and_is_healthy`; MV10 | todo |
| FR-24 | T56 | `library::*`, `mirror::*` | todo |
| FR-25 | T37, T38 | `auth::*`, `oidc::*`, `passkey::*` | todo |
| FR-26 | T20, T36, T37, T55, T56, T75 | `audit::*` and the "is audited" tests | todo |

### Contracts

| Target | Step(s) | Test(s) / check | Status |
| --- | --- | --- | --- |
| Common QUIC rules (framing, limits, close codes, versions) | T16, T17 | `frame::*`, `zstd::*`, `router::*`, `golden::*` | todo |
| 7.3.1 Join | T35 | `join_contract::*` | todo |
| 7.3.2 Probe and hub | T23, T26 | `probe_contract::*` | todo |
| 7.3.3 Probe and helper | T16, T43, T61, T66, T92 | `helper::*`, `keys::*`, `hash::*`, `apply::*`, `it::helper::*` | todo |
| 7.3.4 Peer | T80 | `peer_contract::*` | todo |
| 7.3.5 Operator and Runner | T76, T77 | `operator_contract::*`, `claude_code::*` | todo |
| 7.3.6 MCP | T74, T75 | `mcp_contract::*` | todo |
| 7.3.7 SSH, wrapper, detached steps, Windows dispatcher | T51, T52, T53, T90 | `runcmd::*`, `it::detached::*`, `quote::*`, `Dispatch.Tests` | todo |
| 7.3.8 In-process (`Driver`, `Notifier`, `StoreWriter`, `decide`, Bus) | T18, T24, T33, T46, T54 | `writer::*`, `bus::*`, `notify::*`, `drivers::*`, `decide::*` | todo |
| 7.3.9 Notifiers | T33 | `notify::*` | todo |
| 7.3.10 Relay | T82 | `relay_keys::*`, `relay_lists::*`, `net_tests::relay::*` | todo |
| 7.3.11 Tunnels and transfers | T84, T85 | `tunnel_contract::*`, `xfer_contract::*` | todo |
| 7.3.12 Enrollment | T35, T44, T49, T62 | `join_contract::*`, `it::install::*`, `binding::*`, `it::level::*` | todo |
| 7.3.13 Git mirror | T56 | `mirror::*`, `scan::*` | todo |
| 7.3.14 Metrics endpoint | T40 | `metrics::*` | todo |

### Edge cases

| Target | Step(s) | Test(s) / check | Status |
| --- | --- | --- | --- |
| E1 | T25, T32, T42, T96 | `it::probe_hub::outage_backfills_and_live_stays_fresh`, `perf::outage_2h_...` | todo |
| E2 | T23, T26, T42 | `buffer::full_buffer_drops_oldest_and_records_range` | todo |
| E3 | T23, T26 | `epoch::*`, `probe_contract::rollback_epoch_accepted_at_once` | todo |
| E4 | T25 | `ingest::clock_offset_is_median_of_last_20_live_reports`, `ingest::offset_over_30s_raises_clock_skew` | todo |
| E5 | T26 | `probe_contract::second_probe_with_same_machine_id_gets_0x11` | todo |
| E6 | T87 | `identity::same_endpoint_two_boot_ids_both_refused` | todo |
| E7 | T35 | `join_contract::used_expired_and_wrong_kind_tokens_refused` | todo |
| E8 | T53 | `hostkeys::changed_key_blocks_and_raises_critical`, `it::ssh::accepting_new_key_needs_admin_step_up` | todo |
| E9 | T59 | `it::patch::apt_lock_waits_10_min_then_fails_without_changes` | todo |
| E10 | T59 | `select::hold_never_patched` | todo |
| E11 | T59, L4, L9 | `rollback::only_when_no_report_15_min_auto_rollback_on_not_hub`; `live::m3::broken_guest_rolls_back_after_15_minutes`, `live::real::patch_named_guest_with_snapshot_and_rollback`; MV7 | todo |
| E12 | T59 | `precheck::snapshot_unsupported_fails_unless_optional` | todo |
| E13 | T60 | `hypervisor::reboot_needs_high_risk_approval_listing_guests` | todo |
| E14 | T60 | `it::hubhost::reboot_scheduled_60s_job_resumes_at_verify` | todo |
| E15 | T76 | `operator_contract::decline_tries_next_three_declines_go_human`, `operator_contract::no_operator_goes_human` | todo |
| E16 | T76 | `operator_contract::disconnect_fails_tools_then_failed_after_5_min` | todo |
| E17 | T76 | `operator_contract::hub_restart_reattaches_running_jobs` | todo |
| E18 | T75 | `mcp_contract::exec_outside_job_hosts_out_of_scope_and_audited` | todo |
| E19 | T75 | `mcp_contract::injected_output_does_not_change_approvals` | todo |
| E20 | T54, T75 | `approvals::hash_binds_requester_tool_target_args_revision`, `mcp_contract::different_arguments_give_approval_mismatch` | todo |
| E21 | T76, T79 | `assist::deadline_with_pending_approval_needs_human_and_resume` | todo |
| E22 | T54, T72 | `exclusions::never_quarantined_roles_and_tag`, `quarantine::hypervisor_with_same_finding_not_quarantined` | todo |
| E23 | T72 | `quarantine::isolation_failure_sets_failed_and_critical` | todo |
| E24 | T72, L5 | `quarantine::pve_firewall_off_fails_with_instructions_never_enables`; `live::m4::datacenter_firewall_off_fails_with_instructions`; MV11 | todo |
| E25 | T81 | `net_tests::peer_watch::three_hubs_one_cut_exactly_one_callout` | todo |
| E26 | T83 | `net_tests::holepunch::hard_nat_no_relay_unreachable_with_explanation` | todo |
| E27 | T82 | `net_tests::relay::refused_client_sees_reason` (and priority if S2 allows) | todo |
| E28 | T82 | `relay_lists::garbage_and_10000_entries_keep_first_100_valid` | todo |
| E29 | T85 | `xfer_contract::bulk_waits_for_direct_and_raises_info_after_10_min` | todo |
| E30 | T52, T85 | `xfer_contract::resume_from_last_verified_chunk`, `it::receive::hash_mismatch_keeps_temp_and_no_rename` | todo |
| E31 | T33 | `notify::retries_1_5_15_then_failed_raises_notifier_failed` | todo |
| E32 | T25 | `ingest::disk_below_2_percent_stops_replay_and_new_jobs` | todo |
| E33 | T45 | `selfwatch::quick_check_failure_stops_writes_and_alerts` | todo |
| E34 | T21, T99, L8 | `vault::recovery_code_round_trips_the_master_key`, `docs/recovery.md`; `live::m8::recovery_procedure_restores_the_master_key`; MV13 | todo |
| E35 | T87 | `it::address::hub_address_change_config_and_keys_update` | todo |
| E36 | T67, T68 | `capability::no_ebpf_reports_sampling`, `ebpf_tests::capture::load_failure_falls_back_to_sampling` | todo |
| E37 | T10, T68, L5, L9 | `live::m4::lxc_connection_attributed_to_its_cgroup`, `live::real::lxc_attribution_on_a_real_host`; MV2 | todo |
| E38 | T30, T42 | `silence::expected_offline_gives_info_only` | todo |
| E39 | T92 | `it::update::broken_release_restored_within_3_minutes` | todo |
| E40 | T56 | `scan::refuses_each_secret_kind` | todo |
| E41 | T37 | `auth::source_backoff_after_5_failures_per_15_min`, `auth::account_never_locked` | todo |
| E42 | T54, T58 | `approvals::first_decision_wins` | todo |
| E43 | T87 | `identity::rename_and_new_address_keep_machine_and_host_key_check` | todo |
| E44 | T25, T30, T32, T65 | `it::recovery::*`, `ingest::startup_compacts_leftover_staging` | todo |
| E45 | T80 | `peer_contract::joblog_denied_by_default` | todo |
| E46 | T34 | `scheduler::spring_forward_...`, `scheduler::fall_back_...` | todo |
| E47 | T76 | `assist::daily_cap_routes_to_person_with_note` | todo |
| E48 | T71 | `exemptions::memfd_runc_child_exempt` | todo |
| E49 | T55, T62, T75 | `actions::monitor_machine_ssh_step_fails_monitor_only_before_sending`, `mcp_contract::exec_on_monitor_machine_refused` | todo |
| E50 | T49, T62 | `binding::reported_mac_of_other_guest_sets_mismatch_and_event`, `guard::*` | todo |
| E51 | T50, T51, T63, T90 | `params::leading_dash_refused_unless_allowed`, `runcmd::leading_dash_value_refused` | todo |
| E52 | T26 | `probe_contract::unknown_label_id_drops_sample_keeps_report` | todo |
| E53 | T16, T26 | `zstd::decompression_past_16_mib_fails_with_0x15` | todo |
| E54 | T52, T55, T59 | `it::detached::job_survives_ssh_disconnect`, `it::executor::ssh_cut_during_detached_step_recovers` | todo |
| E55 | T55, T57 | `it::executor::detached_step_timeout_not_killed_machine_locked`, `incidents::timed_out_detached_step_opens_incident` | todo |
| E56 | T57 | `attempts::two_automatic_starts_per_24h_then_human` | todo |
| E57 | T57 | `routing::success_waits_for_clear_then_failed_after_10_min` | todo |
| E58 | T28, T30 | `threshold::duration_below_4_intervals_raised_to_4`, `silence::machine_warning_at_max_60s_or_4_intervals` | todo |
| E59 | T67, T70 | `aggregate::over_500_tuples_keeps_most_bytes_folds_rest`, `conn_store::daily_cap_...` | todo |
| E60 | T51 | `install::unsigned_expired_or_not_newer_list_refused` | todo |
| E61 | T37 | `auth::account_flood_limits_new_browsers_not_known_ones` | todo |
| E62 | T60, L4 | `hypervisor::approval_names_hub_when_hub_is_a_guest`; `live::m3::hypervisor_hosting_the_hub_finishes_at_verify`; MV8 | todo |
| E63 | T93 | `update::unsigned_or_lower_version_refused_no_slot_change_audited` | todo |
| E64 | T44, T91, T93 | `release::verify_accepts_current_and_standby_keys`, `it::install::standby_key_signature_accepted` | todo |
| E65 | T92 | `download::unreachable_url_reports_info_and_keeps_version` | todo |
| E66 | T72, L5 | `quarantine::changed_config_stops_release`; `live::m4::changed_firewall_during_quarantine_stops_release`; MV11 | todo |

### Non-functional requirements (design 5.2)

| Target | Step(s) | Test(s) / check | Status |
| --- | --- | --- | --- |
| Probe footprint | T06, T96 | S6 report, `perf::probe_soak_1h_within_budget` | todo |
| Hub footprint | T96 | `perf::hub_load_200_probes_1h`, `perf::fill_2y_...` | todo |
| Latency | T33, T39, T42, T81, T96 | `query::vitals_visible_before_compaction`, `notify::critical_sent_...`, `perf::hub_load_...` | todo |
| Availability | T97 | `it::offline::*` | todo |
| Security | T17, T21, T37, T41, T93 | `router::*`, `vault::*`, `it::hub_start::*`, `it::updater::*` | todo |
| Privacy | T70, T79 | `conn_store::summary_mode_...`, `pages::operator_setup_states_provider_data_use` | todo |
| Platforms | T86, T89, T91 | `cross::cli_builds_for_windows_and_macos_targets`, `ci win`, release workflow | todo |
| Compatibility | T16, T95 | `golden::*`, `compat::*` | todo |
| Supply chain | T01 (`cargo deny`), T44, T91 | `it::install::bad_signature_...`, `release::*`, `repro::*` | todo |
| Language (Rust only, no Node) | T01, T36 | `arch::no_node_or_interpreter_in_server_crates`, `web::vendored_assets_match_checksums` | todo |

## Manual verifications

Each row names who runs it: the owner, or the run itself with access the owner provides. Results are recorded here
and in the run log, with evidence redacted per D71.

| ID | Step | Why not automated | Steps | Expected | Verified by / date | Result |
| --- | --- | --- | --- | --- | --- | --- |
| MV1 | T04 | Changes the runner service's configuration and GitHub organization settings, outside this repository | Add the `linux-docker` and `linux-kvm` profiles; allow the repository in the runner group; set the three repository variables | The `runners` jobs green on all three label sets | Owen | |
| MV2 | T10, T68, L9 | Confirms on a real Proxmox host kernel what `pve9` showed in T10 and L5 | In L9, `live::real::lxc_attribution_on_a_real_host` on the owner's test node | The connection is attributed to the LXC's cgroup | The run (L9), with the owner's access | |
| MV3 | T11, L9 | A real host's ZFS ARC under real load | In L9, `live::real::zfs_memory_reading` on the owner's ZFS host | `mem.available_pct` per the chosen formula stays above the warning line on a healthy host | The run (L9), with the owner's access | |
| MV4 | T12, L9 | Confirms the minimal privileges on the owner's real PVE 8 and 9 nodes | The owner creates a token and names a test guest; in L9, `live::real::proxmox_minimal_privileges` | Every operation works with the minimal role; firewall round trip identical | The run (L9); the owner creates and revokes the token | |
| MV5 | T13 | Needs a Claude Code sign-in | Owner signs in in the spike's configuration directory; run the S5 script | Only stub tools called; no other MCP servers start | Owen | |
| MV6 | T14 | Needs a TrueNAS instance and API key | Owner creates a read-only key; run the S9 script | Every TrueNAS metric found; fixtures redacted | Owen | |
| MV7 | T59, L4, L9 | Real snapshots and reboots on real Proxmox storage (AC19, E11) | In L9, `live::real::patch_named_guest_with_snapshot_and_rollback` on the named test guest | Snapshot taken and pruned to 3, updates installed, verify passes; the broken guest is rolled back after 15 minutes | The run (L9), with the owner's access | |
| MV8 | T60, L4, L9 | Rebooting a real hypervisor that hosts a hub (AC73, E62) | Only if `real.env` names a test hypervisor hosting a test hub: approve its reboot | Approval lists the hub; the job finishes at verify after the hub is back | The run (L9), if configured | |
| MV9 | T62, L5, L9 | Real Proxmox firewall on a monitor guest (AC58) | In L9, the monitor part of `live::real::quarantine_named_guest_and_release` | The auto rule does nothing; the approved quarantine applies from the hypervisor | The run (L9), with the owner's access | |
| MV10 | T64, L4, L9 | Real VM provisioning with hardware virtualization (AC33) | In L9, `live::real::provision_vm_on_a_named_node` | The VM boots, enrolls and is healthy | The run (L9), with the owner's access | |
| MV11 | T72, L5, L9 | Real guest firewall and conntrack (AC17, AC72, E66) | In L9, `live::real::quarantine_named_guest_and_release`: quarantine the named guest after approval with step-up; test reachability; release; repeat with a change during quarantine (the datacenter-firewall-off case, E24, is tested only in L5) | Only DHCP and the hub reachable; diagnostics work; forensic snapshot exists; release restores identical config; a change stops release | The run (L9), with the owner's access | |
| MV12 | T38, T39 | A real browser passkey with a trusted certificate (the page walks are done by the run in L2 to L8) | Register a passkey on the lab hub and sign in with it | Passkey works | Owen | |
| MV13 | T94, L8, L9 | A real Proxmox host for the LXC script (AC32); recovery (E34) is tested in L8 | In L9, `live::real::lxc_script_on_a_real_node` | The hub runs and links | The run (L9), with the owner's access | |
| MV14 | T77, L6 | Needs the owner's Claude Code sign-in (AC25) | The owner signs in once in the operator's configuration directory on the lab's `operator` machine; the run does the three runs in L6 | In at least 2 of 3 runs the assistant calls `run_diagnostic`, requests `compose-restart`, and after approval the incident resolves within 30 minutes | The run (L6); the owner signs in | |
| MV15 | T83, L7, L9 | Real internet NATs (AC27) | Only if `real.env` names a second site: link the hubs through a relay | They connect (direct if possible) and exchange summaries | The run (L9), if configured | |
| MV16 | T89, T90 | No Windows runner (D81) (AC35 Windows, AC56) | Follow `docs/windows-checklist.md` on a Windows 10/11 machine | Every checklist line passes | Owen | |
| MV17 | T91 | Signing keys are offline and held by the maintainer (D90) | Follow `docs/maintainers/signing.md` once with a throwaway key pair | The procedure produces signatures that `rackhand-release` verifies | Owen | |
| MV18 | L9 | The owner's hosts and credentials | Fill `lab/real.env` from `lab/real.env.example`: the hub VM or LXC, one managed VM, an SSH key with sudo, Proxmox test nodes with a named test guest and a token, a TrueNAS read-only key, and optionally a second site | `cargo xtask ci live --target real --milestone real -- --list` shows every configured host answering | Owen | |

## Deviations

*Recorded by `/design:run` the moment the work departs from this plan. Plan-level deviations (files, approach, step
split or order, tests) are recorded and the run continues. Design-level deviations (behaviour, contracts, acceptance
criteria, data formats) need the owner's agreement and a design change-log entry.*

| ID | Date | Step | Planned | Actually done | Reason | Level (plan / design) | Agreed by (design-level) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| D1 | 2026-11-19 | all | Test names `<module>::<name>` | Unit tests sit in a `tests` submodule, so nextest reports `<module>::tests::<name>` | Rust convention; the plan's `test(<module>::)` filters still select them | plan | - |
| D2 | 2026-11-19 | preflight | `cargo install --locked bpf-linker` | The static `bpf-linker` 0.13.0 binary from the project's GitHub release, in `~/.local/bin` | Building it needs a system libLLVM matching rustc's LLVM 23; Ubuntu 22.04 has LLVM 14 | plan | - |
| D3 | 2026-11-19 | T02 | `xtask kernels fetch` downloads prebuilt test kernels | Fetches the pinned kernel.org tarballs (SHA-256 from sha256sums.asc) and builds bzImages in a Debian container with `tests/vm/kernel.config` | No trustworthy prebuilt kernels with built-in 9p and BTF; the plan names this fallback | plan | - |
| D4 | 2026-11-19 | T02 | VM tests run on the host rootfs | A Debian bookworm rootfs built with Docker (has `qemu-guest-agent`), run with `unshare -r vmtest`, with a PATH that drops WSL's Windows entries | vmtest needs qemu-guest-agent in the guest (not installed on the host, and installing needs sudo); WSL's PATH breaks vmtest's init script | plan | - |
| D5 | 2026-11-19 | T02 | The current Proxmox kernel series | First pinned 6.17; the lab's `pve9` node installed `proxmox-kernel-7.0.14`, so the third eBPF kernel is now 7.0.14 (kernel.org `linux-7.0.14.tar.xz`, SHA-256 pinned) | Needed a concrete series to pin; corrected from the real node | plan | - |
| D6 | 2026-11-19 | T03, T04 | A guard-free lint job runs on every push | No unguarded job: every `ci.yml` job carries the guard and its runner variable (lint runs in `fast`); one `runners-*` job per label set | An unguarded job would need a GitHub-hosted runner or would let fork events reach self-hosted ones; `job_without_guard_is_reported` forbids it | plan | - |
| D7 | 2026-11-19 | T03 | `perf` runs nightly | `perf` also needs `schedule` or `workflow_dispatch` in its condition; the fixtures carry a separate `perf` expectation | Keeps the slow tier off every push | plan | - |
| D8 | 2026-11-19 | T08, T09, T10 | Spike support in xtask lands with the first spike that uses it | `ci net --spike` and `ci ebpf --spike` (build `spikes/<id>`, run `measure` in the VM with a writable out dir, then `report` on the host) commit with L1, which edits the same file | L1 was in progress in `tiers.rs` | plan | - |
| D9 | 2026-11-19 | T09, T83 | Full-cone NAT in the network VM | Full cone is a static UDP DNAT of the listener's fixed port at its NAT; plain masquerade on both sides is the symmetric-like case | Linux masquerade never hole punches against masquerade (spike S3) | plan | - |
| D10 | 2026-11-19 | T16 onward | M1 starts after every spike is done (T16 depends on T15) | M1 steps start once the spikes in their own Depends on are done; T05 (24-hour recording), T06, T10 to T14 finish in parallel | T05 needs 24 h of data and T13, T14 wait for the owner; the gating table already lists which steps each spike gates | plan | - |
| D11 | 2026-11-19 | T16 | `tests/fixtures/golden/*.bin` and one file per contract | Six .proto files (common, join, probe, peer, operator, tunnel incl. xfer); the MCP auth line and the helper protocol are serde JSON types; tests in `src/tests/` (names `tests::<module>::<name>`); `cargo xtask golden --update` added | MCP and the helper socket are JSON by design (7.3.3, 7.3.6) | plan | - |
| D12 | 2026-11-19 | T17 | `cargo deny check` over every target and every unmaintained notice | `deny.toml` lists the shipped targets (wasm-only crates under Unlicense drop out) and fails on unmaintained crates only when we depend on them directly; vulnerabilities always fail | iroh-relay pulls wasm-only and unmaintained transitive crates that Rackhand never builds or calls | plan | - |
| D13 | 2026-11-19 | T18 | `WriteCmd` variants carry typed row structs | Each 7.3.8 variant carries a column map (`Row`) for now; a `Batch` variant writes rows to several tables in one transaction; owning systems replace the stubs (and may type the payloads) in their steps | Keeps T18 to the writer's guarantees; the row shapes are owned by the systems built later | plan | - |
| D14 | 2026-11-19 | T20 | Chain code in `rackhand-hub/src/audit/` | The row hash lives in `rackhand-store::audit` (the writer computes it inside the append transaction); append, checkpoint and verify are in the hub's Audit module | The store writer is the only writer of `audit_log` and must hash inside its transaction; the store can't depend on the hub | plan | - |
| D15 | 2026-11-19 | T23 | Probe modules in the binary crate | `rackhand-probe` has a library target (`rackhand_probe`) with the buffer and helper modules and a thin binary | Tests and the later daemon share the modules | plan | - |
| D16 | 2026-11-19 | T30 | Peer hub silent at 2 min (scaled to the larger of 2 min and 3 summary intervals, 7.9) and down at 10 min | Down is the larger of 10 min and the silent time | At a summary interval over 200 s the silent time passes 10 min, and down can't come before silent. The design doesn't say; this keeps the order. For the owner to confirm | design gap | pending |
| D17 | 2026-11-19 | T31 | Baseline details as 7.6.4 | Hours are counted in UTC (hour of week 0 is Monday 00:00); a baseline warning clears after 2 samples in a row back inside the band; a deviation freezes the hour-of-day and hour-of-week buckets of the hour it is in, until 2 hours after its last deviating sample | 7.6.4 doesn't say which clock, how a baseline warning clears, or which buckets freeze; these follow the threshold rules and the schema's per-bucket `frozen_until_ms` | design gap | pending |
| D18 | 2026-11-19 | T34 | `windows.rrule` holds a daily or weekly rule, start time and duration (format not set) | The text is `daily HH:MM <minutes>m` or `weekly <mon..sun> HH:MM <minutes>m` (at most 7 days); timezones come from jiff with its bundled database. With no saved state a window already open fires once, and a window missed entirely while the hub was down is skipped; periodic tasks run at start and collapse missed runs into one | The design names the parts but not the text or the restart rules; the restart rule makes `schedule_state` the only thing preventing a second run, as `state_survives_restart_without_double_firing` checks | plan | - |
| D19 | 2026-11-19 | T28 | `worked_example_opens_warning_at_5_and_critical_at_27_and_resolves` as first written: the series starts at 86% at minute 0 | The test starts with one normal sample at minute 0, each sample covering the interval that ends at its time | With 80% presence, a series that starts in breach with no history fires a 5-minute rule after 16 of 20 samples (3.75 minutes); the design's example assumes normal readings before minute 0. The implementation is unchanged and the 80% test still checks the boundary | plan | - |
| D20 | 2026-11-19 | T35 | A failed join counts against 10 per minute per remote address | Direct callers are counted per IP (any port); relayed callers per relay, since the relay is the only address the hub sees; at most 4096 addresses are tracked, dropping the one idle longest | The design doesn't say what the remote address of a relayed caller is; an endpoint id costs nothing to change, so counting by it limits nothing. Counting per relay means failures through one relay can delay other joins through it for a minute. For the owner to confirm | design gap | pending |
| D21 | 2026-11-19 | T35 | Registry tables written by plain row commands; join writes the host keys | `WriteCmd::RegistryChange` carries a typed change: an optional token to use up (checked for kind, use and expiry in the same transaction) plus inserts and column updates (never a row replace, so a machine's policy, tags and guest binding survive). The join hands a managed machine's host keys to the SSH system through a `Joined` event, since SSH owns `ssh_host_keys`; the keys, sudoers and command list come from a `ManagedSetupSource` that T51 and T53 provide. Joins register machines for `probe`, devices for `tunnel` and `xfer`, operators for `operator` and `mcp`, peers for `peer` and `xfer`. Tokens are 26 Crockford base32 characters (128 bits), hashed upper case | Single use under concurrency, ownership per 7.2, and the ALPN users in 7.3.2 to 7.3.11 | plan | - |
| D22 | 2026-11-19 | L1 | Proxmox nodes snapshotted as `pristine`; 6 live tests | The provisioned base image is the pristine state (`lab reset` drops the overlay); `base.provisioned` holds a hash of the image, the cloud-init seed and `proxmox.sh`, so a changed input provisions that base again. The site NIC's bridge port has learning off. A seventh live test checks that every guest answers steadily | QEMU's multicast socket NIC hands frames back to their sender, which made the bridges learn guest MACs on the uplink; one lucky ping had passed the VM test | plan | - |
| D23 | 2026-11-19 | T50 | Runbook model as 7.8.7 and 7.8.8 | Parameter types are `string`, `int` and `bool`; a parameter's regex is its pattern wrapped as `^(?:...)$` (or the type's own); a `cmd` parameter must be a whole argument; steps take `cmd`, `windows_script`/`windows_args`, `checks`, `call`, `message`, `source`/`dest`, `port`, `timeout` (`30s`, `5m`, `2h`), `on_failure`, `retries`, `idempotent`, `resumable` and `detached`, and nothing else; `commands.json` lists `{runbook, step, args}` with each arg `{"literal"}` or `{"param", "regex", "allow_leading_dash"}`; a playbook needs all five sections and `max_runtime` of at most 2 h. `builtin/` is created by the steps that add built-in runbooks | The design gives the example and the rules, not the full field list or the JSON shape; the wrapper (T51) reads this shape | plan | - |
| D24 | 2026-11-19 | T54 | `decide()` as 7.6.8 | Requesters are the hub itself, a person in the dashboard, a peer, a personal key and an assistant job; for the hub and assistant jobs level 0 refuses (`TellOnly`) before risk is looked at, since nothing runs at level 0; a person's own dashboard action runs (high risk still needs an approval with step-up, which they may give themselves); `exec` is for assistant jobs only; diagnostics are read tools at every level (a personal key needs an approval for `journal` and `docker_logs`); actions needing an account on a monitor machine are refused with `monitor_only`, the rest need an approval. Policy and quarantine-rule writes are upserts so references survive; deciding and using an approval are conditional updates (the first decision wins) | The design states the rules by requester and risk; these settle how they combine | design gap | pending (the level-0 rule) |
| D25 | 2026-11-19 | T36 | Settings are "stored with revisions, and mirrored to git" (7.8); no table is named | Settings are library items of kind `config` (`config/hub.toml`, matching the mirror layout): the `library_items.kind` check allows `config`, and the `PutLibraryRevision` handler is built here instead of T56. First run takes the installer's one-time setup code (7.7.4), a password of at least 12 characters (Argon2id) and a verified TOTP code; the admin, both credentials, the site and the first settings revision are one write that succeeds only while `users` is empty, and the recovery code is shown in that response only. The TLS certificate and key live in the Vault. `/sign-in` is a placeholder until T37, which also adds TOTP replay protection and limits. Two tests beyond the plan: HTTPS with the generated certificate, and the RFC 6238 vectors | Fills the storage gap with the tables the design already has; the setup code and the one-write first run close the unauthenticated first-run window. For the owner to confirm the settings storage | design gap | pending |
| D26 | 2026-11-19 | T37 | Sign-in as 7.7.2 | Two steps: the password (then a 5-minute pending sign-in held in memory), then the TOTP code; 5 wrong codes drop the pending sign-in. A code is accepted only for a time step later than the last one used, by a conditional update, so sign-in and step-up share that rule. After a threshold is reached, the first attempt goes through and then one a minute. The code step is limited per source only (the account limit applies to the password step). Limits and pending sign-ins live in memory and start empty when the hub restarts. A missing account is checked against a dummy hash so it takes as long as a wrong password. TOTP stays in `web/totp.rs` from T36; sessions in `web/session.rs` | The design states the limits and their numbers, not where they are kept or how the two steps combine | plan | - |
| D27 | 2026-11-19 | T22 | The 7.4.2 catalogue and default exclusions | Metric ids live in `rackhand_proto::catalogue` (stable numbers shared by probe and hub). `cpu.busy_pct` counts user, nice, system, irq and softirq time; `disk.used_pct` is df's used over used plus available; `net.errors` is new errors in the interval; `conn.outbound_count` counts established TCP sockets on ephemeral local ports until T67's capture replaces it. The ZFS ARC is added only when `/proc/meminfo` isn't an lxcfs view (inside an LXC the host's ARC isn't the container's). Besides the design's list, the read-only image filesystems `fuse.snapfuse`, `fuse.squashfuse`, `iso9660`, `udf` and `erofs` are excluded, and pseudo filesystems with no space are skipped. `ServiceState.since_ms` is 0 until T42 | Found on the captured fixtures and the real WSL system: snaps through FUSE and mounted images always read 100% and would open disk incidents | design gap | pending (the extra exclusions) |
| D28 | 2026-11-19 | T51 | `it::runcmd::first_list_arrives_with_join` in T51 | Moved to T44, which builds enrollment (the probe side of the join); T51 provides the installer it uses. The wrapper is the probe binary when started as `run` (or `rackhand-probe run-cmd`); it clears the environment and execs the matched program with no shell; its paths are fixed (no override, so nothing passed through sudo can point it at another list). `commands.json` is the signed list's body plus its `version`; `probe.toml` pins the hub as `[hub] id` (64 hex characters), which T42 extends | The join's probe side doesn't exist until T44 | plan | - |
| D29 | 2026-11-19 | T52 | Detached steps start the command in its own unit | `job-start` records the matched command and starts a supervisor (the wrapper's internal `job-supervise`) as a `systemd-run --collect` unit, or with `start-stop-daemon --background` on OpenRC, or in a new session elsewhere; the supervisor runs the command without a shell and records its output and exit code under `/var/lib/rackhand-run/jobs/<job>/<step>/`. `job-status` prints JSON (`state` running, exited, stopped, lost or unknown; `exit_code`; `output` from the offset, at most 1 MiB; `next_offset`). `receive <dest> <blake3> <offset>` appends to `<dest>.rackhand-partial` (offset 0 starts over) and renames when the hash matches; `transfer_roots` travel in the signed command list. The survival test runs a 10-second command rather than 30 seconds | Uniform behaviour across init systems with the exit code kept; the hub-side policy roots must be signed to be trusted on the machine | plan | - |
| D30 | 2026-11-19 | T53 | `ssh/{client, quote, hostkeys, pool}.rs` | No connection pool yet: one connection per command (the Executor in T55 can add reuse). Host key alerts go out on a channel for the composition (T41) to turn into events and incidents, since `events` belongs to Ingest; the key a machine offers instead is held in memory until an admin accepts it on `POST /machines/{id}/host-key/accept` (admin; a stale step-up redirects to /step-up). Keys are Ed25519 only (russh without its RSA feature). T44's installer check uses this client when T44 is built | Keeps table ownership per 7.2; nothing yet needs pooling | plan | - |
| D31 | 2026-11-19 | T56 | Library modules `items, revisions, drafts, builtins, mirror, scan` | Items, revisions and drafts are one `items.rs`; there are no built-ins to load yet (the steps that write them add the loader's list). The 30 s debounce counts from the first change of a run, so a run of edits is one commit `<users>: <summaries>`. The mirror learns the server's host key on its first push (the fingerprint is kept in the config afterwards when T41 wires the worker); a later mismatch fails the push. `restore-library` reads a checkout directory (`git clone` it first), since the hub's mirror credentials are push-only | One coherent module; the host key has no other channel to arrive by | plan | - |
| D32 | 2026-11-19 | T55 | `actions/{coordinator, locks, jobs}.rs`, `executor/{steps/*.rs, detached.rs, verify.rs}`; every step kind executes | Files are `actions/{coordinator, jobs, locks, runner}.rs` (`runner` is the step interface the Executor and test fakes implement) and `executor/{mod, detached, commands}.rs` (`commands` signs the command list built from the runbooks). Only `ssh` steps (plain and detached) and assistant `exec` execute; the other step kinds go to a runner that fails `<kind>_unavailable` until their owning systems exist (tests carried into T33, T42, T46, T47, T59), and E55's incident is carried into T57. A job that waits out the machine lock is a row `queued` then `failed` with outcome `machine_busy` and `JobFinished`; `run` returns `Err` only when no job was created (unknown machine or runbook, bad parameters, an approval that doesn't hold). The unit test sets a 600 ms lock wait instead of an injected clock. New `Actions::exec` and `open_assistant_job` cover AC50's assistant half (T76 builds on them); `Library::current_in` and `revision_in` let Actions read runbooks; `ed25519-dalek` is a normal hub dependency (signing); a new `executor` container image (systemd, sshd, wrapper). Added tests: concurrent execs and the store's job handlers | The systems these step kinds need don't exist yet; a row for every attempt keeps Incidents' reconciliation to one rule | plan | - |
| D33 | 2026-11-19 | T55 | 7.3.7: the quoted argument list is sent as the exec request | Plain runbook `ssh` steps are sent as `timeout -k 5 <seconds> <quoted argv>`: dropping the connection at the step's timeout doesn't stop a command without a terminal (the container test showed `sleep 600` still running), so without it the machine is free while the old command runs. Assistant `exec` is still sent as-is (7.3.7), so a timed-out `exec` may keep running; Windows steps (T90) need their own stop | AC12's timeout must not leave work running behind the lock | design gap | pending (confirm the `timeout` prefix, and what a timed-out `exec` should do) |
| D34 | 2026-11-19 | T38 | 5.3: `openidconnect` (OIDC) | The code flow with PKCE is written in `web/auth/oidc.rs`, and ID tokens are checked with ring (RS256, ES256, EdDSA; `none` and HMAC refused); the provider is reached with hyper over rustls on ring with the Mozilla roots (`webpki-roots`). `openidconnect` depends on the `rsa` crate, whose RUSTSEC-2023-0071 (Marvin) has no fixed version, so `cargo deny` fails with it (checked: `cargo deny check advisories` failed after adding it with default features off). The fake provider is `web/auth/fake_oidc.rs`, not `tests/support/fake_oidc.rs` | Keeps one crypto provider and the advisory gate as it is; negative tests cover each check | design | pending (confirm the library change; 5.3 still names `openidconnect`) |
| D35 | 2026-11-19 | T38 | 7.7.2: accounts, OIDC users and their local factor | An admin creates every account on the settings page: a local one with a password, an OIDC one with the provider's subject (`sub`), and each gets a TOTP secret shown once, so an OIDC user has a local factor from the start (the provider alone never approves high risk, D49) and nobody gets in through the provider without an account. The store refuses to demote or disable the last enabled admin. The OIDC callback answers with a page that moves on to `/` (the session cookie is `SameSite=Strict`, so it isn't sent on the redirect chain from the provider's site); the cookie binding `state` to the browser is `SameSite=Lax` for the same reason. Passkeys are turned on by the composition (`Web::with_passkeys`) when the hub has a hostname and a trusted certificate; the browser half is `static/passkey.js`, checked only by MV12 | The design names the factors but not how accounts come to exist | design gap | pending (how OIDC accounts are created, and whether an admin issuing their TOTP is right) |
| D36 | 2026-11-19 | T63 | `crates/rackhand-runbook/builtin/diagnostics.toml`; `actions/diagnostics.rs`; templates in `commands.json` generation | As planned, plus: Linux and Alpine commands only (the Windows ones run through the dispatcher's scripts, T90: `Unsupported` until then); a diagnostic doesn't wait for the machine's job lock, since it is read-only and a detached step can hold a machine for long (E55); within a job it is a step of that job (output stored there only), otherwise it is audited without its output; the hub keeps stdout then stderr, and `du_top` is sorted by size, `top_processes` cut to 20 and `dmesg_tail` to 200 lines by the hub; the diagnostics' templates are added by the hub's `signed_command_list`, not by the runbook crate's `command_list`. The container image has a stand-in `docker` CLI | Read-only work shouldn't queue behind a stuck package step | plan | - |
| D37 | 2026-11-19 | T74 | 5.3: rmcp for the MCP server; `mcp/{server, auth, tools_read, keys}.rs` | The hub speaks the part of MCP it serves (initialize, ping, `tools/list`, `tools/call`, the stdio framing after the auth line) in `mcp/mod.rs`: the current rmcp (3.11) needs Rust 1.88, above the workspace's 1.85, and the framing is the design's own. `get_vitals` and the services, containers and updates of `get_machine` come through an `Observations` interface that the time-series store and ingest fill (tests carried into T25 and T27). Devices are admitted to `rackhand/mcp/1` too (people reach MCP from their device). Personal keys start `rk_` and job tokens `rj_`; a job token works only from its operator's endpoint and while its job runs. The request and job tools are listed for the callers that may use them and come with their gating in T75 | The design's MSRV and framing; series and facts aren't stored yet | design | pending (confirm not using rmcp in the hub; the CLI and operator may still use it) |
| D38 | 2026-11-19 | T75 | `mcp/{tools_act.rs, gate.rs}`; the three tools | As planned, plus: `add_incident_note` writes through `incidents::notes` (Incidents owns `incident_events`; the `AppendIncidentEvent` handler is added); `finish_job` takes `resolved`, `unresolved` or `handed_over` and ends the job through Actions (only `resolved` succeeds); an approval asked for over MCP lasts an hour; the hash covers the call's arguments but not its `reason`; `run_runbook` answers when the job has ended (a long runbook holds the call); `exec` runs for at most 10 minutes; runbooks other than `quarantine-release` are refused on a quarantined machine (any state but `none`); the caller is checked on every request; `quarantine` and `quarantine-release` are judged as quarantine; a runbook runs at the lower of the job's level and its own `autonomy` | The design gives the rules, not these limits | plan | - |
| D39 | 2026-11-19 | T58 | `web/pages/{approvals, jobs, library, patching}.rs` | As planned, plus `policy/store.rs`: Policy owns `policies` and `windows`, so it writes them and renders `config/policies.toml` (policies and windows) as a new revision on every change. The patching page shows policies (holds are `patch = hold`), windows and the latest `patch-*` jobs; pending updates per machine need the reports' facts (carried into T59). A decision in the dashboard doesn't publish `ApprovalDecided` yet: the Web has no Bus handle until the composition (T41) | Ownership per 7.2; facts and the Bus arrive later | plan | - |
| D40 | 2026-11-19 | T76 | `assist/{offers, tokens, transcripts, cap, resume}.rs`; `tests/operator_contract.rs` | Tokens are issued and rebound to the next operator through `mcp::keys` (no `assist/tokens.rs`); the fake operator is in the test file. Assist ends a job nobody took with `no_operator` or `declined` and publishes `JobFinished`; moving the incident to `human` and the callout are Incidents' and Notify's (carried into T78). An operator's 5-minute grace and `hub_unreachable` are the operator's side (carried into T77); the hub waits for it. A job token from another endpoint now gets `out_of_scope` at the auth line (it was `unauthorized`). The daily cap counts assistant jobs since 00:00 UTC (20 by default; the setting is wired in T79). A job whose operator never reports stops being usable when its token expires at the deadline; a hub-side end for it is carried into T78 | Incidents and the operator binary come later | plan | - |
| D41 | 2026-11-20 | T05 | Record 24 h from the WSL machine and from one lab VM the owner names | Recorded the WSL host only; added integer, quantized and tick-stamped encodings and retention options to the measurement | No lab VM was named and the real lab isn't connected yet; an idle local lab VM wouldn't represent a server. The extra encodings show what it takes to meet the budget after plain Gorilla missed it | plan | - |
| D42 | 2026-11-20 | T05, T19 | T05 deletes the spike code and data; T19 tests `gorilla::` with the 120-point and hour rules | T05 kept a 4-hour sample of its recording as T19's fixture; T19's tests follow D109 (codec, step and chunk tests for the new encoding and the tier 0-only hour rule, plus a refused out-of-order append: 11 instead of 6) | T19's spike-figure test needs recorded data, and the owner's S8 decision changed the encoding and the chunk rule | plan | - |
| D43 | 2026-11-20 | T25 | `ingest/{staging, compact, window, clock, replay_limits, events}.rs`; `CompactStaged` as in 7.3.8 (no payload); 11 tests | As planned, plus: `CompactStaged` carries the machine's decoded points (`series::compact::Compaction`), because the store can't decode probe frames (it depends on nothing of ours) and Ingest owns the decoding; store schema adds `report_staging.offset_ms` and `rollup_dirty` (design change log, owner to confirm); points older than a series' newest are written as closed backfill rows; the staging limit counts the frames' received bytes and is recounted from the table after each compaction; the window is rebuilt from tier 0 after the start-up compaction (which has moved staging into tier 0); low disk raises `hub.disk_low` (critical) and turns off `accepting_jobs()`, which Actions checks from T41 (carried in); a 12th test for the latest facts; the writer test that used `CompactStaged` as an unimplemented command now uses `PutConnRecords` | Store dependency rule (7.2); restart placement and dirty ranges need somewhere to live; Actions and the composition come in T41 | plan | - |
| D44 | 2026-11-20 | T26 | `crates/rackhand-probe/src/link/` (client); `ingest/probe_server.rs`; `tests/probe_contract.rs` | As planned, plus: each unidirectional stream starts with a one-byte tag (`rackhand_proto::streams`, 1 live, 2 replay), since 7.3.2 numbers the streams but QUIC doesn't; async frame helpers in `rackhand-net::frames`; the server learns which machine an endpoint is through a `ProbeDirectory` trait (the Registry wires it in T41) and which probe versions it takes through a predicate (T95 sets the rule); a resend of committed reports is acked again so the probe can delete them; the probe gains `rackhand-net`, `iroh` and `tokio`. The process-level checks (exit code 3, hourly retry, label sets after a new epoch) are the daemon's and go to T42; the contract asserts `Stop::exit_code` and `Stop::retry_after` | QUIC streams carry no names; the Registry and the daemon come later | plan | - |
| D45 | 2026-11-20 | T27 | `rackhand-store/src/{rollup.rs, retention.rs}`; the `Rollup`, `RetentionBatch` and `MarkRollupDirty` handlers; 6 tests | As planned, plus: minute rollups come from Ingest's recent window (7.4.1 says so; tier 0 lags compaction by up to 5 minutes), handed to the store by a new `PutRollups` command, with `ingest/series.rs` making them and reading series for MCP and the dashboard (tier chosen by the range); `Rollup` recomputes the dirty ranges after rolling up; `RetentionBatch` carries the rule, cutoff and batch size; `backfill` takes several columns; the age rules this step runs are the three series tiers and `events`, and every other rule of 7.4.1 is listed and built in T98; tables 7.4.1 gives no rule (`jobs`, `silences`, `library_revisions` among them) are listed as fixed size; 2 more tests, and the carried `get_vitals` test | The design's own rollup source; the scheduler wiring comes in T41 | plan | - |
| D46 | 2026-11-20 | T32 | `incidents/{lifecycle, evaluate, dedupe, silences, reconcile}.rs`; the three handlers | As planned, plus: detect's threshold state follows the highest matching level while active, so severity falls as 7.5.2 says (T28 only rose; a detect test added); the store gets an upsert row mode so an incident and its event commit together without the cascade a REPLACE would fire; Incidents reads warning and critical events from the `events` table after the last row it saw (Ingest can't call Incidents); an unresolved event incident takes every matching event (the store allows one unresolved incident per key) and a resolved one reopens for a matching event within 24 hours of its last event, while condition incidents reopen within 30 minutes (owner to confirm); a rule that fired under a silence opens its incident once the silence ends; a failed job's incident goes to a person until T57 and T78 route it | Design 7.5.2 and the schema's unique index | plan | - |
| D47 | 2026-11-20 | T33 | `notify/{discord, smtp, grouping, retry}.rs`; a `wiremock` Discord endpoint and `tests/support/smtp_sink.rs` | As planned, plus: a hub-wide `http` module (one HTTP/1.1 request over rustls with the webpki roots, plain HTTP to loopback only) because hub systems may not use Web's OIDC client; the SMTP client is written here (STARTTLS or implicit TLS, AUTH PLAIN) rather than pulling in a mail library; the Discord test endpoint is a local axum server (no new dependency) and the SMTP sink lives in `notify/smtp_sink.rs` under `cfg(test)`; Notify follows `incident_events` (the callout flag Incidents writes) instead of the bus; Notify is the Executor's runner for `notify` steps; notifiers from `config/notifiers.toml` and the Vault are built in T41 (carried in); a 9th test | Dependency rules (7.2); fewer dependencies | plan | - |
| D48 | 2026-11-20 | T25, T32, T33, new T32b | The steps as planned | A review after T33 found four gaps the tests didn't cover, each now with a test seen failing first: compaction marked every point dirty, so only late points do now; open condition incidents now resolve after a restart; SMTP headers stay on one line; and forecasts, baselines, machine silence and counted rules were wired by no step, so step T32b is added before T41. Notify's and Ingest's in-memory state across restarts and the probe's events and connections are carried into T41 and T67 | Found in review | plan | - |
| D49 | 2026-11-20 | T32b | `incidents/{forecasts, baselines, machine_silence, counted}.rs` | As planned, plus `incidents/conditions.rs` (one tracker for every non-threshold rule: open, severity change, and resolve after the rule's own count); Ingest keeps per-machine counters for down services, container restarts and pending security updates, the last report time, and reads stored series by tier; baselines are kept in memory and written to `baseline_buckets` through Ingest each hour, and on start the learning time is taken from the hour-of-day buckets' counts (one update a day each) since it isn't stored; any reported service not active counts until the hub knows which services are watched (T41's probe config); the check-failing rule and certificate expiry wait for checks (T46) and maintenance windows for silence for T59 (carried in) | The tests and the data the rules need | plan | - |
| D50 | 2026-11-20 | T39 | `web/pages/{overview, site, machine, incidents, audit, settings_notifiers}.rs`; `query/vitals.rs` | Pages in `web/pages/{monitoring, audit, overview}.rs`; `query/vitals.rs` merges through `Ingest::series` (the merge of the recent window and chunk rows was built there in T27) and cuts to 2000 points; the probe's `Hello` capabilities are kept by Ingest for the machine page's capture method; the overview's empty state already existed (T36), so its test also asserts the new incident summary; the vitals partial shows the last hour as an SVG line with now, min and max; Send test is audited | Reuse of T27's merge | plan | - |
| D51 | 2026-11-20 | T40 | `web/metrics.rs`; counters in Ingest, Actions, Notify, Peers and Assist; a Prometheus text parser in the test | `/metrics` is answered before the session gate (it has its own bearer token); the only in-memory counter is Ingest's reports; jobs running, notifier failures, staging rows, the database size and peer and operator state are read from their tables, so Actions, Notify, Peers and Assist need no counters; the latest values come from the recent window; the Prometheus check is a strict line grammar in the test rather than a new dependency | Fewer moving parts | plan | - |
| D52 | 2026-11-20 | T41 | One step; the two `hub_start` tests in the integration tier (systemd containers) | Done in parts, each committed: T41a (`hub init`, `hub run` as the composition root, `hub detect replay`, the unit file), then the carried-in wiring; the `hub_start` checks run in the live tier on the lab's Debian 12 hub (`m1::`, L2) because systemd in Docker can't hand a service's user its credential, and were run by hand there now; `hub_cmd` tests and the carried-in tests were written with their code and seen failing with the behaviour removed; `config/notifiers.toml`'s format (`[[discord]]`, `[[smtp]]`, `secret:` references) and a `probe_ranges` table (the committed seq ranges outliving staging) fill design gaps, owner to confirm | Size of the step; the container can't host the check | plan | - |
| D53 | 2026-11-20 | T41 | The `ManagedSetupSource` from T51 and T53 (D21) | Composed in `hub_cmd::joins`: the automation and assistant public keys from the Vault, the wrapper's one sudoers line, and the command list of the current runbooks plus the diagnostics, signed with the node key, valid 1 hour, versioned by the signing time. The join server is built at the first join after first run names the hub's site (before that no token exists; the connection closes as from an unknown peer). A join tells the machine the QUIC endpoint's direct addresses (its interfaces, or the one address it is bound to) other than loopback and link-local, then each certificate name that is an IP address, on the QUIC port, read when the join server is built; the probe settings are the design defaults (15 s, 500 tuples, 64 MB). The 1-hour validity and the address rule fill design gaps, owner to confirm | Nothing else provided the managed setup; the site is only known after first run | plan | - |
| D54 | 2026-11-20 | T42 | One step; `vitals_visible_within_30s` lists containers; `probe_check` in T42 | Done in parts, each committed: T42a (the daemon, with unit tests and the carried-in `probe::` tests in `crates/rackhand-hub/tests/probe_daemon.rs` against the real probe server), T42b (the integration tests and the unit file), T42c (`wait_report`). Containers come from the helper (T43), so T42 asserts metrics and services and T43 carries the container check. `probe_check` has no fields and no wire message, so its test moves to T46 with the checks, owner to define. `probe.toml` gains `hub.addrs`, `hub.relays` and a `[machine]` section (`id`, `access`, `mode`), read through one module by the wrapper and the daemon; `probe.state` is JSON (`state` connecting, connected, disconnected or stopped; `version`, `at_ms`, `reason`, `retry_in_ms`, `epoch`, `buffered`) replaced whole on each change. The probe runs on a single-thread runtime (its footprint budget). Design gaps, owner to confirm | Size of the step; the helper and the check message don't exist yet | plan | - |
| D55 | 2026-11-21 | T42 | `disk_rule_callouts_and_resolution` through the hub binary; `wait_report` in the integration tier; the buffer cap and the 5 s interval as test knobs | The disk-rule callout test composes the hub's own Ingest, Incidents and Notify in the test process with the real probe daemon, because the hub binary trusts only public CA roots for SMTP over TLS (D113) and a local test mail server can't hold a public certificate (Discord over plain HTTP is allowed to loopback); the hub's SMTP sink is shared through a `testing` feature. `wait_report` is tested in the hub's own tests (it only reads Ingest). `config/hub.toml` gains a `[probe]` section (`interval_s` 5 to 300, `connection_tuples` 100 to 5000, `buffer_max_mb` 1 to 64) read when the hub starts, which is how the tests set the 5 s interval and the 1 MB cap (D114; pushing an edit as `ConfigUpdate` is carried into T98). The buffer test makes each report large with 1500 failed units, since a normal report is about 0.6 KB. The integration tests were written after the daemon; the daemon's behaviour they rely on was seen failing in T42a's mutation checks, and the hub-side rules in T32 and T32b | The binary can't trust a test mail server; settings had no probe section | plan | - |
| D56 | 2026-11-21 | T13 | A separate Unix user with an empty configuration directory | The same user with its own `CLAUDE_CONFIG_DIR` (the owner signed in there), and each run from a fresh directory holding only a copy of `.credentials.json`; the isolation under test is the configuration directory, which this keeps | No second account in WSL needed | plan | - |
| D57 | 2026-11-21 | T43 | `packaging/openrc/` in T43; a test image with a fake `apt-get` and `apk`; Docker in the container for AC1's containers | The OpenRC scripts go with the Alpine installer in T44, where they are tested. The fake `apt-get` is copied into the systemd test image by the test (Alpine's `apk` parse is a recorded-output unit test). The containers test mounts the test host's Docker socket into the machine and starts two named containers there, so the helper reads a real engine without Docker-in-Docker. Filled in (7.3.3): the helper refreshes the package lists at start as well as every 6 hours; at start it puts the ownership table right (creates root's and the probe's directories, re-owns root's files as `root 0644`, never follows a symlink); the socket is answered only for the probe user's uid even inside the probe's group. The systemd test image gains D-Bus and socat | Size of the step; no Docker-in-Docker needed | plan | - |
| D58 | 2026-11-21 | T44 | `offline_variant_checks_script_hash` and the hub's SSH test in T44 | The offline variant needs the hub to serve `install.sh` and the release files, and the SSH test's result belongs on the Add page; both go to T49 with that page. Filled in (7.3.12): the install command's ticket is `rackhand1:<hub endpoint id hex>@<addr>,<addr>[!<relay>,...]`; `install.sh` also takes `--release-url` (a mirror, and the tests); the service files are release files too, signed and checked like the binary; `rackhand-probe enroll` performs the join as root, writes `probe.toml`, installs the first command list through the wrapper's own checks and leaves the accounts' `authorized_keys` lines and sudoers in root-only `/var/lib/rackhand-run/enroll/` for the installer, which deletes it; accounts are key-only (`*` password, not locked). Release keys: until the maintainer creates them (T91), a release build pins none and verifies nothing | Both need the Add page; formats the design didn't give | plan | - |
| D59 | 2026-11-21 | T45 | `it::backup::restore_on_new_machine_probes_reconnect`; a critical incident on corruption | The restore test is `probe_hub::backup::restore_on_new_machine_probes_reconnect` (it uses the probe-and-hub harness). On a failed `quick_check` the hub writes nothing, so the critical goes straight to the notifiers instead of through an incident (E33's "keeps alerting from memory"). Filled in: the backup file format (chunks sealed with the master key, each bound to its index and whether it is last), `rackhand hub restore <file> --master-key <path>` onto a machine without a hub, the self-watch at 02:30 site time beside the 02:00 backup, the release manifest beside `hub.toml` (`release-manifest.json` and `.minisig`, installed with the release, T93), the config files checked (`master.key` at most 600, `hub.toml` at most 640, root's). Backups to peers are T85's | No database to write the incident into; formats the design didn't give | plan | - |
| D60 | 2026-11-21 | new T39b | No form to add a notifier | Settings: Notifiers gains a form to add or replace a Discord or SMTP notifier (T39b), because no step let the dashboard add one and L2's callout test needs it. Secrets are named `notifier.<name>.webhook` and `notifier.<name>.password`. A saved notifier applies when the hub restarts, and the page says so; applying it at once is carried into T98. Removing a notifier is by editing the file for now | A gap found while writing L2 | plan | - |
| D61 | 2026-11-21 | L2 | `/metrics` behind the token in the Vault | `rackhand hub metrics-token [--config]` prints it: `hub init` makes the token but nothing gave it to the owner for a scrape config. It reads the database read-only with the master key, so it needs root and is safe while the hub runs | A gap found while writing L2's metrics test | plan | - |
| D62 | 2026-11-21 | L2 | WSL-side fakes for a Discord webhook and an SMTP server; `lab deploy`; the tests as listed | The fake webhook runs on the hub machine at 127.0.0.1, because the hub sends plain HTTP only to loopback and SMTP only to servers with a public certificate (D113), so a WSL-side SMTP fake can't be reached: the live callout test uses the webhook alone, and SMTP stays covered by T42's tests. Only failed and watched units are reported and nothing sets watched services yet (T43's probe config), so the services the tests see are units they make fail: `rackhand-live-boot` before the install and `rackhand-live.service`, killed and started again, for the callout. The install is measured by a fixture that installs `target` when the hub doesn't know it and records the seconds until vitals, services and updates were on the hub; `target_installs_and_reports_within_30s` checks that record, so the tests run in any order. The tampered install runs on the hub machine, which has no probe. `cut_link_backfills_without_stale_incidents` waits up to 90 s for live data after the heal (the probe's reconnect backoff tops out at 60 s) and then, as AC2 says, checks live data stays under 30 s old while the 10 minutes replay, the hole closing in the last-hour chart. `lab deploy` gains `--restore <backup> --master-key <key>`; the machine page gains its updates (7.7.1); `hub lab-token` takes `--addr` and prints the ticket | What the hub accepts (D113), what the probe reports, and test order | plan | - |
| D63 | 2026-11-21 | L2 | (none: no step wrote the logs) | The hub and the probe log JSON lines to stderr, which journald keeps, at info unless `RACKHAND_LOG` names another filter (design 13 "Logs"); started by `hub run`, `probe run`, `probe helper` and `probe enroll`. The join server logs a request it can't read. Found in L2: a failed join left nothing in the journal | No step covered design 13's logs | plan | - |
| D64 | 2026-11-21 | L2 | iroh's QUIC defaults | The endpoint turns QUIC segmentation offload (GSO) off. On a NIC without TX checksum offload the first segmented send fails with EIO; the UDP layer stops segmenting, but iroh keeps the segment count a connection started with, so that connection's large sends never arrive: in the lab the join's answer was lost, the token spent and the machine left registered without a config. Rackhand's traffic is small, so one datagram per send costs little. To raise upstream with iroh | Found in L2 | plan | - |
| D65 | 2026-11-21 | L2 | (a bug the lab found) | After a hub restart the counted rules' report counts and first-seen times start again, so an open critical incident resolved: at the hub's first evaluation, before the machine had reported again (it is known from its received ranges, with empty counts), and at the first report of a service still down (which counted 1); it then reopened as a warning, with a false resolution and new callouts. Pending security updates resolved the same way. Counted rules now wait for a machine's first report after the start, and while the condition is still there an incident open across a restart keeps at least its severity. Escalating on time across a restart needs the counts kept, carried into T98 | Found in L2 (`hub_reboot_keeps_history_and_rules`) | plan | - |
| D66 | 2026-11-21 | L2 | (a bug the lab found) | `rackhand hub backup` run as root left `/var/lib/rackhand/backups` root's with mode 700, so the hub's own 02:00 backup could neither write nor prune there; the command now gives the directory and its files to the data directory's owner | Found in L2 (`backup_restores_on_a_fresh_hub`) | plan | - |
| D67 | 2026-11-21 | L2 | The live tests as written | Found while running them: `reboot` waits for a new boot id (a transient timer fires up to a minute late by default, so the old system still answered); the pause test waits until the hub has run 3 minutes (no silence in its first 3, E44) and sets `target`'s clock from WSL's after the resume (a paused VM's clock stays behind, which opened `clock_skew`); the live profile prints passing tests' output, kept as evidence; `lab deploy` builds release binaries (the debug probe was 254 MB) | Lab behaviour | plan | - |
| D68 | 2026-11-21 | L2 | Expected 8 m1 and 6 lab tests; MV12 done by the run | 10 m1 tests (the 8 listed and the 2 carried from T41) and 7 lab tests. The page walk waits for the owner: the in-app browser refuses the hub's self-signed certificate, and continuing past that warning is the owner's choice | Counts grew; a browser trust setting | plan | - |
| D69 | 2026-11-21 | L2 | (a bug found while checking D65's kind) | An open `machine.silent` resolved at the first evaluation after a hub restart: in the 3-minute start grace the rule gives no severity, which the tracker read as the condition clearing, so every restart while a machine was down sent a false resolution and, 3 minutes later, a new callout. A machine that hasn't reported since the start is now left as it is during the grace. A container-restarts incident has the same exposure (the restart window is in memory): carried into T98 | Found reviewing L2 | plan | - |
| D70 | 2026-11-21 | T46 | One step | Split into T46a (the drivers crate and its 4 tests), T46b (the hub's schedule, results, series and incidents, `config/checks`, the integration test) and T46c (the carried executor and `probe_check` tests), one commit each. Filled in for the drivers: `crates/rackhand-drivers/src/driver.rs` for the trait (a module can't be called `trait`); series `check.up`, `check.latency_ms`, `check.status_code` and `check.cert_days` (7.4.2 names only what they measure); settings per kind, unknown ones refused: HTTP `status` (200) and `body_contains`, DNS `server` (the first `nameserver` of `/etc/resolv.conf`) and `expect`, TLS `server_name`; HTTP doesn't follow redirects and HTTPS trusts the public roots only, as D113 does for notifiers (a self-signed internal service then fails its HTTPS check: a per-check option is on the owner's list); the TLS check reads the certificate whoever signed it, since its expiry is what's watched, and fails once expired; ICMP uses an unprivileged ICMP socket and falls back to a raw one (`CAP_NET_RAW`) | A large step; values the design didn't give | plan | - |
| D71 | 2026-11-21 | T46b | `checks/{schedule.rs, results.rs}`; Checks depends on Drivers and Store | `checks/{mod.rs, config.rs}` and `incidents/checks.rs`. Filled in: the `config/checks.toml` format (`[[check]] name, kind, target, interval_s, machine` and `[check.settings]`), validated on save; the hub picks up a new revision within 15 s; a check taken out keeps its row (its results refer to it) with `interval_s` 0 and its incidents resolve; a check with no machine has its series under `hub` and its incidents without a machine (shown as the hub's), 7.4.1 and 7.4.2 naming no home for it; check series go through Ingest (`put_points`), the one writer of the series, so Checks depends on Ingest too; check failing and certificate expiry are read from the stored results and the latest `check.cert_days` point, so a restart doesn't start a count again; 2 good runs resolve a failing check, a renewed certificate resolves at once; the test image `web` (HTTP and HTTPS in Python) | The series' owner; formats the design didn't give | plan | - |
| D72 | 2026-11-21 | T46c | `verify` with `containers_running:<project>`; `api` makes "the driver call" | Filled in: `verify`'s names are `containers_running:<project>` (the latest report has the Docker Compose project's containers, all running; the report now carries each container's `project`, from `com.docker.compose.project`, a new field 8 of `ContainerState`) and `check:<name>` (the newest result of a check bound to the machine, newer than the step's start, passed), retried every 2 s until the step's timeout, failing with the first failing name; an unknown name fails at once (`unknown_check:<name>`). Services and mounts aren't names yet: only failed and watched units are reported, and nothing sets watched services until T43's probe config. `api` calls the machine's driver (its `driver` column) at its address with the step's `call` as the operation and records the answer as the output; the API drivers register with it in T47 to T49. `probe_check` moves to T46d | The design names one check and no call format | plan | - |
| D73 | 2026-11-21 | T46d | `it::executor::probe_check_step_runs_check_on_probe` | `checks::probe_check_step_runs_check_on_probe`, in the checks module of the integration tier, with the real probe daemon in this process (as the callouts test runs it), so its machine is the test host and its loopback services are real. Filled in for D115: `RunCheck { id, check, timeout_ms }` is field 6 of `HubToProbe` and `CheckResult { id, ok, detail, latency_ms }` field 3 of `ProbeToHub`; the step's checks run one after the other, each at most 30 s; a name is judged by every address it resolves to, an address is the machine's when it is loopback or a socket can be bound to it, and the check then connects to the address it judged; the probe runs checks off its report loop and gains the drivers crate for the TCP and HTTP kinds | The daemon's machine; the messages' fields | plan | - |
| D74 | 2026-11-21 | T46 regression | (a bug the integration tier found) | A detached step whose `job-start` call lost its answer (SSH cut as it answered) failed `no_exit_status` while its unit ran on, leaving the machine doing work the hub had given up on (E54). The hub now asks `job-status` whether the step started: `unknown` means it never reached the wrapper and the step fails as before; otherwise it polls the unit to its end. Found with 16 copies of the cut test at once (2 failed), fixed and seen passing 16 of 16 | Found in T46's regression run | plan | - |
| D75 | 2026-11-21 | T46 regression | `Container::start_systemd` | The integration tier's systemd containers are used only once their boot has finished (up to 60 s, else the test fails naming it), where the helper went on after 10 s regardless; the detached-step tests' messages carry a post-mortem of the machine's job files and journal | Three runs each lost one detached-step test under the tier's load | plan | - |
| D76 | 2026-11-21 | T47 | Responses recorded in T12; `client.rs, poll.rs, ops.rs, sim.rs`; `it::executor::snapshot_and_rollback_steps_use_proxmox_driver` | T12 recorded none, so `cargo xtask lab record-proxmox` records them first (with `pvesh` on the nodes, redacted). `proxmox/{mod.rs (poll), client.rs, ops.rs, sim.rs}`, the simulator behind a `sim` feature for other crates' tests. Filled in: series `pve.node.cpu_pct`, `pve.node.mem_used_bytes`, `pve.node.mem_used_pct`, `pve.storage.used_bytes`, `.total_bytes`, `.used_pct`, `pve.guest.up`, `.cpu_pct`, `.mem_used_bytes` as labelled points of a reading (a new `points` field); settings `token`, `fingerprint` (SHA-256, hex), `node`; the operations and their arguments (module docs); a firewall read leaves out the digests. The carried test is a hub test against the simulator: the guest's `proxmox_ref.cluster` names its hypervisor machine, whose credentials are the Vault's `driver.<id>` (`{token, fingerprint}`, written by T49's form); a job's snapshot is `rackhand-<job id>` (T60 names patch snapshots) | Fixtures missing; formats the design didn't give | plan | - |
| D77 | 2026-11-21 | T48 | `src/{truenas.rs, redfish.rs, snmp.rs}` and `src/sim/`; a public Redfish mockup set; the integration test here | One module each with its simulator inside (`truenas/`, `redfish/`, `snmp/`, behind the `sim` feature), the pinned TLS shared by the appliance drivers (`pinned.rs`), and a small WebSocket client (`ws.rs`) rather than a new dependency. The Redfish responses are invented in the DMTF schemas' shapes (nothing downloaded), with one supply unhealthy; the SNMP walk is invented. SNMP is written here: BER, v2c, and v3 user security with SHA (HMAC-SHA-96) and AES-128 only, checked against the published vectors. Series named in each module's documentation (labelled `pool`, `disk`, `sensor`, `ifName`, `oid`). The integration test needs T49's Add form, so it moves there | No crate for SNMPv3 or WebSocket in the tree; downloads need the owner; the form is T49's | plan | - |
| D78 | 2026-11-21 | T49 | One step; `registry/guest_binding.rs`, `web/pages/machine.rs` | In four parts, one commit each: T49a guest binding, T49b the Add page's commands and invites, T49c the appliance forms with driver polling and agentless silence, T49d the integration tests. T49a: `registry/guest_binding.rs` (it raises its event through Ingest, the events' owner) and the confirm action in `web/pages/machines.rs` beside the host-key one. Filled in: MACs compared without case or separators; a MAC on two guests' configs proposes nothing; a confirmed machine is a mismatch when it reports another guest's MAC or none of its own guest's, and judged only while its host's guest configuration is known; after a mismatch an admin confirms the binding it had or the guest it now looks like (held in memory until then, so offered again after the next report following a restart); confirming is admin with a fresh step-up, audited `machine.binding_confirmed` | A large step; rules the design didn't give | plan | - |
| D79 | 2026-11-21 | T49 | The Add page's commands and invites (7.7.1) | T49b: `web/pages/add.rs`. Filled in: an invite is the hub's ticket and the one-time secret as `<ticket>#<secret>`, shown with `rackhand operator join`, the Peers page or `rackhand-cli login`; the machine command passes `--ticket`, `--token` and `--monitor`/`--remote` (`-Ticket`, `-Token`, `-Monitor`, `-Remote` on Windows), `wget` without sudo on Alpine; the offline variant appears when the hub holds `<data_dir>/release/install.sh` and reaches the hub at the address the admin used, else the ticket's first address on port 8443, checking the script with `sha256sum -c` and passing `--release-url`; machine names are 1 to 64 letters, digits, `.`, `_` and `-`, unique in the site; audited `machine.added` and `invite.created` | Formats the design didn't give | plan | - |
| D80 | 2026-11-21 | T49 | Four parts (D78); `agentless::` 2 tests; Verification 9 passed | Five parts: T49c the appliance forms, T49d driver polling of agentless machines, their silence and the guest MACs fed to guest binding, T49e the integration tests. T49c: `registry/agentless.rs`, `web/pages/appliance.rs`, `pinned::presented`, a `machines.driver_settings` column (7.4.1: the driver's settings with each credential as `secret:driver.<id>`; the baseline schema, as the version is unreleased) and a token kind `agentless` (60 minutes, no ALPN). Filled in: the form is two posts, the address first (the hub reads the certificate presented, the handshake only, and shows its SHA-256; the pending machine and the token are made, bound to the driver, address and fingerprint shown), then the accepted fingerprint and the credentials (the hub polls once pinned to that fingerprint, and only a poll that succeeds completes the form; the token used up, the Vault entry sealed and the machine enrolled in one transaction); the Vault entry `driver.<id>` holds all the driver's settings (the shape the snapshot step already reads); a Proxmox API can attach to the enrolled machine that runs the host's probe instead of making a second machine; audited `machine.added` or `machine.driver_added`. Three tests beyond the plan's two (Proxmox attach, SNMP, admin only) and one in the drivers crate | The design gives no form flow or storage; the advisor's review found the two-row Proxmox risk | plan, design 7.4.1 | - |
| D81 | 2026-11-21 | T49 | Five parts (D80), T49d with the guest MACs | Six: the guest MACs move to T49e, since the probe doesn't collect its interfaces yet (`interfaces` is always empty) and the hub keeps no reported MACs; T49f the integration tests. T49d: `checks/agentless.rs` and the agentless rule in `incidents/machine_silence.rs`. Filled in: every enrolled machine with a driver is polled as a check `driver:<machine id>` every 60 s (the design gives no interval) with its Vault entry's settings read at each poll; a driver's own readings (`Point`s) are series of the machine with the driver's labels; an agentless machine with no probe is silent from its failed polls in a row as stored (7.6.3, so a restart keeps the count), in the hub's start grace an open incident stays, its next good poll resolves it, and its poll is no `check.failing`; a machine with a probe and an API (a Proxmox host) is silent by its probe's reports, and a failing API poll on it is `check.failing` | The design gives no interval or incident rule for API polls of a machine with a probe; the MAC feed needs probe work | plan | - |
| D82 | 2026-11-21 | T49 | Guest binding fed by "probe `interfaces` against the guest configs" | T49e: the Linux probe now fills its Hello's `interfaces` from `/sys/class/net` (name and MAC; addresses left empty) without the loopback, `veth`, `tap`, `fwbr`, `fwpr`, `fwln`, `docker` and `br-` devices and without devices with no MAC; the Proxmox driver gains a read op `guests` (every guest of every node with its `netN` MACs, failing as a whole if any configuration doesn't load); `GuestBindings` keeps each probe's latest MACs and each host's latest complete guest list in memory and judges again when either arrives; a probe that reports no MACs isn't judged. The Windows probe reports none yet, so a Windows guest is never proposed and never a mismatch: noted as a follow-up | How the two sides meet wasn't given; a probe without MACs must not block a confirmed binding | plan | - |
| D83 | 2026-11-21 | T49 | Six parts (D81) | Eight: T49f the hub's release files and the offline variant's integration test, T49g the machine's address at join and the hub's SSH test after the first report (probe machines had no `address`, so no SSH step could reach them), T49h the appliance integration test. T49f filled in (7.3.12): the hub serves `GET /install.sh` and `GET /release/<name>` from `<data_dir>/release` to anyone, plain names only; the offline command passes `--release-url https://<hub>:8443/release --self-signed`, and `install.sh` gains `--self-signed`, which skips the download's certificate check (the script's SHA-256, the verifier's hash and the signatures are what is trusted). Found in passing: `cargo xtask ci win` fails (a mingw link error in `iroh-relay` and Unix-only file modes in `rackhand-net`); T89 owns that tier | Formats the design didn't give | plan, `packaging/install.sh` | - |
| D84 | 2026-11-21 | T49 | A managed machine is `Pending` until the hub's SSH test passes (design state diagram, 7.3.12) | The machine is `enrolled` at join, as since T42, and the SSH test's outcome is recorded beside it: a `machine.ssh_test_passed` info or `machine.ssh_test_failed` warning event naming the account (`rackhand` or `rackhand-ai`) and the reason. The Add page lists the machines enrolled in the last day with that outcome. Filled in: the join records the machine's `address` as the IP a direct join came from (none for a relayed one; a machine with a driver keeps its API address); the test runs after the first report following each join, and after every report while the last test failed; it logs in at that address on port 22 with a 30 s limit per login. Integration image `debian-install-sshd` added | The probe, its jobs and the dashboard already treat a joined machine as enrolled; holding it `pending` would hide a machine that reports but can't be reached over SSH, where the failure and its account say what to fix | design state diagram (owner to confirm), `registry/join_server.rs`, `ssh/enroll_test.rs`, `web/pages/add.rs` | - |
| D85 | 2026-11-21 | T49 | T49h is a test of what T49c and T49d built | It also fixed what it found: `Ingest::put_points` (T46) stored the hub's own readings (drivers, service checks) in tier 0 without adding them to the machine's recent window, so `/metrics` and the dashboard showed none until a restart rebuilt the window. They now join the window as they are stored, as a probe's reports do; the integration test runs the four simulators in its own process and needs `rackhand-drivers` with `sim` | A defect in designed behaviour (7.4.2), fixed with a unit test seen failing first | `ingest/series.rs`, `tests/it` | - |
| D86 | 2026-11-21 | L3 | The Library page holds runbooks and playbooks (7.7.1) | It also lists and edits the configuration files (`config/checks.toml`, `hub.toml`, `policies.toml`, `notifiers.toml`), each validated as the file it is, admins only (Edit library). Nothing else in the dashboard could add a service check; the git mirror only pushes out | A gap: FR-9's checks had no way in from the dashboard | design 7.7.1 (owner to confirm), `web/pages/library.rs` | - |
| D87 | 2026-11-21 | L3 | The live pass changes only tests and the lab | Also fixed what it found: a hub with no git mirror raised `git_mirror_failed` at every library change (`MirrorAlert::Off` now, no event, no retry); the Add page's offline command for Alpine uses BusyBox's `wget` (a stock Alpine machine has no `curl`); `lab/provision/<name>.sh` per machine, `snmpd` on `agentless`, no unattended upgrades on `target`. The 10-day certificate is made by the test on `target` at run time rather than at provisioning, so it doesn't age with the base image | Defects in designed behaviour, each with a test seen failing first | `library/mirror.rs`, `web/pages/add.rs`, `xtask/src/lab`, `lab/provision` | - |
| D88 | 2026-11-21 | T57 | `incidents/{routing.rs, attempts.rs}`; level 1 leaves a job `waiting_approval`; "a runbook bound to the machine" (7.5.2) | One `incidents/routing.rs` (attempts are counted there from the incident's `runbook.started` events, so they hold across reopens and restarts). Runbook `targets` gains `machines` (names): the binding the design names but the format didn't have; a runbook matches by name, then by a tag or role, then by kind, then with no targets at all, and targets that leave the machine out aren't candidates. Level 1 creates the approval (requested by `incident:<id>`, tool `run_runbook`, bound to the runbook revision) and starts the job when `ApprovalDecided` arrives, so no job row exists before; the Actions-owned `jobs` table keeps only jobs that start. An incident nothing matches goes to `human` at once (7.5.2's Open to Human). `StartJob::runbook(..)` builds the command, as Incidents may use nothing else of Actions. The job starter reports a start that made no job, which hands the incident to a person | The design's lifecycle; fewer moving parts | design 7.8.7 (owner to confirm `targets.machines`), `incidents/routing.rs`, `actions::StartJob::runbook` | - |
| D89 | 2026-11-21 | T59 | One step | Parts as done (T59a and T59b swapped what this row first listed): T59a window selection (`actions/patching/select.rs`, a planner the driver feeds), T59b the precheck and the D45 rollback rules and defaults as pure decisions, T59c the built-in `patch-debian` and `patch-alpine` runbooks seeded into the Library with their precheck, snapshot, record and verify, T59c2 the window driver (Scheduler to Actions, approvals, offline retries, `patch_failed`, D45 rollback), T59d the reboot step, the fake package manager image and the integration tests, T59e the carried patching page and silence tests. T59a fills in: an approve-only approval decided after its window ended is carried to the next window, which runs the machine without asking again; the hub sorts after hypervisors | A step too large to verify at once | plan | - |
| D90 | 2026-11-21 | T49 (owner review) | D84: a managed machine `enrolled` at join | Reversed by the owner: as the design's state diagram says, a managed machine's first join leaves it `pending`, and the hub's first passing SSH test enrolls it. It reports while pending (the probe directory admits `pending` and `enrolled`), its test was said to be retried at each report but ran only when the probe connected (fixed in D94), and the Add page shows the failure ("Pending: SSH test failed as <account>: <reason>"). A monitor machine, and a machine joining again (a level change), is enrolled at join. A pending machine isn't watched for silence or patched; the live install fixture waits for `enrolled`. Two consequences, carried: a managed machine that joined through a relay has no address, so its SSH test can't pass and it stays pending until the hub can reach it (T84's tunnels are the first way; the Add page says why meanwhile); a level change from monitor to managed keeps the machine `enrolled` and its first SSH test's failure shows on the Add page, since it was already enrolled and watched (the run's choices, owner to confirm: the level-change rule, and a machine joining again staying `enrolled`) | Owner decision on D84 | design (owner) | Owen, 2026-11-21, for pending until the test passes and showing its failure |
| D91 | 2026-11-21 | T46, T74, T75 (owner review) | HTTPS checks trust public roots only; machine output alone wrapped as untrusted; an assistant `exec` sent exactly as written | Owner's choices: an HTTPS check may pin its certificate with `fingerprint` (SHA-256, the appliance drivers' pinning); every value a machine reported, or a title or timeline entry built from one, comes back as `{"untrusted_output": <value>}` (so `services`, `containers`, `updates`, `os`, `title`, `subject`, `data`, `container` and `exe` change shape); an exec runs as `timeout -k 5 <s> sh -c '<command>'`, recorded in the job log and shown on its approval. Carried: probe security events (M4) reach `events` with a probe-given `kind` and fields; when M4 ingests them their kind is checked against the known kinds and their fields stay in `data`, so they come back wrapped (T67), and T78's briefs use the same wrapper | Owner decisions B1, B3, B4 | design (owner) | Owen, 2026-11-21 |
| D92 | 2026-11-21 | T59c | T59c: the built-in runbooks with precheck, record and verify; precheck includes "no lock files" and "no other job" | T59c in three parts, one commit each: T59c1 the runbooks, their seeding and the `verify` names; T59c2 the patch snapshot (guest conditions, `rackhand-patch-<YYYYMMDD-HHMM>`, keep 3); T59c3 the window driver. Filled in: precheck, record and the patch verify are `verify` names (`patch_precheck`, `record_state`, `as_recorded`, `required_mounts`, `bound_checks`), so the runbook format is unchanged; the record is the step's output in `job_steps`, read back by job; a lock someone else holds is waited on by the update steps (apt `DPkg::Lock::Timeout=600`, apk `--wait 600`, E9) rather than failing the precheck at once, and no other job can start while the patch holds the machine; the open-critical test leaves out the `updates.*` incidents patching clears; a guest's conditions are judged at the snapshot step, which has the hypervisor's driver; built-ins are seeded at hub start by author `rackhand` and kept up to date until an admin edits one; both runbooks are risk `normal`, autonomy 2 (the policy's `patch` mode decides approvals) | A step too large to verify at once; formats the design didn't give | design 7.5.3 (owner to confirm) | - |
| D93 | 2026-11-21 | T59c2 | The snapshot step names the job's own snapshot `rackhand-<job id>`; precheck judges the guest | A patch job (runbook `patch-*`) snapshots as 7.5.3 names it, `rackhand-patch-<YYYYMMDD-HHMM>` in UTC, and keeps the newest 3 by name; other jobs keep `rackhand-<job id>`; a rollback goes back to the snapshot its job recorded. The guest's part of the precheck runs at the snapshot step, from the Proxmox operations `snapshot_room` (the storages the guest's disks use, their free space and whether they can snapshot) and `snapshots` (new, with the simulator keeping snapshot state); several storages count by the least free. The baseline schema defaulted a policy's `snapshot` to `optional`, against 7.5.3 step 9: now `required` | The design's name and the guest's storage needed the driver | design 7.5.3 (owner to confirm) | - |
| D94 | 2026-11-21 | T49 | The SSH test follows the first report and every report until it passes (7.3.12) | It ran only when a probe connected, which D90 made matter: a pending machine stayed pending after its SSH was fixed. Now it runs when the probe connects and every 60 s while the machine reports (heard from within 60 s), one test per machine at a time; a failure equal to the last recorded one isn't recorded again. In the tests: the probe-and-hub fixture's machine is `monitor` (it has no accounts or sshd), and the enrollment test flushes the journal before counting logins and no longer restarts the probe | Found by the integration tier and reading | design 7.3.12 (the 60 s pace: owner to confirm) | - |
| D95 | 2026-11-21 | T59c3 | The Scheduler fires patch windows (`schedule_state`); an approve-only approval "expires at window end" (7.5.3 step 3) | `scheduler/patching.rs` works out the open windows from the policies each time and `actions/patching/driver.rs` (in Actions, told of them by the hub's wiring) runs them; which machines had their turn comes from the `jobs` table, so a restart during a window needs no saved state. An approval can be decided until the end of the next window, because Actions refuses an expired one and D89 carries a late approval. The site limit and the hypervisors-and-hub-last order hold across a site's policies (`Run::step_with`). Left out until their runbooks exist: roles `hypervisor` and `hub` (T60), kind `windows` (T90). A machine without a policy is in no window. The driver isn't switched on in the hub until the reboot step exists (T59d). The D45 rollback will sit in the driver, which has the job's result, since Incidents may use only `StartJob` | Dependency rules, restarts and D89 | design 7.5.3 (owner to confirm: an approval's life) | - |
| D96 | 2026-11-22 | T59d | The step reboots when the latest report has `reboot_required` | It asks the machine at that moment (`/run/reboot-required`), since the probe's update summary is refreshed every 6 hours and wouldn't have the flag a patch just set; `auto_reboot` off leaves the machine running, the step succeeding with `required_not_allowed`; the reboot is `/sbin/reboot` through the wrapper, in the command list of runbooks with such a step; back means started again and reported; silence for the wait is `no_report_after_reboot`, and a machine that goes on reporting is `did_not_reboot`, which never rolls back. Gaps left open: a stock Debian without `unattended-upgrades` or a similar package never creates the flag, so a new kernel there isn't booted; Alpine has no flag at all; pending-update counts are up to 6 hours old after a patch | The report's flag would be stale | design 7.5.3, 7.8.7 (owner to confirm) | - |
| D97 | 2026-11-22 | T59c3 | `patch_failed` opens and the hub rolls back (7.5.3 step 6); the `rollback` runbook is T61's | Incidents opens `patch_failed` (warning, one per machine) when a `patch-*` job ends without succeeding, unless a person cancelled it, and resolves it at the machine's next patch that succeeds. The driver runs the D45 rollback as a job of the built-in `rollback` runbook (high risk, parameter `job`: the patch job), brought forward from T61; it runs without an approval only there. Only a patch the windows started is rolled back by the hub, not one a person started | Filled in | design 7.5.3 (owner to confirm) | - |
| D98 | 2026-11-22 | T59d | A fake package manager whose update takes 60 s; five `patch::` tests; D92: apt's lock option covers the update | `fakepkg` is real apt against a repository on the machine's disk, its package's install slowed, failed or asking for a reboot by files in `/srv/ctl`. D92 was wrong about `apt-get update`, which doesn't wait for the lists' lock: the update step is a fixed line that tries again while that lock is held, for 10 minutes, and ends at any other result. The lock test shortens the 10 minutes to 12 s, as the plan says. `patch::no_patch_or_silence_alert_during_maintenance_window` moves to T59e with the silence rules it needs | Real apt behaves differently from what D92 assumed | plan | - |
| D99 | 2026-11-22 | T59e | `it::patch::no_patch_or_silence_alert_during_maintenance_window`; maintenance asked when a window selects its machines | The test is a fast one (`hub_cmd::patching::`, the hub's own driver, Actions, Incidents and windows with a stand-in for SSH, the machine outside a maintenance window as the control): AC20 is a unit criterion in the design and a container adds nothing. A machine whose maintenance window starts while it waits its turn was still patched; it now waits as an offline one does (15 minutes, within the window). Incidents asks through a trait (`Quiet`), so it still reaches Actions only by `StartJob`. A silence already open is neither raised, worsened nor resolved by a maintenance window; its repeated callouts go on. The reboot wait is kept in memory, from the job's start, and a `rollback` step counts as a reboot | Found by the test; gaps in 7.6.3 | plan | - |
| D100 | 2026-11-22 | T59 | Integration tests copy the binaries cargo builds into their containers | They copy them stripped, as a release ships them (`support::container_binary`): with symbols they filled the disk's write queue and stalled every container for minutes. No test changed. Measured on one pair of runs of 33 tests; the full tier, with the disk sampled, has to agree before it counts as the cause of the boots that took over 60 s. The clock faults were real, and stay recorded, but a sound clock didn't end those failures | Measured | plan | - |
| D101 | 2026-11-22 | T43, T59 | `disk_rule_callouts_and_resolution`: no critical before 4 minutes, no warning before 4 minutes | On a machine with no history the design's 80% rule (7.6.1; unit test: 16 of 20 samples) matches at the 16th sample, 225 s after the first: the bound is 220 s. The warning, with history, needs the whole 5 minutes: its bound goes from 240 s to 285 s. The rule itself is unchanged; that "for 5 min" can fire after 3 min 45 s on a machine that just began to report was confirmed by the owner (2026-11-22) | Found by the full tier | plan | - |
| D102 | 2026-11-22 | T60 | One step | Split: T60a the two runbooks, hypervisors in the windows, and a hypervisor (by role or kind) never rebooted by its policy's `auto_reboot` (E13); T60b the reboot's approval listing the guests, and one reboot per cluster and window; T60c the reboot 60 s out and the resume at verify, for the hub's host and the hypervisor it runs on, with as much of T65's start-up resume as that needs. The role `hub` stays out of the windows until T60c: rebooting it at once would end the job. Until T60b a hypervisor that needs a reboot only says so in the job log | Size, and nothing unsafe in between | plan | - |
| D103 | 2026-11-22 | T60b | `patch-proxmox-host` asks for the approval; tests `hypervisor::`; the upgrade command's test among them | The window driver asks after a patch whose reboot step left one wanted, for a built-in runbook of its own, `reboot-host` (high risk, not in 7.8.7's list): a patch approval and a reboot approval on one machine would otherwise bind the same call. Only a `reboot-host` job with an approved high-risk approval may reboot a hypervisor. The guest list is in the approval's reason, read when it is asked. A hypervisor's reboot is found by its kernels too (the newest installed isn't running, none pinned), as Proxmox sets no flag. Cluster membership is the API's node list. A host whose guests can't be listed isn't asked about; one try per window; the reboot runs in an open window when nothing else at its site runs or waits. The tests are in `driver::` (`hypervisor_*`) and `builtin::` | The runs need the driver's state | plan | - |
| D104 | 2026-11-22 | T60c | The reboot marks `resumable_step = verify`; T65 owns start-up resume; `it::hubhost::` in a container that is restarted | `actions/recovery.rs` takes up only jobs with a `resumable_step` (T65 adds detached steps and interrupts the rest). A resumed job first waits for the machine's restart, as it was waiting, then goes on at the verify step. A reboot is scheduled when the machine has role `hub`, or is a hypervisor the hub's confirmed binding names (its machine, or its node's name); should the hub turn out to survive it, the job simply goes on. `REBOOT_IN_60S` joins the command list of every runbook with a reboot step. The hub host's reboot is asked for like a hypervisor's (`reboot-host`) unless its policy has `auto_reboot`. A new write command, `ResumeJobAt`. The integration test stands a new Actions on the same database for the restarted hub | Size; the wait is what makes verify meaningful | plan | - |
| D105 | 2026-11-22 | T61 | One step; `compose-restart` as in 7.8.7's example; `reboot` | Split: T61a the five runbooks that need no key or list (`reboot`, `snapshot`, `service-restart`, `compose-restart`, `compose-update`); T61b `ApplyKeys`; T61c `sudoers-refresh`, `keys-rotate`, `unenroll` and the integration tests. The Compose and service runbooks wait for a report from after the restart before they judge (the example would pass on an old one), and have no triggers: an incident starts a runbook without parameters. `reboot` needs a reboot step that doesn't ask whether the machine wants it: a new step field `always`, for reboot steps only; a hypervisor refuses it (`hypervisor_needs_reboot_host`, E13). `service-restart` is for systemd; `compose-update` takes the Compose file's path | Size; a fresh report is what makes the check mean something | plan | - |
| D106 | 2026-11-22 | T61b | `ApplyKeys` rewrites `from=` and the key lines; tests first | The payload's body is `{from: [ip], keys: {user: [ssh-ed25519 key]}}`, and the helper builds the lines with the join's restrictions, so no option can be smuggled in; comments stay, every other line goes. No link in the users' `.ssh` is followed; the file is renamed into place. The last version is in `/var/lib/rackhand-helper/keys.version`; one that can't be read refuses everything. The helper's unit may write the two users' `.ssh` (`ReadWritePaths`), which `ProtectHome=read-only` had ruled out; under systemd it is tested in T61c. The probe's relay of `KeysUpdate` is T61c's | The tests were written with the code; shown by breaking each rule | plan | - |
| D107 | 2026-11-22 | T61c | `sudoers-refresh` is an `ssh` step; the hub signs and sends | Owner agreed (2026-11-22) to a new step kind, `hub`: work the hub does itself, named by `call` from a fixed list (`send_commands`, `rotate_keys`, `revoke`), with no command. `sudoers-refresh` is one `hub` step: the hub signs the command list of every enabled runbook with its node key, versioned by the time in ms as a join's list is, valid 10 minutes, and sends it through the machine's `run install-commands` over SSH (new: SSH with standard input). A hub step needs an account on the machine, except `revoke` (`Step::needs_account` is the one definition for Actions, routing and MCP). The list is the machine's whole list: what the hub no longer enables is gone from it | A signed list can't ride an `ssh` step's argument array | plan | - |
| D108 | 2026-11-22 | T61c | `keys-rotate` and `unenroll` through the helper and the mesh | Keys are delivered through the command wrapper over SSH (`run install-keys`, the same checks as the helper's `ApplyKeys`, which it shares code with), because rotating and unenrolling work while SSH does; the probe's relay of `KeysUpdate` to the helper stays for T87, where an address change leaves SSH unable to reach the machine. A rotation gives the machine a key of its own for the automation user (Vault `ssh.automation.machine.<id>`), made as a pending one first, so one machine's rotation touches no other and a stopped one is taken up again with the same key. Order: both keys installed, the new one logged in with, kept, the old one dropped, found refused. The assistant's key isn't rotated yet. `unenroll` is an `ssh` step that schedules `rackhand-probe uninstall --after 5` and a `hub` step `revoke` that waits for the machine to refuse the hub's key before revoking it; `rackhand-probe uninstall` (root only) is new and removes only the paths in a table | Size; the design names the helper but not what carries the update on a working connection | plan | - |
| D109 | 2026-11-22 | T61 | `it::builtins::compose_restart_restarts_project` in a Docker-in-Docker test machine | Moved to L4's live pass on the lab's `target`, which has real Docker and Compose. The runbooks' parameters, command-list entries, fresh-report wait and the verify step are tested here | A nested Docker daemon is heavy and tells less than the real one | plan | - |
| D110 | 2026-11-23 | T62 | `policy/monitor.rs`, `install.sh --change-level`, and the level tests as named | The monitor rules were already in `decide()` (T54, T55), so the plan's `policy/monitor.rs` isn't added and the approval rule is pinned by a test across every requester and level; `actions/hypervisor_guard.rs` holds the one list of hypervisor-side actions and the refusals (`Hypervisor::guest_call` uses it, and T72's firewall and T64's power use it too). The installer takes no `--change-level` flag: the dashboard's command is the installer with a token bound to the machine and the level, and `--monitor` for monitor; a machine that joins at monitor loses the hub's accounts, one that joins at managed gets them, and the services restart instead of only starting. `guard::` tests are in `executor/tests.rs` and `policy/tests/decide.rs`; the level tests are `install_it::level::*` | Smaller; the existing code did the work | plan | - |
| D111 | 2026-11-23 | T62 | where "no call from the hub alone changes the level" is enforced and tested | In the store's writer: a write that changes `machines.access` is refused unless the same command uses up a join token (`level_guard`), so no route, tool or system can do it by writing the registry; tested in the store (`level::*`) and on the dashboard (the machine page issues a command and changes nothing, `web::tests::level`). `it::level::hub_cannot_change_level_alone` is these two, since a running hub's writer can't be driven from outside | One place that every writer passes | plan | - |
| D112 | 2026-11-23 | T62 | a machine's level command on the dashboard | Machine page, admin only, no step-up: `POST /machines/{{id}}/level` issues a 60-minute one-time command bound to the machine and the new level and changes nothing itself (an enrolled machine with a probe; the same level or a pending machine is refused); the design names the command but not the route or its risk | Size; issuing the command gives nobody access, running it needs root on the machine | plan | - |
| D113 | 2026-11-23 | T64 | how a guest is enrolled, and where the code is | The design says a guest is enrolled with a fresh token and bound by the runbook, and not how the installer gets inside it. The Proxmox API can run nothing in a guest and can't write a cloud-init snippet, so the hypervisor's own wrapper does it: a new `run install-guest` takes a request signed with the node key (kind `guest`, valid at most 10 minutes, newer than the last, refused on a monitor machine) and builds the installer's line itself from a fixed shape: a VM gets user data in `/var/lib/vz/snippets/rackhand-<vmid>.yml` (the runbook then sets `cicustom` and the agent through `config_set`), a container has the installer run inside it with `pct exec`. The guest's host keys then come with its own join, as for any machine. Five `hub` calls carry it (`provision_machine`, `send_guest`, `bind_guest`, `await_machine`; the runbooks' `api` steps do the rest), `call` is now a name and `key=value` words, and the `api` step passes them to the driver and uses the machine's own credentials from the Vault. The token is bound to the machine, not the job, and a hub that holds a release serves the installer itself. Files differ from the plan's (`actions/provision.rs`, `runcmd/guest.rs`, the driver's `create_lxc` and `config_set`) | A guest can't be reached any other way without trusting an unpinned SSH host key | plan | - |
| D114 | 2026-11-23 | T64 | the guest's template and storage | `provision-vm` clones a VM template by id onto a named storage and `provision-lxc` creates an unprivileged container (512 MB, 1 core, 8 GB, DHCP on `vmbr0`) from a `storage:vztmpl/file` template; the VM's snippet storage is `local`. Sizes and the bridge are the driver's defaults until a runbook sets them | The design names neither | plan | - |
| D115 | 2026-11-23 | T65 | what the plan's tests name, and a running job without a way to go on | `StepRunner::adopt` is new: a restarted hub polls a detached step on its machine without starting it again (the Executor's poll loop, split out); a runner that can't says `adopt_unavailable` and the job is interrupted. Every running job with no resumable step and no running detached step ends `interrupted` with the reason `hub_restarted` (T55's test said such a job is not touched; it is changed), and a `job.interrupted` warning event on its machine opens the incident, so the incident doesn't depend on a bus message sent before anything listens. `Incidents::evaluate` does nothing until `Ingest::start` has rebuilt the window. The `it::recovery` tests stop a hub by shutting down the runtime its jobs run in and start a new one over the same database, rather than `kill -9` of a process; `it::recovery::no_silence_incident_in_first_3_minutes` is the existing unit test `silence_stays_open_across_a_restart` (the grace) and the live pass L4 | Smaller; the same states are reached | plan | - |
| D116 | 2026-11-23 | T66 | the helper's modules and tests | `hash.rs`, `auth.rs`, `procscan.rs`, `sockets.rs` (with `ContainerOf`) are in `helper/`; the daemon hashes at start, every 5 minutes and, with inotify on the directories of the list, a moment after a change (a new directory such as a new home is watched from the next hashing); `AuthEventsSince` reads `auth.log` or `secure` when there is one and the journal otherwise, with journald's own cursor and the programs picked out in Rust because `journalctl` skips the first entry after a cursor when a match is given; the unit tests are in the modules and the integration tests in `tests/it/src/helper_scan.rs` (the SSH login is a `logger -t sshd` line, since the image has no sshd, and the container mapping uses a systemd unit named like a container and a fake engine socket) | Smaller than the plan's file list and tests; the same behavior | plan | - | |
| D117 | 2026-11-23 | T67 | how the sampling runs and what the hub does with a report's connections | The probe's reads run on their own task every 5 seconds and a report takes what they have seen (`Pending`), so a report never waits on the helper (a first version held a lock across the helper's answers and slowed reports); `rackhand-probe security` is new, a diagnostic that runs the capture for a few seconds and prints what it saw (7.7.3) and is what the integration tests use; `Hello.capabilities` is now set (sampling, helper, containers); the carried-in storage of a report's `connections` is T70's, which stores them | Small additions the tests need; the storage is built in T70 | plan | - | |
| D118 | 2026-11-23 | T69 | files and names | `intel/{parse.rs, fetch.rs, mod.rs}` instead of one file per list; the sources' toggles were already `Sources` in the hub's config, which gains `airgapped` and the four sources that are off unless enabled (`maxmind`, `reputation`, `relay_lists`, `n0_relays`; nothing downloads them yet); the Settings page gains the air-gapped box only; the Security page's use of the attribution and freshness is T73's; the hub downloads over `http::request_up_to` (a cap per source), follows at most three redirects to https only, keeps the last good download of each list in the data directory, and checks what is due every hour; `flate2` (pure Rust) is a new dependency for DB-IP's gzip | Smaller; the same behavior | plan | - | |
| D119 | 2026-11-23 | T70 | what a record's server process is, and what is stored | A record has the user and the container, not the process's terminal and parents, so a server process is one in a container or run by `root`; a destination not scored (private, or Rackhand's own process) isn't stored either, and a folded record is a summary row; modes other than `full` run only the threat check (no learning, no new-destination events), a machine with no policy and the role `desktop` is `summary`; large egress needs bytes, which only eBPF gives (T68), so sampling never raises it; the `PutConnRecords` and `PutConnBaseline` handlers add to a row that is there; the integration tests give the machine a policy that watches private addresses because the destination is the bridge's gateway | Smaller than the design's process test; the data isn't there yet | plan | - | |
| D120 | 2026-11-23 | T71 | how the exemptions know what they need | The hub can't run `dpkg -S`, so a file under the system's binary directories counts as a package's while a patch job runs (recorded at info with the job id); a command list is exempt while a `sudoers-refresh` job runs or the machine enrolls, not by the hash of what the hub sent (the facts are behind a trait the tests fill in, and the hash form is tested); `probe.toml` is exempt while the machine is pending or its join token was used in the last 10 minutes. The helper's authentication events carry a `detail` (the uid of a new user, the group a user was added to) and the process scan the parent's executable, so `user.added` and `group.changed` and the `memfd` rule have what they need; a login's history comes from the stored `auth.login` events, and a machine's first login only teaches it | The hub has no package database; the data wasn't in the events | plan | - | |
| D121 | 2026-11-23 | T72 | where the pieces live | The state machine, the rules and the state writes are `policy/quarantine.rs`; what a job does to the state, and the block on a quarantined machine, `actions/quarantining.rs` (it is in Actions, so Incidents, the dashboard, the Scheduler and assistant jobs are all stopped, not only MCP); the proposals and the automatic start `incidents/quarantine_routing.rs`, judged in routing before it looks for a runbook of its own (Incidents reach Actions only through `StartJob`); the three `hub` calls `quarantine_isolate`, `quarantine_snapshot` and `quarantine_release` in `executor/quarantine.rs`, with the isolate step's output as the record release needs; the probe's `run quarantine on|off` is a built-in of the wrapper like `install-guest` (it takes only ip:port words, so it needs no entry in the list); the Proxmox guard's `firewall_set` became `firewall_isolate` and `firewall_release`; the MCP gate and patch selection count `applying`, `active`, `releasing` and `failed` as quarantined, not `pending` | One owner for each rule; the dependency rules hold | plan | - |
| D122 | 2026-11-23 | T72 | connection flush on the hypervisor (D112) | A new built-in runbook `conntrack-flush` (hypervisors, high risk, one address parameter that is an address and nothing else) puts the two `conntrack -D` commands in every hypervisor's command list; a quarantine of a Proxmox guest runs them itself over SSH as the hub for each of the guest's addresses, which the quarantine's own approval covers, and takes an exit status of 1 (nothing matched) as done; a hypervisor that isn't managed, or can't be reached, leaves the quarantine standing with `conntrack_not_flushed` and the reason in the record; the guest's address is the one on its machine row | D112 asks for it; the API can't | plan | - |
| D123 | 2026-11-23 | T72 | the in-guest table | Both directions of every allowed path are named (no connection tracking), so a connection that was open before the quarantine and isn't one of those is cut at once; loopback is allowed; conntrack is flushed when its tool is there; the table's hook priority is -300 so nothing earlier changes the verdict; Windows machines have no in-guest quarantine until T90 (`in_guest_quarantine_unsupported`) | A table that needs conntrack would let open sessions through | plan | - |
| D124 | 2026-11-23 | T72 | a failed or repeated isolation | A write that fails while isolating a guest puts the saved configuration back (and says whether that worked), so a retry never takes a half-isolated one for the original; a retry after a failure takes up the record of the oldest isolation since the last release; a quarantine job that was running when the hub restarted is `failed` with a critical event | Otherwise release would restore the wrong thing | plan | - |
| D125 | 2026-11-23 | T72 | proposals | Only security findings (kinds from the probe and the hub's scans) at `critical`, or at any severity when an enabled rule names the kind, are judged for quarantine; a machine whose policy is missing is `approval`; `pending` ends when its approval is rejected, or when no approval is left to decide (checked every 30 seconds, so up to that long after it expired); a machine already quarantined or pending gets only the incident; a rule that matches a monitor machine asks for an approval, as AC58 says | Not every incident is a security finding | plan | - |
| D126 | 2026-11-23 | T72 | what isn't done | A VM's forensic snapshot is taken without its RAM (the design says with RAM when the storage supports it) and a Windows machine's in-guest quarantine waits for T90; the lab passes (L5, MV11) are with the other live passes at the end | Smaller; the lab is last | plan | - |
| D127 | 2026-11-23 | T73 | page files and what they show | One page file, `web/pages/security.rs` (with `templates/security.html`), instead of three: the machine page's Connections and Quarantine are in `monitoring.rs` and its template, since that page is built there; a new Security entry (shortcut `e`) in the sidebar; `Web::with_intel` gives the page the lists' freshness; the rules are edited in a dialog like policies are, with the rule's id made from its name; the record of how a quarantine was done moved from the hub's composition into `policy::quarantine::record` so the page and the executor read the same thing; badges for the connection verdicts; the machine page lists the last day's connections, at most 200 rows | One page and one dialog pattern fit the existing ones | plan | - |
| D128 | 2026-11-23 | T77 | how the token stays out of the runner | The runner starts `rackhand operator mcp-bridge --hub <id> --job <job> --dir <dir>` and that process holds no token: it passes lines to a socket the operator serves for the job (0600, in a 0700 directory), and the operator's broker opens the hub's MCP stream, sends the `{"auth": <token>}` line and forwards each request and its answer, answering a tool call `hub_unreachable` while the hub can't be reached. Jobs on one operator share a user, so one job's runner could in principle connect to another's socket; the operator is one trust domain | The design says the token stays inside the bridge process; the runner starts that process itself, so the token would otherwise be in its reach | plan | - |
| D129 | 2026-11-23 | T77 | files and what was added | `rackhand-operator` has `state`, `join`, `runner`, `claude_code`, `fake`, `bridge` and `run`; `rackhand operator join|run|mcp-bridge` is `operator_cmd.rs` in the composition root; the scripted runner is `--runner fake:<script.json>` in lab builds only; `Ticket` moved from the probe to `rackhand-net` (the probe re-exports it) so the operator reads tickets the same way; the hub's composition now serves `rackhand/operator/1` (Assist) beside MCP, which it had not before; `Assist::connected_operators`; `tests/it` gets `binary_with` for a host binary with features | The operator needed them | plan | - |
| D130 | 2026-11-23 | T77 | what is left for the steps after | The Claude Code runner's prompt is the brief as the last argument, as in the spike, and a real run is the live pass L6; `it::operator::patch_failure_offer_within_60s` needs the routing to playbooks, so it is written with T78; the operator unit file and the invite page are T79's; `operator run` takes `--max-jobs` (2 by default), and the operator's own account setup (the `rackhand-operator` user and its runner directory) is the installer's work in T91 | The routing, the pages and the installer are later steps | plan | - |
| D131 | 2026-11-23 | T78 | playbook precedence | A playbook has no targets of its own in 7.8.8 (only `incident_kinds`), so "the same precedence" as runbooks comes down to the kind, with ties to the name that sorts first; the seven built-in playbooks are in `builtin/playbooks/*.md` and are seeded into the Library at start like the runbooks (`Library::seed_playbooks`), where an admin's edit is kept | There is nothing more specific to match on | plan | - |
| D132 | 2026-11-23 | T78 | how routing and Assist meet | Incidents never depends on Assist: routing asks through a trait (`AssistStarter`) and the composition gives it Assist; an incident no runbook takes, a runbook that failed, and a condition that persisted after a runbook all try a playbook before a person; the "attempt limit reached" count is the incident's `assistant.started` events in 24 hours; a finding that proposes a quarantine goes on to its playbook while the approval waits; an assistant job's end is read from its job row (`outcome`) and decides the incident: `resolved` closes an event incident only at level 2 or 3 for a warning, waits for the condition otherwise (10 minutes), and every other end is a person with a `human` event whose callout the notifier sends; the sweep that ends a silent assistant job (5 minutes after its token's deadline) is `Actions::sweep_assistant_jobs`, run every minute by Assist | One owner for each rule | plan | - |
| D133 | 2026-11-23 | T78 | what an incident's brief reads | The brief is made from the incident row and its events, the machine's latest report, four vitals of the last hour (CPU, memory, disk, load), and the failed steps of the incident's own job or the machine's failed jobs of the last day (output cut at 4 KB); "event incident" means a security or system event kind, not a rule or condition; `finish_job`'s outcome `unresolved` and `handed_over` both end as a person's | The brief's sources, kept to what the hub holds | plan | - |
| D134 | 2026-11-23 | T79 | page files and where things are | One page file, `web/pages/assistant.rs`, with `templates/keys.html` and `templates/assistant_settings.html`, instead of four; the transcript and Resume job are on the incident page (`monitoring.rs` and `incident.html`); the keys are at `/account/keys` (sidebar entry `MCP keys`, a person's own) and the operators, the invite, the daily cap and the AI provider notice at `/settings/assistant` (sidebar entry `Assistant`, admins); `Web::with_assist`; the cap is a new `assistant.daily_cap` in `config/hub.toml` that Assist reads at each job (so a change takes effect at once); Resume job is POST `/incidents/{id}/resume` for roles that can operate | One file and the existing pattern fit the pages built so far | plan | - |
| D135 | 2026-11-23 | T80 | the wire and the files | The peer streams carry one byte first that says what they are (hello, summary, query, request, unlink; the design's messages have no envelope), then length-prefixed frames as the other protocols do; the files are `peers/{mod, wire, summary, queries, requests, unlink, link}.rs`; `PeerLink` is the asking side, over a connection the caller made, for the dashboard, the watch and the tests; a peer's request is kept by `requested_by = peer:<site>:<request id>` on its approval and its job, which is what makes a retry take up the same one and what the approval is bound to; the `PutPeerSummary` handler is an upsert by peer id; the hub's composition now serves `rackhand/peer/1`, follows the approvals people decide to start the jobs peers asked for, and every peer stream reads the peer's row again, so an admin's change of what it may ask, or its removal, takes effect at once | The design leaves the framing open | plan | - |
| D136 | 2026-11-23 | T80 | what waits for later steps | The push of the summary every 30 seconds needs the peer's addresses and relays, which come with the watch (T81) and the connection steps (T83); `it::peers::responder_on_a_requests_compose_restart_on_b` needs peers linked through the dashboard (T88), so it is written there; until then the contract tests cover the same behaviors with a real hub on one side | The link-making pages and the dialing are later steps | plan | - |
| D137 | 2026-11-23 | T81 | the net test | `net_tests::peer_watch::three_hubs_one_cut_exactly_one_callout` needs the network tier (three hubs in network namespaces, a fake webhook) and moves to the end with the other network passes (T83 builds the path between sites); until then the election, the watch's states and the incidents are tested in this process with the summaries a peer would have sent | The network tier isn't run yet | plan | - |
| D138 | 2026-11-23 | T81 | where the watch lives | The watch is `peers/watch.rs` (every 30 seconds with the dead-man URL), the election `peers/election.rs`, the dead-man `peers/deadman.rs`, and the incidents `incidents/peer.rs`, since only Incidents opens them; a peer never heard from counts from when it was linked; a hub that isn't elected writes `peer.down_seen` to the audit log instead of an incident (the incident is the callout, and a second hub's would be a second callout); a hub's own health for the election is its notifiers and self-check; the dead-man URL is `deadman_url` in `config/hub.toml`, set on the Settings page, and the hub's composition runs the watch | One owner for each part; the callout is the incident | plan | - |
| D139 | 2026-11-23 | T82 | the net tests | `net_tests::relay::{private_refuses_unkeyed_admits_keyed, priority_admission_at_capacity, refused_client_sees_reason}` run in the fast tier instead, on loopback against the real relay (`crates/rackhand-relay/tests/relay.rs`), which needs no network namespace; `net_tests::relay::public_unkeyed_limited_to_1_mbit` (measured throughput within 10% of 1 Mbit/s) waits for the network tier, since a rate measured on a busy fast-tier machine would be flaky (S2 measured 119 KB/s at 125 000 B/s), and the fast tier tests the rate value instead | A rate is measured where nothing else runs; admission and eviction need no network | plan | - |
| D140 | 2026-11-23 | T82 | where the code lives | The library is `rackhand-relay` (`keys.rs`, `admission.rs`, and `run.rs`, which holds the limits and the ACME and certificate-file setup), not `main.rs`, `limits.rs` and `acme.rs`; the commands are `rackhand relay run` and `rackhand relay key create` in the composition root (`crates/rackhand/src/relay_cmd.rs`), as 7.2 puts every binary's entry point there; `--cert` and `--key` and a plain-HTTP mode (no certificate, for a relay behind something that ends TLS) are options the design doesn't list; a key's `--expires` date lasts through that day in UTC; the unit file is `packaging/systemd/rackhand-relay.service` | One entry point; the extra options are what a relay on a private network needs | plan | - |
| D141 | 2026-11-23 | T82 | ACME | The Let's Encrypt path is built from iroh-relay's `AcmeConfig` (domains, contact, a cache in the data directory, staging with `--acme-staging`) and is not exercised here, since it needs a public name and the certificate authority; it is for the live pass on the lab relay (L7), and a certificate from files is the tested path | No public name in the fast tier | plan | - |
| D142 | 2026-11-23 | T82 | relay lists are not wired in yet | `peers/relay_lists.rs` fetches, parses (at most 100 valid entries, invalid ones skipped, the status for the dashboard) and orders; `RelayConfig::listed` in `rackhand-net` puts listed relays after the operator's own without the key; the setting that holds the list URLs, the daily fetch task and the status on the Peers and relays page come with T88, and the endpoint taking the listed relays with T83, which builds the paths between sites | Nothing shows or uses them until those steps | plan | - |
| D143 | 2026-11-23 | T83 | the hubs in the net tests | The two hubs in `holepunch` are bare iroh endpoints with the relay and ports a hub would use, and a request and answer on a stream, not full hubs: the peer protocol (summaries every 30 seconds, vitals queries, requests) is tested over any connection in `peer_contract`, and what the NATs decide is which path that connection takes, which is what these tests measure; `peer_watch::three_hubs_one_cut_exactly_one_callout` (D137) still needs three real hubs in namespaces and stays for the end-of-run network pass | The protocol and the path are independent; three hubs is a larger harness | plan | - |
| D144 | 2026-11-23 | T83 | tests and code | `net_tests::relay::public_unkeyed_limited_to_1_mbit` (waiting since D139) is `holepunch::public_unkeyed_limited_to_1_mbit`, since it needs the same topology; `cargo xtask ci net` has no test filter, so the plan's `-- -E 'test(holepunch::)'` is the whole tier; `rackhand-net` gains `paths` (`kind`, `wait_direct`, from S3) and, for tests only, `bind_trusting_relays` (the net tier's relay has a certificate it made itself); the dashboard's path text is `peers/path_status.rs`, shown by T88's page through `PeerLink::path` | One topology; the page comes with T88 | plan | - |
| D145 | 2026-11-23 | T84 | the net tests | `net_tests::tunnel::ssh_through_connect_as_proxycommand` moves to T86, which writes `rackhand-cli`, and the network tier's VM then also needs an SSH client and server; `net_tests::tunnel::runbook_on_remote_mode_machine_through_tunnel` is the integration test `executor_it::runbook_on_remote_mode_machine_through_the_probes_tunnel`, because the VM has no SSH server and the integration tier has one: the probe runs in the test process, so the machine sees the hub's SSH from the test host rather than from `127.0.0.1`, and what `from=` allows on a remote-mode machine stays with the existing `authorized_keys_line` test and the live pass | A real SSH server is in the integration tier; the CLI isn't written yet | plan | - |
| D146 | 2026-11-23 | T84 | where the code lives | The tunnel server is `peers/tunnel.rs` (with `Network`, which makes the connections, and `Forwards`, the hub's own way to a remote-mode machine's SSH, which the Executor takes through a `RemoteReach` it defines, `Executor::with_remote`), the splice is `rackhand-probe/src/remote.rs`, the step is `executor/tunnel_step.rs`; the hub opens a new connection to the probe for each tunnel and a loopback listener for each remote-mode machine stays until the hub stops | One owner for each part; no pooling until it shows | plan | - |
| D147 | 2026-11-23 | T84 | relays in hub.toml | `hub.toml` gains `relays`, the hub's own relays in order (7.3.10): the hub's endpoint uses them, a join hands them to the machine so that it can reach the hub through them, and the hub reaches a remote-mode probe through them (the probe is dialed by endpoint id, which needs a relay unless an address is known); T88 adds relay lists to the page | Without one a hub can't dial a probe behind a NAT | plan | - |
| D148 | 2026-11-23 | T84 | the `tunnel` step | The step opens a tunnel to `port` on the job's machine, which the machine's policy must allow, and closes it again: it checks the path, and what the runbook does with it is a later step's own command; the design doesn't say more | The pbs-sync and restic-backup runbooks (T96) decide what else it needs | plan | - |
| D149 | 2026-11-23 | T85 | the net tests and their names | `net_tests::xfer::zfs_style_stream_pipes_between_hubs` is the integration tests above, since the network tier's VM has no SSH server: a fake `zfs` behind the real wrapper over real SSH, to another machine of the hub and from a peer; `xfer_contract::bulk_waits_for_direct_and_raises_info_after_10_min` is `rackhand-net`'s `xfer::tests::` (it needs no hub); the peer-backup tests are the test file `peer_backup`, not a `peer_backup::` filter; `cargo xtask ci net` has no test filter | A real SSH server is in the integration tier | plan | - |
| D150 | 2026-11-23 | T85 | the protocol | `tunnel.proto` gains `XferAnswer` (a `resume` with the next chunk wanted, or a `done`), the receiver's answer to the offer and to each chunk, which the contract didn't have; each chunk waits for its answer (one in flight), which also resends a refused chunk; a stream ends with an empty chunk; the client is `rackhand_net::xfer` (`send_file`, `send_stream`, `wait_for_direct`), which `rackhand-cli send` will call in T86, so `crates/rackhand-cli/src/send.rs` is not written here | The sender must learn where to go on and which chunk to send again | plan | - |
| D151 | 2026-11-23 | T85 | backup runbooks | `zfs-replicate` is one `transfer` step (`cmd = zfs-send <snapshot>`, `dest = <site>/<machine>:zfs-recv <dataset>`) piping through this hub for a machine of its site, or over `rackhand/xfer/1` to a peer (the machine's id from the peer's summary, a direct path unless `allow_relay`, a new step field); the peer takes a stream only where the machine's policy has `peer_requests = "auto"`, since it is an action a peer asks for (7.5.5); `pbs-sync` and `restic-backup` run their tool through the wrapper, detached, with no `tunnel` step, because the tool's own connection to a remote server can't be brokered by the hub without a forwarder on the machine (the design's `tunnel` step for them); the `transfer` step takes streams only, files go with `send` | The design leaves the step's shape open | plan | - |
| D152 | 2026-11-23 | T85 | peer backups | the hub sends its newest backup to each linked peer after the nightly backup, over a direct path only (the peer is dialed by endpoint id through `relays`), and a peer that gave no space refuses the offer before a byte goes; the waiting notice `bulk_waiting_direct_path` is a hub-level audit entry, not a machine event; `rackhand hub peer-backup export <site> <file>` copies the kept file | The notice has no machine to belong to | plan | - |
| D153 | 2026-11-23 | T85 | resuming a machine's file | the wrapper's `receive` only appends, so a partial file the hub can't vouch for is continued and checked at the end: one that doesn't match fails with `starts over` and the next attempt starts again from nothing; a partial file that ends inside a chunk is continued from its own size; a destination already complete is sent again in full | The wrapper is unchanged | plan | - |
| D154 | 2026-11-23 | T86 | the Windows build | `cargo build -p rackhand-cli --target x86_64-pc-windows-gnu` does not link yet: iroh-relay, a dependency of iroh, declares a `cdylib` crate type besides `lib`, which cargo builds for the dependency too, and its exports pass a Windows DLL's 65 535 (`export ordinal too large`); an optimization level for that package didn't help; the fix is a patched iroh-relay without the `cdylib` (or a newer release), which T89 owns with the rest of the Windows build (D-earlier), so the check moves there; `rackhand-net`'s key file is made portable here (no Unix mode on Windows, `getrandom` instead of `/dev/urandom`) | A patched dependency belongs with the Windows tier | plan | - |
| D155 | 2026-11-23 | T86 | where the code lives and what is new | the commands are `rackhand-cli`'s `commands.rs` and `login.rs` over `config.rs` and `net.rs`, not one file each; `connect`, `forward` and `send` name a machine by its name (`<site>/<machine>`, the site only finds the hub), so the hub resolves a name in a tunnel's or transfer's `target` (16 bytes stay an id), which is a contract addition (owner to confirm); the personal MCP key comes from `--key-file` or `RACKHAND_MCP_KEY`, since `login` doesn't make one; `status` says whether the hub takes this device by connecting and watching for a close code | The CLI has the names and not the ids | plan | - |
| D156 | 2026-11-23 | T87 | the integration tests | `it::address::hub_address_change_config_and_keys_update` is `address_change::hub_address_change_config_and_keys_update` in the hub's contract tests, using the probe's real link and helper code over real endpoints, with the helper's files in a temporary directory: SSH from the new address into a container is not tested there, and moves to the live pass with a hub that really moves; `it::address::set_hub_requires_root_and_rewrites_probe_toml` is a unit test with the caller's root status given, since the command only passes `geteuid` to the same function | The containers add nothing to what the contract shows; a moved hub needs the lab | plan | - |
| D157 | 2026-11-23 | T87 | contract and rules | `ProbeConfig` gains `hub_addrs` and `hub_relays` (the hub's addresses now, in every Welcome and in a `ConfigUpdate` when they change), which a probe keeps in `hub-addrs.json` next to its buffer and prefers to `probe.toml`'s addresses at its next start, never changing the pinned hub id; a hub checks its addresses every 30 seconds and tells every connected probe when they changed, and managed machines get new key lines (7.3.3, 7.3.7); a session counts as the machine's own if it reported within 20 seconds, so a hard reboot is not a clone but two machines reporting are; the hub forgets a conflict when it restarts and finds it again if both are still reporting | The design leaves where the addresses travel and how a reboot differs from a clone open | plan | - |
| D158 | 2026-11-23 | T88 | the step's scope | T88 is also the step that makes links: `peers/links.rs` (the join one hub makes with the other's invite, the live connection each keeps, dialing a peer by endpoint id with the addresses and relays it was given, and the summary every 30 seconds) and `peers/reach.rs` (`PeerReach`, what the dashboard asks of the peers system, with a fake in the page tests); until now nothing sent a summary or a `PeerJoin`, so a peer linked from the page would have been silent at 2 minutes and down at 10 (D136) | The pages had nothing to show without it | plan | - |
| D159 | 2026-11-23 | T88 | the database | `Db::open` gains forward-only upgrades (design 13, 7.4.1): `SCHEMA_VERSION` is 2, `schema.sql` is the newest shape, a database at version 1 gets `peers.addrs` and `peers.relays` added once, in order, safe to run twice; the inviter now keeps the joiner's relays, and the hub's ticket names its relays (`!url` after the addresses) so an invite works for a hub behind a NAT | Peer addresses have to be kept somewhere a restart finds them, and an earlier hub's database must open | plan | - |
| D160 | 2026-11-23 | T88 | where the code lives | the pages, the site page for a peer and the overview tiles are one file, `web/pages/peers.rs` (not `peers.rs`, `peer_site.rs` and `relays.rs`); a peer's site page is `/sites/<name>` when no local site has the name, so there is one site address; the overview shows a tile per site only once a peer is linked; the request for a peer's machine is one form per machine on its site page, with parameters as `name=value` lines; the page results of a request or a join are the next page or a message, with no flash | One place for what is one subject; the plain forms the other pages use | plan | - |
| D161 | 2026-11-23 | T88 | relay lists | `hub.toml` gains `relay_list_urls`, and the toggle for `sources.relay_lists` is on the Peers and relays page beside the addresses (the Settings sources form doesn't show it); `peers::relay_lists::follow` fetches the lists that are due every 10 minutes' look, never when off or air-gapped, and the hub adds what they list to the running endpoint with `Endpoint::insert_relay` as public relays, skipping its own; that last step is not exercised by a test and is for the live pass | The endpoint is bound before any list is fetched; D142 left this to T88 | plan | - |
| D162 | 2026-11-23 | T88 | the tests | the plan's four are in the module `web::tests::pages::peers`, so `test(pages::peer)` selects all four and `test(pages::relay)` none; `it::peers::responder_on_a_requests_compose_restart_on_b` (D136) is the live test `live::m6::cross_hub_request_needs_owner_approval` in L7, since the request path is tested here and in `peer_contract` with real endpoints and a Compose restart needs two hubs and a container | The containers add nothing to the contract; two hubs are for the lab | plan | - |
| D163 | 2026-11-23 | T89 | dependencies | `iroh` and `iroh-relay` 1.5.0 are patched (`[patch.crates-io]`, in `vendor/`, outside the workspace's members and lints): their manifests ask for a cdylib too, which exports more than the 65535 symbols a Windows DLL can hold, so `x86_64-pc-windows-gnu` couldn't link anything that uses them; only `crate-type` differs, and the tests and examples are left out; `windows-sys` (the connection tables, the pipe's descriptor, the service manager) and `sha1` (the service SID) are added to `rackhand-probe`, and tokio's `process` feature | The Windows build has to link, and the patch is the smallest change that makes it | plan | - |
| D164 | 2026-11-23 | T89 | where the code lives | the parsers are `windows/parse/{conntable,procs,logon,wmi,pipe}.rs` and the tests are the module `windows_parse` (so the plan's filter selects them); the parts that run only on Windows are `windows/{collect,conntable,helper_ops,pipe,ps,service}.rs`, with the process list and the logon events in `helper_ops.rs` (the helper's answers) rather than `procs.rs` and `logon.rs`; the vitals and services come from CIM through one PowerShell line instead of WMI calls, the formatted performance classes giving rates so a collection needs no earlier one; the sockets are the Linux capture's own type, so the sampler, the aggregation and the new-listener events are shared; the `security`, `helper::client` (a named pipe) and `helper::server` modules build on Windows and the Unix-only ones (`keys`, `runcmd`, `enroll`, `uninstall`) don't | One capture and one report path for both systems; PowerShell is what a Windows machine always has | plan | - |
| D165 | 2026-11-23 | T89 | rules | an executable under `%TEMP%` or Downloads is `proc.exec_from_tmp` with a Windows path, and the hub gives a drive-letter path warning and a Linux one critical (7.6.6); a failed Windows logon is `auth.failed` and a successful one `auth.login`; logon events start from when the probe first asks (a first ask has no cursor and sees nothing older); the hub-side Windows helper answers socket owners, the process scan and logon events and not file hashes or container states, and key updates and the install are T90 | The design gives the severities and types and not these edges | plan | - |
| D166 | 2026-11-23 | T89 | tests | nothing here runs a Windows service, the pipe's ACL, the connection tables or PowerShell: they build for the Windows target and are the manual checklist MV16 (services start, the pipe refuses another account, AC56's connections, a process from `%TEMP%` and a new listening port reported), which the owner runs on a Windows machine | The parsing is tested everywhere and the calls only on Windows (D81) | plan | - |
| D167 | 2026-11-23 | T90 | the step's scope | the hub runs a Windows step: a step with `windows_script` is one line for the dispatcher, `<script> <json>` over SSH as the identity the job runs as (`executor/windows.rs`), a `windows_args` value takes a declared parameter whole, and the diagnostics of 7.8.3 run on a Windows machine as `diag-<name>` with the same patterns and bindings (they were refused as unsupported); `rackhand-probe enroll` works on Windows (paths under `C:\ProgramData\Rackhand`, the hub's key files named for the accounts where `sshd_config` looks for them, no command list and no sudoers, facts from `cmd /c ver`), which the installer needs | The plan lists only the scripts, but the installer and the hub's side can't be tried without them | plan | - |
| D168 | 2026-11-23 | T90 | detached Windows steps | `detached = true` on a `windows_script` step works like the Linux wrapper's: the dispatcher's `job-start`, `job-status` and `job-clean` take JSON (`{"job":"<job>/<step>","script":...,"args":{...}}`), run the script as a scheduled task of its own as SYSTEM that writes `out.txt` and `exit.txt` under `C:\ProgramData\Rackhand\jobs\<job>_<step>`, and answer the same status JSON, so the hub's polling, its pickup after a restart (adopt) and its cleaning are the same code with other lines | 7.3.7 says a detached Windows step is a scheduled task through the dispatcher and doesn't give the protocol | plan | - |
| D169 | 2026-11-23 | T90 | scripts and schemas | the Windows form of each diagnostic is `scripts/diag-<name>.ps1` with `schemas/diag-<name>.json` holding the hub's own parameters (type and whole-value pattern), generated from `diagnostics.toml` and kept equal to it by a Rust test; `du_top`'s path keeps its Unix-style pattern, so a drive is its first part (`/c/Users` is `C:\Users`); the patch script takes `phase` (`scan` or `install`) and the quarantine script the hub addresses and the probe's QUIC port, and `quarantine-release` restores the firewall profiles it saved; nineteen diagnostics, `patch-windows`, `quarantine` and `quarantine-release` are the shipped set | The design names the cmdlets and not the files | plan | - |
| D170 | 2026-11-23 | T90 | tests | `ci win` runs twelve Pester tests (the plan's six and six more: the dispatcher's job references, the installer's verifier check and its managed order, the case without an assistant key, and the two diagnostics checks); the scripts that call Windows cmdlets (Get-WinEvent, Get-Service, the Windows Update Agent, the firewall) are not run here: they are the manual checklist MV16 on a Windows machine, with the managed and monitor installs, SSH as both identities, the dispatcher, a `patch-windows` run and a quarantine and release | D81: no Windows runner | plan | - |
| D171 | 2026-11-23 | T90 | what Windows doesn't have yet | the release artifacts the installer downloads (`rackhand-verify` and `rackhand-probe` for `x86_64-pc-windows-gnu` and `rackhand-windows-scripts.zip`, each with its signature) are built and signed by T91; a Windows machine's pending updates and reboot-required flag aren't in its probe reports yet, so `reboot_if_required` has nothing to read and a Windows machine isn't rebooted by the patch job (policy `auto_reboot` is false for Windows by default, D67; a reboot runbook for Windows is not shipped); the hub's own quarantine call for a Windows machine is still the hypervisor's only | These need the release pipeline and the helper's Windows update summary | plan | - |
| D172 | 2026-11-23 | T91 | test names and where they live | `xtask::repro::two_builds_identical_hashes` and `xtask::release::artifacts_are_static` are `release::slow_tests::repro::two_builds_identical_hashes` and `release::slow_tests::artifacts_are_static`, and run in a new tier, `cargo xtask ci release` (the nextest `release` profile, with long limits), because each builds the hub; the `ci` profile leaves them out of the fast tier with a default filter, and the default profile gives them the same long limits when they are run by name; `release::verify_accepts_current_and_standby_keys` and `release::verify_rejects_other_key_and_tampered_file` are T44's tests of the same facts, kept under their own names; the plan's total of 3 and 3 is 12 and 28 | The repro builds are too long for the fast tier | plan | - |
| D173 | 2026-11-23 | T91 | release builds in one directory | `release build` and `repro` build in `/tmp/rackhand-release-target` whatever `CARGO_TARGET_DIR` is, and `repro` removes it between the two builds: OpenSSL, built by a build script for libgit2 and the passkeys, keeps the directory it was installed to in the hub (its modules path), so the hub's bytes depend on the target directory; the probe didn't, the hub did, and the first run of the repro test said so; the signing procedure says not to build elsewhere when the aim is the same hashes | A byte-for-byte rebuild needs a fixed place; the path is a convention, not a secret | plan | - |
| D174 | 2026-11-23 | T91 | targets and the workflow | the `release` workflow builds x86_64 Linux musl and Windows (the targets the runners can build now) and not aarch64 musl, which needs a cross linker and C compiler on the runner that `ci/setup-toolchain.sh` doesn't install; `xtask release build --targets` takes aarch64 where those exist, and `install.sh` has a verifier hash for each architecture (the lab fills the aarch64 one with zeros); macOS CLI builds are not made | No cross toolchain is set up on the runners; this is a maintainer's call | plan | - |
| D175 | 2026-11-23 | T91 | what else T91 adds | `rackhand-verify --manifest <dir>` checks a whole release directory (the signed manifest, then every file, then that nothing else is there), `release build` refuses a Linux binary that isn't static (AC43), renders `install.ps1` and builds `rackhand-windows-scripts.zip` (stored, with fixed times, so its bytes depend on the files only) for T90's installer, and signing is `minisign` by hand as `docs/maintainers/signing.md` says (no signing tool is shipped, so none can end up on a runner); the real public keys are made by the maintainer offline before the first release, and until then a release build pins none | The manifest is only worth having if a person can check a release with it | plan | - |
| D176 | 2026-11-23 | T92 | test names and counts | the plan's `apply::` and `download::` tests are 6 and 6 plus the helper's 5, the guard's 5 and the offers' 4 (27 in `rackhand-probe` under `update::`), `rollout::` is 8 in `actions::rollout` and 9 in `actions::rollout_service`, and `it::update::*` are `update::probe::*` in `tests/it/src/update_it.rs`; the plan's totals (4, 2, 3) don't cover the guard, the offers, the release source or the exemptions | The step is larger than its list: the guard and the hub's release source needed tests of their own | plan | - |
| D177 | 2026-11-23 | T92 | where a release's version comes from | the signature's trusted comment is `file:<name> version:<x.y.z>`, and the helper takes the version from it (`rackhand-release::binary`), not from the request: an older release that was really signed, sent with a newer version in the request, is refused (`version_mismatch`), and one that isn't newer than the installed version is refused (`downgrade`; the same version counts as not newer); `docs/maintainers/signing.md` says to sign with it | The design says the helper refuses a lower version and checks the signature, and the socket's version is the probe user's word | plan | the signing line of `docs/maintainers/signing.md` |
| D178 | 2026-11-23 | T92 | the guard | it takes `<old-slot> <new-slot> <version>` (the version is the one the key signed), and its copy of the old binary is `/var/lib/rackhand-helper/update-guard`, not `/run/rackhand-helper/update-guard` (`/run` can be mounted `noexec`, as it is in the integration containers); it also puts the command wrapper `run` back in step with the slot it switches to, since `sudo` runs that copy; a legacy plain file at `rackhand-probe` becomes slot A when the first update goes in, and `install.sh` now makes slot A and the link | The first run in a container showed the guard couldn't start from `/run`; the wrapper must not stay an older version than the probe | plan | - |
| D179 | 2026-11-23 | T92 | where releases come from and the channels | the hub offers the release in its release directory (`<data dir>/release`, the one it serves at `/release/<file>`): the signed `manifest.json` (checked against the pinned keys), each `rackhand-probe-<arch>-unknown-linux-musl` against the manifest's hash, and its `.minisig`; the manifest has an optional `channel` (`stable` when it isn't there, so a stable manifest is the text it was), `release build --channel beta` writes it, the hub setting `release_channel` (stable or beta) says which a hub offers, and the probe fetches `https://<the hub's first address>:<its web port>/release/<file>`, taking whatever certificate it presents (the signature and hash are what it trusts) and following no redirect; only Linux and Alpine machines whose Hello names an architecture the release has a file for are offered it (none for aarch64, D174), and a Windows probe's helper answers `unsupported` because its guard, a scheduled task, isn't built | The design names channels and a URL in `UpdateAvailable` and no source for either | plan | the Windows self-update, to be built; the manifest's `channel`; the hub setting `release_channel` |
| D180 | 2026-11-23 | T92 | the rollout's rules | one canary per site and release (the lowest machine id that is up and behind), the rest an hour after it was offered the release if the canary runs it and opened no incident since; a canary connected on its old version ten minutes after the offer is held as failed (`rollout.canary_failed`) and one with an incident is held (`rollout.held`), both for that release only, a canary away for six hours is replaced, an offer is repeated every ten minutes while a machine is behind, and the state is `schedule_state` rows (`probe_rollout`, `probe_rollout_rest`, `probe_rollout_held`, and `probe_update_offered` per machine and hash) so a restart goes on where it was | The design says canary first and the rest after an hour without new incidents, and nothing of failure, holds or restarts | plan | - |
| D181 | 2026-11-23 | T92 | what the update does to the events and to the fleet | the hub treats the probe's own files changing to the release it offered (and a first slot appearing while an update is offered) as no event (E48), the probe's own connections through the slots are skipped as its own (`conn_score`), a probe that can't reach the URL reports `update_unreachable` (info) and one whose update the helper refused reports `update_refused` (warning), the probe's Hello now carries its architecture, a `lab-build` of the probe honors `RACKHAND_PROBE_VERSION` at build time (refused in a release build like the test keys) so tests can play a newer release | Without them the update would open an incident on its own canary and hold the rollout, and the hub couldn't pick the file | plan | - |
| D182 | 2026-11-23 | T92 | drift found and fixed on the way | the hub's self-watch read a manifest of the form `{"files": {...}}`, and T91 writes `{"artifacts": [...]}`, so it would have called every release binary changed; it reads T91's now (its test was written for the old form and failed first); `install_it.rs` filled in `__VERIFY_SHA256__` and the installer has had two placeholders since T84, which stopped every installer test in the integration tier; a doc line in `helper/client.rs` had been damaged by an earlier edit | Found while running the integration tests of this step | plan | - |
| D183 | 2026-11-24 | T92 | Windows probe self-update, and the hub's own version | built after all, at the owner's request (2026-11-24), in place of D179's "not built": the slots, the copy and its checks are `rackhand_release::slots`, shared by Linux, Windows and the hub's updater, with an `Activation` for what the services run (a link on Linux; on Windows the binary path of `RackhandHelper` and `RackhandProbe`, set with `sc.exe config`); on Windows the slots are `probe-a.exe` and `probe-b.exe` in `C:\Program Files\Rackhand`, the installer's `rackhand-probe.exe` becomes slot A at the first update, the spool is `C:\ProgramData\Rackhand\probe\update`, opened only when no directory on the way and not the file is a reparse point, and the guard is a copy of the running binary in `C:\ProgramData\Rackhand\helper` run once as SYSTEM by the scheduled task `RackhandUpdateGuard`; the hub offers a Windows machine `rackhand-probe-x86_64-pc-windows-gnu.exe`. What needs the services and the task is the Windows checklist's self-update section (MV16). The apply and guard tests moved from `rackhand-probe` to `rackhand-release` (`slots::`). And probes are offered only the hub's own version (FR-22, 7.5.7), which T92 had left out | The owner asked for the Windows update; the hub's version rule was missed in T92 | owner (Windows); plan (the rest) | the Windows checklist's self-update lines |

## Follow-ups (out of scope)

- The assistant's SSH key isn't rotated by `keys-rotate` (T61c, D108); it is the same code with the other identity.
- Going from managed to monitor leaves the hub's per-machine SSH key in the Vault and its pinned host key (T62, D110): harmless without an account, to be removed with `unenroll`'s cleanup.
- `rackhand hub init` under a strict umask (077) leaves `/etc/rackhand` closed to the hub's user, and the service fails with a permission error: `init` should set the directory's mode itself (T94; found installing on the owner's LXC, 2026-11-22).
- The musl release probe is 15 872 048 bytes; the design's limit is 15 MB (T96 measures it; release build at e3d843a, 2026-11-22).
- Review the Feodo Tracker default (S10: nearly empty when checked) after the first release (owner, 2026-11-21).
- The iroh segmentation-offload loss (D64): not raised upstream for now (owner, 2026-11-21); the workaround stays.
- A self-hosted Windows runner, which would move AC35 (Windows) and AC56 from manual to automated (D81).
- A Windows VM in the local lab (an evaluation image with an unattended install), so the run could do MV16's
  checklist itself.
- TrueNAS in the local lab (its installer is interactive, so the owner would install it once).
- The maintainers' documentation space: README, usage and setup pages once there is a release to document.
- Mirroring this plan's milestones as tasks on the maintainers' task board.
- The first release (`0.1.0`, D106): the maintainer signs offline (D90); this plan builds and verifies the artifacts
  but never signs or publishes.
- The maintainer's own lab rollout (which hosts, which sites) belongs in private notes, not in this repository.

## Final verification

| Check | Command | Result | Date |
| --- | --- | --- | --- |
| Fast tier | `cargo xtask ci fast` | | |
| Integration tier | `cargo xtask ci it` | | |
| Network tier | `cargo xtask ci net` | | |
| eBPF tier (5.10, 6.1, current Proxmox series) | `cargo xtask ci ebpf` | | |
| Windows tier | `cargo xtask ci win` | | |
| Performance tier | `cargo xtask ci perf` | | |
| Local live tier, every milestone | `cargo xtask ci live --target local --milestone all` | | |
| Real-lab pass | `cargo xtask ci live --target real --milestone real` | | |
| Licenses and advisories | `cargo deny check && cargo audit` | | |
| Reproducible release build | `cargo xtask release repro` | | |
| Workflow guards | `actionlint && cargo xtask ci-guard` | | |
| CI on self-hosted runners | `ci.yml` green on the branch head | | |
| All acceptance tests | every AC row above `done`, or `unverified` with its MV pending | | |
| Manual verifications | MV1 to MV18 recorded by their listed verifiers | | |
| Traceability complete | every row in the matrix has a step and a passing test or a recorded MV | | |
