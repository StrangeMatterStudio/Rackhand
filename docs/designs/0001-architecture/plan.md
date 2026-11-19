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
| T05 | Spike S8: time-series encoding | T02 | scripted measurement | todo |
| T06 | Spike S6: probe footprint | T02 | scripted measurement | done |
| T07 | Spike S7: git mirror library | T02 | scripted measurement | done |
| T08 | Spike S2: iroh relay admission and limits | T02 | scripted measurement (network VM) | done (owner decision pending for T82) |
| T09 | Spike S3: iroh path detection | T02 | scripted measurement (network VM) | done |
| T10 | Spike S1: aya eBPF | T02, L1 | scripted measurement (eBPF VMs, local Proxmox) | done (owner decision pending for T68) |
| T11 | Spike S11: collectors on current distributions | T02, L1 | scripted measurement (containers, local Proxmox) | done |
| T12 | Spike S4: Proxmox privileges, firewall, upgrade command | T02, L1 | scripted measurement (local Proxmox) | done (owner decision pending for T72) |
| T13 | Spike S5: Claude Code headless | T02 | scripted measurement (owner's login) | todo |
| T14 | Spike S9: TrueNAS API | T02 | lab measurement | todo |
| T15 | Spike S10: threat list and GeoIP terms | T02 | scripted measurement + reading | done (owner decision pending for T69) |
| T16 | Wire format: framing, limits, close codes, messages | T15 | unit, golden | done |
| T17 | Net: endpoint, node key, registry, contract harness | T16, T08, T09 | contract | done |
| T18 | Store: schema, writer task, read pool | T16 | unit | done |
| T19 | Time-series encoding and chunks | T18, T05 | unit, property | todo |
| T20 | Audit log with hash chain and checkpoints | T18 | unit | done |
| T21 | Vault | T18 | unit | done |
| T22 | Probe Linux collectors | T16, T06, T11 | collector (fixtures) | done |
| T23 | Probe buffer, epochs and label table | T16 | unit | done |
| T24 | Bus | T18 | unit | done |
| T25 | Ingest: staging, acks, compaction, recent window, clock | T18, T19, T24 | unit | todo |
| T26 | Probe contract `rackhand/probe/1` | T17, T23, T25 | contract | todo |
| T27 | Rollups and retention | T19, T25, T05 | unit | todo |
| T28 | Detect: threshold rules | T01 | unit | done |
| T29 | Detect: forecasts | T28 | unit | done |
| T30 | Detect: silence | T28 | unit | done |
| T31 | Detect: baselines and counted rules | T28 | unit | done |
| T32 | Incidents: lifecycle and evaluation | T25, T24, T28 to T31 | unit | todo |
| T33 | Notify: Discord, SMTP, grouping, retries | T32 | unit (HTTP and SMTP fakes) | todo |
| T34 | Scheduler and windows | T24 | unit | done |
| T35 | Join contract and Registry | T17, T18, T21 | contract | done |
| T36 | Web foundation and first run | T18, T20, T21 | unit (HTTP) | done |
| T37 | Sign-in, second factor, step-up and limits | T36 | unit (HTTP) | done |
| T38 | Passkeys, OIDC and account settings | T37 | unit (HTTP, fake provider) | todo |
| T39 | Dashboard pages for monitoring | T32, T36 | unit (HTTP) | todo |
| T40 | `/metrics` endpoint | T25, T36 | unit (HTTP) | todo |
| T41 | Hub composition and `rackhand hub` commands | T24 to T40 | integration | todo |
| T42 | Probe daemon | T22 to T26, T41 | integration | todo |
| T43 | Helper basics and package-list refresh | T42 | integration (containers) | todo |
| T44 | Linux and Alpine installer and enrollment | T35, T43 | integration (containers) | todo |
| T45 | Hub self-watch, integrity and backups | T41 | unit + integration | todo |
| L2 | Live tier and the M1 pass | T44, T45, L1 | live (local lab) | todo |
| T46 | Service checks and network drivers | T41 | unit + integration | todo |
| T47 | Proxmox driver | T46, T12 | unit (recorded API) | todo |
| T48 | TrueNAS, Redfish and SNMP drivers | T46, T14 | unit (simulators) + integration | todo |
| T49 | Add page, agentless enrollment and guest binding | T47, T48, T39 | unit + integration | todo |
| L3 | Live pass for M2: agentless and Proxmox | T49, L2 | live (local lab) | todo |
| T50 | Runbook and playbook model | T01 | unit | done |
| T51 | Command wrapper and signed command lists | T50, T16 | unit + integration | done |
| T52 | Wrapper detached steps and file receive | T51 | integration (systemd and OpenRC containers) | done |
| T53 | SSH system | T21, T35 | unit + integration | done |
| T54 | Policy: decisions and approvals | T18 | unit | done |
| T55 | Actions and Executor | T52 to T54, T24 | unit + integration | done |
| T56 | Library and git mirror | T50, T21, T07 | unit + integration | done |
| T57 | Incident routing to runbooks and attempt limits | T32, T55 | unit | todo |
| T58 | Dashboard: approvals, jobs, library, patching | T55, T56, T37 | unit (HTTP) | todo |
| T59 | Patching | T55, T34, T47, T12 | unit + integration + live (L4, L9) | todo |
| T60 | Hypervisor and hub-host patching | T59 | unit + integration + live (L4, L9) | todo |
| T61 | Remaining built-in runbooks and key rotation | T55, T43 | unit + integration | todo |
| T62 | Access levels and monitor enforcement | T44, T55, T49 | unit + integration | todo |
| T63 | Diagnostics allow-list | T55 | unit + integration | todo |
| T64 | Provisioning VMs and LXCs | T59, T49 | unit (recorded API) + live (L4, L9) | todo |
| T65 | Hub restart recovery for jobs | T55, T59 | integration | todo |
| L4 | Live pass for M3: actions and patching | T65, L3 | live (local lab) | todo |
| T66 | Helper security scans | T43, T11 | integration (containers) | todo |
| T67 | Probe sampling capture and security signals | T66, T42 | collector + integration | todo |
| T68 | eBPF capture | T67, T10, T06 | eBPF tier | todo |
| T69 | Threat intel and outside sources | T41, T15 | unit | todo |
| T70 | Connection scoring and connection storage | T67, T69 | unit + integration | todo |
| T71 | Security events, severities and exemptions | T70, T61 | unit + integration | todo |
| T72 | Quarantine | T71, T55, T47 | unit + integration + live (L5, L9) | todo |
| T73 | Dashboard: security pages | T71, T72 | unit (HTTP) | todo |
| L5 | Live pass for M4: security watch and quarantine | T73, L4 | live (local lab) | todo |
| T74 | MCP server and read tools | T17, T54 | contract | todo |
| T75 | MCP gated tools and approval binding | T74, T55, T63 | contract | todo |
| T76 | Operator contract and Assist | T75 | contract | todo |
| T77 | Operator binary and runners | T76, T13 | integration (fake runner) + live (L6) | todo |
| T78 | Incident routing to playbooks and briefs | T77, T57 | unit + integration | todo |
| T79 | Dashboard: assistant pages and settings | T78 | unit (HTTP) | todo |
| L6 | Live pass for M5: a real Claude Code operator | T79, L5 | live (local lab, owner's sign-in) | todo |
| T80 | Peer contract | T35, T41 | contract | todo |
| T81 | Peer watch and callout election | T80 | unit + network | todo |
| T82 | Relay | T17, T08 | unit + network | todo |
| T83 | Hole punching and relay fallback | T82, T09 | network | todo |
| T84 | Tunnels and remote mode | T83, T55 | contract + network | todo |
| T85 | Transfers and backup streams | T84, T09, T45 | contract + network | todo |
| T86 | `rackhand-cli` | T84, T75 | integration + network | todo |
| T87 | Address changes, `set-hub` and identity conflicts | T42, T61 | integration | todo |
| T88 | Dashboard: peers, relays and peer sites | T81, T82 | unit (HTTP) | todo |
| L7 | Live pass for M6: two sites | T88, L6 | live (local lab) | todo |
| T89 | Windows probe and helper | T22, T23, T26, T66, T67 | collector (recorded outputs) + Windows tier + manual | todo |
| T90 | Windows installer, SSH setup, dispatcher and scripts | T89, T61, T72 | Windows tier (Pester) + manual | todo |
| T91 | Release signing, manifests and reproducible builds | T44 | unit + scripted | todo |
| T92 | Probe self-update | T91, T43 | unit + integration | todo |
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
  - [ ] Report committed; finding appended to design 17 with a change-log row
  - [ ] Projection at most 2 GB, or the owner has decided the trade-off and the design is updated (7.4.1 says so)
  - [ ] Spike code deleted
- **Risk / rollback:** a miss changes retention or the budget; that is the owner's call before T19.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

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
  - [ ] Report committed; flags written into 7.3.5; finding in design 17
  - [ ] Spike code deleted; the spike user's configuration directory removed
- **Risk / rollback:** none beyond the finding.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

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
  - [ ] Report and redacted fixtures committed; finding in design 17
  - [ ] Spike code deleted
- **Risk / rollback:** none beyond the finding.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

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
- **Design refs:** 7.4.1 (`series_chunks`, open chunks of 120 points or one hour), D43, S8 finding
- **Goal:** points encode and decode losslessly with the encoding chosen in T05. Chunk rows are opened, appended to and
  closed by the 120-point and hour rules.
- **Depends on:** T18, T05
- **Changes:** `crates/rackhand-store/src/series/{gorilla.rs, chunk.rs, query.rs}`.
- **Tests to write first:**
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `gorilla::round_trip_is_lossless` (property, 10 000 cases) | random timestamps and f64 values, including NaN, infinities and repeats, decode exactly | D43 |
  | `gorilla::bytes_per_value_on_recorded_data_within_spike_result` | the T05 sample encodes within 10% of the spike's figure | S8, 5.2 |
  | `chunk::chunk_closes_at_120_points` | the 121st point opens a new row | 7.4.1 |
  | `chunk::chunk_closes_at_hour_boundary` | a point in the next hour opens a new row, even at 30 points | 7.4.1 |
  | `chunk::append_to_open_chunk_preserves_points` | appending in two batches equals one batch | 7.4.1 |
  | `query::range_query_returns_points_in_order_across_chunks` | a range spanning three chunks returns sorted, deduplicated points | 7.4.1 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-store -E 'test(gorilla::) | test(chunk::) | test(query::)'
  ```
  Expected: 6 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

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
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(ingest::)'
  ```
  Expected: 11 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

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
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-store -E 'test(rollup::) | test(retention::)'
  ```
  Expected: 6 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

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

  Carried in from T55 (the Executor passes these step kinds to the system that owns them; until then they fail `<kind>_unavailable`):
  | Test | Asserts | Covers |
  | --- | --- | --- |
  | `it::executor::notify_step_sends_message` | a runbook `notify` step sends its message through Notify and the step succeeds; a failed send fails the step | 7.8.7 |
- **Fails first:** compile errors.
- **Verification:**
  ```bash
  cargo nextest run -p rackhand-hub -E 'test(notify::)'
  ```
  Expected: 8 passed, 0 failed.
- **Manual verification:** None.
- **Risk / rollback:** revert.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

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
  - [ ] New tests observed failing before the deploy
  - [ ] New tests and the regression suites pass
  - [ ] M1 page walk recorded
  - [ ] Evidence recorded below
- **Risk / rollback:** `lab reset` returns every machine to its base image. Revert the commit.
- **Evidence:**
  | When | Command | Result |
  | --- | --- | --- |

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

### T67: Probe sampling capture and security signals
- **Design refs:** FR-4 (sampling), FR-5, 7.3.2 (connection tuples, overflow), D17, D103, E36, E59, AC13 (sampling
  part), AC71 (sampling part)
- **Goal:** without eBPF the probe reads the connection table every 5 seconds and gets process and container
  attribution from the helper. It aggregates tuples per `(container, exe, dest_ip, dest_port, proto)` with at most 500
  per report, folding the rest, and reports new listeners and exec-from-temp processes. The Machine page shows
  "sampling".
- **Depends on:** T66, T42
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

### T78: Incident routing to playbooks and briefs
- **Design refs:** 7.5.2 (routing to playbooks, `on_failure`, attempt limits, event incidents resolved by assistants),
  7.5.4 (brief contents), D76, D96, AC21
- **Goal:** incidents route to the most specific playbook when no runbook matches or the runbook failed (or to the
  playbook named by `on_failure`), at most one assistant job per incident per 24 hours. The brief holds what 7.5.4
  lists with machine output marked untrusted. Assistants resolve event incidents only at level 2 or 3, and only for
  warning kinds.
- **Depends on:** T77, T57
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
| AC20 | Hold, approve-only, maintenance windows | T34, T59 | `select::hold_never_patched`, `select::approve_only_...`, `it::patch::no_patch_or_silence_alert_during_maintenance_window` | todo |
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

## Follow-ups (out of scope)

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
