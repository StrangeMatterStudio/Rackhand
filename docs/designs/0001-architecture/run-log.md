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
| 2026-11-19 | L1 done: the hub base failed to answer SSH once during re-provisioning (no banner; booted cleanly) and passed on the re-run; live lab 7 of 7 passed, both nodes with nested KVM. T35 done: join contract 9 passed and the hashed-token test 1 passed (D20 rate-limit key for relayed callers, for the owner; D21) |
| 2026-11-19 | T10 done: LXC attribution on pve9 works (`/lxc/100/`); report `spikes/s1.md`; the eBPF licence (MIT is refused) waits for the owner before T68 |
| 2026-11-19 | T11 done: journal-only auth events read on Debian 12 and Ubuntu 24.04; `mem.available_*` counts the ZFS ARC above `c_min` (design 7.4.2 and 17); report `spikes/s11.md` |
| 2026-11-19 | T50 done: runbook and playbook model, command templates and `rackhand hub runbook check` (D23) |
| 2026-11-19 | T54 done: policy decisions, exec step-up patterns, quarantine exclusions and approvals (D24) |
| 2026-11-19 | T12 done: the 7.8.6 role confirmed on PVE 8 and 9; guest rules need the datacenter firewall and the device flag; no conntrack flush in the API (owner decision before T72); report `spikes/s4.md` |
| 2026-11-19 | Review fixes: T50 anchored patterns could be escaped; T54 step-up patterns now match at any word position; T35 admission checked after reload; S4 upgrade wording; S11 also defines `mem.used_*` as total minus available. Open before L3: `lab reset` keeps `extra.qcow2` (the ZFS pool), so it must become an overlay too |
| 2026-11-19 | T36 done: dashboard foundation over HTTPS (ring only), one route table with the first-run gate, permissions and CSRF; first run with setup code, password and TOTP in one write; htmx 2.0.11 and uPlot 1.6.32 vendored from npm with integrity checked (D25: settings as library `config` items, for the owner) |
| 2026-11-19 | T37 done: password and single-use TOTP sign-in, step-up, sessions with idle and absolute limits, limits per source, account and known device, trusted proxies (D26) |
| 2026-11-19 | T22 done: Linux collectors from /proc and /sys with fixtures captured from the lab; `collect --once --json` on the real system found always-full image filesystems, now excluded (D27, for the owner) |
| 2026-11-19 | T51 done: command wrapper and signed command lists, checked behind sudo in a container; the join half of the first-list test moves to T44 (D28) |
| 2026-11-19 | T52 done: detached steps under systemd and OpenRC survive a dropped session; `run receive` with resume and a BLAKE3 check (D29) |
| 2026-11-19 | T53 done: SSH system with russh on ring, POSIX quoting, host key pinning with admin step-up acceptance, 1 MiB output caps; checked against OpenSSH in a container (D30) |
| 2026-11-19 | T56 done: library revisions and drafts, pre-push secret scan, debounced git mirror with git2 checked against a git server, restore-library (D31) |
| 2026-11-19 | Review fixes before T55: the wrapper anchors list regexes itself; job-supervise runs once; fixed wrapper path; step ids match the wrapper format; host key acceptance bound to the shown fingerprint. Noted for T41: mirror on top of the remote branch after a lost work tree, settings changes through the mirror, mirror host key pinning, receive root ownership, setup-code guessing, series-cap ordering |
| 2026-11-19 | T55 done: Actions runs one job per machine (a waiter ends `machine_busy` after 60 s), records each step before it runs, enforces timeouts and publishes `JobFinished`; the Executor runs plain and detached `ssh` steps and assistant `exec` against sshd and the wrapper in a container. Other step kinds wait for their systems (D32); a timed-out plain step is stopped with `timeout` on the machine (D33, design gap pending) |
| 2026-11-19 | T38 part 1: users, roles and devices on the settings page (the last enabled admin is kept by the store); a revoked device's next connection is closed with `0x13`. `collect::once_json_prints_one_sample_set` failed once under load and passed in 4 reruns; carried into T42 as a monotonic-interval test |
| 2026-11-19 | T38 part 2: passkeys with webauthn-rs, offered only with a passkey configuration (trusted certificate); a passkey replaces the code at sign-in and step-up |
| 2026-11-19 | T38 done: OIDC sign-in with PKCE and ring-checked ID tokens (D34: not `openidconnect`, whose `rsa` dependency fails `cargo deny`); OIDC accounts are created by an admin with a TOTP issued (D35, design gap pending) |
| 2026-11-19 | T63 done: the 19 diagnostics of 7.8.3 as built-in templates with limits in their patterns, site and check bindings, 256 KB output, untrusted wrapping; all run read-only against a systemd machine (D36: Windows forms come with T90) |
| 2026-11-19 | T74 done: MCP over `rackhand/mcp/1` with the auth line, personal keys bound to devices and job tokens bound to operators, the 12 read tools, untrusted output, 60 calls a minute and an audit row per call (D37: no rmcp in the hub, pending) |
| 2026-11-19 | T75 done: `run_diagnostic`, `exec` and `run_runbook` go through `decide()` with approvals bound to caller, call and revision and used once; scope, playbook tools, quarantine and monitor rules on every call; drafts, notes and `finish_job` (D38) |
| 2026-11-19 | T75 review fixes: callers checked on every MCP request, failed quarantines refused, quarantine runbooks judged as quarantine, MCP approvals audited, the lower autonomy level used, approvals spent only once the machine is held |
| 2026-11-19 | T58 done: approvals with every bound field and step-up for high risk, job runs with steps and output, library revisions with diffs, validation errors and drafts, patching with policy and window editing as revisions of `config/policies.toml` (D39) |
| 2026-11-19 | T76 done: Assist offers assistant jobs to operators in order with tokens bound to the accepting one, declines and no operator end the job for a person, transcripts up to 5 MB, the daily cap, reattachment after a restart and Resume after a deadline (D40) |
| 2026-11-19 | Lab: the Proxmox nodes' extra disk is an overlay `lab reset` replaces (open since the review before T55); file copies retry after a node's reboot; both nodes provisioned again; live `lab` milestone 7 of 7 |
| 2026-11-20 | T05: S8 analysed on 24 h from the WSL host. Plain Gorilla projects 4.23 GB per 50 machines; the best encoding measured (integer values, samples stamped with their tick) 2.52 GB with G1 retention, 1.88 GB with tier 1 kept 14 days. Over the 2 GB budget, so T05 is blocked on the owner's trade-off (7.4.1); D41. T19 and everything after it wait |
| 2026-11-20 | T05 review: the first integer coder handled large values badly and the row cost was assumed; with an adaptive coder and the row cost measured, the best options project 1.76 to 1.82 GB but each changes chunk sizes, retention or the budget. Design 17 finding added; T05 stays blocked on the owner |
| 2026-11-20 | Owner decisions: S8 tier 2 kept 1 year with integer chunk encoding (D109), S2 one rate per relay (D110), S1 eBPF crate GPL-2.0 OR MIT (D111), S4 conntrack flushed through the hypervisor's enrollment (D112); design updated with change-log rows. T05 done (fixture kept for T19, spike deleted); T19 re-planned for D109 (D42). T08, T10 and T12 no longer pending |
| 2026-11-20 | T19 done: `rackhand-store::series` (codec with three integer coders and f64 Gorilla, per-metric steps, tick snapping, chunk rows by the 120-point and tier 0 hour rules, range queries); 11 tests seen failing first, then passing; the T05 sample within 3% of the spike's figures; fast 252 passed |
| 2026-11-20 | T25 done: Ingest stages and commits before acking, compacts per machine (with backfill rows and dirty ranges), keeps a 35-minute window, corrects clocks by the median offset, limits replay and staging, guards low disk and keeps the latest facts; 12 ingest tests and the carried MCP facts test seen failing first, then passing; fast 265 passed; D43 |
| 2026-11-20 | T26 done: the probe's link and the hub's probe server pass the 13-test `rackhand/probe/1` contract over real endpoints (seen failing first; the run found and fixed an overflow in Ingest's unknown-labels limit); fast 278 passed; D44 |
| 2026-11-20 | T27 done: tier 1 and tier 2 rollups (minute ones from the recent window), dirty ranges recomputed, retention in 10 000-row batches with pauses and a rule registry covering every table; 7 store tests, the window rollup test and the carried `get_vitals` test seen failing first, then passing; fast 287 passed; D45 |
| 2026-11-20 | T32 done: Incidents opens, updates, reopens and resolves condition incidents from the recent window, merges event incidents, honours silences and acknowledgements and reconciles finished jobs; detect's severity can now fall; 10 incident tests and a detect test seen failing first, then passing; fast 298 passed; D46 |
| 2026-11-20 | T33 done: Discord and SMTP callouts with grouping, re-sends, resolutions, retries and `notifier_failed`; the runbook `notify` step goes through Notify; 9 notify tests and the carried IT test seen failing first, then passing (the run found and fixed a lock held across sends); fast 307 passed; D47 |
