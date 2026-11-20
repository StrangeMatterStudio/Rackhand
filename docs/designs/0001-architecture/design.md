# 0001 Rackhand architecture and v0.1

| | |
| --- | --- |
| Depth | Full |
| Status | Approved |
| Authors | Owen Ravelo, Claude |
| Approver | Owen Ravelo (2026-11-18) |
| Created / Updated | 2026-11-18 / 2026-11-18 |
| Related | none (first design) |

## 1. Summary

Rackhand is a self-hosted operations hub for homelabs, written in Rust and released as open source (MIT OR
Apache-2.0). Each site runs a **hub**. A small **probe** on every Linux, Alpine and Windows machine reports vitals and
security signals to a hub, and the hub checks appliances such as NAS boxes and BMCs without an agent. The hub finds
trouble with thresholds, forecasts, baselines and heartbeats, calls out to people by Discord webhook and email, and
fixes routine problems itself with deterministic **runbooks** run over SSH. When a runbook fails, or a problem needs
judgment, the hub hands the incident to an AI assistant (Claude Code first) on a separate **operator** host, which works
only through the hub's MCP tools, inside the hub's scope and approval rules. Hubs at different sites link as equal peers
over a QUIC mesh (iroh) with hole punching and self-hosted **relays**, share summaries, watch each other, and carry
tunnels and large transfers for existing backup tools.

## 2. Problem and context

A typical larger homelab has several sites (a main rack with a few hypervisors, a second location, an offsite backup
box, a small VPS) and dozens of VMs and containers. Problems are usually found when something is already down. A
common example: a VM reboots after an automatic kernel update, Docker starts before an NFS share is mounted, and the
containers that depend on it stay down until someone notices. Uptime checks catch "the site is down" but not "the disk
fills in three days", "this VM never came back after patching", or "this container started talking to an IP it has
never talked to".

Fixing things is also manual. The owner SSHes into each box, remembers which ones must not be updated, takes snapshots
by hand (or forgets), and has no record of what was changed. An AI assistant can help, but only with safe, scoped,
audited access and a reliable picture of the machines.

Existing tools each cover a slice: Prometheus and Grafana for metrics, Uptime Kuma for service checks, Wazuh or
CrowdSec for security, Ansible for changes, Tailscale for connectivity. Running and wiring five systems is the work a
small homelab doesn't have time for, and none of them hands an incident to an assistant with guard rails. Cloud-hosted
operations tools can't reach private networks.

If we do nothing, outages keep being found by visitors, patching stays manual and unsnapshotted, and compromises go
unnoticed.

## 3. Goals

- **G1 Vitals.** Every enrolled machine's CPU, memory, swap, load, disk, network, services, containers and pending
  updates are visible on its hub within 30 seconds, with history (48 hours at 15 seconds, 30 days at 1 minute, 1 year
  at 1 hour).
- **G2 Early warning.** Rackhand calls out before or when something goes wrong: thresholds with durations, forecasts
  (disk full, memory growth, certificate expiry), learned baselines, and silence (a machine or a peer site that stops
  reporting).
- **G3 Security watch.** Rackhand detects unusual outbound connections, known-bad destinations, logins and account
  changes, new listening ports, suspicious processes and changes to critical files, and can quarantine a machine on
  approval or by an opt-in policy.
- **G4 Routine maintenance without AI.** Security updates install daily and other updates weekly, with a snapshot first
  and health checks after, deterministically, with holds, approval-only hosts and maintenance windows.
- **G5 AI on failure.** When a runbook fails or an incident matches a playbook, an assistant is started on an operator
  host, works only through Rackhand's MCP tools, and is bounded by scope, autonomy levels and dashboard approvals.
- **G6 Multi-site.** Hubs at different sites find each other through hole punching or a relay, share summaries, watch
  each other's heartbeat, request actions from each other, and carry tunnels and resumable transfers.
- **G7 Installs.** A fresh Debian or Proxmox box becomes a hub and links to its peers; runbooks provision VMs and LXCs
  on Proxmox and enroll them; playbooks guide larger installs step by step.
- **G8 Anyone can run it.** One-line installers, signed static binaries, a Proxmox LXC helper script, no Node or other
  interpreter on any server, works with no other self-hosted services, documented for strangers.

## 4. Non-goals

- **NG1** A layer-3 VPN. Machines don't get mesh IP addresses; only Rackhand processes join the mesh. Other tools reach
  across sites through Rackhand tunnels.
- **NG2** A backup engine. Rackhand schedules and transports existing tools (ZFS send/receive, Proxmox Backup Server
  sync, restic) and checks freshness; it has no backup format of its own.
- **NG3** Chat-based approvals or commands. Callouts go to Discord webhooks and email; every action is approved inside
  the authenticated dashboard. Matrix support is dropped from v0.1.
- **NG4** Automatic container image updates. Pending image updates are reported; applying them is a runbook that needs
  approval.
- **NG5** Release upgrades of operating systems (for example Debian 12 to 13) or changes to package sources.
- **NG6** Firmware updates (BIOS, BMC, disks). Rackhand may report versions; it never flashes firmware.
- **NG7** Federated user accounts across hubs. Each hub has its own accounts (an OIDC provider can be shared).
- **NG8** Native distribution packages (deb, rpm, apk) and a Docker image in v0.1. Static binaries, the installers and
  the Proxmox LXC script are the supported paths.
- **NG9** Giving an AI a shell. Assistants get MCP tools only: no shell on the operator host and no SSH keys.
- **NG10** Depending on a specific outside service where it isn't needed. Outside sources that are needed (threat lists,
  GeoIP, release updates, section 7.8.5) are named, on by default, and each can be turned off; an air-gapped mode turns
  them all off. Optional services (n0 relays and DNS discovery, online IP reputation, MaxMind) are off unless enabled.
  No telemetry.

## 5. Requirements

### 5.1 Functional

**Probe and collection**
- **FR-1** The probe shall sample vitals every 15 seconds (configurable 5 to 300 seconds) and send a report to its hub.
- **FR-2** The probe shall collect the metric catalogue in section 7.4.2 (CPU, load, memory, swap, per-mount disk and
  inodes, per-disk I/O, per-interface network, uptime, temperatures where exposed, the probe's own use), service states
  (watched services plus every failed unit or service), container states (through the helper), and pending updates
  (count, security count, reboot required).
- **FR-3** The probe shall buffer reports on disk while the hub is unreachable, up to 64 MB or 24 hours (whichever comes
  first, oldest dropped first), and replay them in order when the hub returns, without delaying live reports.
- **FR-4** On systemd Linux with kernel 5.8 or later and BTF available, the probe shall record every outbound TCP
  connect and UDP flow with pid, process name, executable path, container (from the process's cgroup), user,
  destination IP and port, using eBPF (OpenRC machines and LXCs have no capabilities for it, 7.3.3). Elsewhere it shall
  read the connection table every 5 seconds, with process and container attribution from the helper. Windows uses the
  GetExtendedTcpTable and GetExtendedUdpTable APIs every 5 seconds. Sampling sees only connections that are open at a
  poll, so shorter ones are missed on those machines; the Machine page shows which method each machine uses.
- **FR-5** The probe shall report new listening sockets, and process starts whose executable is under `/tmp`,
  `/var/tmp`, `/dev/shm` or a deleted file (Linux: eBPF `sched_process_exec` tracepoint, fallback a helper process scan
  every 5 seconds, since an unprivileged process can't read other users' `/proc/<pid>/exe`), or on Windows under
  `%TEMP%` or a user's Downloads folder (process list every 5 seconds).
- **FR-6** The probe helper (root) shall hash the critical file list (section 7.8.4) every 5 minutes and on inotify
  change, tail authentication logs, and return container states, socket owners and hashes to the probe, never file
  contents.

**Hub, detection and incidents**
- **FR-7** The hub shall store vitals in three tiers (15 s raw for 48 h, 1 min for 30 d, 1 h for 1 y) and events for 90
  days, and expose a Prometheus `/metrics` endpoint.
- **FR-8** The hub shall evaluate threshold, forecast, baseline and silence rules (section 7.6) every 15 seconds, turn
  warning and critical events into incidents, and open, update and resolve incidents.
- **FR-9** The hub shall run service checks (HTTP(S) status and body match, TCP connect, DNS answer, TLS certificate
  expiry, ICMP ping) at a configurable interval (default 60 s) from the hub's site.
- **FR-10** The hub shall check agentless machines through drivers (ICMP, TCP, HTTP, Proxmox VE API, TrueNAS API,
  Redfish, SNMP v2c/v3 read-only) and record the metrics listed per driver in section 7.4.2.
- **FR-11** The hub shall send callouts to configured notifiers (Discord webhook, SMTP email) for warning and critical
  incidents, with the grouping and re-notify rules in section 7.6.7.

**Actions**
- **FR-12** The hub shall execute runbooks over SSH or driver APIs step by step, with per-step timeouts, one job per
  machine at a time, and record every command, exit code and output (stdout and stderr each truncated at 1 MB per step)
  in the job log. Steps that change packages are started detached on the machine and polled, so they survive a hub
  restart or a dropped connection (7.3.7).
- **FR-13** The hub shall run patching per host policy: security updates daily and all updates weekly, inside patch
  windows, with a snapshot before (VMs and LXCs on Proxmox), health verification after, holds, approval-only hosts and
  recurring maintenance windows.
- **FR-14** The hub shall require dashboard approval for any action whose level or risk demands it, and a fresh second
  factor (step-up within 5 minutes) for high-risk actions and for turning on automatic high-risk policies.
- **FR-15** The hub shall quarantine a machine on approval, or automatically when an enabled auto-quarantine rule
  matches, keeping the hub's management path open, and release it only on approval.

**Assistant**
- **FR-16** The hub shall dispatch assistant jobs to operator hosts it invited, with a brief, the matched playbook, a
  job-scoped MCP token limited to the incident's hosts and the playbook's tools, an autonomy level and a deadline, and
  at most a configured number of jobs per day (default 20).
- **FR-17** The hub shall expose MCP tools (section 7.3.6) to operator jobs and to device-bound personal keys, enforce
  scope, allowed tools and autonomy per call, bind approvals to exact calls, and never let an MCP caller grant an
  approval.

**Mesh and multi-site**
- **FR-18** Hubs shall link pairwise through a one-time invite, then connect over QUIC (iroh) directly or through a
  relay, push summaries every 30 seconds, answer allowed on-demand queries, forward action requests, and watch each
  other's heartbeat.
- **FR-19** Rackhand shall provide tunnels (`rackhand-cli connect`, port forwards) and resumable, verified file
  transfers to machines at any site, authorized by the hub that owns the target machine.
- **FR-20** The relay shall support public and private modes, issued keys, priority for keyed users, and per-endpoint
  limits; hubs shall accept relay lists from URLs.

**Enrollment, installs and lifecycle**
- **FR-21** The dashboard shall issue one-time enrollment commands for Linux, Alpine and Windows machines (local or
  remote to the hub, at access level `managed` or `monitor`, 7.3.12), a form for agentless machines, and invites for
  devices, operators and peers; a site bootstrap command shall turn a fresh machine into a hub.
- **FR-22** The probe shall be updated from signed releases by its root helper when the hub says so, with automatic
  rollback if the new version fails to reconnect within 2 minutes.
- **FR-23** Runbooks shall provision VMs and LXCs on Proxmox from templates with cloud-init and enroll them.
- **FR-24** The hub shall store runbooks, playbooks and configuration with revision history and mirror every change to a
  configured git repository, with no secrets in the mirror.

**People**
- **FR-25** The dashboard shall support local accounts with a mandatory second factor (TOTP, or a passkey when the hub
  has a trusted certificate) and optional OIDC sign-in, with the roles and permissions in section 7.7.2.
- **FR-26** Every action, approval, configuration change, sign-in and MCP call shall be written to an append-only,
  hash-chained audit log.

### 5.2 Non-functional

| Area | Requirement |
| --- | --- |
| Probe footprint | Steady RSS at most 25 MB including eBPF maps; at most 1% of one core averaged over 5 minutes at the 15 s interval; static binary at most 15 MB; disk buffer at most 64 MB; average network at most 2 KB/s. Helper RSS at most 8 MB. Confirmed in spike S6. |
| Hub footprint | For 100 machines: RSS at most 300 MB, at most 10% of one core averaged. Database at most 2 GB per 50 machines across all tiers. Minimum host: 2 vCPU, 1 GB RAM, 20 GB disk for 50 machines. |
| Latency | Vitals visible on the dashboard at most 30 s after sampling, including during buffered replay. A critical incident's callout sent at most 60 s after its condition has held for its duration; a warning callout at most 6 minutes after (grouping). Peer site silent detected within 2 minutes, down within 10. |
| Availability | The hub keeps monitoring, alerting and running runbooks at its site with no internet, no peers and no operator. |
| Security | No inbound ports on probes (except a remote-mode probe's tunnel stream from its pinned hub). All Rackhand-to-Rackhand traffic is QUIC with TLS 1.3 and endpoint keys pinned. Secrets encrypted at rest. Second factor mandatory for every dashboard account. The hub, relay and operator run as unprivileged system users (7.1); the only root services are the probe helper, the updater and its guard, and the only other root code is the command wrapper and the steps it starts through sudo. |
| Privacy | No telemetry. Connection logs store destination, port and process, never payloads. Data sent to the AI provider is limited to the job brief and tool results, and documented. |
| Platforms | Probe: Linux x86_64 and aarch64 (static musl, kernel 4.19+; eBPF needs 5.8+ with BTF), Alpine 3.18+, Windows 10/11 and Server 2019+. `rackhand` (hub, relay, operator): Linux x86_64 and aarch64. `rackhand-cli`: Linux, Windows and macOS (x86_64 and aarch64). |
| Compatibility | A hub accepts probes, operators, relays and CLIs of its own minor version and one minor version older. Peers of different minor versions interoperate on the summary and request contracts. |
| Supply chain | Every release artifact is signed (minisign, Ed25519), and a signed manifest lists every artifact's hash. Installers, the helper and the updater verify signatures against two pinned public keys (current and standby) before running anything. The signing keys are kept offline and never on a CI runner (section 13). Builds are reproducible from tags. |
| Language | Rust for every server-side process. No Node, Python or other interpreter on any server. Browser JavaScript is limited to vendored htmx and uPlot plus small page scripts. |

### 5.3 Constraints

- Rust stable, MSRV pinned in `rust-toolchain.toml` (at least what iroh 1.x requires).
- Libraries: iroh 1.x (QUIC, hole punching, relay), aya (eBPF), rusqlite with bundled SQLite (storage), axum and askama
  (web), rmcp (MCP server and client), russh (SSH), prost (wire messages), webauthn-rs and totp-rs (second factors),
  openidconnect (OIDC), chacha20poly1305 (Vault), git2 with vendored libgit2, libssh2 and OpenSSL (the library's git mirror, hub
  only; spike S7).
- Claude Code (native binary) is the first assistant runner. It runs only on operator hosts, never on a hub.
- CI runs on the maintainers' self-hosted runners. GitHub-hosted copies of every workflow exist and are off by default.
  Self-hosted jobs never run for pull requests from forks.
- License MIT OR Apache-2.0; dependencies license-compatible (`cargo deny`). The probe's eBPF program is its own crate
  licensed GPL-2.0 OR MIT, because the kernel helpers it needs are GPL-only (S1, D111).
- Rackhand is standalone: it integrates with no other product of its maintainers.

## 6. Current state

This is a new project. The repository holds a README and the licenses. The environment it targets, using a
representative homelab as the reference:

- **Hypervisors:** Proxmox VE 8 and 9 hosts, some clustered and some standalone, with VMs and LXCs. Proxmox has a REST
  API with API tokens, a per-guest firewall (which only applies when the datacenter firewall is on), and snapshots for
  VMs and LXCs on supported storage.
- **Guests:** mostly Debian and Ubuntu VMs running Docker or Docker Compose, some Alpine LXCs, Windows desktops, and
  appliances (a NAS such as TrueNAS, DNS filters, a Wi-Fi controller, server BMCs, network devices).
- **Sites:** a main site with several hypervisors, one or more smaller sites, an offsite backup machine, and a small
  public VPS. Some sites are linked by an existing VPN, some only through the internet, often behind NAT.
- **Existing monitoring:** typically an uptime checker such as Uptime Kuma. No vitals history, no security monitoring.
- **Common hazards:** hosts that must not be updated; services that need a network mount at boot; servers with
  scheduled daily reboots; desktops that go offline normally.

## 7. Proposed design

### 7.1 Overview

```mermaid
flowchart LR
  subgraph SiteA["Site A (main)"]
    PA1["probe + helper\n(Linux VM)"] -- "QUIC rackhand/probe/1" --> HA["hub A"]
    PA2["probe\n(Windows)"] --> HA
    APP["appliance\n(NAS, BMC)"] -. "API / SNMP / HTTP" .- HA
    HA -- "SSH (rackhand, rackhand-ai)" --> PA1
    HA -- "Proxmox API" --> PVE["Proxmox hosts"]
    OP["operator host\n(Claude Code)"] -- "rackhand/operator/1\nrackhand/mcp/1" --> HA
    UI["browser"] -- "HTTPS :8443" --> HA
    CLI["rackhand-cli\n(laptop)"] -- "rackhand/mcp/1\nrackhand/tunnel/1" --> HA
  end
  subgraph SiteB["Site B"]
    PB["probes"] --> HB["hub B"]
  end
  subgraph Cloud["VPS"]
    R["rackhand relay"]
    PV["probe (remote mode)"]
  end
  HA <-- "rackhand/peer/1\n(direct or via relay)" --> HB
  PV -- "rackhand/probe/1 via mesh" --> HA
  HA -. "home relay" .- R
  HB -. "home relay" .- R
  HA -- "webhook / SMTP" --> N["Discord, email"]
```

Six programs ship as three binaries:

- `rackhand-probe`: the probe (`rackhand-probe run`) and its root helper (`rackhand-probe helper`). Linux and Windows.
- `rackhand`: the hub (`rackhand hub`), the relay (`rackhand relay`) and the operator (`rackhand operator`), plus their
  admin commands. Linux only.
- `rackhand-cli`: the people-side client (`connect`, `forward`, `send`, `mcp`, `login`, `status`). Linux, Windows,
  macOS.

Every Rackhand process has an Ed25519 key, which is its iroh endpoint id. A hub keeps a registry of the endpoint ids it
accepts (probes, devices, operators, peers); every process that joins a hub pins the hub's id. Unregistered processes
can only use the join contract (7.3.1). The hub reaches local machines for actions over SSH on the local network, and
remote-mode machines over SSH through a tunnel to their probe. A machine enrolled at access level `monitor` has no hub
accounts and is never reached over SSH (7.3.12).

**Process users.** The hub runs as the system user `rackhand-hub`, the relay as `rackhand-relay` and the operator as
`rackhand-operator`, each under a hardened service unit (`NoNewPrivileges`, `ProtectSystem=strict`, write access only
to its own data directory). None of them is root:

- The master key file stays `0600` root; the service manager hands it to the hub as a credential
  (`LoadCredential`), so the hub process gets its own private copy and no other user can read the key.
- ICMP checks use the single capability `CAP_NET_RAW` on the hub unit. The relay's port 443 uses the single capability
  `CAP_NET_BIND_SERVICE` on the relay unit.
- Updates are installed by a separate root unit, the updater (7.5.7), which verifies release signatures itself. The
  hub user can ask for an update but can't write its own binary.
- On the hub's own host, `rackhand-hub` is a different user from the `rackhand` automation user (7.3.7).

### 7.2 Systems and responsibilities

| System | Purpose | Owns (single writer) | Depends on | Kind | Location |
| --- | --- | --- | --- | --- | --- |
| Proto | Wire messages, ALPN names, versions | Message schemas | prost | contract | `crates/rackhand-proto` |
| Net | iroh endpoint, relay config, ALPN routing, node key, registry checks | Node key file, relay list cache | iroh, Proto | detail | `crates/rackhand-net` |
| Detect | Pure rule evaluation: thresholds, forecasts, baselines, silence, connection scoring, event severity | Nothing | none | policy | `crates/rackhand-detect` |
| Runbook model | Runbook and playbook parsing and validation, command template generation | Nothing | none | policy | `crates/rackhand-runbook` |
| Drivers | Agentless checks and API calls behind the `Driver` trait | Nothing | HTTP, SNMP, ICMP clients | detail | `crates/rackhand-drivers` |
| Store | SQLite schema, migrations, writer task, read pool, time-series encoding, retention, rollups | The hub database file | rusqlite | detail | `crates/rackhand-store` |
| Registry | Sites, machines, devices, operators, peers, tags, enrollment tokens | `sites`, `machines`, `devices`, `operators`, `peers`, `join_tokens` | Store | policy | `crates/rackhand-hub/src/registry` |
| Ingest | Receive probe and driver data, stage, ack, write series and events, update baselines and connection records | `report_staging`, `probe_labels`, `series_chunks`, `metric_keys`, `events`, `conn_records`, `conn_baseline`, `baseline_buckets`, and the in-memory recent window (7.4.1) | Store, Proto | detail | `crates/rackhand-hub/src/ingest` |
| Checks | Service checks and driver polling on schedules | `checks`, `check_results` | Drivers, Store | detail | `crates/rackhand-hub/src/checks` |
| Incidents | Evaluate Detect over fresh data, incident lifecycle, routing | `incidents`, `incident_events`, `silences` | Detect, Store, Bus | policy | `crates/rackhand-hub/src/incidents` |
| Policy | Host policies, autonomy, risk, approvals, quarantine rules, windows | `policies`, `approvals`, `quarantine_rules`, `windows` | Store | policy | `crates/rackhand-hub/src/policy` |
| Actions | Single coordinator for every job: locks, approvals check, dispatch to the runbook executor or the assistant dispatcher, job records | `jobs`, `job_steps`, `assistant_transcripts` | Policy, Store, Bus | policy | `crates/rackhand-hub/src/actions` |
| Executor | Runs runbook steps (SSH, driver calls, transfers, waits) and reports step results to Actions | Nothing persistent | SSH, Drivers, Net | detail | `crates/rackhand-hub/src/executor` |
| SSH | Connections per identity, quoting, host key pinning | `ssh_host_keys` | russh, Vault | detail | `crates/rackhand-hub/src/ssh` |
| Assist | Offer jobs to operators, job tokens, collect transcripts (through Actions) | `job_tokens` | Net, Policy | detail | `crates/rackhand-hub/src/assist` |
| MCP | Tools for assistants and devices | `mcp_keys` | Policy, Actions, Store reads | detail | `crates/rackhand-hub/src/mcp` |
| Notify | Discord webhook and SMTP behind the `Notifier` trait, retries | `notifications` | Store | detail | `crates/rackhand-hub/src/notify` |
| Peers | Peer links, summaries, queries, request forwarding, peer watch | `peer_summaries` | Net, Registry, Policy, Store | detail | `crates/rackhand-hub/src/peers` |
| Library | Runbook and playbook revisions, drafts, built-ins, git mirror | `library_items`, `library_revisions`, `library_drafts` | Store, Runbook model, git library | detail | `crates/rackhand-hub/src/library` |
| Vault | Encrypted secrets | `secrets` | Store, chacha20poly1305 | detail | `crates/rackhand-hub/src/vault` |
| Intel | Threat lists and GeoIP/ASN refresh and lookup | Files under `/var/lib/rackhand/intel/` | HTTP client | detail | `crates/rackhand-hub/src/intel` |
| Scheduler | Time-based triggers: patch windows, checks, retention, rollups, backups, intel refresh, git mirror debounce, dead-man calls | `schedule_state` | Bus, Store | detail | `crates/rackhand-hub/src/scheduler` |
| Audit | Append-only hash-chained log | `audit_log` | Store | detail | `crates/rackhand-hub/src/audit` |
| Web | Dashboard, auth, approvals, enrollment UI | `users`, `credentials`, `sessions`, `known_devices` | everything above (reads, commands) | detail | `crates/rackhand-hub/src/web` |
| Bus | In-process typed messages between hub systems: one bounded mpsc queue per consumer; report notices are coalesced, the rest are never dropped (7.3.8) | Nothing | tokio mpsc | contract | `crates/rackhand-hub/src/bus` |
| Relay | iroh relay with Rackhand admission and limits | `relay.db` (keys, usage) | iroh-relay, Net | detail | `crates/rackhand-relay` |
| Operator | Run assistant jobs with a `Runner` | Job workdirs | Net, Proto, rmcp | detail | `crates/rackhand-operator` |
| Probe | Collectors, buffer, reports, remote-mode tunnel endpoint | Report buffer, label table, config cache, update spool | Net, Proto, aya, OS APIs | detail | `crates/rackhand-probe` |
| Helper | Root-only file hashing, auth logs, containers, socket owners, binary updates, key updates | Probe binary slots, `authorized_keys` options it writes | OS APIs | detail | `crates/rackhand-probe/src/helper` |
| CLI | People-side client | CLI config and per-hub device keys | Net, Proto, rmcp | detail | `crates/rackhand-cli` |

**Composition roots:** `crates/rackhand/src/main.rs` (hub, relay, operator), `crates/rackhand-probe/src/main.rs`,
`crates/rackhand-cli/src/main.rs`.

**Dependency rules:** policy crates (Detect, Runbook model) depend on nothing of ours. Hub systems never depend on Web.
Runbook completion reaches Incidents only through the Bus event `JobFinished`, so there is no Incidents to Actions to
Incidents cycle: Incidents sends `StartJob` commands to Actions; Actions publishes `JobFinished`; Incidents consumes it.

```mermaid
flowchart TD
  Web --> Actions & Policy & Registry & Library & Peers & MCP & Audit & Incidents
  MCP --> Actions & Policy
  Incidents -- StartJob --> Actions
  Actions -- JobFinished --> Bus
  Bus --> Incidents
  Actions --> Policy & Executor & Assist
  Executor --> SSH & Drivers & Net
  Peers --> Net & Registry & Policy & Actions
  Ingest --> Store
  Checks --> Drivers
  Incidents --> Detect & Notify
  Scheduler --> Bus
  Policy --> Store
  Registry --> Store
```

### 7.3 Contracts between systems

**Common rules for QUIC contracts.** Each contract is its own iroh connection with its own ALPN. The accepting side
looks up the caller's endpoint id in its registry for that ALPN and closes with application error `0x10 UNKNOWN_PEER`
if absent. Except where stated, messages are protobuf frames prefixed with a u32 big-endian length, at most 4 MB each.
The 4 MB limit is the size on the wire. Where a contract compresses a payload (reports and replay batches, zstd), the
receiver decompresses with a hard limit of 16 MB and closes with `0x15` if it is passed, so a small frame can't expand
without bound. The ALPN carries the major version; minor additions are new optional fields. Unknown enum values are
answered with an `unsupported` error, never a crash. Close codes: `0x10` unknown peer, `0x11` identity mismatch, `0x12`
unsupported version, `0x13` revoked, `0x14` rate limited, `0x15` frame too large.

#### 7.3.1 Join (`rackhand/join/1`)

The only ALPN that accepts unregistered endpoint ids. One bidirectional stream, one request, one response.

```rust
enum JoinRequest {
    Machine { token: String, facts: HostFacts, ssh_host_keys: Vec<SshHostKey>, mode: ProbeMode, access: Access },
                                              // ProbeMode: Local | Remote. Access: Managed | Monitor (no host keys for Monitor)
    Device  { invite_secret: String, device_name: String },
    Operator{ invite_secret: String, operator_name: String, runners: Vec<RunnerInfo> },
    Peer    { invite_secret: String, site: String, hub_version: SemVer, relays: Vec<RelayUrl> },
}
enum JoinResponse {
    Machine { machine_id: Ulid, config: ProbeConfig, access: Access, managed: Option<ManagedSetup>,
              hub_addrs: Vec<SocketAddr> },
    Device  { user: String, hub_site: String },
    Operator{ hub_site: String },
    Peer    { site: String, hub_version: SemVer, relays: Vec<RelayUrl> },
    Error   { code: JoinError, message: String }, // expired | used | wrong_kind | site_name_taken | rate_limited | invalid
}
// Present only for Access::Managed: what the installer needs to create the hub's accounts (7.3.7)
struct ManagedSetup { automation_pubkey: String, assistant_pubkey: Option<String>, sudoers: String,
                      commands: SignedPayload /* the first commands.json, hub-signed and versioned */ }
```

- Tokens and invite secrets are 128-bit random, single-use, stored hashed, and bound to a kind. Machine tokens are
  valid 60 minutes, device, operator and peer invites 24 hours.
- On success the caller's endpoint id is added to the registry for the matching ALPNs. A failed attempt counts against
  a limit of 10 per minute per remote address.
- A machine token is bound to the access level chosen in the dashboard; a request with a different `access` fails with
  `invalid`. `managed` is absent for access level `monitor`. `assistant_pubkey` is absent when the machine has role
  `hub` (D62).
- A token issued to change an enrolled machine's access level (7.3.12) is bound to that machine's id; the join then
  keeps the machine id and its history.
- Peer joins are pairwise: linking A with B and B with C doesn't link A with C. A peer join with a site name already
  known to the hub fails with `site_name_taken`.

#### 7.3.2 Probe and hub (`rackhand/probe/1`)

The probe dials its hub and keeps the connection open. Stream 0 (bidirectional) is control. Stream 1 (unidirectional,
probe to hub) carries live reports. Stream 2 (unidirectional, probe to hub, opened only while there is a backlog)
carries replay batches. QUIC orders bytes within a stream, so reports on each stream arrive in order.

```rust
// probe -> hub on stream 0
struct Hello { probe_version: SemVer, machine_id: Ulid, epoch: u64, os: OsInfo, boot_id: String,
               capabilities: Vec<Capability>, interfaces: Vec<IfaceInfo> /* name, mac, addrs */,
               label_table: Vec<LabelEntry> /* id: u32, labels: every label set of this epoch so far */ }
// hub -> probe on stream 0
struct Welcome { hub_version: SemVer, config: ProbeConfig, config_rev: u64, received: Option<EpochRanges>, server_time_ms: i64 }
struct Ack { epoch: u64, ranges: Vec<SeqRange> }      // SeqRange { from: u64, to: u64 }, inclusive, every range the hub has committed
// probe -> hub on stream 0
struct DataDropped { epoch: u64, from_seq: u64, to_seq: u64 } // the probe deleted these unsent reports (buffer full)
// hub -> probe on stream 0
struct ConfigUpdate { config: ProbeConfig, config_rev: u64 }
struct UpdateAvailable { version: SemVer, url: String, sha256: [u8; 32], signature: Vec<u8> }
struct KeysUpdate { payload: Vec<u8>, hub_signature: Vec<u8> } // signed by the hub's node key, relayed to the helper

// stream 1: one Report per interval. stream 2: ReplayBatch { reports: Vec<Report> } (at most 100 reports or 4 MB)
struct Report {
    epoch: u64, seq: u64, sampled_at_ms: i64,
    vitals: Vec<Sample>,                 // Sample { metric: u32 (catalogue id), labels_id: u32, value: f64 }
    label_sets: Vec<LabelEntry>,         // label sets added to the table since this connection's Hello
    services: Vec<ServiceState>,
    containers: Vec<ContainerState>,     // from the helper
    updates: Option<UpdateSummary>,      // at most every 6 h or on change
    events: Vec<ProbeEvent>,
    connections: Vec<ConnRecord>,        // aggregated per (container, exe, dest_ip, dest_port, proto) in the interval,
                                         // at most 500 tuples (below)
}
```

- **Epoch and seq.** The probe picks a random 64-bit `epoch` when it starts with an empty or missing buffer, and numbers
  reports from 1 within an epoch. If `Welcome.received` shows the hub already holds this epoch's seqs at or beyond the
  probe's next seq (a guest rolled back to a snapshot with a non-empty buffer), the probe starts a new epoch at once.
  A new epoch is recorded as `probe.epoch_changed` (info).
- **Received ranges.** The hub keeps, per machine and epoch, the set of committed seq ranges (merged, at most 64 ranges;
  older epochs are forgotten after 48 h). A report whose seq is already in a range is a duplicate and dropped. Any other
  seq is accepted, whether it arrives on stream 1 or stream 2, in any order between streams. A range the probe reports
  in `DataDropped` is merged into the set as closed, so a permanent gap doesn't use up a range. If the set would still
  pass 64 ranges, the hub closes the oldest gap, records it as `probe.data_gap`, and drops any report that arrives for
  it later.
- **Label tables.** A `labels_id` is an entry in the probe's label table for the current epoch. The probe keeps the
  table on disk next to its buffer, never reuses an id within an epoch, and starts a new epoch (once its buffer is
  empty) before the table passes 4096 entries. Every `Hello` carries the whole table, and a live report carries the
  entries added since that `Hello`. Stream 2 carries only reports sampled before the connection's `Hello` (a later
  report the hub never acked waits for the next connection), so every id they use is in the `Hello` table; reports on
  stream 1 arrive in order, so an id is always defined before it is used. A report
  therefore never depends on another report that is still buffered or was dropped. Entries belong to the epoch of the
  report or `Hello` that carries them. A new epoch starts with an empty table, so when the probe changes epoch after
  `Welcome` (the rollback case above), its reports define every label set again in `label_sets`. The hub stores the
  table per
  machine and epoch (`probe_labels`). A sample whose id it can't resolve is dropped and counted in
  `probe.unknown_labels` (info); the rest of the report is kept.
- **Connection tuples.** A report carries at most 500 connection tuples (setting, 7.8.1). Past that, the probe keeps
  the tuples with the most bytes and folds the rest into one record per container and executable with a count and
  byte total but no destination, and the report says so (`conn.overflow`, info, at most once an hour per machine).
- **Acks.** `Ack` lists the committed ranges; the probe deletes buffered reports inside them, and only those.
- **Gaps.** The hub never infers a gap from a seq jump. A gap is recorded (`probe.data_gap`) only when the probe sends
  `DataDropped` for reports it deleted unsent.
- **Durability.** The hub writes each report to `report_staging` (one row, the compressed frame) and commits before
  acking. Every 5 minutes and on shutdown, compaction appends the staged points to each series' open chunk row (created
  if needed) and deletes the staged rows in the same transaction. On start the hub compacts anything left in staging.
- **Replay.** While the backlog is non-empty, the probe sends live reports on stream 1 and old ones on stream 2. Replay
  is limited to 2 MB/s per probe and 20 MB/s across the hub, and staging to 512 MB; past those limits the hub stops
  reading stream 2 (QUIC flow control holds the probe back, and the probe keeps the reports buffered). Stream 1 is never
  delayed. Reports older than 10 minutes feed history and baselines but don't open threshold incidents. When backfilled
  points land in a minute or hour that was already rolled up, that range is marked dirty and rolled up again.
- **Rate limits.** Stream 1: 1 report per second, burst 10. Excess closes with `0x14`.
- **Clock.** The hub stores `sampled_at_ms` and its receive time. It keeps a clock offset per machine (the median of
  receive time minus `sampled_at_ms` over the last 20 live reports) and places every sample at `sampled_at_ms` plus
  that offset. Rule windows (7.6.1) use this corrected time, so a replayed batch that arrives in one burst still lands
  on the times it was sampled. An offset over 30 s raises a `clock_skew` warning.
- **Errors.** `0x11` when the endpoint id isn't the one registered to `machine_id`; `0x12` (the probe keeps buffering
  and retries hourly); `0x13` (the probe stops and exits with code 3).
- **Reconnect.** Exponential backoff from 1 s to 60 s with jitter.
- **Remote mode.** A probe enrolled with `mode = Remote` also accepts `rackhand/tunnel/1` connections from its pinned hub
  only, and splices each tunnel stream to `127.0.0.1:22` only (D60). A remote-mode probe at access level `monitor`
  accepts no tunnel connections at all.

#### 7.3.3 Probe and helper (local socket)

The helper runs as root (a separate service). Linux: `/run/rackhand-helper/helper.sock`, mode 0660, group
`rackhand-probe`, peer checked with `SO_PEERCRED` equal to the `rackhand-probe` user. Windows: a named pipe whose ACL
allows only `NT SERVICE\RackhandProbe`. Newline-delimited JSON, one request per line.

**Who owns what.** Nothing root reads as a trust anchor or executes is writable by the probe user:

| Path | Owner and mode | Holds |
| --- | --- | --- |
| `/run/rackhand-helper/` | root, 0755 | The socket and the update guard's copy of the binary |
| `/usr/local/lib/rackhand/` | root, 0755 | Binary slots and the command wrapper |
| `/etc/rackhand-probe/probe.toml` | root, 0644 | The hub ticket (which holds the pinned hub endpoint id) and the access level |
| `/etc/rackhand/commands.json` | root, 0644 | The command list (7.3.7) |
| `/var/lib/rackhand-helper/` | root, 0700 | Last applied key version |
| `/var/lib/rackhand-run/` | root, 0700 | The command wrapper's state: last applied command list version, detached step output (`jobs/`), received files (`incoming/`) |
| `/run/rackhand-probe/` | `rackhand-probe`, 0755 | `probe.state` |
| `/var/lib/rackhand-probe/` | `rackhand-probe`, 0700 | Node key, buffer, label table, config cache, update spool |

The helper reads the pinned hub id only from `probe.toml`. `rackhand-probe set-hub` and the installer are the only
writers of that file and both need root. On Windows the same split is `C:\Program Files\Rackhand` and
`C:\ProgramData\Rackhand\helper` (SYSTEM and Administrators only) against `C:\ProgramData\Rackhand\probe` (the probe's
service account).

The hub's own host is also a managed machine, so the same rule is applied there against the hub user: the hub's data
directory `/var/lib/rackhand/` belongs to `rackhand-hub`, and nothing in the table above lives under it. That is why
the wrapper's state has a directory of its own.

```rust
enum HelperRequest {
    Ping,
    HashFiles,                                   // the list is compiled in plus a root-owned extras file; never from the socket
    AuthEventsSince { cursor: Option<String> },
    Containers,                                  // Docker and Podman sockets, read-only calls only
    SocketOwners { inodes: Vec<u64> },           // sampling fallback: inode -> pid, exe, user, container
    ContainerOf { cgroup_ids: Vec<u64> },        // eBPF mode: cgroup id -> container name
    ProcessScan,                                 // sampling fallback: processes whose exe is in a watched location
    UpdatesStatus,                               // last package-list refresh result (below)
    ApplyUpdate { version: SemVer, sha256: [u8; 32], signature: Vec<u8> }, // no URL or path: the file is read from the spool
    ApplyKeys { payload: Vec<u8>, hub_signature: Vec<u8> },
}
enum HelperResponse {
    Pong { version: SemVer },
    Hashes { files: Vec<FileHash> },             // path, exists, sha256, mode, uid, gid, mtime
    AuthEvents { events: Vec<AuthEvent>, cursor: String },
    Containers { items: Vec<ContainerState> },   // id, name, image, state, health, restart_count, started_at
    SocketOwners { owners: Vec<SocketOwner> },
    ContainerNames { names: Vec<(u64, String)> },
    Processes { items: Vec<ProcInfo> },          // pid, ppid, exe, user, started_at
    Updates { summary: UpdateSummary, refreshed_at_ms: i64 },
    UpdateStarted, KeysApplied,
    Error { code: String, message: String },
}
```

- **Probe privileges.** Linux with systemd: the probe runs as `rackhand-probe` with `AmbientCapabilities` and
  `CapabilityBoundingSet` set to `CAP_BPF CAP_PERFMON` (plus `CAP_SYS_RESOURCE` on kernels before 5.11 for the memlock
  limit), `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`, and write access only to its buffer
  and state directories. Kernels without `CAP_BPF` (before 5.8) get no capabilities and use sampling. OpenRC (Alpine,
  LXCs): no capabilities, sampling only. Windows: the virtual service account `NT SERVICE\RackhandProbe` with no extra
  privileges. The helper is the only root process.
- The helper never returns file contents. `AuthEvent`: time, kind (`ssh_login`, `ssh_failed`, `sudo`, `su`,
  `user_added`, `group_changed`, `logon`), user, source IP, method; on Windows only logon types 2, 3 and 10.
- **Package lists.** Every 6 hours, at `nice 19` and `ionice idle`, the helper runs a fixed command set to refresh
  package lists and compute pending updates (`apt-get update` then `apt-get -s upgrade` with the security origin
  marked; `apk update` then `apk version -l '<'`; on Windows the Windows Update Agent search). The probe reads the result
  with `UpdatesStatus`. Patch jobs are selected from this data (7.5.3).
- **Updates.** The probe, not the helper, downloads the release file named in `UpdateAvailable` into its spool
  (`/var/lib/rackhand-probe/update/`, one file, at most 64 MB), so no network access happens as root and no URL or path
  crosses the socket. On `ApplyUpdate` the helper opens that one fixed file without following links, copies it into the
  inactive slot (`/usr/local/lib/rackhand/probe-a` or `probe-b`), and checks the copy: it refuses any version lower
  than the one installed (downgrades only by a local reinstall) and verifies the sha256 and the minisign signature
  against the compiled-in release keys (current or standby, section 13). A file that fails is deleted from the slot.
  The helper then copies the current, known-good binary to `/run/rackhand-helper/update-guard` and starts it as a
  separate transient unit (`systemd-run --unit=rackhand-update-guard`, an OpenRC one-shot, or a Windows scheduled task)
  with `update-guard <old-slot> <new-slot>`. The guard points `/usr/local/lib/rackhand/rackhand-probe` at the new slot,
  restarts the helper and probe services, and waits up to 2 minutes for the probe's state file
  (`/run/rackhand-probe/probe.state`) to say `connected` with the new version. If it doesn't, the guard points back to
  the old slot and restarts both. The state file is written by the probe user, so the guard treats it only as a signal:
  a probe that lies in it can keep or lose a correctly signed version and nothing else. Because the guard runs the old
  binary, a broken new helper can't block the rollback. The probe never writes its own binary. The download needs the
  machine to reach the URL; machines with no route to it stay on their version and show as `update_unreachable` (info).
- **Version skew.** Probe and helper must be the same version; on mismatch the probe runs without the helper's features
  and reports `helper_version_mismatch`.
- **Keys.** `ApplyKeys` carries a payload signed by the hub's node key (the id pinned in the root-owned `probe.toml`)
  that can only rewrite the `from=` option and the key lines of the `rackhand` and `rackhand-ai` users'
  `authorized_keys`. The payload holds a version (monotonic per machine) and an expiry (at most 1 hour after signing);
  the helper stores the last applied version and refuses any payload that is older, equal or expired, so a replayed
  payload can't restore rotated keys. The same shape, `SignedPayload { payload, hub_signature }` with a version and an
  expiry, is used for the command list (7.3.7). On a machine at access level `monitor` the helper refuses `ApplyKeys`:
  there are no hub accounts to give keys to.

#### 7.3.4 Hub and peer hub (`rackhand/peer/1`)

```rust
struct PeerHello { site: String, hub_version: SemVer, relays: Vec<RelayUrl> }
// unidirectional stream, every 30 s
struct SiteSummary {
    site: String, generated_at_ms: i64,
    machines: Vec<MachineSummary>,        // id, name, kind, health (ok|warning|critical|silent|quarantined|maintenance), last_seen_ms
    open_incidents: Vec<IncidentSummary>, // id, severity, title, machine_id, opened_at_ms
    hub_health: HubHealth,                // version, db_ok, disk_free_pct, operators_online, notifiers_ok, self_check_ok
    peers_seen: Vec<PeerSeen>,            // other peers this hub can reach and when it last heard from them
    audit_head: [u8; 32],                 // latest audit hash, an external anchor
}
// bidirectional streams, one request each
enum PeerQuery { Vitals { machine: Ulid, metric: String, labels: Labels, from_ms: i64, to_ms: i64, step_s: u32 },
                 Incident { id: Ulid }, Machine { id: Ulid }, JobLog { id: Ulid } }
enum PeerAnswer { Vitals(Series), Incident(IncidentDetail), Machine(MachineDetail), JobLogChunk { data: Vec<u8>, last: bool }, Denied(String) }
struct ActionRequest { request_id: Ulid, requested_by: String, runbook: String, target: Ulid, params: Params, reason: String }
enum ActionRequestStatus { Queued, NeedsApproval, Running { job: Ulid }, Done(JobOutcome), Rejected(String) }
struct PeerUnlink { reason: String }
```

- **Query allow-list per peer.** Default: `Vitals`, `Machine`, `Incident` allowed; `JobLog` denied (job output can
  contain credentials). At most 10 queries per second per peer.
- **Requests.** The owning hub treats an `ActionRequest` like a local request at autonomy level 1: it always needs an
  approval on the owning hub unless that hub's policy for the runbook sets `peer_requests = "auto"`. The status is sent
  on the request's stream each time it changes until a terminal state; if the stream breaks, the requester re-asks
  with the same `request_id` (idempotent).
- `requested_by` is informational; the owning hub never treats it as an authenticated user.
- **Unlink.** Either side sends `PeerUnlink` (or just removes the peer); both remove the other's endpoint id. A removed
  peer gets `0x13` on the next connect.

#### 7.3.5 Hub and operator (`rackhand/operator/1`)

An operator host can be invited to several hubs and keeps one connection to each. Each hub sees it as its own operator.

```rust
struct OperatorHello { operator_version: SemVer, runners: Vec<RunnerInfo>, max_jobs: u32, running: Vec<Ulid> }
struct JobOffer {
    job_id: Ulid, incident_id: Ulid, playbook: String, playbook_rev: u64,
    brief_markdown: String, allowed_tools: Vec<String>, autonomy: u8, hosts: Vec<Ulid>,
    deadline_ms: i64,   // default now + 30 min, max 2 h
    max_turns: u32,     // default 60
    job_token: String,  // valid until deadline or job end
}
enum JobReply { Accepted, Declined { reason: String } }
struct JobEvent { job_id: Ulid, at_ms: i64, kind: JobEventKind, text: String } // message|tool_call|tool_result|error
struct JobDone  { job_id: Ulid, outcome: Outcome, summary: String }            // resolved|needs_human|failed|timed_out
struct JobCancel { job_id: Ulid, reason: String }                              // hub -> operator
```

- The operator declines past `max_jobs`. The hub tries its other operators in configured order. With no operator, or 3
  declines, the incident goes to a person (state `human`) and a callout says so.
- A job token works only on connections from the endpoint id of the operator that accepted the offer; from any other
  endpoint it is refused with `out_of_scope`.
- **Disconnects.** If the hub connection drops mid-job, the operator keeps the runner for up to 5 minutes while it
  reconnects; tool calls fail with `hub_unreachable` meanwhile. After 5 minutes it kills the runner and reports
  `failed` on reconnect. When the hub restarts, the operator's `OperatorHello.running` lets the hub reattach jobs whose
  tokens are still valid.
- **Transcripts.** `JobEvent`s are stored through Actions in `assistant_transcripts`, at most 5 MB per job (later events
  are counted, not stored), kept 90 days or until the size budget trims them (7.4.1).
- The operator never holds SSH keys or hub secrets.

**Runner interface** (operator side):

```rust
#[async_trait]
pub trait Runner: Send + Sync {
    fn info(&self) -> RunnerInfo;                          // name ("claude-code"), version
    async fn start(&self, job: &JobSpec, mcp_bridge: Command) -> Result<RunHandle, RunnerError>;
}
// JobSpec is JobOffer without job_token (the token stays inside the MCP bridge process).
pub struct RunHandle { pub events: mpsc::Receiver<JobEvent>, pub cancel: CancellationToken, pub done: oneshot::Receiver<Outcome> }
```

The Claude Code runner writes the brief to a temporary work directory, writes an MCP config whose only server is
`rackhand operator mcp-bridge --hub <id> --job <job_id>` (stdio, bridging to `rackhand/mcp/1`), and runs
`claude -p --output-format stream-json --mcp-config <file> --allowedTools "mcp__rackhand__*" --max-turns <n>` with no
other tools allowed. The runner process runs as the unprivileged `rackhand-operator` user with a configuration
directory of its own that holds only the AI provider credential set up at `rackhand operator join`, so no MCP server,
tool or setting already present on the host is loaded. It parses stream-json
into `JobEvent`s and kills the process at the deadline (spike S5 confirms the exact flags, including the one that
limits the run to the given MCP config).

#### 7.3.6 MCP (`rackhand/mcp/1`)

Framing: one bidirectional stream per MCP session, carrying newline-delimited JSON-RPC 2.0 (MCP stdio framing). The
first line is `{"auth": "<job token or device key>"}`. Callers:
- **Operator jobs**, through `rackhand operator mcp-bridge`, with a job token.
- **People**, through `rackhand-cli mcp --hub <site>`, a stdio MCP server on their computer that dials the hub with its
  device key (7.3.1) and a personal MCP key (scope `read` or `read_request`, expiry default 90 days, at most 1 year).
  A key never grants more than its user's role does in the dashboard (7.7.2): `read_request` on a viewer's account
  works as `read`.

Machines are named by id or `site/name`.

| Tool | Args | Returns | Who and rules |
| --- | --- | --- | --- |
| `list_machines` | site?, health? | summaries | all |
| `get_machine` | machine | OS, policy, services, containers, updates, open incidents | all |
| `get_vitals` | machine, metric, labels?, from, to, step? | series (at most 2000 points) | all |
| `list_incidents` | state?, severity?, machine? | incidents | all |
| `get_incident` | id | timeline, events, job logs, notes | all |
| `list_security_events` | machine?, since?, kind? | events | all |
| `get_connections` | machine, since | connection records with intel verdicts | all |
| `run_diagnostic` | machine, name, args | output (at most 256 KB) | `read_request` keys and jobs; names from section 7.8.3; runs as the automation identity; job tokens limited to job hosts; with a personal key, the diagnostics marked sensitive in 7.8.3 are gated (below) |
| `exec` | machine, command, reason, approval_id? | exit code, stdout, stderr (each at most 256 KB) | jobs only; machine in job hosts; runs as the assistant identity; gated (below) |
| `list_runbooks`, `get_runbook` | name? | definitions | all |
| `run_runbook` | name, target, params, reason, approval_id? | job id, status | `read_request` keys and jobs; gated (below) |
| `list_playbooks`, `get_playbook` | name? | playbooks | all |
| `propose_library_change` | kind, name, content, reason | draft id | `read_request` keys and jobs; applied only from the dashboard |
| `get_approval` | id | state | all |
| `add_incident_note` | incident, text | note id | `read_request` keys and jobs |
| `finish_job` | outcome, summary | ok | jobs only |

**Gating.** For `exec` and `run_runbook`, the hub computes what the call needs from the autonomy level, the action's
risk, the target's roles and the policy (section 7.6.8). Calls with a personal MCP key are always treated as level 1:
every `run_runbook` from a device needs an approval, so a stolen laptop and key can't change anything alone. For the
same reason a personal key needs an approval for the sensitive diagnostics (`journal` and `docker_logs`, whose output
can hold secrets); other diagnostics run without one. If no approval is needed, the call runs. Otherwise it returns at
once with error `needs_approval {approval_id}`; the approval stores who asked (the job or the key), the exact tool,
target and arguments, for `run_runbook` the runbook's revision, and the SHA-256 hash of all of these. After a person
approves in the dashboard, the caller repeats the same call with `approval_id`; the hub runs it only if the caller is
the one that asked, the hash matches (a runbook edited since then no longer matches) and the approval is unused, then
marks it used. There is no tool that approves or rejects.

**Enforcement.** The hub checks `allowed_tools` from the job's playbook on every call, not just the runner's flags. All
output from machines is returned as `{"untrusted_output": "..."}`. Errors: `out_of_scope`, `tool_not_allowed`,
`needs_approval`, `approval_rejected`, `approval_mismatch`, `deadline_exceeded`, `machine_unreachable`, `machine_busy`,
`monitor_only` (the call needs an account on a machine at access level `monitor`), `machine_quarantined` (7.5.6),
`invalid_args`, `rate_limited` (over 60 calls per minute per token).

#### 7.3.7 Hub and machines over SSH

| Identity | Unix user | Shell | Key | sudo |
| --- | --- | --- | --- | --- |
| Automation | `rackhand` | `/bin/sh` | hub key `automation` (Ed25519) | `/etc/sudoers.d/rackhand`: only the command wrapper (below), `NOPASSWD` |
| Assistant | `rackhand-ai` | `/bin/bash` | hub key `assistant` (Ed25519) | `ALL`, with `Defaults:rackhand-ai log_output, iolog_dir=/var/log/rackhand/sudo-io` |
| Probe | `rackhand-probe` | `nologin` | none | none |

- **Access levels.** The automation and assistant identities exist on every machine enrolled at access level
  `managed`, which is the default: the automation identity runs routine runbooks through the allow-list, and the
  assistant identity is the one an assistant uses to fix what a runbook couldn't. A machine enrolled at `monitor` has
  only the probe user and the helper. The hub holds no key for it, needs no SSH server on it, and can run no command
  on it (7.3.12).
- **Keys** are generated at hub bootstrap, held in the Vault, and installed with
  `from="<hub addresses>",no-agent-forwarding,no-X11-forwarding,no-port-forwarding`. On remote-mode machines the SSH
  connection arrives through the probe's tunnel from `127.0.0.1`, so `from=` is `127.0.0.1,::1` there.
- **No assistant account** on machines with role `hub`. Assistant `exec` on roles `operator`, `relay` and `hypervisor`
  is always high risk.
- **Host keys** come through the authenticated join (7.3.1) and are pinned. A changed host key blocks actions and opens
  a critical incident; an admin accepts the new key with step-up.
- **Command execution.** Runbook commands are argument arrays. The hub quotes each argument POSIX-style (wrap in single
  quotes, replace `'` with `'\''`), joins them with spaces, and sends the string as the SSH exec request, which the
  user's `/bin/sh` runs. Parameters substitute whole arguments only and are validated against their declared type and
  pattern first. A pattern must match the whole value, and a value that starts with `-` is refused unless the parameter
  declares `allow_leading_dash = true`, so a parameter can't turn into an option of the command. Assistant `exec` sends
  the given command string as-is (it's the assistant's shell, logged).
- **Command wrapper.** The automation user's sudo allow-list has one entry:
  `rackhand ALL=(root) NOPASSWD: /usr/local/lib/rackhand/run`. That fixed path is the command wrapper: the probe
  binary started in its `run-cmd` mode, which is separate from the probe daemon (`rackhand-probe run`) and shares no
  state with it. The wrapper reads `/etc/rackhand/commands.json` (root-owned, 0644), which lists each allowed command as
  an argument template with a regular expression per parameter, generated from the enabled runbooks. It matches the
  requested argument list against the templates, applies the same whole-value and leading-dash rules as the hub,
  refuses anything that doesn't match exactly, and executes the match directly (no shell). This works with any sudo
  version. Runbook `ssh` steps call `sudo /usr/local/lib/rackhand/run <args...>` for steps that need root.
- **Command list updates.** The first `commands.json` arrives in the join response (7.3.1). Later versions are
  installed by the wrapper's built-in subcommand `run install-commands`, which reads a `SignedPayload` from standard
  input and writes the file only if the hub's signature verifies against the id pinned in `probe.toml`, the version is
  newer than the last one applied, and the payload hasn't expired (the rules for keys, 7.3.3). The automation key
  alone therefore can't widen its own allow-list: that takes the hub's node key. Sending a new list is the high-risk
  runbook `sudoers-refresh`.
- **Detached steps.** A step marked `detached = true` is started with `run job-start <job>/<step> -- <args...>`. The
  wrapper matches the arguments as usual, starts the command in its own unit (`systemd-run`, an OpenRC supervised
  one-shot, or a Windows scheduled task), writes its output and exit code under `/var/lib/rackhand-run/jobs/`, and returns
  at once. The hub polls `run job-status <job>/<step> <offset>` every 5 seconds for the state, the exit code and new
  output, and `run job-clean` removes the files once the result is recorded. The command doesn't depend on the SSH
  session, so a hub restart, a dropped tunnel or a network break doesn't stop it; the hub picks the step up again by
  polling. A detached step that passes its timeout isn't killed: the job ends `timed_out`, an incident opens, and the
  machine stays locked until the unit exits and its result is recorded. A person can stop it from the job page
  (`run job-stop`, an approval at normal risk). The package steps of the built-in patch runbooks are detached, so a
  package manager is never cut off in the middle of a transaction. These subcommands are built into the wrapper; apart
  from the template-matched command given to `job-start`, they take only a job and step id that the hub generated.
- **Alpine.** The installer adds `sudo` and `bash` with apk.
- **Windows.** OpenSSH Server (installed if missing). `sshd_config` gets `Match User rackhand,rackhand-ai` with
  `AuthorizedKeysFile __PROGRAMDATA__/rackhand/keys/%u`, placed before the default `Match Group administrators` block
  so the assistant key can't log in as other administrators. `rackhand` (local administrator) has
  `ForceCommand` running `C:\Program Files\Rackhand\dispatch.ps1`, which accepts only `<script-name> <json-args>` for
  scripts in `C:\Program Files\Rackhand\scripts` and validates the args against each script's parameter schema.
  Runbook `ssh` steps targeting Windows use `windows_script` and `windows_args` instead of `cmd`. `rackhand-ai` is a
  local administrator with PowerShell transcription to `C:\ProgramData\Rackhand\transcripts`. Detached steps run the
  script as a scheduled task through the same dispatcher. A Windows machine at access level `monitor` gets none of
  this: no OpenSSH Server is installed and no accounts are created.
- **Remote-mode machines** are reached through a tunnel to their probe (7.3.2), then the same SSH.
- **Agentless machines** have no SSH identities; actions use driver APIs.
- **Monitor machines** have no SSH identities either. Steps of kind `ssh` and `transfer` to them, `run_diagnostic` and
  assistant `exec` fail with `monitor_only`. What can still act on a monitor machine is listed in
  7.3.12.

#### 7.3.8 In-process interfaces

```rust
// Drivers
#[async_trait]
pub trait Driver: Send + Sync {
    fn kind(&self) -> DriverKind;                                   // icmp, tcp, http, dns, tls, proxmox, truenas, redfish, snmp
    async fn poll(&self, target: &DriverTarget) -> Result<DriverReading, DriverError>; // metrics + states
    async fn call(&self, target: &DriverTarget, op: DriverOp) -> Result<DriverOpResult, DriverError>; // snapshot, rollback, firewall, clone...
}
// Notifiers
#[async_trait]
pub trait Notifier: Send + Sync {
    fn id(&self) -> &str;
    async fn send(&self, msg: &Callout) -> Result<(), NotifyError>; // NotifyError::{Transient{retry_after}, Permanent(String)}
}
// Store writes go through one task; callers send commands and await the result
pub enum WriteCmd {
    // Ingest
    StageReport(StagedReport), CompactStaged, PutProbeLabels(Vec<ProbeLabelRow>), PutEvents(Vec<Event>),
    PutConnRecords(Vec<ConnRecordRow>),
    UpdateBaselines(Vec<BaselineUpdate>), PutConnBaseline(Vec<ConnBaselineRow>), MarkRollupDirty(DirtyRange),
    // Checks
    PutCheck(CheckRow), PutCheckResults(Vec<CheckResult>),
    // SSH
    PutHostKey(HostKeyRow),
    // Incidents
    UpsertIncident(IncidentWrite), AppendIncidentEvent(IncidentEventRow), PutSilence(SilenceRow),
    // Actions
    CreateJob(JobRow), UpdateJobStep(JobStepRow), FinishJob(JobFinish), AppendTranscript(TranscriptRow),
    // Policy
    PutPolicy(PolicyRow), CreateApproval(ApprovalRow), DecideApproval(ApprovalDecision), UseApproval(Ulid),
    PutQuarantineRule(QuarantineRuleRow), PutWindow(WindowRow),
    // Registry, Peers, Assist, MCP, Web
    RegistryChange(RegistryChange), PutPeerSummary(PeerSummaryRow), PutJobToken(JobTokenRow), PutMcpKey(McpKeyRow),
    PutUser(UserRow), PutCredential(CredentialRow), PutSession(SessionRow), PutKnownDevice(KnownDeviceRow),
    // Library, Vault, Notify, Audit, Scheduler
    CreateLibraryItem(LibraryItemRow), PutLibraryRevision(LibraryRevisionRow), PutDraft(DraftRow), PutSecret(SecretRow),
    PutNotification(NotificationRow), AppendAudit(AuditRow), AppendAuditCheckpoint(AuditCheckpoint),
    PutScheduleState(ScheduleStateRow),
    // Store maintenance (retention covers every table with a retention rule in 7.4.1)
    RetentionBatch(RetentionTarget), Rollup(Tier, TimeRange),
}
pub struct StoreWriter { tx: mpsc::Sender<(WriteCmd, oneshot::Sender<Result<WriteAck, StoreError>>)> }
// Policy
pub fn decide(action: &ProposedAction, ctx: &PolicyContext) -> Decision;
pub enum Decision { Allow, NeedsApproval { risk: Risk, step_up: bool }, Deny(DenyReason) }
// Bus events
pub enum BusEvent { ReportIngested { machine: Ulid }, IncidentChanged { id: Ulid }, JobFinished { job: Ulid, outcome: JobOutcome },
                    ApprovalDecided { id: Ulid, approved: bool }, Tick(ScheduleKind) }
```

`WriteCmd` lists the write operations; each system only sends commands for the tables it owns (7.2). Systems other
than Ingest raise events (`notifier_failed`, `git_mirror_failed`, `ssh.host_key_changed`, `quarantine_failed`,
`clock_skew` and others) through `Ingest::raise_event`, so Ingest stays the single writer of `events`.

**Bus delivery.** Each consumer has its own bounded queue (capacity 1024). Two rules keep a slow consumer from
stalling ingest or locking two systems against each other:

- `ReportIngested` is a notice, not a record. Each consumer holds a set of machines with fresh data; a notice adds the
  machine to the set and never waits, and the consumer reads the data itself (from the recent window, 7.4.1) when it
  gets to that machine. Any number of notices for one machine collapse into one, so Ingest never waits on Incidents and
  live reports are acked however busy rule evaluation is.
- Every other event records a state change that is already committed to the database before it is sent (a finished
  job, a decided approval, a changed incident). Senders await space for these, except Actions sending `JobFinished`:
  Actions and Incidents send to each other, so Actions sends without waiting and leaves a full queue to the
  reconciliation below. Nothing is lost either way, because the database row is the record.

Because a crash can lose queued messages, Incidents also reconciles on start and every minute: any incident in
`automation` or `assistant` whose job has finished is advanced as if `JobFinished` had arrived.

#### 7.3.9 Notifiers

- **Discord webhook:** POST `{username: "Rackhand", embeds: [{title, description, color, url, fields, timestamp}]}`.
  Colors: critical red, warning amber, resolved green. Description at most 2000 characters. `url` points to the
  incident on the dashboard when a public dashboard URL is configured. HTTP 429 `retry_after` is respected.
- **SMTP:** STARTTLS or implicit TLS, plain text plus HTML, subject `[Rackhand] <SEVERITY> <site>/<machine>: <title>`.
- Retries at 1, 5 and 15 minutes, then failed. A failed notifier raises `notifier_failed` (warning) on the dashboard and
  through any other notifier that works.
- Callouts carry no secrets, no command output and no links that act without signing in.

#### 7.3.10 Relay

- `rackhand relay` embeds the iroh relay server. HTTPS on 443 (ACME via Let's Encrypt or a provided certificate) and
  iroh's QUIC address discovery port (confirmed in spike S2).
- **Modes.** `private`: only endpoints that present a valid relay key are admitted. `public`: anyone is admitted; keyed
  endpoints get their key's priority.
- **Keys.** `rackhand relay key create --name <n> --priority <normal|high> --max-endpoints <n>
  --expires <date>` prints a token signed by the relay's key. A hub presents it when it registers;
  the relay binds it to the first `max-endpoints` endpoint ids that use it (default 1).
- **Limits.** One rate applies to every connection the relay serves, set by the operator with `rackhand relay run
  --rate <bits/s>`: 1 Mbit/s by default in `public` mode and none in `private` mode. A relay serves at most 500
  concurrent endpoints. At capacity, high-priority keyed endpoints are admitted first, then normal keyed, then unkeyed.
  iroh-relay has no per-endpoint rate or byte counter, so there are no per-key rates and no daily quotas (S2, D110).
- **Relay lists.** A hub may subscribe to URLs returning TOML `[[relay]] url, name, region, operator`. Fetched daily
  over HTTPS, at most 100 entries, invalid entries skipped, status shown on the dashboard. Listed relays are used after
  the hub's own relays, always as public, and never get keys.

#### 7.3.11 Tunnels and transfers (`rackhand/tunnel/1`, `rackhand/xfer/1`)

- **Who may open one:** devices (with an account on the owning hub, role responder or admin, tunnel ports allowed by
  the target's policy, default 22), runbook jobs (`tunnel` and `transfer` steps), hubs reaching their remote-mode
  probes, and peer hubs sending a backup to a hub that granted them a backup quota. The caller dials the hub that owns the target machine directly (iroh picks direct or relay).
- **Tunnel:** `TunnelOpen { target: Ulid, port: u16, purpose: String }` on a bidirectional stream; the hub checks
  policy, opens TCP to the machine (or a tunnel to its remote-mode probe) and splices bytes. Errors: `out_of_scope`,
  `port_not_allowed`, `machine_unreachable`.
- **CLI:** `rackhand-cli connect <site>/<machine> <port>` (stdin/stdout, for SSH `ProxyCommand`);
  `rackhand-cli forward <local-port> <site>/<machine>:<port>` binds 127.0.0.1 only.
- **Transfer:** content-addressed, BLAKE3-verified, 1 MiB chunks, resumable from the last verified chunk.
  `rackhand-cli send <path> <site>/<machine>:<dest>` and the runbook `transfer` step. The sender streams to the hub that
  owns the target; that hub writes to the machine over SSH as `rackhand`, through the wrapper command
  `run receive <dest>`, which only accepts destinations under the policy's `transfer_roots` (default
  `/var/lib/rackhand-run/incoming`), writes to a temporary file, checks the hash, then renames it into place (owner root,
  mode 0640). Partial files stay in the temporary location for resume.
- **Streams for backup tools:** runbook steps `zfs-replicate`, `pbs-sync` and `restic-backup` don't use files. The
  source hub runs the sending command over SSH (for example `run zfs-send <dataset>@<snap>`), streams its output over
  `rackhand/xfer/1` to the destination hub, which pipes it into the receiving command over SSH (`run zfs-recv
  <dataset>`). PBS sync and restic use a `tunnel` step to reach the remote server's port instead. Bulk transfers use direct paths
  only unless `allow_relay = true`; with only a relay path, a transfer waits and raises `bulk_waiting_direct_path`
  (info) after 10 minutes. Path detection is spike S3.

#### 7.3.12 Enrollment

```mermaid
sequenceDiagram
  participant U as Admin (dashboard)
  participant H as Hub
  participant M as Machine (installer)
  U->>H: Add machine (OS, name, site, policy, local or remote, managed or monitor)
  H-->>U: one-line command with hub ticket + token (60 min)
  U->>M: run command as root
  M->>M: download probe from release URL, verify minisign signature
  M->>H: rackhand/join/1 Machine{token, facts, host keys, mode, access}
  H-->>M: machine_id, config, hub addresses, and for managed the keys, sudoers and command list
  M->>M: write probe.toml, install and start services
  opt managed
    M->>M: create users, install keys, sudoers (visudo -c) and commands.json
  end
  M->>H: rackhand/probe/1 Hello
  opt managed
    H->>M: SSH test as rackhand, and rackhand-ai unless role hub (sudo -n true)
  end
  H-->>U: machine enrolled and healthy
```

- **Linux:** `curl -fsSL https://github.com/StrangeMatterStudio/Rackhand/releases/download/v<X>/install.sh | sudo sh -s
  -- --ticket <ticket> --token <token>`. Trust in the script rests on GitHub's TLS. A POSIX shell can't check minisign
  signatures, so every release also ships a small static verifier, `rackhand-verify`: the script holds the verifier's
  SHA-256 for its own release, checks the downloaded verifier against it, and the verifier then checks every other
  binary against the two pinned release keys (section 13, D105); trust in the hub comes from the endpoint id in the ticket. The offline variant fetches
  from the hub over its self-signed HTTPS and checks the script against a SHA-256 the dashboard puts in the command:
  `curl -fsSLk https://<hub>:8443/install.sh -o /tmp/rackhand-install.sh && echo '<sha256>  /tmp/rackhand-install.sh'
  | sha256sum -c - && sudo sh /tmp/rackhand-install.sh --ticket <ticket> --token <token>`.
- **Windows:** the PowerShell equivalent, which also installs OpenSSH Server if missing (managed only).
- **Access level.** The admin picks `managed` (the default) or `monitor` when adding a machine, and the Machine page
  shows it.
  - `managed`: the probe, the helper, and both hub accounts (7.3.7). Everything in this design applies.
  - `monitor`: the probe and the helper only. The machine reports vitals, services, containers, pending updates and
    security signals, and gets probe updates. The hub has no account on it, so the hub can run no command on it: no
    patching, no `ssh` or `transfer` steps, no diagnostics, no assistant `exec`, no in-guest quarantine. Patch selection
    skips it and pending updates are only reported. Two things still run as root on a monitor machine, both in the
    helper and neither taking a command from the hub: the fixed package-list refresh every 6 hours (7.3.3), and
    installing a probe release that is signed by the release keys.
  - A monitor machine that is a Proxmox guest can still be acted on from outside, through the hypervisor's API:
    snapshot, rollback, power, and guest-firewall quarantine and release. These always need an approval in the
    dashboard, whatever the runbook's autonomy level, and no automatic policy (auto-quarantine, auto-rollback) ever
    applies to a monitor machine.
  - Tunnels and port forwards to a local monitor machine follow its policy: they carry a person's or a backup tool's
    own connection and use no hub account. A remote-mode monitor probe accepts none (7.3.2).
  - Changing the level, in either direction, is done on the machine. The dashboard issues a one-time command (a join
    token bound to the machine's id and the new level); run as root, it adds or removes the users, keys, sudoers file,
    command list and, on Windows, the SSH configuration, and the machine keeps its id and history. The hub can't raise
    a machine from `monitor` to `managed` by itself, because it has no way in. That is the point of the level.
- **Agentless:** a dashboard form per driver. Credentials go into the Vault. HTTPS APIs (Proxmox, TrueNAS, Redfish) pin
  the certificate fingerprint seen when added (accepted by the admin), like SSH host keys.
- **Proxmox:** the probe installer plus an API token (`pveum user token add`) with the Rackhand role (7.8.6), one per
  cluster or standalone host, stored in the Vault through the join.
- **Guest binding.** The hub proposes which VM or LXC a machine is by MAC address (probe `interfaces` against the guest
  configs), and an admin confirms the match on the Machine page; a guest created by `provision-vm` or `provision-lxc`
  is bound by the runbook that created it. The confirmed binding (`proxmox_ref`) is then fixed. What a probe reports
  later never changes it: if the reported MACs stop matching the bound guest's configuration, the hub raises
  `machine.guest_binding_mismatch` (warning) and blocks every hypervisor-side action on that machine (snapshot,
  rollback, guest firewall, power) until an admin confirms a binding again. A probe that claims another guest's MAC
  therefore can't point those actions at the other guest. While a proposed match waits for confirmation, the patch
  precheck fails with `guest_binding_unconfirmed` unless the policy has `snapshot = optional`.
- **Devices, operators, peers:** an invite from the dashboard (endpoint ticket plus secret), used with
  `rackhand-cli login <invite>`, `rackhand operator join <invite>`, or the peer page.
- **Unenroll:** the high-risk runbook `unenroll` (or `rackhand-probe uninstall` locally) removes services, users, keys,
  the sudoers file and the command list; the hub revokes the endpoint id. A monitor machine has no account for the
  runbook to use, so it is unenrolled with `rackhand-probe uninstall` on the machine, or just revoked on the hub.

#### 7.3.13 Git mirror

- Layout: `runbooks/<name>.toml`, `playbooks/<name>.md`, `config/hub.toml`, `config/policies.toml`,
  `config/checks.toml`, `config/notifiers.toml`, generated `README.md`. Secrets appear only as `secret:<name>`.
- A pre-push scan refuses content containing any Vault secret value, PEM or OpenSSH private keys
  (`-----BEGIN [A-Z ]*PRIVATE KEY-----`), Discord webhook URLs (`discord(app)?.com/api/webhooks/`), AWS access keys
  (`AKIA[0-9A-Z]{16}`), or strings like `password = "..."` with a non-reference value.
- Push on every library or config change, debounced 30 s, commit message `<user>: <summary>`, deploy key in the Vault.
  A failed push raises `git_mirror_failed` (warning) and retries hourly. Restore: `rackhand hub restore-library <repo>`.

#### 7.3.14 Metrics endpoint

`GET /metrics` (Prometheus text format) behind a bearer token (`metrics_token` in the Vault), with the latest value of
each series as `rackhand_<metric>{site,machine,<labels>}` plus hub internals (section 12).

### 7.4 Data model

#### 7.4.1 Database

ULIDs for ids, Unix milliseconds (UTC) for times. SQLite in WAL mode at `/var/lib/rackhand/hub.db`, schema version in
`PRAGMA user_version`, migrations embedded and run at start.

| Table | Fields |
| --- | --- |
| `sites` | id, name (unique, `[a-z0-9-]{1,32}`), timezone (IANA), is_local |
| `machines` | id, site_id, name (unique per site), kind (`linux`, `alpine`, `windows`, `appliance`, `hypervisor`), os, address, mode (`local`, `remote`), access (`managed`, `monitor`), probe_endpoint_id, driver (appliances), roles (JSON array, closed set: `hub`, `operator`, `relay`, `hypervisor`, `storage`, `network`, `desktop`), tags (JSON array, free-form), policy_id, proxmox_ref (cluster, node, vmid, type), proxmox_ref_state (`none`, `proposed`, `confirmed`, `mismatch`), proxmox_ref_confirmed_by, enrolled_at, state (`pending`, `enrolled`, `revoked`), quarantine (`none`, `pending`, `applying`, `active`, `releasing`, `failed`) |
| `devices` | id, user_id, name, endpoint_id, created_at, last_seen_ms, revoked_at |
| `operators` | id, name, endpoint_id, runners (JSON), max_jobs, order, last_seen_ms, revoked_at |
| `peers` | id, site, endpoint_id, allowed_queries (JSON), backup_quota_bytes (0 = off), added_at, last_seen_ms, revoked_at |
| `peer_summaries` | peer_id, received_at_ms, summary (protobuf) |
| `join_tokens` | id, kind, hash, site_id, created_by, expires_at, used_at |
| `policies` | id, name, patch (`auto`, `approve-only`, `hold`), security_window, full_window, window_length_min (default 180), auto_reboot, auto_rollback (default false), snapshot (`required`, `optional`), quarantine (`approval`, `never`), expected_offline, connections (`full`, `summary`, `off`; default `summary` for role `desktop`, else `full`), transfer_roots, watch_internal, peer_requests (`approval`, `auto`), tunnel_ports, required_mounts (JSON), thresholds (JSON overrides) |
| `windows` | id, machine_id or tag, kind (`maintenance`), rrule (daily or weekly, start time, duration), timezone |
| `metric_keys` | id, name, unit, label_set (JSON) |
| `report_staging` | machine_id, epoch, seq, received_at_ms, frame (zstd protobuf) |
| `probe_labels` | machine_id, epoch, labels_id, metric_key_id (the probe's label table, 7.3.2) |
| `series_chunks` | machine_id, metric_key_id, tier (0, 1, 2), start_ms, end_ms, count, data (encoded as in Chunk encoding below; tiers 1 and 2 hold min, max, avg) |
| `events` | id, machine_id, at_ms, kind, severity, subject, data (JSON), job_id (if during a job) |
| `conn_records` | machine_id, bucket_ms (5-minute buckets), container (empty for host processes), exe, dest_ip, dest_port, proto, dest_asn, dest_country, verdict, bytes_out, count |
| `conn_baseline` | machine_id, container, exe, dest_asn, dest_country, dest_port, proto, first_seen_ms, last_seen_ms, count |
| `baseline_buckets` | machine_id, metric_key_id, kind (`hour_of_day`, `hour_of_week`), bucket (0 to 23, or 0 to 167), mean, var, n, frozen_until_ms |
| `checks` / `check_results` | id, kind, target, interval_s, machine_id (bound), settings / check_id, at_ms, ok, latency_ms, detail |
| `incidents` | id, machine_id, rule_id, dedupe_key, kind, severity, state (`open`, `automation`, `assistant`, `human`, `resolved`), title, opened_at, acked_at, acked_by, resolved_at, resolved_by |
| `incident_events` | id, incident_id, at_ms, kind, data |
| `silences` | id, machine_id or tag, rule_id or kind, until_ms, created_by, reason |
| `jobs` | id, kind (`runbook`, `assistant`), name, rev, target, params, requested_by, incident_id (if started for an incident), approval_id, state (`queued`, `waiting_approval`, `running`, `succeeded`, `failed`, `interrupted`, `cancelled`, `timed_out`), started_at, ended_at, outcome, resumable_step |
| `job_steps` | job_id, step_id, state, command (JSON), exit_code, stdout, stderr (each at most 1 MB), started_at, ended_at |
| `assistant_transcripts` | job_id, seq, at_ms, kind, text (at most 5 MB per job) |
| `approvals` | id, tool, target, args (JSON), runbook_rev (for `run_runbook`), args_hash (over requester, tool, target, args and revision), risk, step_up, requested_by, reason, state (`pending`, `approved`, `rejected`, `expired`, `used`), decided_by, decided_at, expires_at |
| `quarantine_rules` | id, name, severity_at_least, event_kinds, match (JSON: machine ids, tags, kinds, services), enabled, enabled_by, enabled_at |
| `library_items`, `library_revisions`, `library_drafts` | name, kind, origin (`builtin`, `user`), rev, content, author, created_at; drafts: proposed_by, reason, state |
| `notifications` | id, notifier, incident_id, at_ms, state, attempts, last_error |
| `secrets` | name, nonce, ciphertext, created_at, rotated_at |
| `ssh_host_keys` | machine_id, key_type, fingerprint, accepted_at, accepted_by |
| `users` | id, name, role (`viewer`, `responder`, `admin`), auth (`local`, `oidc`), oidc_subject, created_at, disabled_at |
| `credentials` | id, user_id, kind (`password`, `totp`, `passkey`), data (Argon2id hash, Vault reference, or WebAuthn credential), last_totp_step (the newest time step accepted, so a code is used once), created_at |
| `known_devices` | user_id, cookie_hash, first_seen_at, last_seen_at (browsers that have signed in to the account, 7.7.2) |
| `sessions` | id_hash, user_id, created_at, last_seen_at, step_up_at, expires_at |
| `mcp_keys` | id, user_id, device_id, scope (`read`, `read_request`), hash, expires_at, revoked_at |
| `job_tokens` | job_id, operator_id (the only endpoint that may use it), hash, hosts, tools, expires_at, revoked_at |
| `schedule_state` | kind, key, last_run_ms, next_run_ms |
| `audit_log` | seq, at_ms, actor, action, target, data, prev_hash, hash (SHA-256 over prev_hash and the row); checkpoint rows hold the hash of the last row removed by retention |

**Retention.** Tier 0: 48 h. Tier 1: 30 d. Tier 2: 1 y (S8, D109). `report_staging`: deleted after compaction. `events`: 90 d.
`conn_records`: 30 d. `job_steps` output and transcripts: 90 d (metadata kept). Incidents and approvals: 1 y.
`audit_log`: 1 y, with a checkpoint row written before each deletion so the chain stays verifiable. The retention task
runs hourly and deletes in batches of 10 000 rows until nothing older is left, pausing 50 ms between batches.

Every table that grows has a rule; the rest are these. `check_results`: 30 d (check latency and state are also kept as
series). `incident_events`: with their incident. `notifications`: 90 d. `peer_summaries`: the latest summary per peer
only. `probe_labels`: with their epoch (48 h after a newer epoch starts). `conn_baseline`: entries not seen for 180 d.
`join_tokens` and `job_tokens`: 30 d after they expire. `sessions`: deleted when they expire. `known_devices`: 1 y after
they were last seen.

Two caps bound what the time limits don't:
- **Job output and transcripts** share a size budget (default 100 MB, 7.8.1). When it is full, the oldest output and
  transcripts are trimmed first, before their 90 days are up; job and step metadata stay. Without the cap, 20 assistant
  jobs a day at 5 MB each would reach 9 GB in 90 days.
- **Connection records** are capped per machine per day (default 20 000 rows, 7.8.1). Past the cap, the rest of that
  day's records for the machine are stored in summary form (counts per country and ASN, as for `connections =
  "summary"`); threat-list checks still run on every reported tuple, and `conn.overflow` (info) says the cap was hit.

**Recent window.** The hub keeps the last 35 minutes of samples for every series in memory (the longest rule window in
7.6.1 is 30 minutes). Ingest adds each report's samples to it as the report is staged, so data is usable before
compaction moves it into chunk rows. Rule evaluation reads only the recent window. Dashboard and MCP queries merge it
with the chunk rows, which is how vitals show within seconds while compaction runs every 5 minutes. On start the hub
rebuilds the window from `report_staging` and the newest tier-0 chunks before it evaluates any rule, so a restart
doesn't reset a rule's duration. At 100 machines with 100 series each this is about 1.4 million samples, roughly
20 MB.

**Rollups.** Every minute the rollup task turns the last completed minute of the recent window into tier-1 min, max and
avg; every hour it does the same from tier 1 into tier 2. Then it recomputes any ranges marked dirty by backfilled data
(7.3.2) from the chunk rows. A chunk row is open (appended to by compaction or the rollup task) until it holds 120
points, then it is closed: 30 minutes for tier 0 at 15 s, 2 hours for tier 1 and 5 days for tier 2. A tier 0 chunk also
closes when its hour ends, so a series sampled less often doesn't keep a row open for long.

**Chunk encoding (S8, D109).** A chunk holds a timestamp column and one value column per stored field (one for tier 0;
min, max and avg for tiers 1 and 2).
- **Timestamps** are delta-of-delta encoded. Tier 0 stores each sample's scheduled tick: compaction rounds the
  timestamp to the machine's sample interval, and when two samples land on one tick the later one is kept. Tiers 1
  and 2 store their window starts.
- **Values** of a metric whose 7.4.2 unit has a step are stored as whole multiples of the step: % and ratio 0.01,
  Celsius 0.1, `mem.*`, `swap.*` and `disk.*` bytes 1 KiB (their sources count kB, so nothing is lost), and every
  other unit 1. Each column of each chunk is coded with whichever of delta-of-delta, delta (both with buckets up to 64
  bits) and Gorilla XOR is smallest, behind a 2-bit tag. A metric without a step, such as a driver metric of unknown
  unit, is stored as f64 with Gorilla XOR, without loss.
- **The recent window** keeps values and timestamps as received. Only chunk rows are rounded.

**Storage estimate for 50 machines with 100 series each (the cardinality cap's typical case), measured in spike S8:**
- **Tier 0:** 50 x 100 x 11 520 points = 57.6 M values at about 1.0 byte each = about 58 MB.
- **Tier 1:** 50 x 100 x 43 200 x 3 = 648 M values at about 0.9 bytes = about 0.57 GB.
- **Tier 2:** 50 x 100 x 8 760 x 3 = 131 M values at about 1.6 bytes = about 0.21 GB.
- **SQLite rows:** about 103 bytes for each of the 2.65 M chunk rows, plus 31.5% of the chunk data, for page space left
  partly empty by the key order (measured on the `series_chunks` schema) = about 0.54 GB.
- **Connection records:** about 2 000 rows per machine per day x 30 d x 80 bytes = about 0.24 GB. The per-day cap
  bounds a busy machine at ten times that.
- **Job output and transcripts:** at most 0.1 GB (their budget).
- **Events, check results and the rest:** about 0.1 GB.

The total is about 1.81 GB, inside the 2 GB budget. The budget assumes an average of 100 series per machine. Machines
near the 200-series cap use proportionally more, and the dashboard shows the projected database size. Plain Gorilla on
the recorded values would have needed 5.66 GB with the 2-year tier 2 first designed. That is why tier 2 keeps 1 year
and values are stored at their step (D109).

**Secrets at rest.** XChaCha20-Poly1305 per secret with a 256-bit master key in `/etc/rackhand/master.key` (0600, root,
outside the database). The first-run page shows the key once as a recovery code for the admin to store.

**Probe buffer.** Append-only segment files in `/var/lib/rackhand-probe/buffer/`, 4 MB each, at most 64 MB total, with
the epoch's label table in a file beside them.

#### 7.4.2 Metric catalogue

| Metric | Unit | Labels |
| --- | --- | --- |
| `cpu.busy_pct`, `cpu.iowait_pct`, `cpu.steal_pct` | % | none (per-core `cpu.core_busy_pct` with `core`, off by default) |
| `load.1m`, `load.5m`, `load.15m`, `load.15m_per_core` | ratio | none |
| `mem.used_bytes`, `mem.used_pct`, `mem.available_bytes`, `mem.available_pct`, `mem.cached_bytes` | bytes, % | none (on ZFS hosts, available counts the ARC above `c_min`, and used is total minus available: S11) |
| `swap.used_bytes`, `swap.used_pct` | bytes, % | none |
| `disk.used_bytes`, `disk.total_bytes`, `disk.used_pct`, `disk.inodes_used_pct` | bytes, % | `mount` |
| `diskio.read_bps`, `diskio.write_bps`, `diskio.read_iops`, `diskio.write_iops`, `diskio.busy_pct` | B/s, ops/s, % | `device` |
| `net.rx_bps`, `net.tx_bps`, `net.rx_pps`, `net.tx_pps`, `net.errors` | B/s, pkts/s, count | `iface` |
| `uptime_s` | s | none |
| `temp.c` | Celsius | `sensor` |
| `probe.rss_bytes`, `probe.cpu_pct`, `probe.buffer_bytes` | bytes, % | none |
| `conn.outbound_count` | count per interval | none |
| Drivers: Proxmox | node CPU, memory, storage use per datastore, guest status, guest CPU and memory | `node`, `storage`, `vmid` |
| Drivers: TrueNAS | pool health and use, disk temperatures, SMART status, alerts | `pool`, `disk` |
| Drivers: Redfish | power state, fan and temperature readings, PSU status, health rollup | `sensor` |
| Drivers: SNMP | ifInOctets, ifOutOctets, ifOperStatus, sysUpTime, plus configured OIDs | `ifName`, `oid` |
| Drivers: ICMP, TCP, HTTP, DNS, TLS | up, latency, status code, days to certificate expiry | `check` |

Mounts of type `tmpfs`, `devtmpfs`, `overlay`, `squashfs`, `proc`, `sysfs` and anything under `/run`, `/sys`, `/proc`
and `/var/lib/docker` are excluded by default. Interfaces named `lo`, `veth*`, `tap*`, `fwbr*`, `fwpr*`, `fwln*`,
`docker*`, `br-*` are excluded by default (bridges like `vmbr*` stay). Disk devices `loop*`, `ram*`, `dm-*` are excluded.
A machine with more than 200 series drops the rest and raises `series_cap_reached` (info).

### 7.5 Behaviour and flows

#### 7.5.1 Machine lifecycle

```mermaid
stateDiagram-v2
  [*] --> Pending: token issued
  Pending --> Enrolled: join succeeds, and for managed the SSH test passes
  Pending --> [*]: token expires (60 min)
  Enrolled --> Silent: no report for the silence time (7.6.3)
  Silent --> Enrolled: report arrives
  Enrolled --> Maintenance: maintenance window starts
  Silent --> Maintenance: maintenance window starts
  Maintenance --> Enrolled: window ends
  Enrolled --> Revoked: unenroll
  Silent --> Revoked: unenroll
  Revoked --> [*]
```

Quarantine is a separate state field (7.5.6), shown as `quarantined` health.

#### 7.5.2 Incident lifecycle

```mermaid
stateDiagram-v2
  [*] --> Open: rule fires, or a warning/critical event arrives
  Open --> Automation: runbook trigger matches and policy allows
  Open --> Assistant: playbook matches, operator available, daily cap not reached
  Open --> Human: nothing matches, level 0, no operator, or attempt limit reached
  Automation --> Resolved: job succeeds and the condition clears
  Automation --> Assistant: job fails or the condition persists, playbook matches
  Automation --> Human: job fails or the condition persists, no playbook or limit reached
  Assistant --> Resolved: job resolved and the condition clears
  Assistant --> Human: needs_human, failed, timed_out, or the condition persists
  Human --> Resolved: condition clears, or a person resolves it
  Open --> Resolved: condition clears
  Resolved --> Open: same dedupe key within 30 min (reopen)
  Resolved --> [*]
```

- **Condition incidents** (thresholds, forecasts, baselines, silence, checks) resolve when the condition clears.
  Clearing is counted in the rule's own inputs, never in evaluation ticks: 2 samples for a threshold (7.6.1), 2 runs
  for a check, 2 recomputations for a forecast or a baseline, and the first report for silence. Their severity can rise
  and fall; a fall doesn't send a callout.
- **A job that succeeds isn't the end.** After a runbook succeeds, or an assistant reports `resolved`, the incident
  waits for its condition to clear (10 minutes by default, 7.8.1). If it hasn't, the job is treated as failed for
  routing: a runbook's incident goes on to a playbook or a person, an assistant's incident goes to a person.
- **Attempt limits.** Reopening keeps the incident's history, so the limits count across reopens. For one incident
  (one dedupe key), automatic runbooks start at most 2 times and assistant jobs at most once in any 24 hours (7.8.1);
  a job a person starts or resumes from the dashboard isn't counted. Past a limit the incident goes to a person with
  the note "attempt limit reached", so a service that keeps failing isn't restarted forever and one incident can't use
  up the hub's daily assistant cap.
- **Event incidents** (security and system events of warning or critical severity) have no condition. Dedupe key:
  `<machine>:<kind>:<subject>` (for example the file path, the user, or the exe and ASN). Later matching events within
  24 hours are added to the same incident. They are resolved only by a person, or by an assistant at level 2 or 3 for
  warning kinds only. Info events never open incidents.
- **Routing.** Runbooks declare `triggers = { incident_kinds = [...], auto = true }`. The most specific match wins: a
  runbook bound to the machine, then to one of its tags, then to its kind, then a general one; ties go to the name that
  sorts first. Playbooks match by `incident_kinds` with the same precedence. A runbook is tried first; a playbook only
  if no runbook matches or the runbook failed. When a failed runbook step names `on_failure = { playbook = ... }`, that
  playbook is used and `incident_kinds` matching is skipped.
- **Acknowledge** stops re-notification without changing the state. **Silences** (with an end time, at most 30 days)
  suppress new incidents for a machine or tag and rule or kind.

#### 7.5.3 Patch run

1. **Windows.** Each policy has a security window (default daily 04:00, site timezone) and a full window (default
   Sunday 03:00), each `window_length_min` long (default 180). Times that don't exist on a daylight-saving change run at
   the next valid minute; repeated times run once.
2. **Selection.** At window start, the Scheduler asks Actions to start `patch` jobs (mode `security` or `full`) for
   machines at access level `managed` with policy `auto` and pending updates, not in a maintenance window and not
   quarantined. At most 3 per site at once (configurable). Machines with role `hypervisor`, and the machine with role
   `hub`, go after all other machines at their site, one at a time. Apart from that, v0.1 patches a site's machines in
   no set order. A machine offline at window start is retried every 15 minutes until the window ends,
   then waits for the next window.
3. **Approve-only.** For `approve-only` machines an approval is created at window start that expires at window end; an
   approval decided later waits for the next window.
4. **Steps** (`patch-debian`; `patch-alpine` and `patch-windows` are the same shape):
   precheck (1 GB free on `/`, no lock files, no other job on the machine, no open critical incident on it; for Proxmox
   guests, the guest binding is confirmed (7.3.12) and the datastore has 10% and 5 GB free) then snapshot (Proxmox
   guests; name `rackhand-patch-<YYYYMMDD-HHMM>`; keep the last 3 `rackhand-patch-*` per guest) then record active
   services, running containers and required mounts then update then install (both detached, 7.3.7) then reboot if
   required and `auto_reboot` then wait for a report (up to 15 minutes) then verify.
5. **Verify** passes when the probe reports, every service active before is active, every container running before is
   running, every required mount (policy `required_mounts`) is mounted, and every check bound to the machine passes
   within 5 minutes.
6. **Failure.** Incident `patch_failed` opens. If the machine never reported within the 15 minutes after a reboot,
   `auto_rollback` is true, and the machine's role isn't `hub`, the hub rolls the guest back to the snapshot (an
   allowed automatic high-risk action, D45) and records it. Otherwise the incident routes to the `patch-failure`
   playbook.
7. **Hypervisors** install updates without rebooting. If a reboot is required, a high-risk approval lists every guest
   that goes down with it. Two hypervisors in one cluster are never rebooted in the same window. When the hub itself is
   a guest of the hypervisor (known from its confirmed guest binding), the approval names the hub among those guests and
   the reboot works like step 8: it is scheduled 60 seconds out, the job is marked `resumable_step = verify`, and the
   hub finishes the job when it is back.
8. **The hub's own host** runs `patch-hub-host`: its reboot step schedules the reboot 60 seconds out
   (`systemd-run --on-active=60 systemctl reboot`) and marks the job `resumable_step = verify`. On start the hub
   resumes a job with a `resumable_step` instead of marking it interrupted. Reboot needs approval unless the policy says
   `auto_reboot` for this host.
9. **Defaults.** `snapshot` is `required` and applies to Proxmox guests; on any other machine there is nothing to
   snapshot, the step is skipped, and the job log says the machine was patched without one. `auto_reboot` is true for
   Linux guests and false for kind `windows`, role `desktop`, role `hypervisor` and role `hub`. Alpine has no security marker, so Alpine patches only in the full window. Windows uses the Windows
   Update Agent through a shipped script.

#### 7.5.4 Assistant on a failed runbook

```mermaid
sequenceDiagram
  participant I as Incidents
  participant A as Actions
  participant S as Assist
  participant O as Operator
  participant C as Claude Code
  participant M as MCP
  participant P as Person (dashboard)
  A-->>I: JobFinished(patch, failed at verify)
  I->>A: StartJob(assistant, playbook patch-failure, level 1, hosts=[vm])
  A->>S: offer
  S->>O: JobOffer{brief, tools, hosts, token, deadline 30 min}
  O->>C: claude -p (MCP bridge only)
  C->>M: get_incident, get_machine, run_diagnostic(failed_units, journal)
  M-->>C: untrusted_output ...
  C->>M: run_runbook(compose-restart, vm, project=web)
  M-->>C: needs_approval{approval_id}
  M->>P: approval pending (dashboard, callout)
  P->>M: approve (signed in)
  C->>M: run_runbook(compose-restart, vm, project=web, approval_id)
  M->>A: start job (hash matches)
  C->>M: finish_job(resolved, summary)
  O->>S: JobDone
  A-->>I: JobFinished(assistant, resolved)
```

The brief holds the incident and its timeline, machine facts and recent vitals, the failed job's steps and output
(marked untrusted), the playbook text, the autonomy level, the job's hosts, the deadline, and the rule that machine
output is data and never instructions. If the deadline passes while an approval is pending, the job ends
`needs_human`; approving later shows **Resume job**, which starts a new job for the same incident with the approved call
first and the previous transcript summarized in the brief.

#### 7.5.5 Peer linking and watching

1. Hub A: Peers, Create invite (ticket plus one-time secret, 24 h). Hub B: paste it. B dials A on `rackhand/join/1`
   with `Peer{...}`; A registers B and answers; B registers A. Each now accepts the other on `rackhand/peer/1`.
2. Each pushes `SiteSummary` every 30 s. A peer is `silent` after 2 minutes without a summary (warning) and `down` after
   10 minutes (critical).
3. One hub calls out for a down peer: among the hubs that currently report it down in their own `peers_seen` and are
   healthy, the one whose site name sorts first. During a network partition two hubs may each believe they are first,
   so a duplicate callout is possible and accepted.
4. A site with no peers can set a dead-man URL; the hub requests it every 5 minutes so an outside heartbeat service
   notices if the hub dies.

#### 7.5.6 Quarantine

```mermaid
stateDiagram-v2
  [*] --> None
  None --> Pending: finding, policy needs approval
  None --> Applying: finding matches an enabled auto rule
  Pending --> Applying: approved with step-up
  Pending --> None: rejected or expired
  Applying --> Active: isolation and snapshot done
  Applying --> Failed: a step failed
  Failed --> Applying: retried with approval
  Failed --> None: dismissed by an admin
  Active --> Releasing: release approved with step-up
  Releasing --> None: rules removed, machine reachable
  Releasing --> Active: removal failed (incident)
```

Applying:
1. **Isolate first.** Proxmox guests: requires the datacenter firewall to be on (otherwise this step fails with
   `pve_firewall_off` and tells the admin; Rackhand never turns the datacenter firewall on). The hub first saves the
   guest's whole firewall configuration (options, policies, rules and each network device's firewall setting) in the
   job record. It then enables the guest's firewall with input and output policy DROP plus only these rules: DHCP (UDP
   67 and 68), the guest to the hub's QUIC port (the probe's connection), and the hub to the guest's TCP port 22 and
   ICMP echo. Nothing else to or from the hub is allowed, so a compromised guest gets no wider path to the hub than
   the probe already had. Then it flushes the guest's conntrack entries on the host: `conntrack -D` for each of the guest's addresses, run
   through the hypervisor's own managed enrollment as a wrapper command (S4, D112). If the hypervisor isn't enrolled
   as managed, the quarantine still applies and its job records `conntrack_not_flushed`, so established sessions last
   until they time out. Other managed Linux:
   `/usr/local/lib/rackhand/quarantine on <hub-addresses>` (in the automation allow-list) loads an nftables table
   `rackhand_quarantine` with the same rules and flushes conntrack. Managed Windows: the shipped script adds Windows
   Firewall rules to the same effect. A monitor machine can be quarantined only as a Proxmox guest, from the
   hypervisor, and only on approval (7.3.12). Appliances and remote-mode machines: not supported in v0.1 (cutting a
   remote machine's network would also cut its mesh path to the hub); the incident says so and stays with a person.
2. **Then snapshot** for forensics (Proxmox guests): `rackhand-quarantine-<time>`, with RAM for VMs when the storage
   supports it. Quarantine snapshots are never pruned automatically.
3. Health shows `quarantined`. Patching and runbooks other than diagnostics and release are blocked, and so is
   assistant `exec` (it fails with `machine_quarantined`): an assistant with a root shell could undo an in-guest
   quarantine, and everything the machine prints is suspect. An assistant can still read and run diagnostics.

Releasing puts back exactly what was saved: the hub removes its rules and restores the saved firewall configuration
(for in-guest quarantine, it drops the `rackhand_quarantine` table or its Windows rules, which touch nothing else). If
the guest's firewall configuration was changed by someone else while quarantined, release stops with
`quarantine_config_changed` and a person decides which version to keep.

In-guest firewalls (nftables, Windows Firewall) are advisory against an attacker with root on the machine; only the
hypervisor firewall is enforced from outside. The dashboard says which kind each quarantine is.

Never quarantined: roles `hub`, `operator`, `relay`, `hypervisor`, and tag `no-quarantine`. Auto rules are off by
default; enabling or changing one is a high-risk change that needs step-up. Release always needs an approval with
step-up.

#### 7.5.7 Hub upgrade

`rackhand` updates only when an admin clicks Update (or runs `rackhand self-update`). The hub runs as an unprivileged
user (7.1), so it does the unprivileged part and a root unit does the rest:

1. The hub takes a backup, downloads the signed release into `/var/lib/rackhand/update/`, and writes a request file
   there naming the version.
2. A root unit, the updater (`rackhand-updater.path` and `.service`, the same binary run as `rackhand update-apply`),
   starts when the request appears. It trusts nothing the hub wrote: it reads only the version from the request, opens
   the one fixed download file without following links, copies it into the inactive slot, and checks the copy, not the
   original: it refuses a version lower than the one installed, and verifies the sha256 and the signature against its
   own compiled-in release keys. A copy that fails is deleted and the request is answered with the reason.
3. The updater copies the current binary to `/run/rackhand-updater/update-guard` (root-only) and starts it as a
   transient unit (`systemd-run --unit=rackhand-update-guard`) with `hub <old> <new>`. The guard switches the slot,
   restarts the hub, and polls `https://127.0.0.1:8443/healthz` for up to 2 minutes. If it never answers healthy, the
   guard switches back and restarts the old version; if migrations ran, it first restores the pre-update backup
   (migrations are forward-only).

A hub process that has been taken over can therefore ask for an update but can't install a binary the release keys
didn't sign, and can't go back to an older one. Restoring the pre-update backup loses what the new version wrote in
its 2 minutes: reports acked in that time are gone from the hub and already deleted on the probes, and audit entries,
approvals and job records from that time are gone too. The first audit entry after a restore records it, and the
dashboard shows that the update was rolled back and what window was lost.
Relays and operators update the same way with their own command. After a hub update, probes are offered only the hub's
own version (FR-22).

### 7.6 Algorithms and rules

#### 7.6.1 Threshold rules

A rule is `metric op value for duration`, evaluated every 15 s over the samples in the window (at their corrected
times, 7.3.2). Everything is counted in samples, using the machine's own probe interval, so the rules mean the same at
5 seconds and at 300:

- **Matching.** The number of samples expected in a window is the duration divided by the machine's interval. A window
  matches when at least 80% of the expected samples are present and every present sample matches. A duration shorter
  than 4 intervals is raised to 4 intervals, so no rule fires on fewer than 4 samples.
- **Clearing.** A rule clears when the 2 most recent samples are both on the safe side of the threshold by the clear
  margin. An evaluation with no new sample changes nothing.
- **Clear margin.** 2 points for percentages and temperatures, 0.2 for load per core. A disk rule that opens over 85%
  clears under 83%, so a value sitting at the threshold doesn't open and resolve over and over. Rows without a metric
  value (services, restarts, checks, pending updates) have no margin.

| Rule | Warning | Critical |
| --- | --- | --- |
| `cpu.busy_pct` | over 90 for 15 min | over 98 for 30 min |
| `mem.available_pct` | under 10 for 10 min | under 5 for 5 min |
| `swap.used_pct` | over 50 for 30 min | over 90 for 10 min |
| `disk.used_pct` (per mount) | over 85 for 5 min | over 95 for 5 min |
| `disk.inodes_used_pct` | over 85 for 5 min | over 95 for 5 min |
| `load.15m_per_core` | over 2 for 30 min | over 4 for 30 min |
| `cpu.steal_pct` | over 20 for 15 min | (none) |
| watched service not active | 2 reports | 4 reports |
| container restarts | more than 3 in 10 min | more than 10 in 10 min |
| check failing | 2 in a row | 4 in a row |
| security updates pending | older than 7 days | older than 14 days |
| `temp.c` | over 80 for 5 min | over 90 for 5 min |

Example: `/var` reads 86%, 86%, 87% from minute 0 to minute 5, so a warning opens at minute 5. It reaches 95.2% at
minute 22 and stays above 95%, so at minute 27 the incident becomes critical and a new callout goes out. After cleanup
it reads 70% for two samples (under the 83% clear line), so it resolves.

#### 7.6.2 Forecasts

- **Disk fill:** least-squares lines over tier-1 data for the last 6 hours and tier-2 data for the last 7 days. For each
  fit with a positive slope and R² of at least 0.7, compute the time to 100%. Take the shortest. Warning under 72
  hours, critical under 24.
  Example: 400 of 500 GB used. The 6-hour fit has slope 1.2 GB/h and R² 0.91, which gives 83.3 h (no alert). The 7-day
  fit has slope 1.6 GB/h and R² 0.85, which gives 62.5 h, so a warning: "/data fills in about 2.6 days".
- **Memory growth:** a line over `mem.used_pct` since the last boot, with at least 24 h of data and R² of at least 0.7.
  Warning if the slope is over 2 points per day and the line reaches 95% within 7 days.
- **Certificate expiry:** warning at 14 days, critical at 3 days.

#### 7.6.3 Silence

| Subject | Warning | Critical |
| --- | --- | --- |
| Machine probe (no report) | the larger of 60 s and 4 intervals | the larger of 5 min and 20 intervals |
| Machine with `expected_offline` | info event only | none |
| Agentless machine (driver poll failing) | 2 polls | 5 polls |
| Peer hub | 2 min | 10 min |
| Operator | 10 min (warning only) | none |

Silence is suppressed during a maintenance window, during a job on that machine that includes a reboot (until the job's
wait step ends), and for the first 3 minutes after the hub starts.

#### 7.6.4 Baselines

- Per machine and metric, 24 hour-of-day buckets and 168 hour-of-week buckets, each with a mean, variance and count
  `n`, updated once an hour from the tier-2 average. The first value seeds the mean with variance 0; later values update
  with weight 0.1, so buckets adapt slowly to lasting change.
- A bucket is usable once `n` is at least 3. The hour-of-week bucket is used when usable, otherwise the hour-of-day
  bucket. The standard deviation used is never below half the metric's floor, so a bucket with almost no variance can't
  fire on noise.
- Learning: no baseline alerts for a machine until it has 7 days of data (by then hour-of-day buckets are usable).
- Fires a warning when the tier-1 value deviates from the bucket mean by more than 4 standard deviations for 15 minutes
  and the difference exceeds the metric's floor (CPU 20 points, network 5 Mbit/s, disk I/O 20 MB/s, outbound
  connections 50 per interval). Never critical.
- While a deviation is active, the bucket is frozen (`frozen_until_ms`) so a sustained anomaly doesn't become normal.
  It unfreezes after 2 hours without deviation.
- Applies to `cpu.busy_pct`, `net.rx_bps`, `net.tx_bps`, `diskio.read_bps`, `diskio.write_bps`, `conn.outbound_count`.

Example: Tuesdays 14:00 to 15:00 on `build-vm`, the bucket mean for `net.tx_bps` is 2 Mbit/s with a standard deviation
of 1 Mbit/s. At 14:20 tx rises to 40 Mbit/s and stays there. At 14:35 (15 minutes, 38 standard deviations, over the 5
Mbit/s floor) a warning opens and the bucket freezes.

#### 7.6.5 Connection scoring

For each connection record `(container, exe, dest_ip, dest_port, proto)`, where `container` is the container's name
(the image name when the name was generated) or empty for a host process:
1. Skip private, loopback and link-local destinations unless the policy has `watch_internal`.
2. A destination on a loaded threat list gives a critical `conn.known_bad` event.
3. Look up ASN and country (7.8.5).
4. During learning (first 7 days per machine), add the tuple to `conn_baseline` without events.
5. After learning, a tuple `(container, exe, dest_asn, dest_port)` not in the baseline gives `conn.new_destination` at
   info, naming the container, raised
   to warning when any of: the country is new for this machine; the exe is new on the machine; the port is on the watch
   list (22, 23, 1080, 3389, 4444, 5555, 6667, 9001) or above 49151 from a server process. A server process is one with
   no controlling terminal whose parent chain reaches the service manager or a container runtime.
6. Over 1 GB to a single new destination within an hour gives `conn.large_egress` (warning).
7. Excluded: Rackhand's own processes, and the package manager during a Rackhand patch job.
8. Records folded together by the per-report cap (7.3.2) have no destination, so they are counted but not scored. The
   `conn.overflow` event tells the admin that this machine makes more distinct connections than the cap covers.

Example: on `media-vm`, `ffmpeg` connects on port 4444 to an ASN and country it has never used. That's a warning (new
country and a watch-list port). If the IP is on a threat list, it's critical, and an enabled auto-quarantine rule may
apply.

#### 7.6.6 Security event severities

| Event | Severity |
| --- | --- |
| `conn.known_bad` | critical |
| `proc.exec_from_tmp` (Linux: exe under `/tmp`, `/var/tmp`, `/dev/shm`, or deleted) | critical |
| `proc.exec_from_tmp` (Windows: under `%TEMP%` or Downloads) | warning |
| `user.added` with UID 0 or in `sudo`, `wheel` or Administrators | critical |
| `user.added` (other) | warning |
| `auth.keys_changed` (any `authorized_keys`) | critical |
| `file.changed` for sudoers, sshd_config, PAM, `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/rackhand/commands.json`, `/etc/rackhand-probe/probe.toml` | critical |
| `file.changed` for other listed files | warning |
| `port.new_listener` | warning |
| `auth.login_new_source` | warning |
| `auth.failed_burst` (over 20 failures in 5 min) | warning |
| `auth.root_login` | warning |
| `conn.new_destination` | info, or warning per 7.6.5 |

**Exemptions.** Executables named `memfd:*` whose parent is `runc`, `crun`, `containerd-shim*` or `conmon` (container
runtime internals). During a patch job, `file.changed` for files owned by a package the job upgraded (checked with
`dpkg -S`, `apk info -W` or the Windows installer record) is recorded at info with the job id. Key changes
(`auth.keys_changed`) and account changes are exempt only during `sudoers-refresh`, `keys-rotate`, enrollment and
unenroll, and only for the `rackhand` and `rackhand-ai` users and files those jobs write. Nothing is exempt for any
other user's keys or accounts. A change to `/etc/rackhand/commands.json` is exempt only when it is the version the hub
just sent with `sudoers-refresh` (the hash matches); a change to `probe.toml` only during enrollment and an access
level change. Any other change to either file is critical.

#### 7.6.7 Callout grouping

- Critical: sent at once.
- Warning: grouped per site; the first warning starts a 5-minute group, then one message lists them all.
- Info: dashboard only.
- An open incident is re-sent only when its severity rises, or every 6 hours while open and not acknowledged.
- A resolution message is sent for every incident that was called out.

#### 7.6.8 Autonomy, risk and approvals

| Level | Meaning | Runbooks | Assistant |
| --- | --- | --- | --- |
| 0 | Tell | Not run; a person is told what would run | Read tools only |
| 1 | Propose | Run after approval | `exec` and `run_runbook` need approval |
| 2 | Act, then report | Run; callout with the result | `exec` and runbooks run; callout with summary |
| 3 | Act quietly | Run; result in the log | As 2, info-level summary |

| Risk | Examples | Rule |
| --- | --- | --- |
| low | diagnostics, `service-restart`, `compose-restart` | follows the level |
| normal | patching, `snapshot`, `compose-update`, provisioning, assistant `exec` on ordinary machines | follows the level |
| high | quarantine and release, rollback, hypervisor reboot, `sudoers-refresh`, `unenroll`, key rotation, assistant `exec` on roles `operator`, `relay` or `hypervisor`, accepting a changed host key, confirming a guest binding after a mismatch | always an approval with step-up |

At every risk, requests from peers and from personal MCP keys need an approval (peer requests skip it only when the
owning hub's policy sets `peer_requests = "auto"` for that runbook, and never for high risk). Any action on a machine
at access level `monitor` needs an approval too, whatever the level (7.3.12).

**Exceptions** (D61): an enabled auto-quarantine rule may apply quarantine, and a policy with `auto_rollback` may roll
back after a failed patch (7.5.3), without an approval. Enabling or changing either is itself high risk and needs
step-up. Release from quarantine is never automatic.

New user runbooks and playbooks start at level 1. A runbook with `identity = "assistant"` is treated like an assistant
`exec` of each of its commands.

**Assistant `exec` patterns that always need step-up**, whatever the level: `rm -rf` on `/` or a top-level directory,
`mkfs`, `dd` writing to a device, `zpool destroy`, `zfs destroy` of anything not named `rackhand-patch-*`, `qm destroy`,
`pct destroy`, `do-release-upgrade`, edits to files under `/etc/apt/sources.list*`, `shutdown` or `poweroff`. This
pattern list is best-effort (a determined command can avoid matching it); the real controls are scope, levels and
approvals.

Other `exec` calls by an assistant are normal risk on ordinary machines, so a responder can approve them.

### 7.7 User and developer experience

#### 7.7.1 Dashboard

Server-rendered HTML with askama, htmx for live parts, uPlot for charts, served on HTTPS port 8443.

| Page | Contents | Empty and error states |
| --- | --- | --- |
| First run | Create the admin (password plus TOTP, or a passkey when the hub has a trusted certificate), name the site and timezone, store the master-key recovery code, review outside sources (7.8.5) | Shown until an admin exists |
| Overview | A tile per site (local and peers): machines by health, open incidents, last heartbeat; incident list; approvals waiting | "No machines yet: Add machine" |
| Site | Machines (name, kind, health, CPU, memory, worst disk, updates, last seen), checks | Peer offline: last summary time |
| Machine | Charts (1 h, 24 h, 7 d, 30 d, 1 y), services, containers, updates, security events, connections with verdicts (by container), jobs, policy, windows, quarantine state, access level, connection capture method (eBPF or sampling), guest binding (confirm), actions | "Probe silent since ..."; on a monitor machine, actions that need an account are shown disabled with the reason |
| Incidents | List with filters; detail with timeline, events, job logs, assistant transcript, notes, actions, Resume job | |
| Approvals | Action, target, exact arguments, risk, requester, reason; Approve and Reject (step-up prompt for high risk) | "Nothing waiting" |
| Security | Event feed, baseline status per machine, threat-list and GeoIP freshness, quarantine rules | "Lists not downloaded yet" |
| Library | Runbooks and playbooks, revisions, diffs, validation errors, drafts | |
| Jobs | Runs, steps, commands, exit codes, output | |
| Patching | Windows, maintenance windows, pending updates per machine, holds, last results | |
| Add | Machine (Linux, Alpine, Windows; local or remote; managed or monitor), appliance (per driver), device, operator, peer, site bootstrap | |
| Peers and relays | Peers (state, allowed queries, backup quota), relays and lists, operators | |
| Settings | Notifiers (Send test), users and roles, devices, MCP keys, OIDC, git mirror, outside sources, dead-man URL, assistant daily cap | |
| Audit | Log with search and chain status | Chain broken: critical banner |

Peer site pages render from summaries and allowed queries. An action on a peer's machine creates an `ActionRequest`;
its approval happens on the peer's own dashboard.

#### 7.7.2 Accounts, roles and sessions

| Permission | viewer | responder | admin |
| --- | --- | --- | --- |
| See everything on this hub | yes | yes | yes |
| Acknowledge and silence incidents, add notes | no | yes | yes |
| Approve low and normal risk | no | yes | yes |
| Approve high risk | no | no | yes (step-up) |
| Open tunnels and transfers, run diagnostics | no | yes | yes |
| Edit runbooks, playbooks, policies, quarantine rules | no | no | yes |
| Enroll and unenroll, create invites, MCP keys for others | no | no | yes |
| Confirm a guest binding | no | no | yes (step-up after a mismatch) |
| Users, roles, notifiers, settings | no | no | yes |

- A person may approve their own request; a request from an assistant or a peer can be approved by any responder or
  admin.
- Second factor is mandatory. With the default self-signed certificate, that's TOTP; passkeys are offered when the hub
  is reached by hostname with a certificate the browser trusts (a provided certificate, or ACME with a DNS challenge).
- OIDC users also enroll a local TOTP or passkey, used for step-up.
- Sessions: 12 hours absolute, 2 hours idle; step-up lasts 5 minutes. Cookies `Secure`, `HttpOnly`, `SameSite=Strict`.
- Sign-in failures back off per source (after 5 failures in 15 minutes, 1 attempt per minute) instead of locking
  accounts, so nobody on the network can lock out the admin. A source is an IPv4 address or an IPv6 /64.
- Sources alone don't stop an attacker with many addresses, so each account also has a limit of its own. After 10
  failures for one account in 15 minutes from any sources, sign-in attempts for that account from browsers the account
  has never signed in from are limited to 1 a minute in total. A browser that has signed in to the account before
  carries a device cookie and keeps its own separate limit, so the real owner still gets in while the account is under
  attack.
- A second-factor code is accepted once: a TOTP code or time step that has been used is refused. After 5 wrong codes
  the password step must be passed again, and those failures count toward the limits above.
- Behind a reverse proxy, the hub takes the client address from the forwarding header only when the request comes
  from an address listed in `trusted_proxies` (`hub.toml`, empty by default). Otherwise it uses the connection's
  address, so a client can't fake its source and one proxy address isn't mistaken for every user.
- MCP keys: per user and device, scope `read` or `read_request`, expiry default 90 days (at most 1 year), revocable.
  A key's scope is capped by its user's role (7.3.6).

#### 7.7.3 CLIs

- `rackhand hub init`, `rackhand hub run`, `rackhand hub backup`, `rackhand hub restore <file>`,
  `rackhand hub audit verify`, `rackhand hub runbook check <file>`, `rackhand hub detect replay`,
  `rackhand self-update`, `rackhand relay run`, `rackhand relay key create`, `rackhand operator join <invite>`,
  `rackhand operator run`.
- `rackhand-cli login <invite>`, `rackhand-cli connect`, `rackhand-cli forward`, `rackhand-cli send`,
  `rackhand-cli mcp`, `rackhand-cli status`.
- `rackhand-probe run`, `rackhand-probe helper`, `rackhand-probe collect --once --json`, `rackhand-probe set-hub
  <ticket>` (root), `rackhand-probe uninstall` (root).
- Every command has `--help` and exits non-zero with a message naming what failed.

#### 7.7.4 Site bootstrap

`curl ... install.sh | sudo sh -s -- --hub` on a fresh Debian 12 or later machine, or `rackhand-lxc.sh` on a Proxmox
host, which creates a Debian LXC (2 vCPU, 1 GB RAM, 20 GB disk) and runs the hub installer inside it. The installer
prints the dashboard URL and a one-time setup code.

### 7.8 Configuration and tuning

All configuration is edited in the dashboard, stored with revisions, and mirrored to git. Only these are files:
`/etc/rackhand/hub.toml` (listen addresses, data directory, master key path, trusted proxies),
`/etc/rackhand/master.key`, and the probe's `/etc/rackhand-probe/probe.toml` (hub ticket and access level, root-owned).

#### 7.8.1 Settings

| Setting | Default | Range |
| --- | --- | --- |
| Probe interval | 15 s | 5 to 300 s |
| Dashboard port / hub QUIC port | 8443/tcp / 7443/udp | any |
| Service check interval | 60 s | 15 s to 1 h |
| Security / full patch window | daily 04:00 / Sunday 03:00, 180 min | any |
| Max concurrent patch jobs per site | 3 | 1 to 20 |
| Peer summary interval | 30 s | 10 to 300 s (peer silent warning is the larger of 2 min and 3 intervals) |
| Assistant job deadline / max turns | 30 min / 60 | 5 to 120 min / 10 to 200 |
| Assistant jobs per day per hub | 20 | 0 to 500 |
| Automatic runbook starts per incident per 24 h | 2 | 1 to 10 |
| Assistant jobs per incident per 24 h | 1 | 1 to 5 |
| Wait for the condition to clear after a job | 10 min | 2 to 60 min |
| Connection tuples per report | 500 | 100 to 5000 |
| Connection records per machine per day | 20 000 | 1 000 to 200 000 |
| Job output and transcript budget | 100 MB | 50 MB to 20 GB |
| Approval expiry | 24 h (patch: end of window) | 1 h to 7 d |
| Step-up freshness | 5 min | 1 to 15 min |
| Baseline learning | 7 days | 1 to 30 days |
| Retention tier 0 / 1 / 2 | 48 h / 30 d / 1 y | 12 h to 7 d / 7 to 365 d / 30 d to 10 y |
| Local backups kept | 2 | 1 to 14 |
| Series cap per machine | 200 | 50 to 2000 |

#### 7.8.2 Auto-quarantine rules

Off by default. Example:

```toml
[[quarantine_rule]]
name = "known-bad from DMZ web servers"
severity_at_least = "critical"
event_kinds = ["conn.known_bad", "proc.exec_from_tmp"]
match = { tags = ["dmz"] }   # also: machine ids, kinds, services (unit or container names)
```

Built-in exclusions apply before any rule.

#### 7.8.3 Diagnostics allow-list

Read-only, built in, run as the automation identity:

| Name | Linux | Windows |
| --- | --- | --- |
| `journal` (unit, since, lines at most 2000) | `journalctl -u <unit> --since <t> -n <n> --no-pager` | `Get-WinEvent` for the service's log, same limits |
| `failed_units` | `systemctl --failed` / `rc-status --crashed` | services set to Automatic that aren't running |
| `service_status` (name) | `systemctl status <name>` / `rc-service <name> status` | `Get-Service <name>` |
| `docker_ps`, `compose_ps` | `docker ps -a`, `docker compose ls` | same if Docker Desktop is present |
| `docker_logs` (container, lines at most 2000) | `docker logs --tail <n> <c>` | same |
| `df`, `mounts` | `df -hT`, `findmnt` | `Get-Volume` |
| `du_top` (path, depth at most 3) | `du -xh --max-depth=<d> <path>` sorted | `Get-ChildItem` size summary |
| `free`, `uptime`, `top_processes` | `free -m`, `uptime`, `ps` by CPU and memory, top 20 | `Get-CimInstance Win32_OperatingSystem`, `Get-Process` top 20 |
| `ss_listen`, `ss_established` | `ss -ltnup`, `ss -tnp state established` | `Get-NetTCPConnection` |
| `dmesg_tail` | `dmesg -T` last 200 lines | System log errors, last 200 |
| `updates_pending` | `apt list --upgradable` / `apk version -l '<'` | Windows Update Agent search |
| `last_logins` | `last -n 50` | Security log 4624, last 50 |
| `ping` (target in the same site), `http_head` (URL bound to the machine's checks) | `ping -c 4`, `curl -sSI` | `Test-Connection`, `Invoke-WebRequest -Method Head` |

`docker_logs` and `journal` are the sensitive diagnostics: their output can contain secrets. It is returned as
untrusted output and stored in job logs only (not sent to peers), and a personal MCP key needs an approval to run them
(7.3.6). Parameters follow the runbook rules in 7.3.7, including the refusal of values that start with `-`.

#### 7.8.4 Critical file list (helper)

Linux: `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/sudoers`, `/etc/sudoers.d/*`,
`/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/*`, `/etc/pam.d/*`, `/etc/security/*.conf`, `/root/.ssh/authorized_keys`,
`/home/*/.ssh/authorized_keys`, files named by `AuthorizedKeysFile` in `sshd_config`, `/etc/crontab`, `/etc/cron.d/*`,
`/var/spool/cron/crontabs/*`, `/etc/systemd/system/*.service`, `/etc/systemd/system/*.timer`, `/etc/ld.so.preload`,
`/etc/hosts`, `/etc/resolv.conf`, `/usr/bin/sudo`, `/usr/sbin/sshd`, `/usr/bin/ssh`, `/usr/local/lib/rackhand/*`,
`/etc/rackhand/commands.json`, `/etc/rackhand-probe/probe.toml`.
Windows: `C:\ProgramData\ssh\sshd_config`, `C:\ProgramData\ssh\administrators_authorized_keys`,
`C:\ProgramData\rackhand\keys\*`, `C:\Windows\System32\drivers\etc\hosts`, the scheduled tasks folder
`C:\Windows\System32\Tasks\*`, and `C:\Program Files\Rackhand\*`. Extra paths come from the root-owned
`/etc/rackhand/helper-extra-paths` (at most 500).

#### 7.8.5 Outside sources

On by default (each can be turned off; air-gapped mode turns all off):

| Source | Use | Sends | License notes |
| --- | --- | --- | --- |
| abuse.ch Feodo Tracker IP blocklist | threat list | an HTTPS GET | CC0 (abuse.ch terms 3.4); nearly empty in 2026-11 (S10) |
| Spamhaus DROP | threat list (hijacked networks) | an HTTPS GET of `drop_v4.json` and `drop_v6.json`, at most daily | free for any use; credit The Spamhaus Project on the Security page (S10) |
| DB-IP Lite country and ASN | GeoIP and ASN | an HTTPS GET, monthly | CC BY 4.0, attribution on the Security page |
| GitHub Releases of this project | update checks and downloads | an HTTPS GET, daily | n/a |

Off unless enabled: MaxMind GeoLite2 (own license key), online reputation lookups (own API key, sends destination
IPs), relay lists (URLs the admin adds), n0's public relays and DNS discovery.

#### 7.8.6 Proxmox API role

`Rackhand` role: `VM.Audit`, `VM.Snapshot`, `VM.Snapshot.Rollback`, `VM.PowerMgmt`, `VM.Config.Network`,
`VM.Allocate`, `VM.Clone`, `Datastore.Audit`, `Datastore.AllocateSpace`, `Sys.Audit`, `SDN.Use`. Spike S4 confirmed
the list against PVE 8 and 9: the guest firewall needs `VM.Audit` and `VM.Config.Network` (and `SDN.Use` for the device
flag), and a rollback of a running container on PVE 9 needs `VM.PowerMgmt`. Guest rules apply only with the datacenter
firewall on and the device's `firewall=1`. The API can't flush conntrack; the host's own managed enrollment does (7.5.6, D112).

#### 7.8.7 Runbook format

```toml
name = "compose-restart"
description = "Restart one Docker Compose project and check its containers"
targets = { kinds = ["linux"] }
identity = "automation"          # or "assistant"
risk = "low"                     # low | normal | high
autonomy = 1
triggers = { incident_kinds = ["container.restarting"], auto = false }
[params.project]
type = "string"
pattern = "^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,63}$"   # whole value; a leading "-" is refused in any case (7.3.7)
[[step]]
id = "restart"
kind = "ssh"
cmd = ["sudo", "/usr/local/lib/rackhand/run", "/usr/bin/docker", "compose", "-p", "{{project}}", "restart"]
timeout = "5m"
[[step]]
id = "verify"
kind = "verify"
checks = ["containers_running:{{project}}"]
on_failure = { playbook = "compose-failure" }
```

Step kinds: `ssh` (`cmd`, or `windows_script` and `windows_args`), `snapshot`, `rollback`, `reboot_if_required`,
`wait_report`, `verify`, `probe_check`, `api` (driver call), `transfer`, `tunnel`, `notify`. Steps can set
`retries = n` only when marked `idempotent = true`. `resumable = true` marks a step the hub may resume after its own
restart. `detached = true` on an `ssh` step starts the command in its own unit on the machine and polls it (7.3.7); a
detached step is always resumable. A parameter takes values that start with `-` only with `allow_leading_dash = true`.

Built-in runbooks: `patch-debian`, `patch-alpine`, `patch-windows`, `patch-proxmox-host`, `patch-hub-host`, `reboot`,
`rollback`, `snapshot`, `service-restart`, `compose-restart`, `compose-update`, `quarantine`, `quarantine-release`,
`unenroll`, `sudoers-refresh`, `keys-rotate`, `provision-vm`, `provision-lxc`, `zfs-replicate`, `pbs-sync`,
`restic-backup`.

#### 7.8.8 Playbook format

```markdown
+++
name = "patch-failure"
incident_kinds = ["patch_failed"]
autonomy = 1
risk = "normal"
tools = ["get_incident", "get_machine", "get_vitals", "run_diagnostic", "exec", "run_runbook", "add_incident_note", "finish_job"]
hosts = "incident"               # incident | site
max_runtime = "30m"
+++
## When
## Read first
## Do
## Done when
## Stop and ask if
```

Built-in playbooks: `patch-failure`, `service-down`, `disk-filling`, `security-finding`, `machine-silent`,
`backup-stale`, `guided-install`.

## 8. Edge cases and failure modes

| # | Situation | Expected behaviour | How it's detected / tested |
| --- | --- | --- | --- |
| E1 | Hub down for 6 hours | Probes buffer and replay on stream 2 while live reports flow on stream 1; history backfills; samples older than 10 min don't open threshold incidents | Integration test |
| E2 | Probe buffer full | Oldest segments dropped; hub records `probe.data_gap` | Unit test |
| E3 | Probe reinstalled, buffer lost, or guest rolled back (even with reports still buffered) | New epoch (from an empty buffer, or because `Welcome.received` is ahead); hub accepts it and records `probe.epoch_changed` | Contract test (AC48) |
| E4 | Machine clock wrong by hours | Samples placed at offset-corrected time for alerting; `clock_skew` warning | Unit test |
| E5 | Two probes claim one machine id | Second rejected with `0x11`; critical `probe.identity_conflict` | Contract test |
| E6 | VM cloned with the probe installed | Same endpoint id from two addresses with different boot ids: `identity_conflict`, both refused until one re-enrolls | Integration test |
| E7 | Enrollment token reused, expired or wrong kind | `JoinError` with the reason; shown on the dashboard | Contract test |
| E8 | SSH host key changed | Actions blocked; critical incident; admin accepts with step-up | Integration test |
| E9 | apt busy during a patch | Step waits up to 10 min, then the job fails without changes and retries in the next window | Fault injection |
| E10 | `patch = hold` | Never patched; pending updates reported | Unit test |
| E11 | Reboot loop after a kernel update | No report for 15 min: rollback if enabled (not for role `hub`), else playbook or person | Lab test |
| E12 | Snapshot unsupported on the guest's storage | Precheck fails `snapshot_unsupported` unless policy `snapshot = optional` | Unit test |
| E13 | Hypervisor needs a reboot | Never automatic; approval lists affected guests | Unit test |
| E14 | Hub's own host patched and rebooted | Reboot scheduled 60 s out; job resumes at verify after restart | Integration test |
| E15 | No operator, or all decline | Incident `needs_human`, callout | Integration test |
| E16 | Operator disconnects mid-job | Runner kept 5 min; then killed, job `failed` | Integration test |
| E17 | Hub restarts mid-assistant-job | Operator reattaches the job if its token is valid | Integration test |
| E18 | Assistant `exec` outside job hosts, or a tool not allowed | `out_of_scope` or `tool_not_allowed`; audit entry | Contract test |
| E19 | Machine output tells the assistant to approve something | No approval tool exists; scope and hash binding hold | Contract test |
| E20 | Approved call repeated with different arguments | `approval_mismatch` | Contract test |
| E21 | Approval still pending at the job deadline | Job ends `needs_human`; Resume job offered after approval | Unit test |
| E22 | Auto-quarantine rule matches a hypervisor | Exclusion wins; incident only | Unit test |
| E23 | Quarantine isolation step fails | State `failed`, critical incident | Integration test |
| E24 | Quarantine on a guest when the PVE datacenter firewall is off | Fails `pve_firewall_off` with instructions; never enables it | Lab test |
| E25 | Peer link lost | Silent then down; elected hub calls out; local monitoring continues | Network test |
| E26 | Both peers behind hard NAT and no relay | `unreachable: no path`; dashboard explains a relay is needed | Network test |
| E27 | Relay at capacity | Admission by priority; refused clients see why | Relay test |
| E28 | Relay list returns garbage or 10 000 entries | Invalid skipped, first 100 kept, status shows the error | Unit test |
| E29 | Bulk transfer with only a relay path | Waits; info event after 10 min | Network test |
| E30 | Transfer interrupted | Resumes from last verified chunk; final hash must match | Network test |
| E31 | Notifier failing | Retries, then `notifier_failed` | Unit test |
| E32 | Hub disk below 2% free | Stops accepting stream-2 replays and new jobs, keeps live ingest and alerting, critical incident | Fault injection |
| E33 | Database corruption | Daily `quick_check`; on failure the hub stops writing (probes keep buffering, no acks), keeps alerting from memory, refuses jobs, raises critical; admin restores from backup | Fault injection |
| E34 | Master key lost | Secrets unrecoverable; monitoring continues; admin regenerates keys and re-enrolls machines | Documented, tested once |
| E35 | Hub address changes | Probes reach the hub by endpoint id through a relay; the hub sends `ConfigUpdate` with new addresses and `KeysUpdate` with the new `from=`; at a LAN-only site without a relay, run `rackhand-probe set-hub <ticket>` on each machine | Integration test |
| E36 | eBPF unavailable (old kernel, no BTF, LXC) | Sampling with helper attribution; capability shown | Unit test |
| E37 | Unprivileged LXC | In-container probe samples; the Proxmox host's probe attributes LXC connections by cgroup | Lab test (S1) |
| E38 | Desktop asleep | `expected_offline`: info only | Unit test |
| E39 | Probe update breaks the probe | Helper switches back within 2 min of the restart | Integration test |
| E40 | Git push contains a secret | Push refused, critical audit event | Unit test |
| E41 | Sign-in brute force | Per-IP backoff; account never locked | Unit test |
| E42 | Two admins decide one approval at once | First write wins; second sees "already decided" | Unit test |
| E43 | Machine renamed or re-IPed | Identity is endpoint id and machine id; address follows the probe's report; SSH host key still checked | Unit test |
| E44 | Hub restarts | Silence suppressed 3 min; staged reports compacted; the recent window rebuilt before rules run; jobs with `resumable_step` or in a detached step resume, others become `interrupted` with an incident | Integration test |
| E45 | Peer queries JobLog without permission | `Denied("not allowed")` | Contract test |
| E46 | Daylight-saving change during a window | Nonexistent times run at the next valid minute; repeated times run once | Unit test |
| E47 | Assistant daily cap reached | New incidents route to people with a note | Unit test |
| E48 | Container start produces `memfd:runc_cloned` | Exempt, no event | Unit test |
| E49 | A step or tool needs an account on a monitor machine | Fails with `monitor_only` before anything is sent; hypervisor-side actions need an approval; no automatic policy applies | Unit test, contract test |
| E50 | A probe reports another guest's MAC | Binding unchanged; `machine.guest_binding_mismatch`; hypervisor-side actions on that machine blocked until an admin confirms with step-up | Integration test |
| E51 | A runbook or diagnostic parameter value starts with `-` | Refused by the hub's validation, and by the wrapper if it gets that far | Unit test |
| E52 | A report uses a label id the hub doesn't know | That sample dropped and counted in `probe.unknown_labels`; the rest of the report kept | Contract test |
| E53 | A 4 MB frame decompresses past 16 MB | Connection closed with `0x15`; nothing staged | Contract test |
| E54 | The hub restarts, or the SSH connection drops, during a detached step | The command keeps running on the machine; the hub polls again and records the result | Integration test |
| E55 | A detached step passes its timeout | Not killed; job `timed_out`, incident, machine locked until the unit exits | Integration test |
| E56 | An incident keeps reopening | After 2 automatic runbook starts in 24 h it goes to a person with "attempt limit reached" | Unit test |
| E57 | A runbook succeeds but the condition doesn't clear | After 10 min treated as failed: playbook or person | Unit test |
| E58 | Probe interval set to 300 s | Durations under 4 intervals raised to 4; silence warning at 20 min; clearing needs 2 new samples | Unit test |
| E59 | A machine makes more distinct connections than the caps | The probe folds the excess per container and executable; the hub stores summary rows past the daily cap; `conn.overflow` | Unit test |
| E60 | A command list arrives unsigned, expired, or older than the installed one | `install-commands` refuses; the file is unchanged | Unit test |
| E61 | Sign-in flood against one account from many addresses | Browsers new to the account limited to 1 attempt a minute in total; a browser that signed in before still gets in | Unit test |
| E62 | The hypervisor that hosts the hub is rebooted | Approval names the hub; reboot scheduled 60 s out; the job resumes at verify when the hub is back | Lab test |
| E63 | A hub process asks the updater for an unsigned or older binary | Updater refuses; no slot change; audit entry | Integration test |
| E64 | A release is signed with the standby key | Accepted by installers, the helper and the updater | Unit test |
| E65 | A machine has no route to the probe update URL | Stays on its version; `update_unreachable` (info) | Unit test |
| E66 | A guest's firewall configuration is changed while it is quarantined | Release stops with `quarantine_config_changed`; a person decides | Lab test |

## 9. Error handling and recovery

- **Categories:** transient (network, timeouts, locks), configuration (invalid runbook, bad credentials), safety (scope,
  approvals, exclusions), integrity (host key change, identity conflict, audit chain), resource (disk, memory).
- **Across contracts:** QUIC close codes (7.3), typed error variants, MCP error codes (7.3.6), job step states with
  exit codes, HTTP status plus a message for the dashboard and notifiers.
- **Retries:** network operations back off from 1 s to 60 s with jitter. SSH commands are retried only for steps marked
  `idempotent`. Notifiers retry three times.
- **What people see:** every failure names the step, machine, command and what came back.
- **Hub backups:** nightly at 02:00 site time: `VACUUM INTO` a temporary file, zstd-compress, add the node key, encrypt
  with the master key; keep 2 locally. A peer's `backup_quota_bytes` is the space this hub gives that peer for its
  backups (0, the default, means none). A hub sends its latest backup to each peer that granted it space, over
  `rackhand/xfer/1`, direct paths only like other bulk transfers; the peer keeps one copy. Restore:
  `rackhand hub restore <file>` with the master key, which also restores the node key so probes stay pinned. To get a
  backup from a peer when the original hub is gone, an admin on the peer runs `rackhand hub peer-backup export <site>
  <file>` and copies the file to the new machine.
- **Integrity:** multi-table writes use one transaction. Each job step is recorded before it runs.
- **Logs:** JSON lines to journald (Windows: event log), info level by default, filterable.

## 10. Security, privacy and safety

| Boundary | Threat | Control |
| --- | --- | --- |
| Joiner to hub | Token guessing, replay | 128-bit single-use tokens, short expiry, per-address rate limit |
| Probe to hub | Fake probe, replay, flooding | Registry, mutual pinning, epoch and seq, frame cap, stream rate limits |
| Probe to helper | Probe compromise escalating to root | Fixed requests only, no paths, URLs or commands from the socket; the helper never uses the network; signature-checked updates read from one fixed file; hub-signed key updates checked against a root-owned pin; nothing root executes or trusts is writable by the probe user (7.3.3) |
| Probe to hypervisor actions | A probe lies about which guest it is | Guest binding confirmed by an admin and fixed; a mismatch blocks hypervisor-side actions (7.3.12) |
| Hub process | A bug in the web, mesh or parsing code runs as the hub | Unprivileged user under a hardened unit, single capabilities for ICMP, master key passed as a credential, a separate root updater that verifies signatures itself, decompression limits (7.1, 7.3, 7.5.7) |
| Hub to machines | Stolen hub keys reach every machine | Keys only in the Vault, master key outside the DB, `from=` restriction, no assistant account on hubs, sudo I/O logs, step-up for high risk, self-watch, peer watch, audit anchors in peers |
| Machine output to assistant | Prompt injection | Untrusted wrapping, no approval tool, approvals bound to exact calls, scope enforced in the hub, high risk always human |
| Operator host | Compromise drives tools | Job tokens scoped to hosts, tools and deadline; no keys on the operator |
| Device (CLI) | Stolen laptop | Device keys revocable, MCP keys expire, tunnels need responder role on the owning hub |
| Peer to peer | Malicious peer | Summaries and allowed queries only; requests need the owner's approval; nothing secret crosses |
| Browser to hub | Session theft, CSRF, XSS, password and code guessing | Mandatory second factor, strict cookies, CSRF tokens, strict CSP, auto-escaping templates, limits per source and per account, single-use codes, trusted-proxy list (7.7.2) |
| Relay | Inspection, metadata | End-to-end encryption; relays see endpoint ids, sizes and timing; private relays available; listed relays get no keys |
| Supply chain | Malicious release or dependency, stolen or lost signing key | Signed releases verified before install and update, signing keys offline and never on CI, a standby key for rotation, a maintainer rebuild that must match before signing (section 13), `cargo deny`, `cargo audit`, lockfile, reproducible builds |
| Fetched lists | Hostile content | Strict parsing, size caps, HTTPS only, never executed |

- **Secrets** (SSH private keys, API tokens, webhook URLs, SMTP passwords, TOTP secrets, tokens, the git deploy key)
  live only in the Vault and never appear in logs, callouts, the git mirror, MCP results or peer messages. No assistant
  account exists on a hub host, so no assistant command can read the master key.
- **Hub self-watch:** the hub's host has a probe. Daily, the hub checks its binary's hash against the signed release
  manifest, the audit chain, database integrity, and its config files. Failures are critical and appear in the next
  peer summary.
- **AI provider data:** an assistant job sends the brief and every tool result (including machine output) to the AI
  provider configured on the operator. The operator setup page and docs say so, and the assistant daily cap limits
  volume and cost.
- **Privacy:** machines with role `desktop` default to `connections = "summary"`: counts per country and ASN per 5
  minutes, checks against threat lists still run (a known-bad hit is still critical and names the destination), but no
  per-destination history is stored. Servers default to `full`. Any machine can be set to `full`, `summary` or `off`, and
  the Machine page shows the mode. No telemetry.
- **Public evidence:** test evidence committed to `docs/evidence/` uses documentation IP ranges (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24) and invented names; raw lab output stays out of the repository.

## 11. Performance and resources

- **Probe:** collectors read `/proc` and `/sys` directly; pending-update checks run at most every 6 hours at
  `nice 19` and `ionice idle`; eBPF events aggregate in per-CPU maps drained every interval; reports are
  zstd-compressed. Measured by a 1-hour soak test (RSS, CPU and bytes sent) against section 5.2.
- **Hub:** one writer task; four read connections; staged reports committed per 500 ms batch; compaction every 5
  minutes, in one transaction per machine so a commit of live reports never waits behind the whole fleet. The recent
  window (7.4.1) costs about 20 MB at 100 machines, inside the 300 MB budget. Measured with a load generator of 200 simulated probes for 1 hour (p99 ingest-to-visible under 2 s, RSS under
  300 MB, CPU under 10% of a core) and a synthetic 2-year data fill for 50 machines (database size under 2 GB, retention
  and rollups finishing within their schedule).
- **Network:** a report with 100 samples and no events is about 1.2 KB compressed (about 80 B/s at 15 s). Peer summaries
  for 50 machines are about 8 KB per 30 s.

## 12. Observability and tooling

- Hub internals on `/metrics`: `rackhand_hub_ingest_reports_total`, `rackhand_hub_ingest_lag_seconds`,
  `rackhand_hub_staging_rows`, `rackhand_hub_jobs_running`, `rackhand_hub_db_size_bytes`,
  `rackhand_hub_notifier_failures_total`, `rackhand_hub_peer_up`, `rackhand_hub_operator_up`.
- `rackhand-cli status` and `rackhand-probe collect --once --json` for debugging.
- `rackhand hub runbook check <file>` validates syntax, parameters, step kinds and sudo coverage; the dashboard runs it
  on save.
- `rackhand hub detect replay --machine <id> --from <t> --to <t>` reruns rules over stored data and prints what would
  have fired.
- `rackhand hub audit verify` checks the chain offline.

## 13. Migration, compatibility and rollout

- **Greenfield.** No data or users to migrate.
- **Versions.** 0.x. Forward-only migrations; the hub refuses a database newer than itself. Probes, operators, relays
  and CLIs one minor version older are accepted.
- **Channels.** `stable` and `beta`. Probe updates go to one canary machine per site, then the rest after 1 hour without
  new incidents on the canary.
- **Rollback.** Probes: automatic (7.3.3). Hub, relay, operator: 7.5.7.
- **Release signing** (D90). CI builds the artifacts but never holds a
  signing key. A maintainer rebuilds the tag on a machine that is not a CI runner, checks that every hash matches the
  CI build (builds are reproducible, 5.2), and only then signs each artifact and the release manifest with the current
  key. The key is passphrase-protected and kept offline between releases. Every binary and installer pins two public
  keys, the current one and a standby whose private half is stored separately and used for nothing else. If the
  current key is lost or exposed, the next release is signed with the standby and carries a new pair; binaries already
  installed accept it because they already pin the standby. A release signed by neither key is never installed.
- **First deployment.** A multi-site homelab run by a maintainer: a hub at each site, an operator host at the main site
  invited to all hubs, a relay on a VPS (its own probe enrolled to the main hub in remote mode), an offsite box
  bootstrapped as a new site, and the existing uptime checker retired after Rackhand checks cover its monitors for 2
  weeks. Host-level rollout plans stay out of this repository.
- **CI.** `ci.yml` runs on self-hosted runners only when `github.repository == 'StrangeMatterStudio/Rackhand'` and the
  event is a push, a manual run, or a pull request whose head repository is this repository.
  `ci-github-hosted.yml` has the same jobs on GitHub-hosted runners and runs only when the repository variable
  `RACKHAND_GITHUB_HOSTED` is `true`. The repository requires approval to run workflows from outside contributors. A CI
  job lints both workflow files and tests these conditions with recorded event payloads.

## 14. Testing strategy

| Layer | What | Where |
| --- | --- | --- |
| Unit | Detect rules and the worked examples in 7.6, at several probe intervals; runbook and playbook parsing; command template generation and matching; signed payload checks; Policy decisions (levels, risk, exceptions, exclusions); buffer; epoch logic; time-series encoding; rollups; retention; audit chain and checkpoints; relay list parsing; DST windows | Every CI run |
| Contract | Each QUIC contract with a real endpoint pair in-process; MCP scope, allowed tools, approval hash binding, untrusted output; protobuf old and new versions | Every CI run |
| Collector | Linux collectors on fixture `/proc` and `/sys` trees; Windows collectors on recorded API outputs | Every CI run |
| eBPF | Load and capture a known connect and exec on kernels 5.10, 6.1 and the current Proxmox kernel | Self-hosted privileged Linux runner |
| Integration | Hub, probes and helpers in containers with sshd; enrollment; runbooks; patch flow with a fake package manager; assistant flow with a fake runner; backups and restore | Self-hosted Linux runner |
| Network | Hubs, a relay, devices and probes in Linux network namespaces with nftables NAT (full cone, symmetric, UDP blocked): hole punching, relay fallback, peer watch with three hubs, tunnels, transfers | Self-hosted privileged Linux runner |
| Windows | Probe and helper services, collectors, pipe, enrollment, dispatch script, patch script dry run | Manual on a Windows test machine with a recorded checklist until a self-hosted Windows runner exists; the GitHub-hosted workflow copy can run them in forks |
| Performance | Probe soak; hub load; synthetic 2-year fill | Nightly, self-hosted |
| Live (local lab) | The built product deployed to QEMU/KVM machines on the development machine: a hub managing a Linux VM, nested Proxmox VE 8 and 9 nodes with LXC guests, a second site behind a relay and NAT, a real Claude Code operator | At the end of each milestone, on the development machine (not in CI) (D107) |
| Live (real lab) | The same live tests against the owner's hub VM or LXC and one managed VM, plus the checks that need real hardware: Proxmox snapshot, rollback, guest firewall quarantine, LXC cgroup attribution, provisioning, TrueNAS, multi-site link over the internet | Once at the end of v0.1 and before each minor release, evidence redacted per section 10 (D107) |

The implementer runs both live tiers, with access the owner provides for the real lab. Checks the owner does
themself exist only where the owner's own accounts, devices or offline keys are needed: the runner setup, Claude Code
sign-ins, a passkey, a Windows machine and release signing. Acceptance criteria whose verification says `lab` are
tested in both live tiers.

## 15. Acceptance criteria

| ID | Criterion (Given / When / Then) | Covers | Verification |
| --- | --- | --- | --- |
| AC1 | Given an enrolled Debian 12 test VM (one mount, one disk, one interface, Docker with two containers), when 15 s pass, then every metric in 7.4.2 except `temp.c`, its services, containers and pending updates appear on its machine page within 30 s | G1, FR-1, FR-2 | integration |
| AC2 | Given the hub stopped for 2 hours, when it restarts, then the machine's series for the gap are complete within 15 minutes, live vitals stay under 30 s during replay, and no threshold incident opens for samples older than 10 minutes | G1, FR-3, E1 | integration |
| AC3 | Given the buffer limit, when the hub is down past 64 MB of reports, then the oldest are dropped and `probe.data_gap` names the missing range | FR-3, E2 | integration |
| AC4 | Given retention settings, when retention and rollups run, then data older than each tier's limit is gone, newer data remains, and tier-1 and tier-2 values equal the min, max and avg of their source | FR-7 | unit |
| AC5 | Given `/data` above 95% for 5 minutes, then a critical incident opens and a Discord message and an email are sent within 60 s; given 86% for 5 minutes, then a warning callout is sent within 6 minutes; when it drops to 70% for two samples, then a resolution message is sent | G2, FR-8, FR-11 | integration |
| AC6 | Given the forecast example in 7.6.2, when the detector runs, then it reports a warning with an ETA of 62.5 hours | G2 | unit |
| AC7 | Given the baseline example in 7.6.4, when the data is replayed, then a warning opens at 14:35 and the bucket is frozen | G2, FR-8 | unit |
| AC8 | Given an enrolled machine whose probe stops, then a silent warning opens at 60 s (callout within 6 min); with `expected_offline`, only an info event | G2, E38 | integration |
| AC9 | Given three hubs, each linked to the other two, when one hub's network is cut, then the other two mark it silent within 2 minutes and down within 10, and exactly one of them sends the callout | G2, G6, FR-18 | network |
| AC10 | Given an HTTP check against a stopped service, then a warning opens after 2 failed checks, and a certificate 10 days from expiry gives a warning | FR-9 | integration |
| AC11 | Given simulators replaying recorded Proxmox, TrueNAS, Redfish and SNMP responses, added through the form, then each driver's metrics in 7.4.2 appear and a stopped simulator gives a silent warning after 2 polls | FR-10 | integration |
| AC12 | Given a runbook step that runs past its timeout or prints 2 MB, then the step fails with `timeout` or its output is cut at 1 MB with a marker, and the job log shows command, exit code and output | FR-12 | integration |
| AC13 | Given a machine past learning, when a process connects to a new ASN in a new country on port 4444, then a warning incident opens; on a machine without eBPF the same is found by sampling when the connection stays open across a 5 s poll, and the machine page shows that it uses sampling | G3, FR-4 | unit + eBPF |
| AC14 | Given a loaded threat list, when a machine connects to a listed IP, then a critical incident opens within 60 s | G3 | integration |
| AC15 | Given a binary started from `/tmp`, and separately a new listening port, then a critical and a warning incident open; a container start does not | G3, FR-5, E48 | integration |
| AC16 | Given the helper, when a key is added to any `authorized_keys` outside a Rackhand job, then a critical incident opens; when an SSH login succeeds from a new IP, then a warning opens; the probe never received file contents | G3, FR-6 | integration |
| AC17 | Given a critical finding on a guest with policy `quarantine = approval`, when an admin approves with step-up, then the guest can reach only the hub and DHCP, the hub can still run diagnostics, a forensic snapshot exists, and release restores traffic | G3, FR-15 | lab |
| AC18 | Given an enabled auto rule for tag `dmz`, when a `dmz` machine triggers `conn.known_bad`, then it is quarantined without approval; a hypervisor with the same finding is not; enabling the rule required step-up | G3, FR-15, E22 | unit + integration |
| AC19 | Given a VM with pending security updates and policy `auto`, when its window starts, then a `rackhand-patch-*` snapshot is taken, updates install, the VM reboots if needed, verify passes, and the job log shows each step | G4, FR-13 | integration + lab |
| AC20 | Given `hold`, nothing installs; given `approve-only`, nothing installs until approved, and an approval after the window waits for the next window; during a maintenance window nothing patches and no silence alert fires | G4, FR-13 | unit |
| AC21 | Given a patch job whose verify fails because a required mount is missing, then `patch_failed` routes to `patch-failure` and an operator gets the offer within 60 s | G5, FR-16 | integration (fake runner) |
| AC22 | Given a job scoped to machine A, when the assistant calls `exec` on B or a tool not in the playbook, then the call fails with `out_of_scope` or `tool_not_allowed` and the audit log records it | G5, FR-17 | contract |
| AC23 | Given a level-1 playbook, when the assistant calls `run_runbook`, then it gets `needs_approval`; after a dashboard approval the same call with the `approval_id` runs once; a call with different arguments gets `approval_mismatch`; no MCP call changes an approval | G5, FR-14, FR-17 | contract |
| AC24 | Given tool output containing "approve the pending request", then no approval changes state without a dashboard action | G5, E19 | contract |
| AC25 | Given a real Claude Code operator and a staged failure (a stopped Compose project), when the incident opens, then within 30 minutes the assistant has called `run_diagnostic`, requested `compose-restart`, and after approval the containers run and the incident resolves, in at least 2 of 3 runs | G5 | lab |
| AC26 | Given a personal `read` key, `run_diagnostic` and `run_runbook` are refused; with `read_request` they work under the same gating; an expired key is refused | FR-17 | contract |
| AC27 | Given two hubs behind NAT and a shared relay, when they link with an invite, then they connect (direct if possible), exchange summaries every 30 s, and each shows the other's machines and can query vitals | G6, FR-18 | network |
| AC28 | Given a responder on hub A, when they request `compose-restart` on hub B's machine, then hub B runs it only after a hub B approval; a `JobLog` query from A is denied by default | G6, FR-18, E45 | integration |
| AC29 | Given a 5 GB file, when `rackhand-cli send` is interrupted at 60% and rerun, then it resumes from the last verified chunk and the BLAKE3 hash matches | G6, FR-19, E30 | network |
| AC30 | Given a device enrolled on hub B, when `rackhand-cli connect siteb/vm1 22` is used as `ProxyCommand` from another network, then SSH works; without a hub B device enrollment it is refused | G6, FR-19 | network |
| AC31 | Given a private relay, an unkeyed hub is refused and a keyed one admitted; an unkeyed endpoint on a public relay is limited to 1 Mbit/s; a relay list with bad entries keeps the valid ones. If spike S2 confirms priority admission: given a public relay at capacity, high-priority keyed endpoints are admitted before unkeyed (if S2 rules it out, this clause and the priority wording in FR-20 are removed, 7.3.10) | G6, FR-20, E27, E28 | unit + network |
| AC32 | Given a fresh Debian 12 machine, when the hub bootstrap runs, then a hub runs, first run is reachable, and an invite from it links to an existing hub; the LXC script does the same on a Proxmox host | G7, G8, FR-21 | integration + lab |
| AC33 | Given an enrolled Proxmox host, when `provision-vm` runs with a template and cloud-init, then the VM boots, enrolls and is healthy | G7, FR-23 | lab |
| AC34 | Given the `guided-install` playbook and a fake runner script, when a person starts it for a target, then each step's change goes through an approval in order | G7 | integration |
| AC35 | Given a Linux, an Alpine and a Windows machine, when each runs its installer, then each enrolls and reports; an installer given a binary with a bad signature stops before installing | G8, FR-21 | integration (Linux, Alpine), manual checklist (Windows) |
| AC36 | Given an agentless form, an operator invite and a device invite, each completes its join; a used or expired invite is refused with its reason | FR-21, E7 | contract |
| AC37 | Given a new probe release, then the canary updates first and the rest after 1 hour; given a broken release, the helper restores the previous version within 3 minutes of the update | FR-22, E39 | integration |
| AC38 | Given a library change, then a new revision exists and it is pushed to the git mirror within 60 s with no secret values; a planted secret blocks the push | FR-24, E40 | unit + integration |
| AC39 | Given any action, approval, configuration change, sign-in or MCP call, then an audit entry exists and verify passes; changing one row makes verify fail; retention leaves a verifiable chain | FR-26 | unit |
| AC40 | Given an account without a second factor, it can't sign in; an OIDC user signs in through the provider and steps up with a local factor; a viewer can't approve; a responder can't approve high risk | FR-14, FR-25 | integration |
| AC41 | Given the hub with no internet, no peers and no operator, then it still collects, alerts by email through a LAN SMTP server, and runs runbooks | 5.2 availability | integration |
| AC42 | Given the soak, load and fill tests, then the probe and hub stay inside section 5.2 | 5.2 | performance |
| AC43 | Given the release artifacts, then they are static (no interpreter or shared runtime needed), signed, and rebuilding from the tag gives identical hashes | G8, 5.2 | CI |
| AC44 | Given recorded event payloads, then `ci.yml` runs self-hosted jobs only for upstream pushes and same-repository pull requests, and `ci-github-hosted.yml` runs only with `RACKHAND_GITHUB_HOSTED=true` | 13 | CI |
| AC45 | Given a probe one minor version older than its hub, then it connects and reports, and is offered the update | 5.2 compatibility | integration |
| AC46 | Given a remote-mode probe on a machine at a site without a hub, then it reports to its hub over the mesh and a runbook runs on it through the tunnel | G6, FR-21 | network |
| AC47 | Given a hub backup restored on a new machine with the master key, then probes reconnect without re-enrolling | 9 | integration |
| AC48 | Given a probe whose guest is rolled back to a snapshot with unacked reports in its buffer, then it starts a new epoch on reconnect and its reports are accepted at once | FR-3, E3 | contract |
| AC49 | Given `/metrics` with and without the bearer token, then it returns 401 without it and every series' latest value with it | FR-7 | integration |
| AC50 | Given a job running on a machine, when another runbook or an assistant `exec` targets it, then the second waits up to 60 s and then fails with `machine_busy` | FR-12 | integration |
| AC51 | Given the daily assistant cap reached, when another incident matches a playbook, then it routes to a person with a note | FR-16, E47 | unit |
| AC52 | Given an open, unacknowledged warning, then it is re-sent after 6 hours and not before; acknowledging stops it | FR-11 | unit |
| AC53 | Given an operator, a relay and a `rackhand-cli` one minor version older than the hub, then each connects and works | 5.2 compatibility | integration |
| AC54 | Given the hub database file copied to another machine without the master key, then no secret can be read from it | 5.2 security | unit |
| AC55 | Given a desktop with `connections = "summary"`, then only per-country and per-ASN counts are stored, and a connection to a threat-listed IP still opens a critical incident naming it; with `off`, nothing is stored | 10 privacy, D56 | integration |
| AC56 | Given a Windows machine, then connections, a process started from `%TEMP%`, and a new listening port are reported | FR-4, FR-5 | manual checklist until a Windows runner exists |
| AC57 | Given the command wrapper, when the automation user requests a command that differs from every template in one argument, then it is refused and nothing runs | 7.3.7 | unit + integration |
| AC58 | Given a machine enrolled at access level `monitor`, then it reports vitals and security signals and gets probe updates; no `rackhand` or `rackhand-ai` user, hub key or command list exists on it; patch selection skips it; `ssh` steps, `run_diagnostic` and `exec` fail with `monitor_only`. Given it is a Proxmox guest, a quarantine from the hypervisor runs only after an approval, and an enabled auto-quarantine rule that matches it does nothing | FR-21, FR-15, E49, D88, D89 | integration + lab |
| AC59 | Given a monitor machine, when the one-time level command from the dashboard is run on it as root, then it becomes managed with the same machine id and history, and the reverse command removes the users, keys, sudoers file and command list; no call from the hub alone changes the level | FR-21, D89 | integration |
| AC60 | Given a confirmed guest binding, when the probe reports the MAC of a different guest, then the binding is unchanged, `machine.guest_binding_mismatch` opens, and snapshot, rollback and quarantine for that machine are refused until an admin confirms with step-up; the other guest is never touched | 7.3.12, E50, D93 | integration (simulated Proxmox API) |
| AC61 | Given a runbook parameter value `-f`, then the hub refuses the call and the wrapper refuses the same arguments sent to it directly; given a command list that is unsigned, expired or not newer, `install-commands` leaves `commands.json` unchanged; the first list arrives with the join | 7.3.7, E51, E60, D92 | unit + integration |
| AC62 | Given a reconnect with a backlog, when a live report uses a label set first seen during the outage, then every sample is stored under the right labels; a sample with an unknown label id is dropped and counted while the rest of its report is stored; a frame that decompresses past 16 MB closes the connection with `0x15` | FR-3, E52, E53, D94 | contract |
| AC63 | Given a patch job in its install step, when the hub is restarted, and separately when the SSH connection is cut, then the package manager finishes, the hub records the step's output and exit code, and the job goes on to verify | FR-12, FR-13, E54, D97 | integration |
| AC64 | Given an incident whose automatic runbook succeeds but whose condition returns each time, then the runbook starts at most twice in 24 hours and the incident then goes to a person with "attempt limit reached"; given a runbook that succeeds while the condition never clears, then after 10 minutes the incident routes as if the job had failed | FR-8, E56, E57, D96 | unit |
| AC65 | Given a machine with a 300 s probe interval, then a 5-minute rule needs 4 matching samples, no silence warning opens before 20 minutes without a report, and a rule doesn't clear until 2 new samples are past the clear margin; given a disk above 85% for 5 minutes that then moves between 84% and 86% on every sample, then the one incident stays open, and it resolves only after 2 samples under 83% | FR-1, FR-8, E58, D95 | unit |
| AC66 | Given a rule 20 minutes into a 30-minute duration, when the hub restarts, then the incident still opens at 30 minutes; given rule evaluation stalled for 60 s under 200 simulated probes, then live reports are still acked within 2 s | FR-8, 5.2 latency, E44, D100, D102 | integration |
| AC67 | Given a running hub, relay and operator, then none of their processes is root and the hub can't open the master key file by path; given an update request for an unsigned binary or a lower version, the updater refuses and no slot changes; given a release signed with the standby key, installers, the helper and the updater accept it | 5.2 security, 5.2 supply chain, E63, E64, D90, D98 | integration + unit |
| AC68 | Given 10 failed sign-ins for one account from different addresses, then a browser new to the account is held to 1 attempt a minute while a browser that signed in before still signs in; a used TOTP code is refused; a forwarding header from an address outside `trusted_proxies` is ignored | FR-25, E61, D99 | unit + integration |
| AC69 | Given a retention run, then every table in 7.4.1 holds nothing older than its rule and `peer_summaries` holds one row per peer; given job output past its budget, the oldest is trimmed and metadata stays; given a machine reporting 100 000 distinct destinations in a day, then at most 20 000 connection rows plus summary rows are stored and a threat-listed destination among them still opens a critical incident | FR-7, E59, D100 | unit + performance |
| AC70 | Given a job token used from an endpoint other than the operator that accepted the job, the call is refused; a `read_request` key on a viewer's account can't run a diagnostic; an approval can't be used by a different caller or after the runbook was edited; a personal key gets `needs_approval` for `journal` and runs `df` without one | FR-17, D101 | contract |
| AC71 | Given two containers running the same executable, when one of them connects to a destination new for it, then the event and the connection record name that container, with eBPF and with sampling | G3, FR-4, D103 | integration + eBPF |
| AC72 | Given a guest with firewall rules of its own, when it is quarantined and released, then its firewall configuration is identical to before; while quarantined it reaches only DHCP and the hub's QUIC port; assistant `exec` on it fails with `machine_quarantined`; if its configuration was changed meanwhile, release stops with `quarantine_config_changed` | FR-15, E66, D104 | lab + contract |
| AC73 | Given the hypervisor that hosts the hub, when its reboot is approved, then the approval lists the hub among the affected guests and the job finishes at verify after the hub is back | FR-13, E62 | lab |

## 16. Alternatives considered

| Alternative | Pros | Cons | Decision |
| --- | --- | --- | --- |
| Do nothing (Uptime Kuma, manual SSH) | No work | The failures in section 2 continue | Rejected |
| Assemble existing tools (Prometheus, Grafana, Alertmanager, Wazuh, Ansible, Tailscale) | Mature parts | Five systems to run and wire; no assistant hand-off with guard rails | The integration is the product |
| Extend a cloud-hosted operations hub | Existing dashboard | Can't reach private networks | Rejected |
| Full layer-3 VPN | Any program works across sites | Root networking everywhere, clashes with existing VPNs, largest surface | Rejected: Rackhand-only mesh plus tunnels |
| Require an existing overlay | Least work | Ties Rackhand to another product | Rejected |
| Go | Mature WireGuard libraries | Garbage-collected runtime, more memory | Rejected: Rust |
| TypeScript / Node | Code reuse | Node on servers | Rejected |
| Probe executes commands | No keys on machines | Root agent on every machine taking orders | Rejected: SSH with scoped identities |
| Single root probe | Simpler | Every bug is a root bug | Rejected: probe plus helper |
| Probe in the docker group | Simpler container data | Root-equivalent | Rejected: helper serves container data |
| Chat approvals (Matrix, Discord bot) | Approve from chat | Outside the authenticated app | Rejected |
| AI approvals from a desktop session | Convenient | AI could approve its own request | Rejected |
| Claude Code on the hub host | One fewer machine | AI runtime next to the keys | Rejected: operator hosts |
| Own agent loop on the Anthropic API | No external CLI | Much more to build | Deferred to the runner interface |
| Peers vouch for each other's users | Convenient | A compromised hub acts at others | Rejected: devices enroll per hub |
| External time-series database | Powerful | Another service | Rejected: `/metrics` export |
| Single-page app dashboard | Richer UI | Node at build time | Rejected |
| Hub runs its own certificate authority | Passkeys everywhere | Every device must trust a new CA | Rejected for v0.1 |

## 17. Risks

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| v0.1 is very large | High | High | The plan orders work so each milestone is usable (single-site monitoring first); the version stays `0.1.0` and releasing is the maintainer's call after the run (D106) |
| A compromised hub has root on every machine | Low | Critical | Vault and master key split, `from=`, no assistant account on hubs, step-up, self-watch, peer watch, audit anchors, hardening guide |
| Prompt injection steers the assistant | Medium | High | No approval tool, hash-bound approvals, scoped exec, untrusted wrapping, level 1 start |
| eBPF portability | Medium | Medium | CO-RE, sampling fallback, kernel matrix (S1) |
| iroh relay can't do key-based priority as designed | Medium | Medium | Spike S2; modes and keys without priority as fallback, maintainer told |
| Hole punching often fails for some users | Medium | Medium | Relays, dashboard diagnostics, relay guide |
| Security detection is noisy | Medium | High | Learning period, info for new destinations, replay tool, silences |
| Windows support is large, and there's no Windows runner yet | High | Medium | Fixed signal list; manual checklist until a Windows runner is added |
| Self-hosted runners exposed | Low | High | Repository guard, fork exclusion, outside-contributor approval, AC44 |
| Time-series size or speed misses budget | Medium | Medium | Spike S8, cardinality cap, retention fallback |
| Probe footprint misses budget with iroh, aya and tokio | Medium | Medium | Spike S6; trim features, single-threaded runtime |
| Proxmox privilege names differ by version | Medium | Low | Spike S4 |
| Claude Code headless behaviour changes | Medium | Medium | Runner interface; everything else works without AI |
| Threat-list or GeoIP terms change | Low | Medium | Spike S10, sources switchable |

**Spikes** (findings recorded here, spike code deleted). The design is approved as a whole first; the spikes are then
the first steps of the implementation plan (D87). As with S8, a finding that contradicts this document goes back to
the owner and the document is updated before the work that depends on it starts.
- **S1** aya eBPF: connect, UDP and exec tracing on 5.10, 6.1 and the current Proxmox kernel; memory; LXC attribution by
  cgroup from the host; resolving the executable path and the cgroup id inside the eBPF program; and the licence the
  kernel requires an eBPF program to declare for the helpers it uses, against this project's licence (5.3).
  **Finding (2026-11-19):** aya programs on `cgroup_sock_addr` (`connect4`, `sendmsg4`) and the
  `sched_process_exec` tracepoint capture TCP connects, UDP sends and execs with pid, executable path (resolved in the
  program) and cgroup id on 5.10.274, 6.1.192 and 7.0.14, with 0.5 to 1.1 MB of map memory. On the lab's Proxmox VE 9
  node a container's connection is attributed to `/lxc/<vmid>/` from the host. The kernel refuses the program when it
  declares `MIT` (`bpf_probe_read_kernel` is GPL-only); `Dual MIT/GPL` loads. **Decided (2026-11-20, D111):** the eBPF
  program is its own crate licensed GPL-2.0 OR MIT (5.3). Report: `spikes/s1.md`.
- **S2** iroh relay: admission with keys, per-endpoint rate limits, priority at capacity, ports.
  **Finding (2026-11-19):** iroh-relay 1.5 admits by key (an `AccessControl` hook sees the handshake-verified
  endpoint id and the client's bearer token, sent with `RelayConfig::with_auth_token`), enforces one rate limit for
  every connection (1 MB in 8.4 s at 1 Mbit/s), and supports priority at capacity (a keyed endpoint evicts an unkeyed
  one with `Clients::disconnect`). Per-key rates and daily quotas are not possible: there is no per-endpoint rate
  setting and no per-endpoint byte counter. Ports: TCP 80 (HTTP, captive-portal probe), TCP 443 (HTTPS), UDP 7842
  (QUIC address discovery). **Decided (2026-11-20, D110):** one rate per relay set by the operator; no per-key rates or
  daily quotas (7.3.10). Report: `spikes/s2.md`.
- **S3** iroh path detection: direct versus relayed, waiting for a direct path.
  **Finding (2026-11-19):** iroh 1.5 reports paths with `Connection::paths()` (`is_ip`, `is_relay`, `is_selected`)
  and `paths_stream()` for changes; a `wait_direct(timeout)` over the stream works. Without NAT, or with full-cone
  NAT (a UDP port forward) at one side, the connection went direct within 1 ms of connecting; with UDP blocked it
  stayed on the relay and `wait_direct` timed out cleanly. Two Linux masquerade NATs never went direct, even with
  addresses given, because masquerade re-maps the port after a conntrack clash. So the network tier builds full cone
  with a static UDP forward, and the relay guide should mention port forwarding or UPnP for hubs behind Linux NATs.
  Report: `spikes/s3.md`.
- **S4** Proxmox: role privileges (snapshot, rollback, guest firewall, conntrack flush, clone, power) on PVE 8 and 9,
  and the datacenter firewall prerequisite; whether each network device's own firewall setting must be on for guest
  rules to apply, and saving and restoring it; and which upgrade command Proxmox requires on its own hosts (a full
  upgrade or a plain one), for `patch-proxmox-host` and for the helper's count of pending updates there.
  **Finding (2026-11-19):** the 7.8.6 role works for snapshot, rollback, power, guest firewall, the device flag and full
  clone on PVE 8.4 and 9.2; saving and restoring a guest's firewall configuration is exact. Guest rules apply only with
  the datacenter firewall on and the device's `firewall=1` (measured by pings from the hub). The API has no way to
  flush conntrack, so a quarantine flushes them with `conntrack -D` through the hypervisor's own managed enrollment
  (decided 2026-11-20, D112). Proxmox hosts
  take a full upgrade (`apt full-upgrade` or `dist-upgrade`). Report: `spikes/s4.md`.
- **S5** Claude Code headless: stdio MCP only, `--allowedTools` limited to MCP tools, stream-json events, kill at
  deadline; the flag that limits a run to the given MCP config; any extra flag stream-json needs in a non-interactive
  run; and running with a configuration directory that holds only the provider credential.
- **S6** Probe footprint: static musl binary size and steady RSS with iroh, aya and tokio.
  **Finding (2026-11-19):** A static musl probe skeleton (iroh 1.5 endpoint, aya tracepoint, tokio, /proc reads and a
  1.2 KB zstd frame every 15 s) is 5.55 MB on x86_64 and 4.43 MB on aarch64, with 4.9 MB steady RSS and 0.019% of a
  core over 30 minutes: inside the 15 MB, 25 MB and 1% budgets. The probe uses a current-thread tokio runtime and
  iroh with only `tls-ring` (default features add 0.7 MB for nothing a probe needs). Report: `spikes/s6.md`.
- **S7** Git mirror push in pure Rust (gix) or with libgit2 (git2, statically linked).
  **Finding (2026-11-19):** `git2` 0.21 (features `ssh`, `vendored-libgit2`, `vendored-openssl`) pushes twice over
  SSH with an Ed25519 deploy key held in memory, refuses a non-fast-forward update with `NotFastForward`, and builds
  as a static musl binary; it adds about 5.8 MB to the hub. `gix` 0.90 has no push. Report: `spikes/s7.md`.
- **S8** Time-series encoding: real bytes per value on recorded data.
  **Finding (2026-11-20):** on 24 hours of the 7.4.2 set from one host, plain Gorilla needs 5.3, 3.3 and 4.5 bytes
  per value (tiers 0, 1, 2), and SQLite adds 103 bytes per chunk row plus 31.5% of the blob (measured on the
  `series_chunks` schema; 7.4.1 counted no row cost), so 50 machines project to 5.66 GB. Storing whole multiples of a
  per-metric step, stamping samples with their tick and picking the cheapest integer coder per chunk, all at the hub,
  bring values to about 1 byte (2.40 GB with the 7.4.1 chunk rule); meeting 2 GB also needs larger tier 1 chunks, a
  shorter retention or a larger budget. **Decided (2026-11-20, D109):** integer columns at a per-metric step with tick timestamps,
  tier 1 and 2 chunks of 120 points and tier 2 kept 1 year, projected at 1.81 GB (7.4.1). Report: `spikes/s8.md`.
- **S9** TrueNAS API: which API (REST or JSON-RPC over WebSocket) the current releases support for pool, disk and alert
  reads.
- **S10** Threat list and GeoIP terms for default use in an open-source product, and whether the default lists still
  carry enough entries to be worth shipping as the defaults.
  **Finding (2026-11-19):** All three default sources may be used by default: Feodo Tracker is CC0 (abuse.ch terms
  3.4), Spamhaus DROP is free for any use with credit to The Spamhaus Project, DB-IP Lite is CC BY 4.0 with an "IP
  Geolocation by DB-IP" link. Entry counts on 2026-11-19: DROP 1 747 IPv4 networks (use the JSON files; EDROP is
  merged into DROP), DB-IP 732 796 country and 485 292 ASN ranges, Feodo Tracker 1 address (its datasets are nearly
  empty). Keeping Feodo Tracker as a default is the owner's call before T69 (report: `spikes/s10.md`).
- **S11** Collectors on current distributions: authentication events on systems that log only to the journal (no
  auth log file), read by a static binary; and memory readings on hosts where a ZFS cache holds most of the memory, so
  the memory rules in 7.6.1 don't fire on a healthy host.
  **Finding (2026-11-19):** on Debian 12 and Ubuntu 24.04 without an auth log, `journalctl -o json` with a cursor file
  and a pure-Rust journal reader both return every SSH login, invalid user and sudo event, and the cursor prevents
  re-reads; the probe uses `journalctl`, with the reader as fallback. On the lab's Proxmox VE 9 node with a full ARC,
  `MemAvailable` gave 16.4% available against 53.1% when the ARC above `c_min` is counted, so `mem.available_*` counts
  it (7.4.2). Report: `spikes/s11.md`.

## 18. Decisions

| # | Question | Decision | Rationale | Decided by | Date |
| --- | --- | --- | --- | --- | --- |
| D1 | Where does the project live? | Public repo StrangeMatterStudio/Rackhand | Open source from day one | Owen | 2026-11-18 |
| D2 | Name | Rackhand (a play on "ranch hand") | | Owen | 2026-11-18 |
| D3 | License | MIT OR Apache-2.0 | Rust default, permissive, patent grant | Owen | 2026-11-18 |
| D4 | Integration with other products of the maintainers | None; standalone | Must work for anyone | Owen | 2026-11-18 |
| D5 | Assistant phasing | MCP for desktops and headless jobs on failure, both in v0.1 | AI only on failure | Owen | 2026-11-18 |
| D6 | Topology | Equal peer hubs per site | Each site works alone | Owen | 2026-11-18 |
| D7 | Mesh | Rackhand-only QUIC mesh with hole punching and relays; local machines on local IPs; cross-site hops through Rackhand nodes | Smaller than a VPN | Owen | 2026-11-18 |
| D8 | Language | Rust for every server process, no Node | Footprint, safety | Owen | 2026-11-18 |
| D9 | Browser code | Server-rendered HTML with htmx and uPlot | No Node at all | Owen | 2026-11-18 |
| D10 | v0.1 scope | Vitals and alerts, MCP and playbooks, mesh, patching and installs, security watch | | Owen | 2026-11-18 |
| D11 | Monitored kinds | Linux and Proxmox, agentless appliances, Alpine/OpenRC, Windows | | Owen | 2026-11-18 |
| D12 | Callouts | Discord webhook and email; Matrix dropped | Notifications only | Owen | 2026-11-18 |
| D13 | History | Built-in SQLite tiers plus `/metrics` | No extra services | Owen | 2026-11-18 |
| D14 | Service checks | Built in; can replace Uptime Kuma | One place for alerts | Owen | 2026-11-18 |
| D15 | Detection | Thresholds, forecasts, silence, baselines | | Owen | 2026-11-18 |
| D16 | Security watch | Connections, logins and accounts, ports and processes, file integrity | | Owen | 2026-11-18 |
| D17 | Connection capture | eBPF with sampling fallback | | Owen | 2026-11-18 |
| D18 | Findings response | Quarantine on approval by default; opt-in auto rules by severity, signal, machine, tag or service | | Owen | 2026-11-18 |
| D19 | Threat intel | Offline lists; online lookups opt-in | Privacy | Owen | 2026-11-18 |
| D20 | Autonomy | Levels 0 to 3 per playbook, new ones at 1 | | Owen | 2026-11-18 |
| D21 | Approvals | Dashboard only, step-up for high risk; assistants and desktop sessions can't approve | Authenticated actions; prompt injection | Owen | 2026-11-18 |
| D22 | Playbook kinds | Runbooks plus assistant playbooks | AI only when needed | Owen | 2026-11-18 |
| D23 | Action path | SSH from the hub; assistant only through MCP | | Owen | 2026-11-18 |
| D24 | Probe privileges | Unprivileged probe plus tiny root helper | | Owen | 2026-11-18 |
| D25 | Assistant key | Separate identity in the hub's Vault, used only through MCP | | Owen | 2026-11-18 |
| D26 | Sudo scope | Automation allow-list; assistant full sudo, I/O-logged, gated | | Owen | 2026-11-18 |
| D27 | Enrollment | One-line installer with a one-time token | | Owen | 2026-11-18 |
| D28 | Patching | Security daily, all weekly, snapshot, verify, holds | | Owen | 2026-11-18 |
| D29 | Sign-in | Local accounts with second factor, plus OIDC | | Owen | 2026-11-18 |
| D30 | Peer trust | See and request; owner decides | | Owen | 2026-11-18 |
| D31 | Transfers | Transport and scheduling for existing backup tools plus `send` | | Owen | 2026-11-18 |
| D32 | Peer data | Summaries pushed, details on demand | | Owen | 2026-11-18 |
| D33 | Config home | Hub is the source of truth, git mirror | | Owen | 2026-11-18 |
| D34 | Relays | Self-hosted default; public or private; keys for access and priority; relay lists from URLs | | Owen | 2026-11-18 |
| D35 | Installs | Site bootstrap, provisioning, guided playbooks | | Owen | 2026-11-18 |
| D36 | Packaging | Signed static binaries, installers, Proxmox LXC script | | Owen | 2026-11-18 |
| D37 | CI | Self-hosted runners; GitHub-hosted copies off by default; no fork PRs on self-hosted | Unlimited runners, safe | Owen | 2026-11-18 |
| D38 | AI provider | MCP for any client; Claude Code runner first; all else works without AI | | Owen | 2026-11-18 |
| D39 | Assistant location | Operator hosts, any number | AI runtime off the hub | Owen | 2026-11-18 |
| D40 | Design split | One complete design | | Owen | 2026-11-18 |
| D41 | Wire format | Protobuf, length-prefixed, ALPN per contract with major version | Schema evolution | Claude (delegated) | 2026-11-18 |
| D42 | Binaries | `rackhand-probe`, `rackhand` (Linux), `rackhand-cli` (Linux, Windows, macOS) | Probe footprint; desktop client | Claude, then Owen chose the separate CLI | 2026-11-18 |
| D43 | Time-series storage | Gorilla chunks in SQLite with staging for durability | Fits the budget | Claude (delegated) | 2026-11-18 |
| D44 | Detection parameters | As in 7.6 | Tunable defaults | Claude (delegated) | 2026-11-18 |
| D45 | Auto-rollback | Only when the guest doesn't report within 15 min, `auto_rollback` is on (default off), and the role isn't hub | Rollback loses data | Owen (default off), Claude (conditions) | 2026-11-18 |
| D46 | Container image updates | Reported; applied by an approved runbook | | Claude (delegated) | 2026-11-18 |
| D47 | Peer-down callouts | One elected hub calls out | Avoid duplicates | Claude (delegated) | 2026-11-18 |
| D48 | Users across hubs | Accounts per hub; approvals on the owning hub | | Claude (delegated) | 2026-11-18 |
| D49 | Dashboard TLS and second factor | Self-signed by default with TOTP; passkeys with a trusted certificate; OIDC users enroll a local factor for step-up | Browsers refuse passkeys without trusted TLS | Owen | 2026-11-18 |
| D50 | Desktop MCP | `rackhand-cli mcp` stdio bridge over the mesh with a device key and personal MCP key | No open port | Claude (delegated) | 2026-11-18 |
| D51 | n0 infrastructure | Not used by default | Self-hosted | Claude (delegated) | 2026-11-18 |
| D52 | Footprint budgets | As in 5.2 | Measurable targets | Claude (delegated) | 2026-11-18 |
| D53 | Windows privileges | Forced-command script dispatcher for automation, transcription for the assistant, per-user key files | Windows has no sudo allow-list | Claude (delegated) | 2026-11-18 |
| D54 | Alpine patching | Full window only | No security marker | Claude (delegated) | 2026-11-18 |
| D55 | Installer download | Signed binaries from GitHub releases; hub trust from endpoint id | Avoid trusting self-signed TLS | Claude (delegated) | 2026-11-18 |
| D56 | Desktop connections | Summary by default on role `desktop` (threat-list hits still reported); servers full | Personal browsing privacy | Owen | 2026-11-18 |
| D57 | Quarantine exclusions | Roles hub, operator, relay, hypervisor; tag `no-quarantine` | Protect core infrastructure | Claude (delegated) | 2026-11-18 |
| D58 | Hub backups | 2 local compressed copies; peers keep 1 only with an opt-in quota; 20 GB minimum disk | Fit the disk | Owen | 2026-11-18 |
| D59 | Cross-site people access | Devices enroll per hub with a user on that hub; the CLI dials the owning hub | Per-hub accounts | Owen | 2026-11-18 |
| D60 | Machines without a local hub | Probe in remote mode to a hub over the mesh; actions over SSH through a tunnel to the probe (127.0.0.1:22 only) | No extra hub | Owen | 2026-11-18 |
| D61 | Automatic high-risk actions | Auto-quarantine and auto-rollback are opt-in exceptions; enabling them needs step-up; release always needs approval | Speed where chosen | Owen | 2026-11-18 |
| D62 | Assistant on infrastructure | No assistant account on hubs; `exec` on operator, relay and hypervisor hosts is high risk | Protect keys | Owen | 2026-11-18 |
| D63 | Operators across sites | An operator can be invited to several hubs; never reached through a peer | Peers can't run commands at other sites | Owen | 2026-11-18 |
| D64 | Container data | Through the root helper | Keep the probe unprivileged | Owen | 2026-11-18 |
| D65 | Outside sources | Needed sources named and on by default, each can be disabled; air-gapped mode | Don't depend on services that aren't needed | Owen | 2026-11-18 |
| D66 | Patch hazards | Recurring maintenance windows and a required-mounts verify check | Scheduled reboots, NFS dependencies | Owen | 2026-11-18 |
| D67 | Patch defaults | `auto_rollback` off; no auto-reboot for Windows and desktops | Safer defaults | Owen | 2026-11-18 |
| D68 | Night-time approvals | Job ends at its deadline; Resume job after approval | Simple and safe | Owen | 2026-11-18 |
| D69 | Peer queries | Per-peer allow-list; `JobLog` off by default | Job output can hold credentials | Claude (delegated) | 2026-11-18 |
| D70 | Assistant cost and data | Daily job cap (default 20); provider data use documented | Cost and privacy | Claude (delegated) | 2026-11-18 |
| D71 | Public evidence | Redacted with documentation IP ranges and invented names | Public repository | Claude (delegated) | 2026-11-18 |
| D72 | Role names | viewer, responder, admin (not "operator") | Avoid clashing with operator hosts | Claude (delegated) | 2026-11-18 |
| D73 | Probe updates | The root helper verifies and swaps binaries with A/B slots and refuses downgrades | The probe must not write its own root-run binary | Claude (delegated) | 2026-11-18 |
| D74 | Permission matrix | As in 7.7.2; people may approve their own requests; responders may open tunnels and run diagnostics | Works for a one-person lab, limits viewers | Claude (delegated) | 2026-11-18 |
| D75 | Default outside sources | abuse.ch Feodo Tracker, Spamhaus DROP, DB-IP Lite, GitHub Releases | Free, no account needed | Claude (delegated) | 2026-11-18 |
| D76 | Event incidents | Resolved by a person, or by an assistant at level 2 or 3 for warning kinds only | Security findings need a human look | Claude (delegated) | 2026-11-18 |
| D77 | In-guest quarantine | Allowed but shown as advisory; only hypervisor firewalls are enforced from outside | Be honest about what root can undo | Claude (delegated) | 2026-11-18 |
| D78 | Hub, relay and operator updates | Manual (dashboard button or command), with backup and automatic switch back | The hub holds the keys; updates are deliberate | Claude (delegated) | 2026-11-18 |
| D79 | Package lists | Refreshed by the helper every 6 hours with a fixed command set | The probe is unprivileged | Claude (delegated) | 2026-11-18 |
| D80 | Remote-mode limits | `from=` is localhost on remote-mode machines; no quarantine for them in v0.1 | The tunnel arrives from localhost; quarantine would cut the mesh | Claude (delegated) | 2026-11-18 |
| D81 | Windows testing | Manual checklist until a self-hosted Windows runner exists (a privileged Linux runner exists) | No Windows runner today | Owen | 2026-11-18 |
| D82 | Public wording | The design describes a generic homelab; no maintainer-specific lab details or internal tool names | Public repository | Owen | 2026-11-18 |
| D83 | Report acks | Range acks and explicit `DataDropped`; epochs restart when the hub is ahead | Replay must not be dropped | Claude (delegated) | 2026-11-18 |
| D84 | Root commands | One sudo entry for a command wrapper that matches argument templates, instead of sudo regular expressions | Works on every sudo version (Ubuntu 22.04 has 1.9.9) | Claude (delegated) | 2026-11-18 |
| D85 | Personal MCP keys | Always level 1: their runbook calls need an approval | A stolen laptop can't act alone | Claude (delegated) | 2026-11-18 |
| D86 | Update rollback | A guard process running the old binary switches back on failure, for probes and hubs | A broken new version can't block its own rollback | Claude (delegated) | 2026-11-18 |
| D87 | When do the spikes run? | The design is approved as a whole; the spikes are the first steps of the implementation plan | The usual approve, plan, run sequence | Owen | 2026-11-18 |
| D88 | Accounts and access levels | Both hub accounts (automation and assistant) on every managed machine; a `monitor` level with no hub accounts also exists; `managed` is the default | Actions run through the accounts; some machines should only be watched | Owen | 2026-11-18 |
| D89 | What `monitor` allows | The hub has no account and can run no command on the machine (the helper still refreshes package lists and installs signed probe updates); hypervisor-side actions on a monitor guest only with an approval, never automatically; the level changes only by a command run on the machine | The hub has no way in, so it can't let itself in | Claude (delegated) | 2026-11-18 |
| D90 | Release signing keys | Offline, never on a CI runner; signed after a maintainer rebuild matches the CI build; two pinned keys (current and standby) for rotation | The helper and updater install signed releases as root | Claude (recommended), Owen (confirmed) | 2026-11-18 |
| D91 | Helper boundary | The probe downloads updates and the helper reads one fixed file; root-only directories for what root runs or trusts; the hub pin lives in root-owned `probe.toml` | A compromised probe user must not reach root | Claude (delegated) | 2026-11-18 |
| D92 | Command list | First list in the join response; later lists are hub-signed, versioned payloads installed by the wrapper; patterns match whole values and refuse a leading `-` | The automation key can't widen its own allow-list; no option injection | Claude (delegated) | 2026-11-18 |
| D93 | Guest binding | Proposed by MAC, confirmed by an admin, then fixed; a mismatch blocks hypervisor-side actions | A probe can't redirect a snapshot, rollback or firewall to another guest | Claude (delegated) | 2026-11-18 |
| D94 | Label tables and frame size | Label ids come from a per-epoch table sent whole in every `Hello`; decompressed frames capped at 16 MB | A report never depends on another report; no decompression bomb | Claude (delegated) | 2026-11-18 |
| D95 | Rule timing | Windows, clearing and silence counted in samples at the machine's interval; a clear margin; samples placed at offset-corrected time | Rules must mean the same at any interval and not flap | Claude (delegated) | 2026-11-18 |
| D96 | Incident attempts | At most 2 automatic runbook starts and 1 assistant job per incident per 24 h; a job whose condition doesn't clear in 10 min counts as failed | No endless restart loop; one incident can't use the daily assistant cap | Claude (delegated) | 2026-11-18 |
| D97 | Long steps | Package steps run detached on the machine and are polled; a timed-out detached step isn't killed | A hub restart or dropped connection must not cut a package manager off | Claude (delegated) | 2026-11-18 |
| D98 | Process users | Hub, relay and operator run unprivileged; a separate root updater verifies and installs releases | A bug in the hub shouldn't be a root bug or a way to install unsigned code | Claude (delegated) | 2026-11-18 |
| D99 | Sign-in limits | Per source and per account, with device cookies so the owner isn't locked out; single-use codes; trusted-proxy list | Per-address limits alone don't stop many addresses | Claude (delegated) | 2026-11-18 |
| D100 | Storage bounds and the recent window | A retention rule for every table; size caps for job output, transcripts and connection records; a 35-minute in-memory window feeds rules, live charts and rollups | The budget must hold in the worst case; data must be usable before compaction | Claude (delegated) | 2026-11-18 |
| D101 | MCP bindings | Key scope capped by role; job tokens tied to the accepting operator; approvals tied to the requester and runbook revision; sensitive diagnostics need an approval with a personal key | Close gaps a stolen key or token could use | Claude (delegated) | 2026-11-18 |
| D102 | Bus | Report notices coalesce per machine; Actions never waits on Incidents | A slow consumer must not stall ingest or lock two systems | Claude (delegated) | 2026-11-18 |
| D103 | Container attribution | Connection records and baselines carry the container | The problem statement asks which container talked to a new address | Claude (delegated) | 2026-11-18 |
| D104 | Quarantine details | Only the probe's port, SSH from the hub, ICMP echo and DHCP stay open; the prior firewall configuration is saved and restored; no assistant `exec` on a quarantined machine | A quarantined machine shouldn't get a wide path to the hub or be released by the assistant | Claude (delegated) | 2026-11-18 |
| D105 | How the POSIX-sh installer verifies signatures | Each release ships a small static `rackhand-verify`; `install.sh` holds its SHA-256 and checks it, and the verifier checks every other binary against the two pinned keys | A shell can't check minisign signatures; trust in `install.sh` already rests on GitHub's TLS | Owen | 2026-11-18 |
| D106 | Versions and pre-releases | The version is `0.1.0` from the start (no 0.0.x pre-releases); the implementation plan builds and verifies artifacts but schedules no release, which stays the maintainer's call | The maintainers' versioning rule starts at 0.1.0; signing is offline (D90) | Owen | 2026-11-18 |
| D107 | Where the built product is tested live | Local lab first: the implementer deploys each milestone's build to QEMU/KVM machines on the development machine (a hub managing one VM, nested Proxmox, a second site) and runs live tests; a final pass runs them against the owner's real hub VM or LXC and one VM, plus the real-hardware checks | Finds integration problems early without the owner's time; the real lab still proves real hardware | Owen | 2026-11-18 |
| D108 | CI runners | CI runs on the maintainers' self-hosted runner service; where a tier needs something a runner profile lacks (Docker, `/dev/kvm`, memory, time), the owner adjusts the service | One runner platform, sized to the project | Owen | 2026-11-18 |
| D109 | Time-series encoding and tier 2 retention | Integer columns at a per-metric step with tick timestamps, the cheapest of three coders per chunk, f64 Gorilla for metrics without a step; tier 1 and 2 chunks of 120 points; tier 2 kept 1 year | Spike S8: Gorilla as designed projects 5.66 GB per 50 machines, this 1.81 GB | Owen | 2026-11-20 |
| D110 | Relay limits | One rate per relay set by the operator (default 1 Mbit/s public, none private); no per-key rates or daily quotas | Spike S2: iroh-relay has no per-endpoint rate or byte counter | Owen | 2026-11-20 |
| D111 | eBPF program licence | Its own crate, GPL-2.0 OR MIT | Spike S1: the kernel helpers it needs are GPL-only | Owen | 2026-11-20 |
| D112 | Existing connections of a quarantined Proxmox guest | `conntrack -D` on the host through the hypervisor's managed enrollment | Spike S4: the Proxmox API can't flush conntrack | Owen | 2026-11-20 |

## 19. Deferred decisions

None.

## 20. Glossary

| Term | Meaning |
| --- | --- |
| Site | A place with its own network and one hub |
| Hub | The Rackhand server for a site: data, detection, runbooks, dashboard, MCP |
| Probe | The small monitoring daemon on a machine; it reports and never runs commands for the hub |
| Command wrapper | A separate mode of the probe binary, run through sudo by the automation account, that runs only commands matching the hub-signed command list |
| Access level | `managed` (the hub has its two accounts on the machine) or `monitor` (probe and helper only; the hub has no account and can run no command on the machine) |
| Guest binding | The confirmed link between an enrolled machine and its VM or LXC on a hypervisor |
| Updater | The root unit that verifies and installs hub, relay and operator releases |
| Recent window | The last 35 minutes of samples the hub keeps in memory for rules, live charts and rollups |
| Clear margin | How far past its threshold a value must be before a rule clears |
| Remote mode | A probe enrolled to a hub at another site over the mesh, which also accepts SSH tunnels from that hub |
| Helper | The probe's small root companion |
| Peer | Another site's hub linked to this one |
| Relay | A server that helps Rackhand nodes connect and carries traffic when a direct path fails |
| Operator host | A machine that runs assistant jobs for one or more hubs |
| Device | A person's computer running `rackhand-cli`, enrolled to a hub for a user |
| Assistant | An AI working an incident through Rackhand's MCP tools |
| Runbook | A deterministic step file the hub runs |
| Playbook | Markdown guidance for an assistant, with tools and an autonomy level |
| Incident | A tracked problem with a lifecycle and timeline |
| Autonomy level | 0 tell, 1 propose, 2 act then report, 3 act quietly |
| Risk | low, normal or high; high always needs an approval with step-up, except the opt-in automatic actions in D61 |
| Step-up | A fresh second-factor check |
| Quarantine | Cutting a machine's network except the hub's path and DHCP |
| Maintenance window | A recurring period with no patching or silence alerts for a machine |
| Endpoint id | A node's Ed25519 public key |
| Ticket | An endpoint id plus addresses and relays, for the first connection |
| Epoch | A probe's random id for one run of report numbering |

## 21. Change log

| Date | Change | Reason | Agreed by |
| --- | --- | --- | --- |
| 2026-11-18 | First draft | Design interview | Owen (review pending) |
| 2026-11-18 | Revision after independent review: join contract, epochs and replay streams, helper-driven updates, approval binding, per-hub devices, operators on several hubs, no assistant on hubs, metric catalogue and storage recount, silence rules, baseline freezing, event incidents, routing, roles, outside sources, backups, maintenance windows, ACs for every FR | Review findings and Owen's answers | Owen (review pending) |
| 2026-11-18 | Closure check fixes: range acks and epoch restart, hub-wide replay budget, compaction into open chunks and re-rollups, lossless bus with reconciliation, command wrapper instead of sudo regex, update guard processes, versioned key updates, transfer write path, peer backup export, baseline seeding, narrower exemptions, desktop summary mode, generic public wording, Windows tests manual, ACs 48 to 57 | Closure review and Owen's answers | Owen (review pending) |
| 2026-11-18 | Third review: `monitor` access level; spikes moved into the plan; release signing keys offline with a standby; helper boundary (no URL over the socket, root-only directories, root-owned hub pin); signed command list and leading-dash rule; fixed guest binding; per-epoch label tables and decompression cap; rules counted in samples with a clear margin; incident attempt limits; detached package steps; unprivileged hub with a root updater; sign-in limits per account; retention and caps for every table and the recent window; MCP bindings; bus coalescing; container attribution; quarantine narrowing and restore; table and wording fixes; spike S11; E49 to E66; ACs 58 to 73 | Review findings and Owen's answers (D87, D88, D90) | Owen (review pending) |
| 2026-11-18 | Approved as a whole, including every decision marked "Claude (delegated)" (D41 to D86, D89, D91 to D104); next step is the implementation plan, whose first steps are the spikes (D87) | Owner approval | Owen |
| 2026-11-18 | Planning findings: the installer verifies signatures through a small verifier binary (D105, 7.3.12); the version is 0.1.0 with no scheduled pre-releases (D106, section 17) | Gaps found while writing the implementation plan | Owen |
| 2026-11-18 | Live testing: a local lab on the development machine at each milestone, then a real-lab pass (D107, section 14); CI runners adjusted to fit the tiers (D108) | Owner decision during plan review | Owen |
| 2026-11-19 | S7 finding: the git mirror uses `git2` (statically linked); `gix` can't push (5.3, section 17) | Spike S7 finding | Implementation run |
| 2026-11-19 | S2 finding: relay admission by key, one server-wide rate and priority at capacity work; per-key rates and daily quotas are not possible (owner decision pending; section 17) | Spike S2 finding | Implementation run |
| 2026-11-19 | S3 finding: path detection and `wait_direct` as designed; two masquerade NATs stay relayed, so the network tier builds full cone with a UDP forward (section 17) | Spike S3 finding | Implementation run |
| 2026-11-19 | S10 finding: default outside sources allowed (CC0, free with credit, CC BY 4.0); 7.8.5 license notes updated; Feodo Tracker nearly empty (owner decision pending before T69) | Spike S10 finding | Implementation run |
| 2026-11-19 | S6 finding: probe footprint inside the 5.2 budgets; current-thread runtime and iroh `tls-ring` only (section 17) | Spike S6 finding | Implementation run |
| 2026-11-19 | S1 finding: aya capture works on 5.10, 6.1 and 7.0 with LXC attribution from the host; an MIT-only program is refused (GPL-only helper), so the eBPF program's licence is the owner's decision before T68 (section 17) | Spike S1 finding | Implementation run |
| 2026-11-19 | S11 finding: journal-only authentication events read with `journalctl -o json`; `mem.available_*` counts the ZFS ARC above `c_min` (7.4.2, section 17) | Spike S11 finding | Implementation run |
| 2026-11-19 | S4 finding: the 7.8.6 role confirmed on PVE 8 and 9; guest rules need the datacenter firewall and the device flag; conntrack can't be flushed through the API (owner decision pending before T72); Proxmox hosts take a full upgrade (7.8.6, section 17) | Spike S4 finding | Implementation run |
| 2026-11-20 | S8 finding: Gorilla and the 7.4.1 estimate miss the 2 GB budget (5.66 GB projected); hub-side integer coding with tick timestamps reaches about 1 byte per value; chunk size, retention or budget to be decided by the owner before T19 (section 17) | Spike S8 finding | Implementation run |
| 2026-11-20 | D109: chunk encoding (integer columns at a step, tick timestamps, three coders), tier 1 and 2 chunks of 120 points, tier 2 kept 1 year; storage estimate replaced with the S8 measurement (G1, FR-7, 7.4.1, 7.8.1 settings) | Owner decision on S8 | Owen |
| 2026-11-20 | D110: relays have one operator-set rate and no per-key rates or daily quotas (7.3.10) | Owner decision on S2 | Owen |
| 2026-11-20 | D111: the eBPF program is its own crate licensed GPL-2.0 OR MIT (5.3) | Owner decision on S1 | Owen |
| 2026-11-20 | D112: quarantine flushes a Proxmox guest's conntrack entries through the hypervisor's managed enrollment; `conntrack_not_flushed` otherwise (7.5.6, 7.8.6) | Owner decision on S4 | Owen |
