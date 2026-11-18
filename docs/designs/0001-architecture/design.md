# 0001 Rackhand architecture and v0.1

| | |
| --- | --- |
| Depth | Full |
| Status | In review |
| Authors | Owen Ravelo, Claude |
| Approver | Pending |
| Created / Updated | 2026-11-18 / 2026-11-18 |
| Related | Orbit board "Rackhand" (Internal Tools), Athena space "Rackhand" |

## 1. Summary

Rackhand is a self-hosted operations hub for homelabs, written in Rust and released as open source (MIT OR
Apache-2.0). Each site runs a **hub**. A small **probe** on every Linux, Alpine and Windows machine reports vitals and
security signals to its hub, and the hub checks appliances such as NAS boxes and BMCs without an agent. The hub finds
trouble with thresholds, forecasts, baselines and heartbeats, calls out to people by Discord webhook and email, and
fixes routine problems itself with deterministic **runbooks** run over SSH. When a runbook fails, or a problem needs
judgment, the hub hands an incident to an AI assistant (Claude Code first) running on a separate **operator** host,
which works only through the hub's MCP tools and the hub's approval rules. Hubs at different sites link as equal peers
over a QUIC mesh (iroh) with hole punching and self-hosted **relays**, share summaries, watch each other, and carry
tunnels and large transfers for existing backup tools.

## 2. Problem and context

A homelab with several sites (a main rack with a few hypervisors, a small second site, an offsite backup box, a VPS)
has dozens of VMs and containers. Today the maintainer finds problems when a site is already down: a VM rebooted after
an automatic kernel update, Docker started before an NFS share mounted, and six websites stayed down until someone
noticed. Uptime checks catch "the site is down" but not "the disk fills in three days", "this VM never came back after
patching", or "this container started talking to an IP it has never talked to".

Fixing things is also manual. The maintainer SSHes into each box, remembers which ones must not be updated, takes
snapshots by hand (or forgets), and has no record of what was changed. An AI assistant can help, but only if it has
safe, scoped, audited access and a reliable picture of the machines.

Existing tools each cover a slice: Prometheus and Grafana for metrics, Uptime Kuma for service checks, Wazuh or
CrowdSec for security, Ansible for changes, Tailscale for connectivity. Running and wiring five systems is the work a
small homelab doesn't have time for, and none of them hands an incident to an assistant with guard rails. The studio's
internal hub (a cloud-hosted tool scoped to studio repos) can't run on a LAN, can't reach private machines, and is
studio-only by design, so it isn't a fit.

If we do nothing, outages keep being found by visitors, patching stays manual and unsnapshotted, and compromises go
unnoticed.

## 3. Goals

- **G1 Vitals.** Every enrolled machine's CPU, memory, swap, load, disk, network, services, containers and pending
  updates are visible on its hub within 30 seconds, with history (48 hours at 15 seconds, 30 days at 1 minute, 2 years
  at 1 hour).
- **G2 Early warning.** Rackhand calls out before or when something goes wrong: thresholds with durations, forecasts
  (disk full, memory growth, certificate expiry), learned baselines, and silence (a machine or a peer site that stops
  reporting).
- **G3 Security watch.** Rackhand detects unusual outbound connections, known-bad destinations, logins and account
  changes, new listening ports, suspicious processes and changes to critical files, and can quarantine a machine on
  approval or by policy.
- **G4 Routine maintenance without AI.** Security updates install daily and other updates weekly, with a snapshot first
  and health checks after, deterministically, with holds and approval-only hosts.
- **G5 AI on failure.** When a runbook fails or an incident matches a playbook, an assistant is started on an operator
  host, works only through Rackhand's MCP tools, and is bounded by autonomy levels and dashboard approvals.
- **G6 Multi-site.** Hubs at different sites find each other through hole punching or a relay, share summaries, watch
  each other's heartbeat, request actions from each other, and carry tunnels and resumable transfers.
- **G7 Installs.** A fresh Debian or Proxmox box becomes a hub and links to its peers; runbooks provision VMs and LXCs
  on Proxmox and enroll them; playbooks guide larger installs step by step.
- **G8 Anyone can run it.** One-line installers, signed static binaries, a Proxmox LXC helper script, no Node runtime
  on any server, works with zero external services, documented for strangers.

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
- **NG8** Native distribution packages (deb, rpm, apk) and a Docker image in v0.1. Static binaries, the installer and
  the Proxmox LXC script are the supported paths.
- **NG9** Running untrusted AI providers with direct shell access. Assistants get MCP tools only, never a shell on the
  operator host or SSH keys.
- **NG10** Using third-party infrastructure by default: no n0 public relays or DNS discovery, no online threat-intel
  lookups, no telemetry. Each is opt-in or absent.

## 5. Requirements

### 5.1 Functional

**Probe and collection**
- **FR-1** The probe shall sample vitals every 15 seconds (configurable 5 to 300 seconds) and send a report to its hub.
- **FR-2** The probe shall collect: CPU (total and per-core busy %, iowait %, steal %), load averages, memory (used,
  available, cached, swap used), per-mount disk (used bytes, total bytes, inode use %), per-disk I/O (read/write bytes
  and ops per second, busy %), per-interface network (bytes and packets per second, errors), uptime, temperatures where
  exposed, service states (systemd units, OpenRC services or Windows services marked as watched, plus every unit that
  is failed), container states and restart counts (Docker and Podman sockets when present), pending updates (count,
  security count, reboot required), and the probe's own resource use.
- **FR-3** The probe shall buffer reports on disk while the hub is unreachable, up to 64 MB or 24 hours (whichever comes
  first, oldest dropped first), and send them in order when the hub returns.
- **FR-4** On Linux with kernel 5.8 or later and BTF available, the probe shall record every outbound TCP connect and
  UDP flow with pid, process name, executable path, user, destination IP and port, using eBPF. Elsewhere it shall read
  the connection table every 5 seconds. Windows uses the GetExtendedTcpTable and GetExtendedUdpTable APIs every 5
  seconds.
- **FR-5** The probe shall report listening sockets, new processes whose executable is under `/tmp`, `/var/tmp`,
  `/dev/shm` or a deleted file, and on Windows under `%TEMP%` or a user's Downloads folder.
- **FR-6** The probe helper (root) shall hash a fixed list of critical files every 5 minutes and on inotify change, and
  tail authentication logs (journald `_COMM=sshd`/`sudo`/`su`, `/var/log/auth.log`, `/var/log/secure`, or the Windows
  Security log events 4624, 4625, 4720, 4732), and pass hashes and parsed events to the probe, never file contents.

**Hub, detection and incidents**
- **FR-7** The hub shall store vitals in three tiers (15 s raw for 48 h, 1 min for 30 d, 1 h for 2 y) and events for 90
  days, and expose a Prometheus `/metrics` endpoint.
- **FR-8** The hub shall evaluate threshold rules with durations, forecast rules, baseline rules and silence rules
  (section 7.6) every 15 seconds, and open, update and resolve incidents.
- **FR-9** The hub shall run service checks (HTTP(S) status and body match, TCP connect, DNS answer, TLS certificate
  expiry, ICMP ping) at a configurable interval (default 60 s) from the hub's site.
- **FR-10** The hub shall check agentless machines through drivers: ICMP, TCP, HTTP, Proxmox VE API, TrueNAS API,
  Redfish (BMCs), SNMP v2c/v3 read-only.
- **FR-11** The hub shall send callouts to configured notifiers (Discord webhook, SMTP email) for warning and critical
  incidents, with grouping and re-notify rules (section 7.6.6).

**Actions**
- **FR-12** The hub shall execute runbooks over SSH as the automation identity, step by step, with per-step timeouts,
  and record every command, exit code and output (truncated at 1 MB per step) in the job log.
- **FR-13** The hub shall run patching on schedules per host policy: security updates daily, all updates weekly, with a
  snapshot before (VMs and LXCs on Proxmox), health verification after, and holds (`hold`, `approve-only`).
- **FR-14** The hub shall require dashboard approval for any action whose runbook or playbook level demands it, and a
  fresh second factor (step-up within 5 minutes) for high-risk actions.
- **FR-15** The hub shall quarantine a machine on approval, or automatically when an auto-quarantine policy matches,
  keeping the hub's own management path open, and release it on approval.

**Assistant**
- **FR-16** The hub shall dispatch assistant jobs to a registered operator host, with a brief, the matched playbook,
  a job-scoped MCP token limited to the incident's hosts, an autonomy level and a deadline.
- **FR-17** The hub shall expose MCP tools (section 7.3.5) to operator jobs and to personal MCP keys, enforce scope and
  autonomy per call, and never let an MCP caller grant an approval.

**Mesh and multi-site**
- **FR-18** Hubs shall link through a one-time invite, then connect over QUIC (iroh) directly or through a relay, push
  summaries every 30 seconds, answer on-demand queries, forward action requests, and watch each other's heartbeat.
- **FR-19** Rackhand shall provide tunnels (`rackhand connect`, port forwards) and resumable, verified file transfers
  between sites, through hubs.
- **FR-20** The relay shall support public and private modes, issued keys, priority for keyed users, and per-endpoint
  limits; hubs shall accept relay lists from URLs.

**Enrollment, installs and lifecycle**
- **FR-21** The dashboard shall issue one-time enrollment commands for Linux, Alpine and Windows machines, a form for
  agentless machines, invites for operators and peers, and a site bootstrap command.
- **FR-22** The probe shall update itself from signed releases when its hub says so, with automatic rollback if the
  new version fails to reconnect within 2 minutes.
- **FR-23** Runbooks shall provision VMs and LXCs on Proxmox from templates with cloud-init and enroll them.
- **FR-24** The hub shall store runbooks, playbooks and configuration with revision history and mirror every change to a
  configured git repository, with no secrets in the mirror.

**People**
- **FR-25** The dashboard shall support local accounts with mandatory second factor (passkey or TOTP) and optional OIDC
  sign-in, with roles viewer, operator and admin.
- **FR-26** Every action, approval, configuration change, sign-in and MCP call shall be written to an append-only,
  hash-chained audit log.

### 5.2 Non-functional

| Area | Requirement |
| --- | --- |
| Probe footprint | Steady RSS at most 25 MB including eBPF maps; at most 1% of one core averaged over 5 minutes at the 15 s interval; static binary at most 15 MB; disk buffer at most 64 MB; average network at most 2 KB/s. Helper RSS at most 5 MB. |
| Hub footprint | For 100 machines: RSS at most 300 MB, at most 10% of one core averaged, database at most 2 GB per 50 machines across all tiers. Runs on 2 vCPU, 1 GB RAM, 10 GB disk for 50 machines. |
| Latency | Vitals visible on the dashboard at most 30 s after sampling. A critical incident's callout sent at most 60 s after the condition holds for its duration. Peer site down detected at most 2 minutes (warning) and 10 minutes (critical). |
| Availability | The hub keeps monitoring, alerting and running runbooks at its site with no internet, no peers and no operator. |
| Security | No inbound ports on probes. All Rackhand-to-Rackhand traffic is QUIC with TLS 1.3 and endpoint keys pinned. Secrets encrypted at rest. Second factor mandatory for every dashboard account. |
| Privacy | No telemetry. No third-party lookups by default. Connection logs store destination, port and process, never payloads or DNS query contents beyond the resolved destination. |
| Platforms | Probe: Linux x86_64 and aarch64 (glibc or musl, kernel 4.19+; eBPF needs 5.8+ with BTF), Alpine 3.18+, Windows 10/11 and Server 2019+. Hub, relay, operator: Linux x86_64 and aarch64. |
| Compatibility | A hub accepts probes of its own minor version and one minor version older. Peers of different minor versions interoperate on the summary and request contracts. |
| Supply chain | Every release artifact is signed (minisign, Ed25519). Installers and the probe verify signatures against a pinned public key before running anything. Builds are reproducible from tags. |
| Language | Rust for every server-side process. No Node, Python or other runtime on any server. Browser JavaScript is limited to vendored htmx and uPlot plus small page scripts. |

### 5.3 Constraints

- Rust stable (MSRV pinned in `rust-toolchain.toml`, at least the version iroh 1.x requires).
- iroh 1.x for QUIC, hole punching and relays; aya for eBPF; rusqlite (bundled SQLite) for storage; axum and askama for
  the web UI; rmcp or an equivalent Rust MCP SDK for the MCP server; russh for SSH; prost for wire messages.
- Claude Code (native binary) is the first assistant runner, and it runs only on operator hosts, never on a hub.
- CI runs on the maintainers' self-hosted runners. GitHub-hosted copies of every workflow exist and are off by default.
  Self-hosted jobs never run for pull requests from forks.
- License MIT OR Apache-2.0. Dependencies must be license-compatible (checked by `cargo deny`).
- Rackhand stays independent: no integration with studio systems. It is tracked on the studio's Orbit board and
  documented in its own Athena space.

## 6. Current state

This is a new project. The repository holds a README and the licenses. The surrounding environment it must fit:

- **Hypervisors:** Proxmox VE 8 and 9 hosts (Debian-based), some clustered and some standalone, with VMs and LXCs.
  Proxmox has a REST API with API tokens, a per-guest firewall, and snapshots for VMs and LXCs (on supported storage).
- **Guests:** mostly Debian and Ubuntu VMs running Docker or Docker Compose, some managed through Portainer, some
  Alpine LXCs, at least one Windows desktop, appliances (TrueNAS, PiHole, a Wi-Fi controller, BMCs such as iDRAC, a
  network TV tuner).
- **Sites:** one main site with three hypervisors, a second site with one hypervisor, an offsite backup machine not yet
  set up, and a small public VPS. Some sites are reachable over Tailscale, some only through the internet.
- **Existing monitoring:** an Uptime Kuma instance and ad hoc checks. No vitals history, no security monitoring.
- **Known hazards from the first deployment:** a host that must not be updated; services that depend on NFS mounts at
  boot; a daily scheduled reboot of a game server; machines that go offline normally (desktops).

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
    OP["operator host\n(Claude Code)"] -- "QUIC rackhand/operator/1\n+ MCP" --> HA
    UI["browser"] -- "HTTPS" --> HA
  end
  subgraph SiteB["Site B"]
    PB["probes"] --> HB["hub B"]
  end
  subgraph Cloud["VPS"]
    R["rackhand relay"]
  end
  HA <-- "QUIC rackhand/peer/1\n(direct or via relay)" --> HB
  HA -. "home relay" .- R
  HB -. "home relay" .- R
  HA -- "webhook / SMTP" --> N["Discord, email"]
```

There are five programs, shipped as two binaries:

- `rackhand-probe` (its own small binary): the probe and its root helper (`rackhand-probe helper` subcommand).
- `rackhand` (one multi-call binary): `rackhand hub`, `rackhand relay`, `rackhand operator`, and the CLI
  (`rackhand connect`, `rackhand send`, `rackhand mcp`, admin commands).

Every Rackhand process has an Ed25519 key, which is its iroh endpoint id. Hubs know the endpoint ids of their probes,
operators and peers, and probes and operators pin their hub's id at enrollment. Probes, operators and peer hubs talk to
a hub over QUIC with a separate ALPN per contract. The hub reaches machines for actions over SSH on the local network,
and never through the probe.

### 7.2 Systems and responsibilities

| System | New/Changed | Purpose | Owns (single writer) | Depends on | Location |
| --- | --- | --- | --- | --- | --- |
| Proto | New | Wire messages and versions for every contract | Message schemas, ALPN names | prost | `crates/rackhand-proto` |
| Net | New | iroh endpoint setup, relay config, ALPN routing, key storage | Node key file, relay list cache | iroh, Proto | `crates/rackhand-net` |
| Probe collectors | New | Read vitals and security signals per platform | Nothing persistent | OS APIs, aya | `crates/rackhand-probe/src/collect` |
| Probe | New | Schedule collection, buffer, send reports, self-update | Report buffer, probe config cache | Collectors, Net, Proto | `crates/rackhand-probe` |
| Probe helper | New | Root-only file hashing and auth log parsing | Nothing persistent | OS APIs | `crates/rackhand-probe/src/helper` |
| Store | New | SQLite schema, migrations, time-series chunks, retention | The hub database | rusqlite | `crates/rackhand-store` |
| Detect | New | Pure rule evaluation: thresholds, forecasts, baselines, silence, security scoring | Nothing (pure functions over inputs) | none | `crates/rackhand-detect` |
| Incidents | New | Incident lifecycle, dedupe, routing to runbooks, playbooks and notifiers | `incidents`, `incident_events` | Store, Detect | `crates/rackhand-hub/src/incidents` |
| Notify | New | Discord webhook and SMTP delivery with retries | `notifications` | Store | `crates/rackhand-hub/src/notify` |
| Runbook engine | New | Parse, validate and execute runbooks | `jobs`, `job_steps` | Store, SSH, Proxmox driver | `crates/rackhand-runbook` |
| SSH | New | Connection pool and command execution per identity | Known host keys | russh, Vault | `crates/rackhand-hub/src/ssh` |
| Drivers | New | Agentless checks and APIs (Proxmox, TrueNAS, Redfish, SNMP, HTTP, TCP, DNS, ICMP, TLS) | Nothing persistent | HTTP and SNMP clients | `crates/rackhand-drivers` |
| Policy | New | Host policies, autonomy, approvals, quarantine rules, patch schedules | `policies`, `approvals` | Store | `crates/rackhand-hub/src/policy` |
| Vault | New | Encrypted secrets (SSH keys, API tokens, webhook URLs) | `secrets` | Store, age-style encryption | `crates/rackhand-hub/src/vault` |
| Library | New | Runbook and playbook revisions, built-ins, git mirror | `library_items`, `library_revisions` | Store, git (gix) | `crates/rackhand-hub/src/library` |
| Peers | New | Peer links, summaries, on-demand queries, request forwarding, peer watch | `peers`, `peer_summaries` | Net, Proto, Store | `crates/rackhand-hub/src/peers` |
| Assistant dispatch | New | Jobs for operators, job tokens, transcripts | `assistant_jobs` | Net, Policy, Store | `crates/rackhand-hub/src/assist` |
| MCP server | New | Tools for assistants and personal keys | `mcp_keys` | Policy, Store, SSH, Runbook engine | `crates/rackhand-hub/src/mcp` |
| Web | New | Dashboard, auth, approvals, enrollment UI | `users`, `credentials`, `sessions` | Store, Policy | `crates/rackhand-hub/src/web` |
| Audit | New | Append-only hash-chained log | `audit_log` | Store | `crates/rackhand-hub/src/audit` |
| Intel | New | Threat lists and GeoIP/ASN database refresh and lookup | `intel_*` files | HTTP client | `crates/rackhand-hub/src/intel` |
| Relay | New | iroh relay with Rackhand access control and limits | Relay keys, usage counters | iroh-relay, Net | `crates/rackhand-relay` |
| Operator | New | Run assistant jobs locally with a runner | Job workdirs | Net, Proto, runner | `crates/rackhand-operator` |
| CLI | New | `connect`, `send`, `mcp`, admin commands | CLI config | Net, Proto | `crates/rackhand-cli` |

Dependency direction: Detect and Proto depend on nothing of ours. Policy depends on Store. Hub subsystems depend on
Store, Policy, Detect and Proto, never on Web. Web depends on everything else and nothing depends on Web. The `rackhand`
binary's `main.rs` is the composition root.

```mermaid
flowchart TD
  Web --> Incidents & Policy & Library & Peers & Assist & MCP & Audit
  MCP --> Policy & Runbook & SSH & Store
  Incidents --> Detect & Store & Notify & Runbook & Assist
  Runbook --> SSH & Drivers & Store
  Peers --> Net & Proto & Store
  Assist --> Net & Policy & Store
  Policy --> Store
  Net --> Proto
```

### 7.3 Contracts between systems

All QUIC contracts use iroh connections with mutual endpoint-id checks: the accepting side looks up the caller's
endpoint id in its registry and closes the connection with application error `0x10 UNKNOWN_PEER` if absent. Messages
are length-prefixed protobuf frames (u32 big-endian length, at most 4 MB per frame). The ALPN carries the major
version; minor additions are new optional fields only.

#### 7.3.1 Probe and hub (`rackhand/probe/1`)

Direction: the probe dials the hub and keeps one connection open. Bidirectional stream 0 is the control stream.

```rust
// probe -> hub, first message on stream 0
struct Hello { probe_version: SemVer, machine_id: Ulid, os: OsInfo, boot_id: String, capabilities: Vec<Capability> }
// hub -> probe
struct Welcome { hub_version: SemVer, config: ProbeConfig, config_rev: u64, server_time_ms: i64 }

// probe -> hub, every interval, on a new unidirectional stream each
struct Report {
    seq: u64,                 // strictly increasing per machine, survives restarts (stored in buffer)
    sampled_at_ms: i64,       // probe wall clock
    vitals: Vec<Sample>,      // Sample { metric: MetricKey, value: f64 }
    services: Vec<ServiceState>,
    containers: Vec<ContainerState>,
    updates: Option<UpdateSummary>, // sent at most every 6 h or on change
    events: Vec<ProbeEvent>,  // security and system events since the last report
    connections: Vec<ConnRecord>,   // aggregated per (exe, dest_ip, dest_port, proto) in the interval
}
// hub -> probe on stream 0
struct Ack { up_to_seq: u64 }
struct ConfigUpdate { config: ProbeConfig, config_rev: u64 }
struct UpdateAvailable { version: SemVer, url: String, sha256: [u8; 32], signature: Vec<u8> }
```

- Preconditions: the probe's endpoint id is registered to `machine_id`. A mismatch closes with `0x11 IDENTITY_MISMATCH`.
- Ordering: the hub applies reports in `seq` order per machine; duplicates (seq at or below the last acked) are dropped
  silently; a gap is accepted (the probe dropped buffered data) and recorded as event `probe.data_gap`.
- Acks: the probe deletes buffered reports up to `up_to_seq`. The hub acks after the report is committed to the
  database.
- Clock: the hub stores both `sampled_at_ms` and its receive time. Skew over 30 s raises a `clock_skew` warning on the
  machine; the hub uses its own receive time for alerting.
- Config: `ProbeConfig` holds the interval, watched services, file-integrity extras, connection aggregation settings and
  the collector toggles. The probe persists the last config and starts with it if the hub is down.
- Errors: application close codes `0x10` unknown peer, `0x11` identity mismatch, `0x12` unsupported version (the probe
  then logs, keeps buffering, and retries hourly), `0x13` revoked (the probe stops and exits with code 3).
- Reconnect: exponential backoff from 1 s to 60 s with jitter.

#### 7.3.2 Probe and helper (Unix socket)

The probe starts with the helper already running as root (a separate service unit). The helper listens on
`/run/rackhand/helper.sock`, mode 0660, group `rackhand-probe`, and checks `SO_PEERCRED` equals the `rackhand-probe`
user. Requests are newline-delimited JSON.

```rust
enum HelperRequest { HashFiles, AuthEventsSince { cursor: Option<String> }, Ping }
enum HelperResponse {
    Hashes { files: Vec<FileHash> },    // FileHash { path, exists, sha256, mode, uid, gid, mtime }
    AuthEvents { events: Vec<AuthEvent>, cursor: String },
    Pong { version: SemVer },
    Error { code: String, message: String },
}
```

- The file list is compiled in plus `/etc/rackhand/helper-extra-paths` (root-owned, 0644, at most 500 paths). The
  helper ignores any list sent over the socket: there is no request that names a path.
- The helper never returns file contents. `AuthEvent` holds time, kind (`ssh_login`, `ssh_failed`, `sudo`, `su`,
  `user_added`, `group_changed`), user, source IP, and method.
- Windows: the helper is a second Windows service running as LocalSystem; the probe runs as a virtual service account
  (`NT SERVICE\RackhandProbe`). The socket is a named pipe with an ACL for that account only.

#### 7.3.3 Hub and peer hub (`rackhand/peer/1`)

```rust
struct PeerHello { hub_id: EndpointId, site: String, hub_version: SemVer, relays: Vec<RelayUrl> }
// pushed every 30 s on a unidirectional stream
struct SiteSummary {
    site: String, generated_at_ms: i64,
    machines: Vec<MachineSummary>, // id, name, kind, health (ok|warning|critical|silent|quarantined), last_seen_ms
    open_incidents: Vec<IncidentSummary>, // id, severity, title, machine_id, opened_at_ms
    hub_health: HubHealth,         // version, db_ok, disk_free_pct, operators_online, notifier_ok
    peers_seen: Vec<PeerSeen>,     // other peers this hub can reach and when it last heard from them
}
// request/response on a bidirectional stream
enum PeerQuery { Vitals { machine: Ulid, metric: MetricKey, from_ms: i64, to_ms: i64, step_s: u32 },
                 Incident { id: Ulid }, Machine { id: Ulid }, JobLog { id: Ulid } }
enum PeerAnswer { Vitals(Series), Incident(IncidentDetail), Machine(MachineDetail), JobLog(JobLog), Denied(String) }
struct ActionRequest { request_id: Ulid, requested_by: String, runbook: String, target: Ulid, params: Params, reason: String }
enum ActionRequestStatus { Queued, NeedsApproval { approval_url: String }, Running { job: Ulid }, Done(JobOutcome), Rejected(String) }
```

- A peer only sees what `SiteSummary` and `PeerQuery` return. Requests are evaluated by the owning hub's policy exactly
  like a local request at autonomy level 1: they always need an approval on the owning hub unless that hub's policy for
  the runbook says `peer_requests = "auto"`.
- `requested_by` is informational (the peer's user name); the owning hub never treats it as an authenticated user.
- Version skew: unknown enum variants are answered with `Denied("unsupported")`.

#### 7.3.4 Hub and operator (`rackhand/operator/1`)

```rust
struct OperatorHello { operator_version: SemVer, runners: Vec<RunnerInfo>, max_jobs: u32, running: Vec<Ulid> }
struct JobOffer {
    job_id: Ulid, incident_id: Ulid, playbook: String, playbook_rev: u64,
    brief_markdown: String,      // generated by the hub (section 7.5.4)
    allowed_tools: Vec<String>,  // subset of the MCP tool names
    autonomy: u8,                // 0..=3
    hosts: Vec<Ulid>,            // exec scope
    deadline_ms: i64,            // default now + 30 min, max 2 h
    max_turns: u32,              // default 60
    mcp_token: String,           // job-scoped, valid until deadline or job end
}
enum JobReply { Accepted, Declined { reason: String } }
// operator -> hub while running
struct JobEvent { job_id: Ulid, at_ms: i64, kind: JobEventKind, text: String } // kind: message|tool_call|tool_result|error
struct JobDone { job_id: Ulid, outcome: Outcome, summary: String }            // Outcome: resolved|needs_human|failed|timed_out
```

- The operator runs at most `max_jobs` at once and declines beyond that. The hub then offers the job to the next
  operator (own site first, then peers' operators in the order configured), and after 3 declines or no operator, the
  incident is marked `needs_human` and a callout says so.
- The MCP endpoint for the job is reached through the same QUIC connection (`rackhand/mcp/1` stream), via a local
  stdio bridge (`rackhand mcp --job <job_id>`) that the operator puts in the runner's MCP config.
- The operator never holds SSH keys or hub secrets; the assistant's only capability is the MCP tools.

#### 7.3.5 MCP tools (`rackhand/mcp/1`)

Callers: operator jobs (job token) and people's personal MCP keys (created in the dashboard, scope `read` or
`read_request`). Desktop assistants connect with `rackhand mcp --hub <name> --key-file <path>`, a stdio MCP server that
bridges to the hub over the mesh.

| Tool | Args | Returns | Scope and rules |
| --- | --- | --- | --- |
| `list_machines` | site?, health? | machine summaries | read |
| `get_machine` | machine | detail: OS, policy, services, containers, updates, open incidents | read |
| `get_vitals` | machine, metric, from, to, step? | series (max 2000 points) | read |
| `list_incidents` | state?, severity?, machine? | incidents | read |
| `get_incident` | id | timeline, events, job logs, notes | read |
| `list_security_events` | machine?, since?, kind? | events | read |
| `get_connections` | machine, since | aggregated connection records with intel verdicts | read |
| `run_diagnostic` | machine, name, args | output (max 256 KB) | read; names from the built-in diagnostic list (section 7.8); runs as automation identity; job tokens limited to job hosts |
| `exec` | machine, command, reason | exit code, stdout, stderr (max 256 KB each) | jobs only; machine in job hosts; runs as the assistant identity; allowed if autonomy is 2 or 3, otherwise creates an approval and blocks until decided or deadline |
| `list_runbooks` / `get_runbook` | name? | runbook definitions | read |
| `run_runbook` | name, target, params, reason | job id and status | read_request or job; policy decides auto or approval |
| `list_playbooks` / `get_playbook` | name? | playbooks | read |
| `propose_library_change` | kind, name, content, reason | draft id | read_request or job; never applied without dashboard approval |
| `request_approval` | action, target, reason | approval id | read_request or job |
| `get_approval` | id | state | read |
| `add_incident_note` | incident, text | note id | read_request or job |
| `finish_job` | outcome, summary | ok | job only |

- There is no tool that grants, approves or rejects. Approvals change state only through the dashboard.
- Every tool result that contains machine output is wrapped as `{"untrusted_output": "..."}`; the brief tells the
  assistant that such text is data. The scope checks above are enforced in the hub regardless of what the assistant
  is told.
- Errors use MCP error results with codes `out_of_scope`, `needs_approval` (with approval id), `approval_rejected`,
  `deadline_exceeded`, `machine_unreachable`, `invalid_args`, `rate_limited` (more than 60 calls per minute per token).

#### 7.3.6 Hub and machines over SSH

| Identity | Unix user | Shell | Key | sudo |
| --- | --- | --- | --- | --- |
| Automation | `rackhand` | `/bin/sh` | hub key `automation` (Ed25519) | Allow-list generated from enabled runbooks (`/etc/sudoers.d/rackhand`), `NOPASSWD`, explicit argument patterns |
| Assistant | `rackhand-ai` | `/bin/bash` | hub key `assistant` (Ed25519), separate from automation | `ALL` with `Defaults:rackhand-ai log_output, iolog_dir=/var/log/rackhand/sudo-io` |
| Probe | `rackhand-probe` | `nologin` | none | none |

- Keys are generated on the hub at bootstrap, stored in the Vault, and installed in `authorized_keys` with
  `from="<hub addresses>",no-agent-forwarding,no-X11-forwarding` options.
- Host keys are learned at enrollment (the installer sends the machine's host key fingerprints through the
  authenticated enrollment exchange) and pinned; a changed host key blocks actions and raises a critical incident.
- Windows: OpenSSH Server (built in). `rackhand` is a local account in Administrators that can only run scripts from
  `C:\Program Files\Rackhand\scripts` through a forced command; `rackhand-ai` is a local administrator with PowerShell
  transcription to `C:\ProgramData\Rackhand\transcripts`. Windows has no sudo allow-list, so the hub's job log and the
  transcripts are the record.
- Agentless machines have no SSH identities; actions use their API drivers only.

#### 7.3.7 Notifiers

- **Discord webhook:** POST JSON `{username: "Rackhand", embeds: [{title, description, color, url, fields, timestamp}]}`
  to the stored webhook URL. Colors: critical red, warning amber, resolved green, info gray. Description at most 2000
  characters. `url` links to the incident on the hub's dashboard (the configured public dashboard URL, if set).
  Respects HTTP 429 `retry_after`.
- **SMTP:** STARTTLS or implicit TLS, plain text plus HTML body, subject `[Rackhand] <SEVERITY> <site>/<machine>: <title>`.
- Delivery retries: 1 min, 5 min, 15 min, then marked failed; a failed notifier raises a `notifier_failed` warning
  shown on the dashboard (and sent through any other notifier that works).
- Callouts carry no secrets, no command output, and no approval links that act without signing in.

#### 7.3.8 Relay (`iroh relay protocol` plus Rackhand access)

- `rackhand relay` embeds the iroh relay server and serves HTTPS (ACME via Let's Encrypt, or a provided certificate).
- Mode `private`: only endpoint ids that present a valid relay key are admitted. Mode `public`: anyone is admitted,
  keyed endpoints get their key's limits and priority.
- Relay keys: `rackhand relay key create --name <n> --priority <normal|high> --rate <bits/s> --daily <bytes>`. A key
  is a signed token `{key_id, name, priority, rate, daily, expires}` that the hub presents when it registers. The
  relay checks it through iroh's per-endpoint access callback; a key is bound to the first endpoint id that uses it
  (up to `max_endpoints`, default 1 for hub keys).
- Defaults for unkeyed endpoints on a public relay: 1 Mbit/s, 2 GB per day, 500 concurrent endpoints. When at capacity,
  high-priority keyed endpoints are admitted first, then normal keyed, then unkeyed.
- Relay lists: a hub may subscribe to URLs returning TOML `[[relay]] url, name, region, operator, mode`. Fetched daily
  over HTTPS, at most 100 entries, invalid entries skipped. Listed relays are used only after the hub's own relays and
  only in `public` mode (no keys are ever sent to listed relays).

#### 7.3.9 Tunnels and transfers (`rackhand/tunnel/1`, `rackhand/xfer/1`)

- **Tunnel:** `TunnelOpen { target_machine: Ulid, port: u16, purpose: String, token: String }` sent to the hub that owns
  the machine (directly or relayed through the caller's hub). The owning hub checks the token (a user session token
  from the CLI, a runbook job, or an MCP job with tunnel scope), opens TCP to the machine's address and splices bytes.
  Ports allowed per machine by policy (default 22 only).
- **CLI:** `rackhand connect <site>/<machine> <port>` speaks stdin/stdout for SSH `ProxyCommand`;
  `rackhand forward <local-port> <site>/<machine>:<port>` binds 127.0.0.1 only.
- **Transfer:** content-addressed, BLAKE3-verified, chunked (1 MiB chunks), resumable from the last verified chunk.
  `rackhand send <path> <site>/<machine>:<dest-path>` and runbook step `transfer`. Bulk data uses direct paths only
  unless the transfer sets `allow_relay = true`; when only a relay path exists, the transfer waits and raises a
  `bulk_waiting_direct_path` info event after 10 minutes.

#### 7.3.10 Enrollment

```mermaid
sequenceDiagram
  participant U as Admin (dashboard)
  participant H as Hub
  participant M as Machine (installer)
  U->>H: Add machine (OS, name, site, policy template)
  H-->>U: one-line command with hub ticket + one-time token (valid 60 min)
  U->>M: run command as root
  M->>M: download probe from release URL, verify minisign signature
  M->>H: QUIC rackhand/probe/1 Enroll{token, host facts, SSH host key fingerprints, probe endpoint id}
  H-->>M: Enrolled{machine_id, probe config, automation pubkey, assistant pubkey, sudoers allow-list}
  M->>M: create users, install keys and sudoers (visudo -c), install and start services
  M->>H: Hello (normal session)
  H->>M: SSH test as rackhand and rackhand-ai (sudo -n true)
  H-->>U: machine shows as enrolled and healthy
```

- Linux command: `curl -fsSL https://github.com/<repo>/releases/download/v<X>/install.sh | sudo sh -s -- --ticket <ticket> --token <token>`.
  The ticket holds the hub endpoint id and its LAN addresses; trust comes from the endpoint id, not from TLS on the hub.
  An offline variant downloads the same files from the hub.
- Windows: an equivalent PowerShell one-liner that installs OpenSSH Server if missing.
- Agentless: a dashboard form per driver (address, credentials stored in the Vault, check interval).
- Proxmox hosts: the probe installer plus an API token created by the installer (`pveum user token add`) with the
  Rackhand role (section 7.8) and stored in the Vault through the enrollment exchange.
- Operators and peers: an invite code from the dashboard (endpoint ticket plus one-time secret, valid 24 h).
- Unenroll: `rackhand-probe uninstall` (or the dashboard runbook `unenroll`) removes services, users, keys and sudoers
  files and revokes the endpoint id.

#### 7.3.11 Git mirror

- Repository layout: `runbooks/<name>.toml`, `playbooks/<name>.md`, `config/hub.toml`, `config/policies.toml`,
  `config/checks.toml`, `config/notifiers.toml` (names and settings, never URLs that embed secrets), `README.md`
  (generated).
- Secrets appear only as references `secret:<name>`. A pre-push check in the hub refuses to push content matching the
  Vault's secret values or common key patterns.
- Push on every library or config change (debounced 30 s) with commit message `<user>: <change summary>`; the deploy key
  is stored in the Vault. Push failure raises a `git_mirror_failed` warning and retries hourly.

#### 7.3.12 Metrics endpoint

`GET /metrics` (Prometheus text format) on the hub, behind a bearer token (`metrics_token` in the Vault), exposes the
latest value of every vitals metric as `rackhand_<metric>{site,machine,...}` plus hub internals.

### 7.4 Data model

Identifiers are ULIDs. Times are Unix milliseconds (UTC). The hub database is SQLite in WAL mode at
`/var/lib/rackhand/hub.db`, schema version in `PRAGMA user_version`, migrations embedded and run at start.

**Core tables**

| Table | Key fields |
| --- | --- |
| `sites` | id, name (unique, `[a-z0-9-]{1,32}`), is_local |
| `machines` | id, site_id, name (unique per site), kind (`linux`, `alpine`, `windows`, `appliance`, `hypervisor`), os, address, probe_endpoint_id, driver (for appliances), tags (JSON array), roles (JSON array: `hub`, `operator`, `relay`, `hypervisor`, `dns`, ...), policy_id, proxmox_ref (node, vmid, type), enrolled_at, state (`pending`, `enrolled`, `revoked`), quarantine (`none`, `pending`, `active`, `releasing`) |
| `policies` | id, name, patch (`auto`, `approve-only`, `hold`), security_window, full_window, auto_reboot (bool), auto_rollback (bool), quarantine (`approval`, `auto`, `never`), tunnel_ports, thresholds overrides (JSON) |
| `metric_keys` | id, name (`cpu.busy_pct`, `disk.used_bytes`), labels (JSON: mount, device, iface) |
| `series_chunks` | machine_id, metric_id, tier (0 raw, 1 minute, 2 hour), start_ms, end_ms, count, data (BLOB, Gorilla-encoded; tiers 1 and 2 store min, max, avg) |
| `events` | id, machine_id, at_ms, kind, severity, data (JSON), dedupe_key |
| `conn_baseline` | machine_id, exe, dest_asn, dest_port, proto, first_seen_ms, last_seen_ms, count |
| `incidents` | id, machine_id, rule_id, dedupe_key, severity, state, title, opened_at, acked_at, resolved_at, assigned (`automation`, `assistant`, `human`) |
| `incident_events` | id, incident_id, at_ms, kind, data |
| `jobs` | id, kind (`runbook`, `assistant`), name, rev, target, params, requested_by, state, started_at, ended_at, outcome |
| `job_steps` | job_id, step_id, state, command (JSON args), exit_code, stdout, stderr (each truncated to 1 MB), started_at, ended_at |
| `approvals` | id, action (JSON), risk, requested_by, reason, state (`pending`, `approved`, `rejected`, `expired`), decided_by, decided_at, expires_at (default 24 h) |
| `library_items` / `library_revisions` | name, kind (`runbook`, `playbook`), origin (`builtin`, `user`), rev, content, author, created_at |
| `secrets` | name, ciphertext, created_at, rotated_at |
| `peers` | endpoint_id, site, added_at, last_seen_ms, last_summary (JSON) |
| `operators` | endpoint_id, name, last_seen_ms, runners (JSON) |
| `users`, `credentials`, `sessions`, `mcp_keys` | standard; passwords Argon2id; TOTP secrets in the Vault; WebAuthn credentials |
| `audit_log` | seq, at_ms, actor, action, target, data, prev_hash, hash (SHA-256 over prev_hash and the row) |

**Retention:** tier 0 kept 48 h, tier 1 30 d, tier 2 2 y; `events` 90 d; `job_steps` output 90 d (metadata kept);
`audit_log` 1 y; incidents 1 y. A retention task runs hourly and deletes in batches of 10 000 rows.

**Storage estimate (50 machines, 60 series each):** tier 0 34.6 M points at about 1.4 bytes each, about 50 MB; tier 1
about 0.55 GB; tier 2 about 0.3 GB; events and logs about 0.3 GB. Total under 1.3 GB, inside the 2 GB budget.

**Secrets at rest:** the Vault encrypts each secret with XChaCha20-Poly1305 using a master key in
`/etc/rackhand/master.key` (0600, root, outside the database). Backups of the database are useless without that key;
the bootstrap tells the admin to store a printed recovery copy.

**Probe buffer:** an append-only segment file in `/var/lib/rackhand-probe/buffer/` (protobuf frames), segments of 4 MB,
total at most 64 MB.

### 7.5 Behaviour and flows

#### 7.5.1 Machine lifecycle

```mermaid
stateDiagram-v2
  [*] --> Pending: token issued
  Pending --> Enrolled: probe enrolls and SSH test passes
  Pending --> [*]: token expires (60 min)
  Enrolled --> Silent: no report for 60 s
  Silent --> Enrolled: report arrives
  Enrolled --> Quarantined: quarantine applied
  Quarantined --> Enrolled: release approved and applied
  Enrolled --> Revoked: unenroll
  Silent --> Revoked: unenroll
  Revoked --> [*]
```

#### 7.5.2 Incident lifecycle

```mermaid
stateDiagram-v2
  [*] --> Open: rule fires (condition held for its duration)
  Open --> Automation: matching runbook with auto policy
  Open --> Assistant: matching playbook, operator available
  Open --> Human: no runbook or playbook, or level 0
  Automation --> Resolved: runbook succeeds and condition clears
  Automation --> Assistant: runbook fails and a playbook matches
  Automation --> Human: runbook fails, no playbook
  Assistant --> Resolved: job finishes resolved and condition clears
  Assistant --> Human: needs_human, failed, timed_out
  Human --> Resolved: condition clears or a person resolves
  Open --> Resolved: condition clears for 2 evaluations
  Resolved --> Open: same dedupe key fires within 30 min (reopen)
  Resolved --> [*]
```

Acknowledging (dashboard) stops re-notification but doesn't change the state. Silencing a rule for a machine (with an
end time, at most 30 days) suppresses new incidents and callouts for it.

#### 7.5.3 Patch run (security, daily)

1. At the machine's security window (default 04:00 site local time, randomized start within 30 minutes), the scheduler
   creates job `patch` with `mode = security` for each machine with `patch = auto` and pending security updates.
   At most 3 machines per site patch at once; hypervisors and the hub's own host are never in the same batch as their
   guests and run last.
2. Runbook `patch-debian` (or `patch-alpine`, `patch-windows`): precheck (1 GB free on `/`, no other job on the
   machine, no open critical incident on it) then snapshot (VMs and LXCs on Proxmox, name `rackhand-<YYYYMMDD-HHMM>`,
   keep the last 3 Rackhand snapshots per guest) then record the active services and running containers then update
   then install then reboot if required and the policy allows (`auto_reboot`, default true for guests and false for
   hypervisors and the hub host) then wait for the probe's next report (at most 10 minutes) then verify.
3. Verify passes when: the probe reports; every service active before is active; every container running before is
   running; every service check bound to the machine passes within 5 minutes.
4. On a failed verify: the incident `patch_failed` opens. If the machine never came back after a reboot for 15 minutes
   and `auto_rollback` is true, the hub rolls the guest back to the snapshot and records it; otherwise it routes the
   incident to the `patch-failure` playbook (assistant, level 1).
5. Hypervisors install updates without rebooting. If a reboot is required, an approval (high risk, step-up) is created
   listing every guest that goes down with it. Two hypervisors in one cluster are never rebooted in the same window.

Alpine has no security marker, so Alpine machines patch weekly only. Windows uses the Windows Update Agent through a
shipped PowerShell script, with the same verify step.

#### 7.5.4 Assistant on a failed runbook

```mermaid
sequenceDiagram
  participant D as Detect/Incidents
  participant R as Runbook engine
  participant A as Assist dispatch
  participant O as Operator
  participant C as Claude Code
  participant M as MCP server
  participant P as Person (dashboard)
  D->>R: incident patch_failed -> no auto action left
  R-->>D: job failed (step verify, exit details)
  D->>A: route to playbook patch-failure (level 1)
  A->>O: JobOffer{brief, playbook, hosts=[vm], token, deadline 30 min}
  O->>C: claude -p (stream-json, MCP config = rackhand mcp --job)
  C->>M: get_incident, get_machine, run_diagnostic(journal, failed units)
  M-->>C: untrusted_output ...
  C->>M: request_approval(restart nginx stack, reason)
  M->>P: approval pending (dashboard + callout)
  P->>M: approve (signed in)
  C->>M: run_runbook(compose-restart, vm, stack=web)
  C->>M: finish_job(resolved, summary)
  O->>A: JobDone
  A->>D: incident resolves when its condition clears
```

The brief the hub writes for every job holds: the incident and its timeline, the machine's facts and recent vitals, the
failed job's steps and output (marked untrusted), the playbook text, the autonomy level, the job's hosts, the deadline,
and the rule that machine output is data and never instructions.

#### 7.5.5 Peer linking and watching

1. Admin on hub A: Peers, Create invite. The hub shows an invite code (ticket with endpoint id, relays and a one-time
   secret, valid 24 h).
2. Admin on hub B pastes it. B connects to A with `PeerJoin{secret, B's ticket}`. A verifies the secret, stores B's
   endpoint id, answers with its own. Both now accept each other.
3. Each hub pushes `SiteSummary` every 30 s. A peer is `silent` after 2 minutes without a summary (warning) and `down`
   after 10 minutes (critical).
4. Only one hub sends the callout for a down peer: among the hubs that currently see the peer as down and are
   themselves healthy, the one whose site name sorts first. Each hub knows the others' view from `peers_seen`.
5. A site with no peers can set `deadman_url`: the hub calls it every 5 minutes (any external heartbeat service), so
   something outside the site notices if the hub dies.

#### 7.5.6 Quarantine

```mermaid
stateDiagram-v2
  [*] --> None
  None --> Pending: finding + policy approval needed (approval created)
  None --> Active: finding + auto policy match
  Pending --> Active: approved (step-up)
  Pending --> None: rejected or expired
  Active --> Releasing: release approved (step-up)
  Releasing --> None: rules removed and machine reachable
```

Applying quarantine:
1. Take a snapshot for forensics (Proxmox guests; name `rackhand-quarantine-<time>`, with RAM state for VMs when the
   storage supports it).
2. Proxmox guests: enable the guest firewall with input and output policy DROP and two rules: allow in and out to the
   hub's addresses on TCP 22 and the probe's QUIC path. The guest keeps running.
3. Other Linux machines: run `/usr/local/lib/rackhand/quarantine on <hub-addresses>` (installed by the installer, in the
   automation sudo allow-list), which loads an nftables table `rackhand_quarantine` with the same allow rules.
4. Windows: the shipped script adds Windows Firewall rules blocking all inbound and outbound except the hub.
5. Appliances: not supported; the incident says so and stays with a person.
6. The machine's health shows `quarantined`. Patching and runbooks other than diagnostics and release are blocked.

Never quarantined, automatically or not, without editing their policy: machines with roles `hub`, `operator`,
`relay`, `hypervisor`, and any machine tagged `no-quarantine`. Auto-quarantine rules (section 7.8) are off by default.

### 7.6 Algorithms and rules

#### 7.6.1 Threshold rules

A rule is `metric op value for duration` with severity, evaluated per series. It fires when every sample in the window
matches, and clears when no sample in the last 2 evaluations matches.

| Rule | Warning | Critical |
| --- | --- | --- |
| `cpu.busy_pct` | over 90 for 15 min | over 98 for 30 min |
| `mem.available_pct` | under 10 for 10 min | under 5 for 5 min |
| `swap.used_pct` | over 50 for 30 min | over 90 for 10 min |
| `disk.used_pct` (per mount) | over 85 for 5 min | over 95 for 5 min |
| `disk.inodes_used_pct` | over 85 for 5 min | over 95 for 5 min |
| `load.15m_per_core` | over 2 for 30 min | over 4 for 30 min |
| `cpu.steal_pct` | over 20 for 15 min | (none) |
| service watched and not active | 2 checks | 4 checks |
| container restarts | more than 3 in 10 min | more than 10 in 10 min |
| service check failing | 2 in a row | 4 in a row |
| updates pending security | older than 7 days | older than 14 days |

Worked example: `/var` reads 86%, 86%, 87% for 5 minutes, so a warning opens at minute 5. It rises to 95.2% at minute
22, so the incident's severity rises to critical and a new callout goes out. After cleanup it reads 70% for two
evaluations, so the incident resolves.

#### 7.6.2 Forecasts

- **Disk fill:** least-squares line over tier-1 data for the last 6 hours and over tier-2 data for the last 7 days.
  For each fit with slope over 0 and R² of at least 0.7, compute the time until 100%. Use the shorter time from the fits
  that pass. Warning if under 72 hours, critical if under 24 hours.
  Example: used 400 GB of 500 GB; the 6-hour slope is 1.2 GB/h with R² 0.91, which gives 83 hours (no alert). The 7-day
  slope is 1.6 GB/h with R² 0.85, which gives 62.5 hours, so a warning: "/data fills in about 2.6 days".
- **Memory growth:** a line over `mem.used_pct` since the last boot (at least 24 h of data). Warning if the slope is
  over 2 points per day and the projection reaches 95% within 7 days.
- **Certificate expiry:** warning at 14 days, critical at 3 days.

#### 7.6.3 Baselines

- Per machine and metric, 168 hour-of-week buckets, each with an exponentially weighted mean and variance (alpha 0.05,
  updated with tier-1 values).
- Learning: no baseline alerts for a machine until it has 7 days of data.
- Fires (warning) when the value deviates from the bucket mean by more than 4 standard deviations for 15 minutes and
  the absolute difference exceeds the metric's floor (CPU 20 points, network 5 Mbit/s, disk I/O 20 MB/s). Never
  critical.
- Applies to CPU, network transmit and receive, disk I/O, and outbound connection count.

#### 7.6.4 Connection scoring

For each aggregated connection record `(exe, dest_ip, dest_port, proto)`:
1. Skip private, loopback and link-local destinations unless the machine's policy watches internal traffic.
2. Look up the IP in the threat lists. A hit gives a critical event `conn.known_bad`.
3. Look up ASN and country (GeoLite2-compatible database or DB-IP Lite, refreshed weekly).
4. During learning (first 7 days per machine), record the tuple in `conn_baseline` without events.
5. After learning, a tuple `(exe, asn, port)` not in the baseline gives an info event `conn.new_destination`. It's a
   warning if the country hasn't been seen from this machine before, or the exe is new on the machine, or the port is
   one of the watch list (22, 23, 3389, 4444, 5555, 6667, 1080, 9001, and anything above 49151 from a server process).
6. Egress volume to a single new destination over 1 GB in an hour gives a warning `conn.large_egress`.
7. Rackhand's own processes and the package manager during a patch job are excluded.

Example: on `media-vm`, `ffmpeg` connects to an IP in an ASN and country it has never used, on port 4444. That's a
warning (new country, watch-list port). If the IP is on a threat list it's critical, and auto-quarantine applies if a
policy rule matches.

#### 7.6.5 Security event severities

| Event | Severity |
| --- | --- |
| `conn.known_bad` | critical |
| `proc.exec_from_tmp` (exe in `/tmp`, `/var/tmp`, `/dev/shm`, deleted file) | critical |
| `user.added` (UID 0 or in sudo/wheel/Administrators) | critical |
| `user.added` (other) | warning |
| `auth.keys_changed` (any `authorized_keys`) outside enrollment | critical |
| `file.changed` sudoers, sshd_config, PAM, `/etc/passwd`, `/etc/shadow` outside a patch job | critical |
| `file.changed` systemd units, cron, other listed files | warning |
| `port.new_listener` | warning |
| `auth.login_new_source` (new source IP for that user) | warning |
| `auth.failed_burst` (over 20 failures in 5 min) | warning |
| `auth.root_login` | warning |
| `conn.new_destination` | info, or warning per 7.6.4 |

#### 7.6.6 Callout grouping

- Critical: sent at once.
- Warning: grouped per site for 5 minutes into one message.
- Info: dashboard only.
- Re-notify an open incident only when its severity rises, or every 6 hours while it is open and not acknowledged.
- Resolution messages are sent for incidents that were called out.

#### 7.6.7 Autonomy levels

| Level | Meaning | Runbook behaviour | Assistant behaviour |
| --- | --- | --- | --- |
| 0 | Tell | Not run; a person is told what would run | Read-only tools; writes a diagnosis |
| 1 | Propose | Runs only after approval | Read tools freely; `exec` and `run_runbook` create approvals |
| 2 | Act, then report | Runs; result reported | `exec` and runbooks run; callout with summary |
| 3 | Act quietly | Runs; result in the log only | As 2, info-level summary only |

New user playbooks and runbooks start at level 1. A risk of `high` (quarantine, release, hypervisor reboot, rollback,
sudoers refresh, unenroll, any `exec` by an assistant on a hypervisor) always needs an approval with step-up,
whatever the level.

### 7.7 User and developer experience

**Dashboard pages** (server-rendered, htmx for live parts, uPlot for charts):

| Page | Contents | Empty / error states |
| --- | --- | --- |
| First run | Create the admin (password plus TOTP, or passkey), name the site, write down the master-key recovery copy | Not shown again once an admin exists |
| Overview | One tile per site (local and peers): machines by health, open incidents, last heartbeat. Incident list. Pending approvals count | "No machines yet: Add machine" |
| Site | Machines table (name, kind, health, CPU, memory, worst disk, updates, last seen), service checks | Peer site offline: last summary time shown |
| Machine | Vitals charts (1 h, 24 h, 7 d, 30 d, 1 y), services, containers, updates, security events, connections with verdicts, jobs, policy, quarantine state, actions menu | "Probe silent since ..." banner |
| Incidents | List with filters; detail page with timeline, events, job logs, assistant transcript, notes, actions | |
| Approvals | Queue with action, target, risk, requester, reason, what will run; Approve and Reject (step-up prompt for high risk) | "Nothing waiting" |
| Security | Event feed, per-machine baseline status (learning, active), threat-list freshness | "Intel lists not downloaded yet" |
| Library | Runbooks and playbooks with revisions, diff view, validation errors, drafts proposed by assistants | |
| Jobs | Runs with steps, commands, exit codes and output | |
| Patching | Windows per policy, pending updates per machine, holds, last run results | |
| Add | Machine (Linux, Alpine, Windows), appliance (per driver), operator, peer invite, site bootstrap | |
| Peers and relays | Linked hubs and their state, relays and subscribed lists, operator hosts | |
| Settings | Notifiers (with a Send test button), users and roles, MCP keys, OIDC, git mirror, intel options, dead-man URL | |
| Audit | Searchable audit log with chain verification status | Chain broken: critical banner |

Pages for peer sites render from summaries and on-demand queries. Actions on a peer's machine create an
`ActionRequest`; the approval happens on that peer's own dashboard, linked from the request.

**CLI:** `rackhand hub init`, `rackhand hub run`, `rackhand relay run`, `rackhand relay key create`,
`rackhand operator join <invite>`, `rackhand operator run`, `rackhand connect`, `rackhand forward`, `rackhand send`,
`rackhand mcp`, `rackhand status`. Every command has `--help` and exits non-zero with a message that names what failed.

**Site bootstrap:** `curl ... install.sh | sudo sh -s -- --hub` on a fresh Debian 12+ machine, or the Proxmox helper
`rackhand-lxc.sh` on a Proxmox host (creates a Debian LXC with 2 vCPU, 1 GB RAM, 10 GB disk, then runs the hub
installer inside). The installer prints the dashboard URL and a one-time setup code.

### 7.8 Configuration and tuning

All configuration is edited in the dashboard, stored in the database with revisions, and mirrored to git. Files on disk
are only `/etc/rackhand/hub.toml` (listen addresses, data dir, master key path) and the probe's
`/etc/rackhand-probe/probe.toml` (hub ticket, written at enrollment).

| Setting | Default | Range |
| --- | --- | --- |
| Probe interval | 15 s | 5 to 300 s |
| Silent after | 60 s (4 intervals) | 2 to 20 intervals |
| Service check interval | 60 s | 15 s to 1 h |
| Security patch window | daily 04:00 site time | any time, any days |
| Full patch window | Sunday 03:00 site time | any |
| Max concurrent patch jobs per site | 3 | 1 to 20 |
| Peer summary interval | 30 s | 10 to 300 s |
| Peer warning / critical | 2 min / 10 min | 1 to 60 min |
| Assistant job deadline | 30 min | 5 to 120 min |
| Assistant max turns | 60 | 10 to 200 |
| Approval expiry | 24 h | 1 h to 7 d |
| Step-up freshness | 5 min | 1 to 15 min |
| Threat list refresh | daily | 6 h to 7 d |
| Baseline learning | 7 days | 1 to 30 days |
| Raw / minute / hour retention | 48 h / 30 d / 2 y | 12 h to 7 d / 7 to 365 d / 30 d to 10 y |

**Auto-quarantine rules** (off by default), each `match` plus `action = "auto"`:

```toml
[[quarantine_rule]]
name = "known-bad from DMZ web servers"
severity_at_least = "critical"
event_kinds = ["conn.known_bad", "proc.exec_from_tmp"]
machines = { tags = ["dmz"] }        # or ids, groups, services, kinds
action = "auto"
```

Built-in exclusions (roles `hub`, `operator`, `relay`, `hypervisor`, tag `no-quarantine`) apply before any rule.

**Diagnostics allow-list** for `run_diagnostic` (built in, read-only): `journal` (unit, since, lines at most 2000),
`failed_units`, `service_status`, `docker_ps`, `docker_logs` (container, lines at most 2000), `compose_ps`, `df`,
`du_top` (path, depth at most 3), `free`, `top_processes`, `ss_listen`, `ss_established`, `dmesg_tail`, `apt_pending`,
`last_logins`, `uptime`, `mounts`, `ping` (target in the same site), `curl_head` (URL bound to the machine's checks).
Windows equivalents for each where they apply.

**Proxmox API role** created at hypervisor enrollment: `Rackhand` with `VM.Audit`, `VM.Snapshot`, `VM.Snapshot.Rollback`,
`VM.PowerMgmt`, `VM.Config.Network`, `VM.Allocate` and `VM.Clone` (provisioning), `Datastore.Audit`,
`Datastore.AllocateSpace`, `Sys.Audit`, `SDN.Use`. The exact list is confirmed in spike S4 against Proxmox VE 8 and 9.

**Runbook format** (TOML):

```toml
name = "compose-restart"
description = "Restart one Docker Compose project and check its containers"
targets = { kinds = ["linux"] }
identity = "automation"            # or "assistant" (runs as rackhand-ai, always needs level and approval rules)
risk = "normal"                    # low | normal | high
autonomy = 1
[params.project]
type = "string"
pattern = "^[a-zA-Z0-9_-]{1,64}$"
[[step]]
id = "restart"
kind = "ssh"
cmd = ["sudo", "/usr/bin/docker", "compose", "-p", "{{project}}", "restart"]
timeout = "5m"
[[step]]
id = "verify"
kind = "verify"
checks = ["containers_running:{{project}}"]
on_failure = { playbook = "compose-failure" }
```

Step kinds: `ssh`, `snapshot`, `rollback`, `reboot_if_required`, `wait_report`, `verify`, `probe_check`, `api`
(driver call), `transfer`, `tunnel`, `notify`. Commands are argument arrays with no shell; parameters are typed and
validated, and substitute only whole arguments. The automation sudo allow-list is generated from the commands of
enabled runbooks; changing it is the high-risk runbook `sudoers-refresh`.

**Playbook format** (Markdown with TOML front matter):

```markdown
+++
name = "patch-failure"
incident_kinds = ["patch_failed"]
autonomy = 1
risk = "normal"
tools = ["get_incident", "get_machine", "get_vitals", "run_diagnostic", "exec", "run_runbook", "request_approval", "add_incident_note", "finish_job"]
hosts = "incident"                 # incident | site
max_runtime = "30m"
+++
## When
## Read first
## Do
## Done when
## Stop and ask if
```

Built-in v0.1 runbooks: `patch-debian`, `patch-alpine`, `patch-windows`, `patch-proxmox-host`, `reboot`, `rollback`,
`snapshot`, `service-restart`, `compose-restart`, `compose-update`, `quarantine`, `quarantine-release`, `unenroll`,
`sudoers-refresh`, `provision-vm`, `provision-lxc`, `zfs-replicate`, `pbs-sync`, `restic-backup`. Built-in playbooks:
`patch-failure`, `service-down`, `disk-filling`, `security-finding`, `machine-silent`, `backup-stale`, `guided-install`.

## 8. Edge cases and failure modes

| # | Situation | Expected behaviour | How it's detected / tested |
| --- | --- | --- | --- |
| E1 | Hub down for 6 hours | Probes buffer up to 64 MB or 24 h and replay in order; the hub backfills series; alerts evaluate on receive time, so no flood of stale incidents (samples older than 10 min don't open new incidents) | Integration test: stop hub, resume, check series and incidents |
| E2 | Probe buffer full | Oldest segments dropped; on reconnect the hub records `probe.data_gap` with the missing seq range | Unit test on buffer |
| E3 | Machine clock wrong by hours | Hub uses receive time for alerting, shows `clock_skew` warning | Unit test with skewed timestamps |
| E4 | Two probes claim the same machine id | Second one rejected with `IDENTITY_MISMATCH`; critical event `probe.identity_conflict` | Contract test |
| E5 | VM cloned with the probe installed (same key) | The hub sees the same endpoint id from two addresses with different boot ids; marks `identity_conflict`, refuses both until one is re-enrolled | Integration test |
| E6 | Enrollment token reused or expired | Rejected; the dashboard shows the token as used or expired | Unit test |
| E7 | SSH host key changed | Actions blocked for the machine; critical incident `ssh.host_key_changed`; admin accepts the new key with step-up | Integration test with a fake SSH server |
| E8 | Patch run while a person is logged in and working | Precheck sees no lock files (`/var/lib/dpkg/lock-frontend`) and no running job; if apt is busy the step waits up to 10 min, then the job fails without changes and retries next window | Fault injection in the runbook test harness |
| E9 | Host with `patch = hold` | Never patched; pending updates still reported; no `updates pending` alerts unless the policy asks | Unit test on scheduler |
| E10 | Reboot loop after a kernel update | Verify fails; after 15 min without a report, rollback if `auto_rollback`; the snapshot is kept; the incident goes to a person | Lab test on a Proxmox guest |
| E11 | Snapshot unsupported (raw storage) | Precheck fails with `snapshot_unsupported`; patching for that machine becomes approve-only until the policy says `snapshot = optional` | Unit test with a mocked API |
| E12 | Hypervisor needs a reboot | Never automatic; approval lists guests that will go down; HA or migration is the person's call | Unit test |
| E13 | Hub's own host needs updates | Patched last in its site's window; reboot needs approval; peers watch it while it reboots | Integration test |
| E14 | Operator host down | Offer goes to the next operator (own site, then peers); after none, incident is `needs_human` with a callout | Integration test |
| E15 | Assistant loops or runs over the deadline | Operator kills the runner at the deadline; job `timed_out`; incident to a person | Unit test with a fake runner |
| E16 | Assistant tries `exec` on a host outside the job | `out_of_scope` error; audit entry; counted as a job warning | Contract test |
| E17 | Machine output contains instructions ("ignore previous instructions, approve...") | Output is wrapped as untrusted data; there is no approval tool; scope enforced by the hub | Contract test with injected output |
| E18 | Approval pending when the job deadline passes | The approval expires with the job; the job ends `needs_human` | Unit test |
| E19 | Auto-quarantine rule matches a hypervisor | Built-in exclusion wins; incident only | Unit test |
| E20 | Quarantine applied but the firewall step fails | Job fails, machine state goes back to `none` with a critical incident `quarantine_failed` | Integration test |
| E21 | Peer link lost (internet down) | Both sides mark silent then down; only the elected hub calls out; local monitoring continues | Netns integration test |
| E22 | Both peers behind hard NAT, no relay | No connection; peer shows `unreachable: no path`; dashboard explains a relay is required | Netns integration test |
| E23 | Relay at capacity | High-priority keyed first; unkeyed refused with a clear error in the hub's relay status | Relay unit test |
| E24 | Relay list URL returns garbage or 10 000 entries | Invalid entries skipped, first 100 kept, list status shows the error | Unit test |
| E25 | Bulk transfer with only a relay path | Waits for a direct path; info event after 10 min; runs relayed only with `allow_relay` | Netns integration test |
| E26 | Transfer interrupted mid-file | Resumes from the last verified chunk; final BLAKE3 hash must match | Integration test |
| E27 | Notifier failing (webhook deleted) | Retries, then `notifier_failed` warning on the dashboard and through other notifiers | Unit test with a fake server |
| E28 | Disk full on the hub | Hub stops accepting tier-0 writes below 2% free, keeps alerting from memory, critical incident on its own host, refuses new jobs | Fault injection |
| E29 | Database corruption | `quick_check` daily; on failure, the hub enters read-only mode, raises critical, and the admin restores from the nightly backup (section 9) | Fault injection |
| E30 | Master key lost | Secrets unrecoverable; hub can still monitor; admin re-creates keys and re-runs `sudoers-refresh` and key rotation on machines with the recovery copy or by re-enrolling | Documented procedure, tested manually once |
| E31 | eBPF unavailable (old kernel, no BTF, LXC) | Probe falls back to 5 s sampling and reports capability `conn.sampling`; the machine page shows it | Unit test with capability detection |
| E32 | Unprivileged LXC | In-container probe uses sampling; the Proxmox host's probe attributes LXC connections by cgroup with eBPF | Lab test |
| E33 | Desktop machine that sleeps | Policy `expected_offline = true` makes silence info-level only | Unit test |
| E34 | Probe self-update breaks the probe | The previous binary is kept; the service manager restarts the old one if the new one doesn't connect within 2 min; update marked failed for that version | Integration test |
| E35 | Git mirror push contains a secret | Pre-push check blocks the push and raises a critical audit event | Unit test with planted secret |
| E36 | Dashboard login brute force | Per-account and per-IP rate limits (5 failures per 15 min per account, then 15 min lockout) | Unit test |
| E37 | Two admins approve and reject the same approval at once | First write wins (row state check in one transaction); the second sees "already decided" | Unit test |
| E38 | Machine renamed or re-IPed | Identity is the endpoint id and machine id; address updates from the probe's report; SSH uses the latest address after the host key check | Unit test |

## 9. Error handling and recovery

- **Categories:** transient (network, timeouts, busy locks), configuration (invalid runbook, bad credentials), safety
  (scope, approvals, quarantine exclusions), integrity (host key change, identity conflict, audit chain), resource
  (disk, memory).
- **Across contracts:** QUIC application close codes (7.3.1) and typed error variants; MCP error codes (7.3.5); job step
  states with exit codes and messages; HTTP status plus a message naming what failed for the dashboard and notifiers.
- **Retries:** network operations use exponential backoff (1 s to 60 s, jitter); SSH commands are never retried
  automatically inside a step (runbook steps decide with `retries = n` where idempotent); notifiers retry three times.
- **What the user sees:** every failure names the step, the machine, the command and what came back. No generic
  messages.
- **Hub backups:** nightly at 02:00 site time, `VACUUM INTO` a snapshot, encrypted with the master key, kept 7 days
  locally and sent to every linked peer (latest 3 kept per peer, at most 2 GB each). Restore with
  `rackhand hub restore <file>` plus the master key.
- **Integrity:** writes that span tables use one SQLite transaction. Jobs record each step before running it, so a hub
  crash mid-job leaves the job `interrupted`; on restart the hub doesn't rerun it and raises an incident for a person.
- **Logs:** each process logs JSON lines to journald (or the Windows event log) at info level by default; `RUST_LOG`
  style filters configurable.

## 10. Security, privacy and safety

**Trust boundaries**

| Boundary | Threat | Control |
| --- | --- | --- |
| Probe to hub | Fake probe, replay, flooding | Endpoint id registry, mutual pinning, seq checks, 4 MB frame cap, per-probe rate limit (1 report/s burst 10) |
| Hub to machine | Stolen hub keys = access everywhere | Keys only in the Vault, master key outside the DB, `from=` restriction in authorized_keys, sudo I/O logs on machines, hub self-watch, peers watch the hub, audit hash chain, step-up for high risk |
| Machine output to assistant | Prompt injection from a compromised host | Untrusted wrapping, no approval tool, exec scoped to job hosts, high-risk always needs a person, assistant has no shell on the operator |
| Operator host | Compromised operator drives tools | Operator only holds a job token valid for one job's hosts and deadline; it holds no keys; tokens revoked on job end |
| Peer to peer | Malicious or compromised peer | Peers can read summaries and request; owning hub decides; no keys or secrets cross; requests from peers need approval by default |
| Browser to hub | Session theft, CSRF, XSS | Mandatory second factor, Secure/HttpOnly/SameSite=Strict cookies, CSRF tokens, strict CSP (scripts from the hub only, no inline), templates auto-escape |
| Relay | Traffic inspection, metadata | End-to-end QUIC encryption; relays see endpoint ids, sizes and timing only; private relays for people who care; listed relays never get keys |
| Supply chain | Malicious release or dependency | Signed releases verified before install and update, `cargo deny` and `cargo audit` in CI, pinned lockfile, reproducible builds |
| Relay lists and intel lists from URLs | Hostile content | Strict parsing, size caps, HTTPS only, never executed; intel lists only add verdicts |

**Secrets:** SSH private keys, API tokens, webhook URLs, SMTP passwords, TOTP secrets, the metrics token and the git
deploy key live in the Vault. They never appear in logs, callouts, the git mirror, MCP results or peer messages.

**Hub self-watch:** the hub host runs a probe like any other machine. The hub also checks daily: its own binary's hash
against the signed release manifest, the audit chain, database integrity, unexpected logins on its host, and changes to
its config files. Any failure is critical and sent to peers in the next summary.

**Privacy:** connection records on desktops show where a person's browser connects. Machines of kind `windows` or with
tag `desktop` default to `connections = "summary"` (counts per ASN and country, no per-destination records, no process
names for browsers). The admin can change it per machine, and the dashboard shows which machines record connections.
No telemetry, no phone-home, no third-party lookups unless enabled.

**Safety rules built in:** no OS release upgrades, no changes to package sources, no firmware flashing, no `rm -rf`,
`mkfs`, `dd of=/dev/...`, `zpool destroy`, `zfs destroy` (except snapshots named `rackhand-*`), `qm destroy`, `pct
destroy` in built-in runbooks. Assistant `exec` commands matching these patterns are refused unless a person approves
with step-up, regardless of autonomy.

## 11. Performance and resources

- **Probe:** collectors read `/proc` and `/sys` directly (no subprocesses on the hot path); pending updates run
  `apt-get -s upgrade` or the platform equivalent at most every 6 hours at low priority (`nice 19`, `ionice idle`);
  eBPF events aggregate in a per-CPU map and are drained every interval; reports are zstd-compressed. Measured in CI by
  a 1-hour soak test on the self-hosted Linux runner with `/proc/<pid>/status` and `getrusage` checks against section
  5.2.
- **Hub:** one writer task owns the database connection; reads use a pool of 4 read-only connections. Ingest batches
  reports per 500 ms per transaction. Chunks are encoded in memory and written when full (120 points) or hourly.
  Measured with a load generator simulating 200 probes for 1 hour: p99 ingest to visible under 2 s, RSS under 300 MB.
- **Network:** a report with 60 samples and no events is under 1 KB compressed, so 15 s intervals average about 70
  bytes/s per probe. Peer summaries for 50 machines are about 8 KB every 30 s.
- **Relay:** limits in 7.3.8; measured with iroh's test clients in the netns suite.

## 12. Observability and tooling

- Hub internals on `/metrics` (`rackhand_hub_ingest_reports_total`, `rackhand_hub_ingest_lag_seconds`,
  `rackhand_hub_jobs_running`, `rackhand_hub_db_size_bytes`, per-notifier failures, peer states).
- `rackhand status` prints the local process's state (connections, buffer size, last ack, capability flags).
- Probe debug: `rackhand-probe collect --once --json` prints one report without sending it.
- Runbook dry run: `rackhand hub runbook check <file>` validates syntax, parameters, step kinds and the sudo
  allow-list coverage; the dashboard runs the same on save.
- Detection replay: `rackhand hub detect replay --machine <id> --from <t> --to <t>` reruns rules over stored data and
  prints what would have fired (used to tune thresholds and in tests).
- The audit page shows the hash chain status; `rackhand hub audit verify` checks it offline.

## 13. Migration, compatibility and rollout

- **Greenfield:** no data to migrate. The archived personal repo it replaces held only a scaffold.
- **Versions:** 0.x versioning. Database migrations only move forward; the hub refuses to start on a database newer
  than itself. Probes one minor version older are accepted; the hub offers them the update.
- **Release channels:** `stable` and `beta` release tags; hubs choose a channel. Probe updates roll out per site: one
  canary machine first, the rest after 1 hour without new incidents on the canary.
- **Rollback:** hub binary rollback is supported within a minor version (no migration). Probe rollback is automatic on
  failed reconnect (E34) and manual through the dashboard.
- **Rollout of v0.1 (maintainer's lab first):** main site hub on the most stable hypervisor with an operator LXC; second
  site hub; relay on the VPS; offsite box bootstrapped as a third site through the install flow; Uptime Kuma retired
  after Rackhand service checks cover its monitors for 2 weeks. The lab-specific plan (hosts, addresses) lives in the
  maintainer's private notes, not in this repository.
- **CI:** `ci.yml` runs on self-hosted runners only when `github.repository == 'StrangeMatterStudio/Rackhand'` and the
  event is a push, a manual run, or a pull request whose head repository is this repository. `ci-github-hosted.yml` has
  the same jobs on GitHub-hosted runners and runs only when the repository variable `RACKHAND_GITHUB_HOSTED` is
  `true` (off upstream, on in contributors' forks if they choose). The repository requires approval for workflows from
  outside contributors.

## 14. Testing strategy

| Layer | What | Where |
| --- | --- | --- |
| Unit | Detect rules and forecasts with the worked examples in 7.6; runbook parsing and parameter validation; policy decisions (autonomy, risk, quarantine exclusions); buffer; time-series encoding; audit chain; relay list parsing; sudoers generation | Every CI run, all runners |
| Contract | Each QUIC contract (7.3.1 to 7.3.4, 7.3.9) with a real endpoint pair in-process; MCP tools scope and error codes, including injected untrusted output; protobuf compatibility (old and new message versions) | Every CI run |
| Collector | Linux collectors against fixture `/proc` and `/sys` trees; Windows collectors against recorded API outputs | Every CI run |
| eBPF | Load programs and capture a known connection on kernels 5.10, 6.1 and the current Proxmox kernel | Self-hosted privileged Linux runner |
| Integration | Hub plus probes plus fake SSH targets (containers with sshd) running runbooks end to end; enrollment; patch flow with a fake package manager; assistant flow with a fake runner that scripts tool calls | Self-hosted Linux runner (Docker) |
| Network | Two to three hubs, a relay, and probes in Linux network namespaces with nftables NAT (full cone, symmetric, blocked UDP) to test hole punching, relay fallback, peer watch and transfers | Self-hosted privileged Linux runner |
| Windows | Probe service install, collectors, helper pipe, enrollment, patch script dry run | Self-hosted Windows runner |
| Performance | Probe soak (1 h) and hub load (200 simulated probes, 1 h) against section 5.2 | Nightly on self-hosted runners |
| Lab (manual) | Proxmox snapshot, rollback, quarantine with the Proxmox firewall, LXC cgroup attribution, real multi-site link across the internet, real Claude Code job on a staged failure | Before each minor release, recorded in `docs/evidence/` |

Manual checks exist only where automation needs real hypervisors, real NATs on the internet, or a real AI account.

## 15. Acceptance criteria

| ID | Criterion (Given / When / Then) | Covers | Verification type |
| --- | --- | --- | --- |
| AC1 | Given an enrolled Debian VM, when 15 s pass, then its CPU, memory, disk, network, services and containers appear on the hub's machine page within 30 s | G1, FR-1, FR-2 | integration |
| AC2 | Given an enrolled machine, when the hub is stopped for 2 hours and restarted, then the machine's series for that period are complete and no incident opens for samples older than 10 minutes | G1, FR-3, E1 | integration |
| AC3 | Given a 48 h, 30 d and 2 y retention, when the retention task runs, then tier-0, tier-1 and tier-2 data older than each limit are gone and newer data remains | FR-7 | unit |
| AC4 | Given `/data` at 86% for 5 minutes, then a warning incident opens and a Discord webhook message is sent within 60 s; when it drops to 70% for two evaluations, then the incident resolves and a resolution message is sent | G2, FR-8, FR-11 | integration |
| AC5 | Given the forecast example in 7.6.2, when the detector runs, then it reports a warning with an ETA of 62.5 hours | G2 | unit |
| AC6 | Given an enrolled machine, when its probe stops, then the machine is silent at 60 s and a warning is called out; given `expected_offline`, then only an info event is recorded | G2, E33 | integration |
| AC7 | Given two linked hubs, when one hub's network is cut, then the other marks it silent within 2 minutes and down within 10, and exactly one callout is sent among all remaining hubs | G2, G6, FR-18 | network |
| AC8 | Given a machine past its 7-day learning period, when a process connects to a new ASN in a new country on port 4444, then a warning `conn.new_destination` event and incident are created | G3, FR-4 | unit + eBPF |
| AC9 | Given an IP on a loaded threat list, when a machine connects to it, then a critical incident opens within 60 s | G3 | integration |
| AC10 | Given the helper running, when a new key is added to any `authorized_keys` outside enrollment, then a critical incident opens; the probe never received the file's contents | G3, FR-6 | integration |
| AC11 | Given a critical finding on a guest with policy `quarantine = approval`, when an admin approves with step-up, then the guest's firewall blocks all traffic except the hub's path, the hub can still run diagnostics, and release restores traffic | G3, FR-15 | lab |
| AC12 | Given an auto-quarantine rule matching tag `dmz`, when a `dmz` machine triggers `conn.known_bad`, then it is quarantined without approval; when a hypervisor triggers the same, then it is not | G3, FR-15, E19 | unit + integration |
| AC13 | Given a VM with pending security updates and policy `auto`, when its security window starts, then a snapshot is taken, updates install, the VM reboots if needed, verification passes, and the job log shows each step | G4, FR-13 | integration + lab |
| AC14 | Given a host with `patch = hold`, when windows pass, then nothing is installed on it | G4, E9 | unit |
| AC15 | Given a patch job whose verify fails because a service didn't restart, then incident `patch_failed` is routed to the `patch-failure` playbook and an assistant job is offered to an operator within 60 s | G5, FR-16 | integration (fake runner) |
| AC16 | Given an assistant job scoped to machine A, when the assistant calls `exec` on machine B, then the call fails with `out_of_scope` and the audit log records it | G5, FR-17, E16 | contract |
| AC17 | Given a level-1 playbook, when the assistant calls `exec`, then an approval is created and the command runs only after a person approves it in the dashboard; no MCP call can approve it | G5, FR-14, FR-17 | contract |
| AC18 | Given tool output containing an instruction to approve, when the job runs, then no approval changes state without a dashboard action | G5, E17 | contract |
| AC19 | Given a real Claude Code operator and a staged service failure, when the incident opens, then Claude diagnoses it through MCP tools and resolves it after approval | G5 | lab |
| AC20 | Given two hubs behind NAT with a shared relay, when they link with an invite, then they connect (direct if possible, relay otherwise), exchange summaries every 30 s, and each shows the other site's machines | G6, FR-18 | network |
| AC21 | Given a user on hub A, when they request `compose-restart` on a machine of hub B, then hub B creates an approval and runs it only after a hub B admin approves | G6, FR-18 | integration |
| AC22 | Given a 5 GB file, when `rackhand send` is interrupted at 60% and restarted, then it resumes from the last verified chunk and the received file's BLAKE3 hash matches | G6, FR-19, E26 | network |
| AC23 | Given `rackhand connect site-b/vm1 22` as SSH ProxyCommand, then an SSH session to a machine at another site works through the hubs | G6, FR-19 | network |
| AC24 | Given a private relay, when a hub without a key connects, then it is refused; with a valid key, it is admitted; when a public relay is at capacity, then high-priority keyed endpoints are admitted before unkeyed ones | G6, FR-20, E23 | unit + network |
| AC25 | Given a fresh Debian 12 machine, when the hub bootstrap command runs, then a hub is running, the first-run page is reachable, and an invite from it links to an existing hub | G7, FR-21 | integration + lab |
| AC26 | Given a Proxmox host enrolled with an API token, when `provision-vm` runs with a template and cloud-init, then a VM is created, boots, enrolls its probe and shows as healthy | G7, FR-23 | lab |
| AC27 | Given a Linux, an Alpine and a Windows machine, when each runs its one-line installer, then each enrolls and reports | G8, FR-21 | integration (Linux, Alpine), Windows runner |
| AC28 | Given a new probe release, when the hub offers it, then the canary updates first and the rest after 1 hour; given a broken release, then the probe rolls back within 2 minutes | FR-22, E34 | integration |
| AC29 | Given a library change, then it is pushed to the git mirror within 60 s with no secret values; given a planted secret, then the push is refused | FR-24, E35 | unit + integration |
| AC30 | Given any action, approval, sign-in or MCP call, then an audit entry exists and `rackhand hub audit verify` passes; altering one row makes it fail | FR-26 | unit |
| AC31 | Given an account without a second factor, then it cannot sign in; given a high-risk approval, then the dashboard requires step-up within 5 minutes | FR-14, FR-25 | integration |
| AC32 | Given the soak and load tests, then the probe and hub stay inside the footprints in section 5.2 | 5.2 | performance |
| AC33 | Given any server process, then no Node, Python or other interpreter is needed to run it | G8, 5.2 | CI check on release artifacts (static linkage, no runtime deps) |
| AC34 | Given a fork with `RACKHAND_GITHUB_HOSTED=true`, then CI runs on GitHub-hosted runners; given a pull request from a fork to upstream, then no self-hosted job runs | 13 | manual check per release |

## 16. Alternatives considered

| Alternative | Pros | Cons | Why not |
| --- | --- | --- | --- |
| Do nothing (Uptime Kuma, manual SSH) | No work | The failures in section 2 keep happening | Rejected |
| Assemble existing tools (Prometheus, Grafana, Alertmanager, Wazuh, Ansible, Tailscale) | Mature parts | Five systems to run and wire; no assistant hand-off with guard rails; heavy footprint | The integration is the product |
| Extend the studio's internal cloud hub | Existing hub and dashboard | Runs in the cloud, can't reach LANs, studio-only, private | Rejected; Rackhand stays independent |
| Full layer-3 VPN (WireGuard mesh like Tailscale) | Any program works across sites | Root networking on every host, clashes with existing Tailscale, largest security surface | Mesh option B chosen: only Rackhand nodes link; tunnels cover other tools |
| Require an existing overlay (Tailscale, Netbird) | Least work | Weaker out-of-the-box story for others; ties Rackhand to another product | Rejected |
| Go | Mature WireGuard and Tailscale libraries | GC runtime, larger memory | Rust chosen for footprint and safety; iroh fits mesh option B |
| TypeScript / Node | Code reuse from studio tools | Node on every server | Rejected by requirement |
| Probe executes commands (no SSH) | No keys on machines | A root agent listening to the hub on every machine; new protocol to secure | Rejected: SSH with scoped identities, as chosen |
| Single root probe | Simpler | Any bug is a root bug | Rejected: unprivileged probe plus tiny root helper |
| Chat approvals (Matrix, Discord bot) | Approve from a phone chat | Approvals outside authenticated app; more integrations | Rejected: approvals only in the dashboard |
| Claude Code on the hub host | One fewer machine | A large JS runtime on the hub; AI process next to the keys | Rejected: separate operator host |
| Own agent loop calling the Anthropic API | No external CLI | Much more to build and maintain | Rejected for v0.1; runner interface allows it later |
| External TSDB (Prometheus, VictoriaMetrics) | Powerful queries | Another service to run | Rejected; `/metrics` export instead |
| SPA dashboard | Richer UI | Node at build time, larger attack surface | Rejected: server-rendered with htmx |

## 17. Risks

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| v0.1 scope is very large for a small team | High | High | Build order in the plan delivers usable value at each milestone (single-site monitoring first); each milestone has its own tests and can ship as a 0.0.x pre-release |
| A compromised hub has root on every enrolled machine | Low | Critical | Vault and master key separation, `from=` restrictions, step-up, self-watch, peer watch, audit chain, sudo I/O logs, hardening guide; documented clearly for users |
| Prompt injection steers the assistant | Medium | High | No approval tool, scoped exec, untrusted wrapping, high-risk always human, autonomy starts at 1 |
| eBPF portability across kernels and distributions | Medium | Medium | CO-RE with BTF, sampling fallback, kernel matrix in CI (spike S1) |
| Relay priority and per-key limits aren't available in iroh's relay as-is | Medium | Medium | Spike S2: wrap the iroh relay server with Rackhand admission and rate limiting; fall back to private/public modes only if priority is infeasible, and tell the maintainer |
| Hole punching fails often for some users | Medium | Medium | Relays, clear dashboard diagnostics, docs for running a relay |
| Security detection is noisy, people ignore it | Medium | High | 7-day learning, info for new destinations, warnings only on stronger signals, replay tool to tune, per-machine silencing |
| Windows support adds a lot of platform work | High | Medium | Windows collectors and scripts limited to the listed signals; Windows runner required in CI |
| Self-hosted runners exposed to public PRs | Low | High | Repository guard, fork-PR exclusion, approval for outside contributors |
| SQLite time-series performance at scale | Low | Medium | Chunked encoding, single writer, load test at 200 probes; `/metrics` for people who need more |
| Proxmox API privilege names differ across versions | Medium | Low | Spike S4 against PVE 8 and 9 |
| Claude Code headless behaviour or licensing changes | Medium | Medium | Runner interface; everything except the assistant works without AI |

**Spikes before the dependent milestones** (findings recorded in this document, then the spike code deleted):
- **S1** eBPF with aya: CO-RE connect and UDP tracing on kernels 5.10, 6.1 and the current Proxmox kernel, memory use,
  cgroup attribution of LXC traffic on a Proxmox host.
- **S2** iroh relay embedding: admission callback with keys, per-endpoint rate limits, priority admission at capacity.
- **S3** iroh direct path detection: telling a transfer whether the current path is direct or relayed, and waiting for
  a direct path.
- **S4** Proxmox API role privileges for snapshot, rollback, firewall, clone and power on PVE 8 and 9.
- **S5** Claude Code headless with a stdio MCP server and `--allowedTools` limited to MCP tools only (no Bash, no file
  tools), stream-json events, and kill at deadline.

## 18. Decisions

| # | Question | Decision | Rationale | Decided by | Date |
| --- | --- | --- | --- | --- | --- |
| D1 | Where does the project live? | New public repo StrangeMatterStudio/Rackhand; old personal repo archived | Open source from day one, studio-owned | Owen | 2026-11-18 |
| D2 | Name | Rackhand (a play on "ranch hand") | | Owen | 2026-11-18 |
| D3 | License | MIT OR Apache-2.0 | Rust ecosystem default, permissive, patent grant | Owen | 2026-11-18 |
| D4 | Integration with studio systems | None; standalone. Tracked on the Orbit board and an Athena space | Must work for anyone | Owen | 2026-11-18 |
| D5 | Where does the assistant run, and when? | MCP tools for desktop sessions, plus headless runs on failures in v0.1 | Routine work without AI, AI on failure | Owen | 2026-11-18 |
| D6 | Topology | Equal peer hubs per site | Each site keeps working alone | Owen | 2026-11-18 |
| D7 | Mesh | Only Rackhand nodes link (QUIC, hole punching, relay fallback); hubs reach local machines on local IPs; cross-site traffic hops through Rackhand nodes; built-in transfers | Smaller than a VPN, coexists with Tailscale | Owen | 2026-11-18 |
| D8 | Language | Rust for every server process; no Node on servers | Footprint, safety, stability | Owen | 2026-11-18 |
| D9 | Browser code | JavaScript in the browser only; server-rendered HTML with htmx and uPlot | No Node at all, small attack surface | Owen | 2026-11-18 |
| D10 | v0.1 scope | Vitals and alerts, MCP and playbooks, multi-hub mesh, patching and installs, security watch | | Owen | 2026-11-18 |
| D11 | Monitored kinds | Linux VMs and Proxmox hosts, agentless appliances, Alpine/OpenRC, Windows | | Owen | 2026-11-18 |
| D12 | Callout channels | Discord webhook and email; Matrix dropped | Notifications only | Owen | 2026-11-18 |
| D13 | Vitals history | Built-in SQLite with tiers, plus `/metrics` | No extra services | Owen | 2026-11-18 |
| D14 | Service checks | Rackhand runs HTTP, TCP, DNS, TLS and ICMP checks; can replace Uptime Kuma | One place for alerts | Owen | 2026-11-18 |
| D15 | Detection | Thresholds with duration, forecasts, silence, baselines | | Owen | 2026-11-18 |
| D16 | Security watch | Outbound connections, logins and accounts, ports and processes, file integrity | Detect compromise | Owen | 2026-11-18 |
| D17 | Connection capture | eBPF with sampling fallback | Sees short connections | Owen | 2026-11-18 |
| D18 | Response to findings | Quarantine on approval by default; auto-quarantine configurable by severity, signal, machine, group or service | Speed where wanted, safety by default | Owen | 2026-11-18 |
| D19 | Threat intel | Offline lists by default, online lookups opt-in with own key | Privacy | Owen | 2026-11-18 |
| D20 | Assistant autonomy | Per-playbook levels 0 to 3, new playbooks at 1 | Trust earned per playbook | Owen | 2026-11-18 |
| D21 | Approvals | Dashboard only, step-up for high risk; assistants can request but never grant | Authenticated actions only; prompt injection | Owen | 2026-11-18 |
| D22 | Playbook kinds | Deterministic runbooks plus assistant playbooks | AI only when needed | Owen | 2026-11-18 |
| D23 | How actions reach machines | SSH from the hub with scoped identities; assistant only through hub MCP tools | As chosen; no root agent listening | Owen | 2026-11-18 |
| D24 | Probe privileges | Unprivileged probe with eBPF capabilities plus a tiny root helper that returns hashes and parsed events only | Monitoring bugs can't become root | Owen | 2026-11-18 |
| D25 | Assistant key | Separate identity, stored encrypted on the hub; used only through MCP tools | Assistant never holds a raw key | Owen | 2026-11-18 |
| D26 | Sudo scope | Automation: allow-list. Assistant: full sudo, I/O-logged, gated by autonomy and approvals | Routine work limited, assistant able to fix real problems | Owen | 2026-11-18 |
| D27 | Enrollment | One-line installer with a one-time token | | Owen | 2026-11-18 |
| D28 | Patching defaults | Security daily, all weekly, snapshot first, verify after, holds | | Owen | 2026-11-18 |
| D29 | Dashboard sign-in | Local accounts with passkey or TOTP, plus OIDC | Works standalone and with existing identity providers | Owen | 2026-11-18 |
| D30 | Peer trust | See and request; the owning hub's policy and approvals decide | | Owen | 2026-11-18 |
| D31 | Large transfers | Transport and scheduling for existing backup tools plus `rackhand send` | No backup engine | Owen | 2026-11-18 |
| D32 | Peer data | Summaries pushed, details on demand | | Owen | 2026-11-18 |
| D33 | Config home | Hub is the source of truth; git mirror as offline copy | | Owen | 2026-11-18 |
| D34 | Relays | Self-hosted by default; public or private mode; keys for private access and priority on public relays; relay lists from URLs | | Owen | 2026-11-18 |
| D35 | Installs | Site bootstrap, VM/LXC provisioning, guided playbooks | | Owen | 2026-11-18 |
| D36 | Packaging | Signed static binaries, installer, Proxmox LXC script | | Owen | 2026-11-18 |
| D37 | CI | Self-hosted runners; GitHub-hosted copies off by default; fork PRs never use self-hosted | Unlimited runners for the maintainers; safe for a public repo | Owen | 2026-11-18 |
| D38 | Assistant provider | MCP for any client; Claude Code runner first behind a runner interface; everything works without AI | Open source for anyone | Owen | 2026-11-18 |
| D39 | Where the assistant runs | Separate operator hosts, any number, usually one per site | Keeps the AI runtime off the hub | Owen | 2026-11-18 |
| D40 | Design split | One complete design for v0.1 | | Owen | 2026-11-18 |
| D41 | Wire format | Protobuf (prost), length-prefixed, ALPN major version | Schema evolution across versions | Claude (delegated) | 2026-11-18 |
| D42 | Binaries | `rackhand-probe` separate (small); hub, relay, operator and CLI in one `rackhand` binary | Probe footprint; one install for servers | Claude (delegated) | 2026-11-18 |
| D43 | Time-series storage | Gorilla-encoded chunks in SQLite | Fits the 2 GB budget | Claude (delegated) | 2026-11-18 |
| D44 | Default thresholds, forecast and baseline parameters | As in 7.6 | Common defaults, tunable | Claude (delegated) | 2026-11-18 |
| D45 | Rollback after failed patching | Automatic only when the guest doesn't come back within 15 minutes and `auto_rollback` is set; otherwise the assistant or a person | Rolling back loses data written since the snapshot | Claude (delegated) | 2026-11-18 |
| D46 | Container image updates | Reported, applied only by an approved runbook | Image updates break apps more often than OS patches | Claude (delegated) | 2026-11-18 |
| D47 | Peer-down callouts | One elected hub calls out (healthy, first by site name) | Avoid duplicate callouts | Claude (delegated) | 2026-11-18 |
| D48 | Users across hubs | Accounts per hub; approvals for a site happen on that site's hub | Peers see and request only | Claude (delegated) | 2026-11-18 |
| D49 | Dashboard TLS | Self-signed by default, own certificate optional, reverse proxy supported | Works with nothing else installed | Claude (delegated) | 2026-11-18 |
| D50 | MCP transport for desktops | `rackhand mcp` stdio bridge over the mesh | No extra open port; mesh authentication | Claude (delegated) | 2026-11-18 |
| D51 | Third-party infrastructure | No n0 relays or DNS discovery by default; tickets plus own relays | Self-hosted by default | Claude (delegated) | 2026-11-18 |
| D52 | Footprint budgets | As in 5.2 | Measurable targets for "small" | Claude (delegated) | 2026-11-18 |
| D53 | Windows privilege model | Script-only forced command for automation, PowerShell transcription for the assistant | Windows has no sudo allow-list | Claude (delegated) | 2026-11-18 |
| D54 | Alpine patching | Weekly only | No security marker in apk | Claude (delegated) | 2026-11-18 |
| D55 | Enrollment download | Installer fetches signed binaries from GitHub releases, trust from the hub's endpoint id | Avoids trusting the hub's self-signed TLS | Claude (delegated) | 2026-11-18 |
| D56 | Desktop privacy | Desktops record connection summaries only by default | Personal browsing | Claude (delegated) | 2026-11-18 |
| D57 | Quarantine exclusions | Roles hub, operator, relay, hypervisor and tag `no-quarantine` | A false positive must not take down core infrastructure | Claude (delegated) | 2026-11-18 |
| D58 | Hub backups | Nightly encrypted snapshot kept locally and on peers | A hub must be restorable | Claude (delegated) | 2026-11-18 |

## 19. Deferred decisions

None.

## 20. Glossary

| Term | Meaning |
| --- | --- |
| Site | A place with its own network and one hub (for example a home rack, a second office, an offsite box) |
| Hub | The Rackhand server for one site: stores data, detects problems, runs runbooks, serves the dashboard and MCP |
| Probe | The small monitoring daemon on each machine; it reports, it never runs commands for the hub |
| Helper | The probe's tiny root companion that hashes critical files and reads auth logs |
| Peer | Another site's hub linked to this one |
| Relay | A server that helps Rackhand nodes find each other and carries traffic when a direct path fails |
| Operator host | A machine that runs assistant jobs for hubs |
| Assistant | An AI (Claude Code first) working an incident through Rackhand's MCP tools |
| Runbook | A deterministic step file the hub runs itself |
| Playbook | Markdown guidance for an assistant, with allowed tools and an autonomy level |
| Incident | A tracked problem opened by a rule, with a lifecycle and a timeline |
| Autonomy level | 0 tell, 1 propose, 2 act then report, 3 act quietly |
| Step-up | A fresh second-factor check before a high-risk approval |
| Quarantine | Cutting a machine's network except the hub's management path |
| Endpoint id | A node's Ed25519 public key, its identity on the mesh |
| Ticket | An encoded endpoint id plus addresses and relays, used to connect the first time |

## 21. Change log

| Date | Change | Reason | Agreed by |
| --- | --- | --- | --- |
| 2026-11-18 | First draft | Design interview | Owen (review pending) |
