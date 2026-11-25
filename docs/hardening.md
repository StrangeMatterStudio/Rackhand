# Hardening guide

A hub holds SSH keys that reach every managed machine, so it is the part most worth protecting. This guide lists what
Rackhand already does, and what you should do around it. It follows the threat table in section 10 of the
[design](designs/0001-architecture/design.md).

## What Rackhand does by default

- **Unprivileged services.** The hub runs as `rackhand-hub`, the relay as `rackhand-relay`, the probe as
  `rackhand-probe`, each under a systemd unit with `NoNewPrivileges` and a read-only system. The hub has only
  `CAP_NET_RAW` (for ICMP checks), the relay only `CAP_NET_BIND_SERVICE`, the probe only `CAP_BPF`.
- **The master key stays out of the hub's reach.** `/etc/rackhand/master.key` is root-only. systemd hands the hub a
  private copy as a credential, so the hub's user can't open the file by path. Secrets are encrypted in the database
  with it, so a copy of `hub.db` alone reveals no secret.
- **Root on machines is narrow.** On each machine the only root process is the probe's helper, which takes fixed
  requests and never uses the network. The automation account's sudo rule allows only the command wrapper, which runs
  only commands from a list the hub signed.
- **SSH keys are restricted.** The hub's keys are installed with a `from=` option naming the hub's addresses, and with
  agent, X11 and port forwarding off. Host keys are pinned at enrollment; a changed host key blocks actions and opens a
  critical incident until an admin accepts it with step-up.
- **Updates are signed.** Installers, the probe's helper and the hub's updater accept only files signed by one of the
  two pinned release keys, and never a lower version. A failed probe update rolls back by itself.
- **The dashboard.** A second factor is required for every account. Cookies are `Secure`, `HttpOnly` and
  `SameSite=Strict`, forms carry CSRF tokens, and the content security policy is strict. Sign-in failures slow down per
  source and per account instead of locking the account. Sessions last at most 12 hours (2 hours idle).
- **Self-watch.** At 02:30 site time the hub checks its own binary against the signed release manifest, the audit
  log's hash chain, the database's integrity and its config files. A failure is critical and is reported to peers.
- **The assistant can't approve anything.** There is no approval tool, approvals are bound to the exact call, high risk
  always needs a person with step-up, and machine output is marked as untrusted. See [operators.md](operators.md).

## The hub host

- Give the hub a machine, VM or LXC container of its own. Install nothing else there that other people log in to.
- Copy the recovery code and `/etc/rackhand/master.key` to offline storage (see [recovery.md](recovery.md)). Don't
  leave a copy on the hub's own disks or in its backups' location.
- Keep `/etc/rackhand` root-owned. `hub.toml` is `root:rackhand-hub` 0640 and the master key root 0600; the self-watch
  reports config files that others can write.
- The design says no assistant account exists on a hub's host. Machine roles can't be set from the dashboard yet, so a
  hub host added as `managed` gets the `rackhand-ai` account (full sudo). Until roles can be set, add the hub's own host
  at access level `monitor`.
- Don't run `rackhand-probe uninstall` on the hub host: it removes `/etc/rackhand`, including the master key.

## Network

- The dashboard (TCP 8443) and the mesh (UDP 7443) only need to be reachable from your own networks. Don't expose 8443
  to the internet. Probes need no inbound port.
- The dashboard's certificate is self-signed. Check its fingerprint the first time your browser shows it, and use the
  same name each time so a changed certificate stands out.
- If you put a reverse proxy in front of the dashboard, list its address in `trusted_proxies` in `hub.toml`. The hub
  takes the client address from the forwarding header only from those addresses; otherwise sign-in limits would treat
  every user as the proxy.
- Use your own relay (see [relays.md](relays.md)). Listed relays from relay lists are always treated as public and are
  never sent a key.

## Accounts

- Give people the smallest role that works: `viewer` sees everything, `responder` can acknowledge incidents, approve
  low and normal risk, open tunnels and run diagnostics, `admin` can do the rest. Keep few admins.
- Personal MCP keys: prefer scope `read`, keep the expiry short (90 days by default, a year at most), and revoke a key
  or a device as soon as a laptop is lost (Settings, Devices; Account, keys).
- A device enrolled with `rackhand-cli login` can open tunnels only with a responder or admin account, and only to the
  ports a machine's policy allows (22 by default).

## Machines

- Use access level `monitor` for machines the hub never needs to change. The hub then holds no key for them and can run
  nothing on them.
- On managed machines, every sudo session of `rackhand-ai` is recorded under `/var/log/rackhand/sudo-io` (Windows:
  PowerShell transcripts in `C:\ProgramData\Rackhand\transcripts`). Keep those logs, or ship them off the machine.
- Leave auto-quarantine rules and `auto_rollback` off until you have watched what they would do. Turning either on is
  high risk and needs step-up.

## The assistant

- Run the operator on a host of its own: the brief is written to its work directory and passed on Claude Code's
  command line.
- Keep new runbooks and playbooks at level 1 (propose) until you trust them.
- Set the assistant's daily cap (Assistant page) to what you are willing to send to the AI provider. `0` turns the
  assistant off.
- Read [operators.md](operators.md#what-the-ai-provider-receives) for exactly what leaves your network.

## Outside sources

On by default, each can be turned off on the Settings page:

| Source | What it sends |
| --- | --- |
| abuse.ch Feodo Tracker | an HTTPS GET of the blocklist |
| Spamhaus DROP | an HTTPS GET of the lists, at most daily |
| DB-IP Lite country and ASN | an HTTPS GET, monthly |

Off unless you turn them on: MaxMind GeoLite2 (your own license key), online reputation lookups (these send
destination addresses out), and relay lists. **Air-gapped mode** turns every outside request off. There is no
telemetry.

## Watching the watcher

- Link hubs at different sites as peers. Peers watch each other's heartbeat, and a peer's request to act on your
  machines always needs your approval (unless your policy allows it for a runbook, never for high risk).
- A hub without peers can call a dead-man URL every 5 minutes (Settings), so a service outside the site notices when it
  goes quiet.
- Check the audit chain from the shell now and then, as root:

  ```sh
  rackhand hub audit verify
  ```

- Scrape `/metrics` with the token from `rackhand hub metrics-token` if you run Prometheus.

## Not available yet

- A certificate of your own for the dashboard, and passkeys.
- Setting machine roles (`hub`, `operator`, `relay`, `hypervisor`, `desktop` and the others) from the dashboard, which
  the risk rules and the hub-host rule above depend on.
- Relay keys on the hub, so private relays can't be used yet.
