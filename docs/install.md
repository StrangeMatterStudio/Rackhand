# Installing a hub

Each site runs one hub. The hub stores the site's data, serves the dashboard, checks machines and runs runbooks. This
page covers making a hub, signing in for the first time, and how the release files are checked.

Rackhand has no published release yet. The commands below use `v<version>` where the release tag goes.

## What a hub needs

- Debian 12 or later, with systemd. The installer refuses anything else before it downloads a file.
- An x86_64 or aarch64 machine, a VM or an LXC container. The Proxmox script below makes a container with 2 vCPU,
  1 GB of memory and a 20 GB disk.
- `curl`.
- These ports reachable from your network: TCP 8443 (the dashboard) and UDP 7443 (Rackhand's QUIC traffic from probes,
  devices, operators and peers).

## Install on Debian

Run as a user with sudo:

```sh
curl -fsSL https://github.com/StrangeMatterStudio/Rackhand/releases/download/v<version>/install.sh | sudo sh -s -- --hub
```

The installer:

1. Downloads `rackhand-verify` and checks it against the SHA-256 written into the installer.
2. Downloads the hub binary, its units and the release manifest, and has `rackhand-verify` check each against the two
   release keys pinned in it. If any file fails, nothing is installed.
3. Puts the binary in `/usr/local/lib/rackhand-server` (two slots, so an update can roll back) with `/usr/local/bin/rackhand`
   pointing at it, and creates the system user `rackhand-hub`.
4. Runs `rackhand hub init` the first time only. That makes the master key (`/etc/rackhand/master.key`, root, 0600),
   the hub's node key, `/etc/rackhand/hub.toml`, the database in `/var/lib/rackhand`, and the SSH keys the hub uses on
   managed machines.
5. Installs and starts `rackhand-hub.service` and `rackhand-updater.path`, then waits for the hub to answer on its
   health endpoint.

When it finishes it prints three things:

- **Dashboard:** `https://<address>:8443/`, using the machine's first address.
- **Setup code:** a one-time code in the form `SETUP-XXXX-XXXX-XXXX`, needed once for first sign-in.
- **Recovery code:** a long code in groups of five characters. It is the master key written out. Store it offline. See
  [recovery.md](recovery.md).

Run on a machine that already has a hub, the installer keeps the existing keys and database and prints that instead of
new codes.

## Install on Proxmox (LXC)

Run as root on a Proxmox host:

```sh
curl -fsSL https://github.com/StrangeMatterStudio/Rackhand/releases/download/v<version>/rackhand-lxc.sh | sudo sh
```

The script downloads the newest Debian 12 template if the host doesn't have one, creates an unprivileged container
(2 vCPU, 1 GB memory, 512 MB swap, 20 GB disk, DHCP on `vmbr0`, nesting on for systemd, started at boot), and runs the
hub installer inside it. The output is the same as above.

Options, with their defaults:

| Option | Default |
| --- | --- |
| `--vmid <n>` | the next free id |
| `--hostname <name>` | `rackhand` |
| `--storage <id>` | `local-lvm` |
| `--bridge <name>` | `vmbr0` |
| `--template-storage <id>` | `local` |
| `--release-url <url>` | this release |

For example, to pick the id and the storage:

```sh
curl -fsSL https://github.com/StrangeMatterStudio/Rackhand/releases/download/v<version>/rackhand-lxc.sh | sudo sh -s -- --vmid 200 --storage local-zfs
```

## First sign-in

Open the dashboard address in a browser. The hub uses a self-signed certificate that it makes on first start, so the
browser warns about it the first time.

First run has two steps:

1. **Details:** the setup code, the admin name (lowercase letters, digits, dots, dashes and underscores), a password of
   at least 12 characters, the site name (lowercase letters, digits and dashes, up to 32), its time zone, and which
   outside sources to use (threat lists and GeoIP, see [hardening.md](hardening.md)).
2. **Second factor:** scan the QR code with an authenticator app and enter a code from it. A second factor is required
   for every account.

Nothing is saved until the code is right. The last page shows the recovery code again. It is the same code the
installer printed. It is not shown after that.

## Files and services on a hub

| Path | What |
| --- | --- |
| `/etc/rackhand/hub.toml` | Listen addresses, data directory, key paths, trusted proxies, certificate names, the hub's relays |
| `/etc/rackhand/master.key` | The master key; root only. systemd hands a copy to the hub as a credential |
| `/etc/rackhand/node.key` | The hub's identity on the mesh; probes pin it |
| `/var/lib/rackhand/` | The database (`hub.db`), backups (`backups/`), release files the hub serves (`release/`) |
| `rackhand-hub.service` | The hub, as `rackhand-hub`, with only `CAP_NET_RAW` (for ICMP checks) |
| `rackhand-updater.path`, `rackhand-updater.service` | The root updater that installs signed hub updates |

The keys of `hub.toml`, with the values `rackhand hub init` writes:

| Key | Written by `hub init` | What |
| --- | --- | --- |
| `web` | every IPv4 address, port 8443 | The dashboard's listen address |
| `quic` | every IPv4 address, port 7443 | The mesh's listen address (UDP) |
| `data_dir` | `/var/lib/rackhand` | Database, backups, release files |
| `master_key`, `node_key` | `/etc/rackhand/master.key`, `/etc/rackhand/node.key` | Key paths |
| `trusted_proxies` | empty | Reverse proxies whose forwarding header the hub believes (see [hardening.md](hardening.md)) |
| `names` | `["localhost"]` | Names the dashboard's self-signed certificate is made for, on the hub's first start (the certificate is then kept) |
| `relays` | empty | The hub's own relays, in order (see [relays.md](relays.md)) |

Unknown keys are refused. Restart the hub after editing the file (`systemctl restart rackhand-hub`). Everything else
is set in the dashboard.

Logs go to the journal: `journalctl -u rackhand-hub`.

## Hub commands

These run on the hub. Commands that read the master key (`backup`, `metrics-token`) must run as root; the others need
read access to `/var/lib/rackhand`, so run them as root too.

```sh
rackhand hub backup
rackhand hub audit verify
rackhand hub runbook check <file>
rackhand hub detect replay --machine <id> --from <ms> --to <ms>
rackhand hub metrics-token
```

- `hub backup` writes an encrypted backup now; see [recovery.md](recovery.md).
- `hub audit verify` checks the audit log's hash chain offline.
- `hub runbook check` validates a runbook (`.toml`) or a playbook (`.md`).
- `hub detect replay` reruns the detection rules over stored data for one machine and prints what would have fired.
  Times are milliseconds since the Unix epoch.
- `hub metrics-token` prints the bearer token for `GET /metrics` (Prometheus format), for a scrape config.
- `rackhand --version` prints the installed version.

The `--db <path>` option of `audit verify` and `detect replay` defaults to `/var/lib/rackhand/hub.db`, and `--config
<hub.toml>` defaults to `/etc/rackhand/hub.toml`.

## Release files and how they are checked

A release holds, for each target (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` and, for the probe and
the CLI, `x86_64-pc-windows-gnu`):

- `rackhand-<target>`: the hub, the relay and the operator (Linux only).
- `rackhand-probe-<target>`: the probe and its helper.
- `rackhand-cli-<target>`: the client for people's computers.
- `rackhand-verify-<target>`: the verifier the installers use.

and also `install.sh`, `install.ps1`, `rackhand-lxc.sh`, `rackhand-windows-scripts.zip`, the systemd and OpenRC unit
files, and `manifest.json`, which lists every file with its SHA-256. Every file has a `.minisig` signature beside it.

How trust works:

- `install.sh` and `install.ps1` are downloaded over HTTPS from GitHub; trust in the script itself rests on that.
- A POSIX shell can't check minisign signatures, so each installer carries the SHA-256 of its release's
  `rackhand-verify` and refuses a verifier that doesn't match.
- `rackhand-verify` pins two public keys, the current release key and a standby key, and checks every other file
  against them. Each signature's trusted comment names the file and its version, so a signature can't be moved to
  another file or replayed as a newer version.
- Probe and hub updates are checked the same way by the probe's helper and the hub's updater, and a version lower than
  the installed one is refused.

To check a downloaded release directory yourself, run the verifier from that release with `--manifest <dir>`. It
prints `ok` only when the manifest is signed by a pinned key, every listed file has its listed hash, and no other file
is in the directory.

The maintainers' signing procedure is in [maintainers/signing.md](maintainers/signing.md).

## Not available yet

- The hub doesn't download new releases by itself. The offline install commands on the Add page, and probe updates,
  use release files placed in `/var/lib/rackhand/release`.
- The dashboard always uses its own self-signed certificate. A certificate you provide, and passkeys (which need a
  certificate the browser trusts), are not available yet.
- There are no deb, rpm or apk packages and no Docker image.
