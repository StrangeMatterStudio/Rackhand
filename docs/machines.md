# Adding machines

A machine is a Linux, Alpine or Windows host with Rackhand's probe on it. The probe reports vitals, services,
containers, pending updates and security signals to its hub. This page covers the choices you make when adding one,
the install commands, what the probe and its helper are allowed to do, and removing them.

## Access levels

You pick one when you add the machine. The Machine page shows it.

| | `managed` (the default) | `monitor` |
| --- | --- | --- |
| Probe and helper | yes | yes |
| Hub accounts on the machine | `rackhand`, and `rackhand-ai` unless the machine has the role `hub` | none |
| SSH server needed | yes (installed on Windows if missing) | no |
| Patching, runbooks, diagnostics, assistant commands | yes, within your autonomy levels and approvals | no |
| Probe updates | yes | yes |

On a managed machine:

- `rackhand` is the automation account. Its sudo rule allows one command, the wrapper `/usr/local/lib/rackhand/run`,
  which runs only commands listed in `/etc/rackhand/commands.json` (made from the enabled runbooks and signed by the
  hub). Its key works only from the hub's addresses.
- `rackhand-ai` is the account an assistant uses. It has full sudo, and every sudo session is recorded to
  `/var/log/rackhand/sudo-io`. Assistant commands still go through the hub's approvals (see
  [operators.md](operators.md)).

On a monitor machine the hub holds no key and can run no command. The only things that run as root there are the
helper's fixed tasks: the package-list refresh every 6 hours and installing a signed probe release.

To change the level later, use the Machine page. It shows a one-time command (60 minutes) that you run as root on the
machine. The hub can't raise a machine from `monitor` to `managed` by itself; that is the point of the level.

## Local and remote mode

- **Local** (the default): the hub reaches the machine over SSH on your network.
- **Remote**: for a machine the hub can't reach directly, such as a VPS. The probe accepts tunnels from its pinned hub
  only and connects each one to the machine's own SSH port, so the hub's SSH arrives through the probe. A remote-mode
  monitor probe accepts no tunnels.

## The join ticket and token

On the dashboard, open **Add**, choose **Machine**, and fill in the system (Linux, Alpine or Windows), the name, the
access level and the mode. The hub shows the install command. It carries two values:

- the **ticket**, which names the hub's endpoint id (its public key), addresses and relays. The probe pins that id, so
  it only ever talks to this hub.
- the **token**, a single-use secret for this one machine. It works once, for 60 minutes.

Run the command on the machine. The machine appears on the Overview once its probe connects. For a managed machine the
hub then tests SSH as each account before it marks the machine enrolled.

## Linux

As a user with sudo:

```sh
curl -fsSL https://github.com/StrangeMatterStudio/Rackhand/releases/download/v<version>/install.sh | sudo sh -s -- --ticket <ticket> --token <token>
```

`install.sh` options:

| Option | Effect |
| --- | --- |
| `--ticket <ticket>`, `--token <token>` | Required: the values from the Add page |
| `--monitor` | Access level `monitor` |
| `--remote` | Remote mode |
| `--role <role>` | Sent with the join, but the hub ignores it: roles come from the dashboard (below) |
| `--release-url <url>`, `--self-signed` | Download from another place, such as the hub itself (below) |

The installer needs systemd or OpenRC, runs as root, and works on x86_64 and aarch64. It checks every file before
installing anything (see [install.md](install.md#release-files-and-how-they-are-checked)). For a managed machine it
installs `sudo` if missing.

**Offline variant.** When the hub holds the release files in `/var/lib/rackhand/release`, the Add page also shows a
command that downloads `install.sh` from the hub itself, checks it against a SHA-256 printed in the command, and runs
it with `--release-url https://<hub>:8443/release --self-signed`. The hub's certificate is self-signed, so the downloads
don't check it; the SHA-256 and the release signatures still do.

## Alpine (OpenRC)

As root (a stock Alpine machine has neither sudo nor curl):

```sh
wget -qO- https://github.com/StrangeMatterStudio/Rackhand/releases/download/v<version>/install.sh | sh -s -- --ticket <ticket> --token <token>
```

The installer adds `sudo` and `bash` with apk for a managed machine. Under OpenRC the probe has no capabilities and
collects connections by sampling (below). Debian or Ubuntu LXC containers with systemd are installed as Linux.

## Windows

In PowerShell, as Administrator, the command the Add page shows:

```powershell
iwr -useb https://github.com/StrangeMatterStudio/Rackhand/releases/download/v<version>/install.ps1 -OutFile $env:TEMP\rackhand-install.ps1; & $env:TEMP\rackhand-install.ps1 -Ticket <ticket> -Token <token>
```

`install.ps1` takes `-Monitor`, `-Remote`, `-Role <role>`, `-ReleaseUrl <url>` and `-SelfSigned`, like the Linux
options. It installs:

- the probe as `C:\Program Files\Rackhand\rackhand-probe.exe`, with its data in `C:\ProgramData\Rackhand`;
- two services: `RackhandHelper` (as SYSTEM) and `RackhandProbe` (as the virtual account `NT SERVICE\RackhandProbe`,
  with no extra privileges).

For a managed machine it also installs OpenSSH Server if missing, creates the local accounts `rackhand` and
`rackhand-ai`, and adds a `Match User rackhand,rackhand-ai` block to `sshd_config`. `rackhand` can only run the
scripts in `C:\Program Files\Rackhand\scripts` through `dispatch.ps1`, with arguments checked against each script's
schema. `rackhand-ai` is a local administrator with PowerShell transcription to `C:\ProgramData\Rackhand\transcripts`.
A monitor machine gets none of this, and loses it if it had it.

[windows-checklist.md](windows-checklist.md) has the manual checks for Windows.

## What runs on a Linux machine

| Process | User | Privileges | Does |
| --- | --- | --- | --- |
| `rackhand-probe run` (`rackhand-probe.service`) | `rackhand-probe` | `CAP_BPF` only, under systemd; none under OpenRC | Collects and reports; writes only its state and buffer directories |
| `rackhand-probe helper` (`rackhand-probe-helper.service`) | root | the only root process of a probe | Answers a fixed set of requests from the probe |
| `/usr/local/lib/rackhand/run` | root, through sudo | only on managed machines | Runs commands that match the signed command list |

**The probe** dials its hub and keeps one connection. It has no listening port, except a remote-mode probe's tunnel
from its pinned hub. Its unit sets `NoNewPrivileges`, `ProtectSystem=strict` and a read-only home, and it can write
only `/var/lib/rackhand-probe` (its key, buffer and update spool) and `/run/rackhand-probe` (its state file). It never
writes its own binary.

**The helper** is root and listens only on `/run/rackhand-helper/helper.sock`, which accepts the `rackhand-probe` user
only. It takes no paths, URLs or commands from the socket and never uses the network. It:

- loads and attaches the eBPF connection capture (the program built into the binary, never one from the socket) and
  hands the probe the maps' file descriptors. The probe only reads and drains them, which is why it keeps `CAP_BPF`
  and nothing else. Loading the capture needs root, so the helper does it (design decision D196).
- reports socket owners, processes, containers (read-only calls to the Docker and Podman sockets), login and account
  events, and hashes of critical files, without ever returning file contents;
- refreshes package lists every 6 hours at low priority and computes pending updates;
- installs probe updates (below) and the hub's key updates for the two accounts, each checked against a signature.

**Connection capture.** On kernels with `CAP_BPF` (5.8 and later) under systemd, connections and process starts come
from eBPF. Under OpenRC, on older kernels, or when the capture can't load, the probe samples sockets instead. The
Machine page shows which method a machine uses.

**Probe updates.** The probe downloads a release into its spool. The helper copies it into the inactive slot
(`/usr/local/lib/rackhand/probe-a` or `probe-b`), refuses a lower version, and checks its SHA-256 and signature. A
separate guard process switches the link, restarts both services, and switches back if the probe doesn't report
`connected` with the new version within 2 minutes.

Files the installer writes:

| Path | Owner | Holds |
| --- | --- | --- |
| `/usr/local/lib/rackhand/` | root | Binary slots, the link `rackhand-probe`, the wrapper `run` |
| `/etc/rackhand-probe/probe.toml` | root | The hub ticket (the pinned hub id) and the access level |
| `/etc/rackhand/commands.json` | root | The command list (managed only) |
| `/etc/sudoers.d/rackhand` | root | The sudo rules (managed only) |
| `/var/lib/rackhand-probe/` | `rackhand-probe` | Node key, buffer, update spool |

The probe binary isn't on `PATH`; run it as `/usr/local/lib/rackhand/rackhand-probe`.

## Checking a probe by hand

As root on the machine:

```sh
/usr/local/lib/rackhand/rackhand-probe collect --once --json
/usr/local/lib/rackhand/rackhand-probe security --seconds 10
```

`--version` prints the installed version. `collect --once --json` prints one sample set taken over one second. `security` runs the sampling capture for the given
seconds and prints the connections and events it would report. Logs are in the journal (`journalctl -u
rackhand-probe -u rackhand-probe-helper`).

## Pointing a probe at a new hub

If a hub is rebuilt with a new identity, a probe can be given the new hub's ticket as root:

```sh
/usr/local/lib/rackhand/rackhand-probe set-hub <ticket>
```

Then restart the probe (`systemctl restart rackhand-probe`). A hub restored from its backup keeps its identity, so its
probes need nothing (see [recovery.md](recovery.md)).

## Removing Rackhand from a machine

- **Managed Linux or Alpine:** run the `unenroll` runbook on the machine from the dashboard. It is high risk, so it
  needs an approval with step-up. It removes everything below, then revokes the machine on the hub.
- **Monitor machine, or by hand:** as root on the machine:

  ```sh
  /usr/local/lib/rackhand/rackhand-probe uninstall
  ```

`uninstall` stops and removes the two services, deletes the users `rackhand`, `rackhand-ai` and `rackhand-probe` with
their home directories, and removes `/etc/sudoers.d/rackhand`, `/etc/rackhand`, `/etc/rackhand-probe`,
`/var/lib/rackhand-probe`, `/var/lib/rackhand-helper`, `/var/lib/rackhand-run`, the run directories, the unit files
and `/usr/local/lib/rackhand`. Nothing else is touched. `--after <seconds>` (at most 3600) returns at once and does it
later.

Warning: don't run `uninstall` on the hub's own machine. There, `/etc/rackhand` also holds the hub's master key, node
key and `hub.toml`, and `uninstall` removes the whole directory.

## Not available yet

- Windows has no uninstall command: `rackhand-probe uninstall` is Linux and Alpine only, and the `unenroll` runbook
  targets Linux and Alpine.
- The dashboard has no action that revokes a machine without the `unenroll` runbook. A monitor machine that ran
  `uninstall` stays listed and shows as silent.
- Roles (`hub`, `operator`, `relay`, `hypervisor`, `storage`, `network`, `desktop`) can't be set from the dashboard
  yet, and the hub doesn't take them from the machine. In particular a hub's own host added as `managed` gets the
  `rackhand-ai` account, which the design rules out for hubs. Until roles can be set, add the hub's own host at access
  level `monitor` (see [hardening.md](hardening.md)).
