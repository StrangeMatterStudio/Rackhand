# Lab checklist

A checklist for rolling Rackhand out in a homelab: one hub, a few machines of each kind, and optionally an operator, a
relay and a second site. Work through it on test machines before you enroll anything you depend on, and record each
line as passed or failed with the date. Commands run as root unless the line says otherwise. The examples use the
names `hub.example.com` and `relay.example.com` and addresses from 192.0.2.0/24; use your own.

The Windows-only checks are in [windows-checklist.md](windows-checklist.md).

## Hub (install.md)

| # | Do | Expect |
| --- | --- | --- |
| 1 | `install.sh --hub` on a fresh Debian 12 or later machine (or `rackhand-lxc.sh` on a Proxmox host) | It ends with the dashboard address on port 8443, a setup code `SETUP-XXXX-XXXX-XXXX` and a recovery code |
| 2 | Store the recovery code and a copy of `/etc/rackhand/master.key` offline | Both are off the hub |
| 3 | `systemctl show -p User rackhand-hub` | `User=rackhand-hub` |
| 4 | `sudo -u rackhand-hub cat /etc/rackhand/master.key` | Permission denied |
| 5 | Run `install.sh --hub` again | "This machine had a hub already"; no new codes |
| 6 | `install.sh --hub` on Debian 11, or on another distribution | Refused before anything is downloaded |

## First run

| # | Do | Expect |
| --- | --- | --- |
| 7 | Open the dashboard; enter a wrong setup code | "That isn't the setup code the installer printed"; everything else typed is kept |
| 8 | Complete both steps with the right code and an authenticator app | The admin exists; the last page shows the same recovery code as the installer |
| 9 | Sign out and sign in again | Password, then a code from the app; the same code a second time is refused |

## Machines (machines.md)

| # | Do | Expect |
| --- | --- | --- |
| 10 | Add a Linux machine, managed, local; run the command on it | `Rackhand: enrolled as machine <id> (managed).`; the machine is on the Overview within a minute |
| 11 | Run the same command again | The join is refused: the token works once |
| 12 | `sudo -l -U rackhand` on that machine | Only `/usr/local/lib/rackhand/run`, without a password |
| 13 | `ps -o user=,comm= -C rackhand-probe` | One process as `rackhand-probe` (the probe), one as `root` (the helper) |
| 14 | `systemctl show -p AmbientCapabilities rackhand-probe` | `cap_bpf` and nothing else |
| 15 | The Machine page, on a kernel 5.8 or later | Connection capture: eBPF |
| 16 | Add an Alpine machine (or an OpenRC LXC) at `monitor`; run the `wget` command as root | `(monitor)` in the last line; `id rackhand` says there is no such user; the Machine page shows sampling |
| 17 | On the monitor machine's page, try a runbook or a diagnostic | It doesn't run: the hub has no account on a monitor machine |
| 18 | Change the managed machine to `monitor` from its Machine page and run the command | The `rackhand` and `rackhand-ai` users and `/etc/sudoers.d/rackhand` are gone; its history is kept |
| 19 | Add a Windows machine | Work through [windows-checklist.md](windows-checklist.md) |
| 20 | Add the hub's own host with the role `hub` (see hardening.md) | It reports; it has no `rackhand-ai` account |

## Runbooks and approvals (operators.md)

| # | Do | Expect |
| --- | --- | --- |
| 21 | On a managed machine, start `service-restart` for a harmless service | An approval request on the Approvals page with the exact arguments; nothing runs yet |
| 22 | Approve it as a responder | The job runs; its steps, commands and exit codes are on the Jobs page |
| 23 | Start a high-risk runbook (for example `sudoers-refresh`) | A responder can't approve it; an admin can, after step-up |
| 24 | `rackhand hub audit verify` on the hub | `audit log verified:` with the row count |

## Backups and recovery (recovery.md)

| # | Do | Expect |
| --- | --- | --- |
| 25 | `rackhand hub backup` three times | Each prints a path under `/var/lib/rackhand/backups/`; 2 files are left |
| 26 | The next morning | A backup made at 02:00 site time is there |
| 27 | On a second fresh Debian machine, `rackhand hub restore <file> --master-key <path>`, then `install.sh --hub` | "This machine had a hub already"; after it takes the old hub's address, the probes report to it without enrolling again |

## Operator (optional; operators.md)

| # | Do | Expect |
| --- | --- | --- |
| 28 | Invite an operator; `rackhand operator join '<ticket>#<secret>'` on the operator host | `Joined the hub of site <site>.` |
| 29 | `rackhand operator run`; open the Assistant page | The operator shows as connected, with its runner |
| 30 | Make a runbook fail on a test machine with a matching playbook | An assistant job starts; its transcript is on the incident; any `exec` or runbook waits for an approval at level 1 |
| 31 | Set the daily cap to 0 and repeat | The incident goes to a person with a note about the cap |

## Relay and a second site (optional; relays.md)

| # | Do | Expect |
| --- | --- | --- |
| 32 | `rackhand relay run --mode public --acme-domain relay.example.com --acme-contact mailto:admin@example.com` on a VPS | `https://relay.example.com` answers; a certificate is issued |
| 33 | Add the relay to `relays` in the hub's `hub.toml`; restart the hub; add the VPS as a remote-mode machine | It enrolls and reports through the relay |
| 34 | Make a second hub at another site and link the two on the Peers and relays page | Each shows the other's site tile; stopping one raises a peer-silent warning on the other |

## Removing Rackhand (machines.md)

| # | Do | Expect |
| --- | --- | --- |
| 35 | Run the `unenroll` runbook on a managed test machine | It needs an admin approval with step-up; afterwards the machine's Rackhand users, services and files are gone and it is revoked on the hub |
| 36 | `/usr/local/lib/rackhand/rackhand-probe uninstall` on the monitor test machine | `uninstalled`; the services, the `rackhand-probe` user and `/usr/local/lib/rackhand` are gone |
