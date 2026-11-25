# Relays

Rackhand processes (hubs, probes, operators, people's computers) talk to each other over QUIC with their keys pinned.
They connect directly when they can, including through NAT by hole punching. A **relay** is a server both sides can
reach that forwards their traffic when no direct path works. Traffic stays end-to-end encrypted: a relay sees endpoint
ids, sizes and timing, not content.

## When you need one

- A hub is behind NAT and things outside its network must reach it: a remote-mode probe on a VPS, a hub at another
  site, an operator or a laptop away from home.
- Two sites can't hole-punch to each other (for example both are behind carrier-grade NAT).

A single site where every machine, the operator and your computers are on the hub's network needs no relay.

Bulk transfers (backups to peers, `rackhand-cli send`) wait for a direct path and don't use a relay unless they are
allowed to (`--allow-relay` for `rackhand-cli send`).

## Running a relay

A relay is the `rackhand` binary on a small public machine such as a VPS, run as `rackhand relay run`. It needs a DNS
name and these ports open:

| Port | What |
| --- | --- |
| TCP 443 | HTTPS, where the relay is reached |
| TCP 80 | HTTP |
| UDP 7842 | QUIC address discovery |

With a Let's Encrypt certificate:

```sh
rackhand relay run --mode public --acme-domain relay.example.com --acme-contact mailto:admin@example.com
```

With a certificate you already have:

```sh
rackhand relay run --mode public --cert /etc/ssl/relay.example.com/fullchain.pem --key /etc/ssl/relay.example.com/privkey.pem
```

Options:

| Option | Default | What |
| --- | --- | --- |
| `--data-dir <dir>` | `/var/lib/rackhand-relay` | The relay's key, key bindings and Let's Encrypt cache |
| `--mode private\|public` | `private` | `private`: only endpoints with a valid relay key. `public`: anyone; keyed endpoints get their key's priority |
| `--rate <bits/s>` | 1 Mbit/s in `public` mode, none in `private` | One rate for every connection |
| `--http <addr>`, `--https <addr>`, `--quic <addr>` | ports 80, 443 and 7842 on every IPv4 address | Listen addresses |
| `--acme-domain <name>` | none | Let's Encrypt for this name; may be given more than once; needs `--acme-contact` |
| `--acme-staging` | off | Use Let's Encrypt's staging service, for testing |
| `--cert <chain.pem> --key <key.pem>` | none | A certificate from files, instead of Let's Encrypt |

Without `--acme-domain` or `--cert`, the relay serves plain HTTP only, for use behind something that terminates TLS.
A relay serves at most 500 endpoints at once.

### As a service

The release has `rackhand-relay.service`, which runs the relay as the system user `rackhand-relay` with only
`CAP_NET_BIND_SERVICE`, and `rackhand-relay-updater.path` and `.service` for signed updates. There is no relay
installer yet. On the relay machine:

1. Install the checked `rackhand` binary as `/usr/local/bin/rackhand` (see
   [install.md](install.md#release-files-and-how-they-are-checked)).
2. Create the system user and group `rackhand-relay`.
3. Install `rackhand-relay.service` in `/etc/systemd/system`. Its `ExecStart` passes only `--data-dir`, so add the mode
   and the certificate options with a drop-in (`systemctl edit rackhand-relay`) that replaces `ExecStart`.
4. `systemctl enable --now rackhand-relay`.

## Relay keys

For a `private` relay, or for priority on a busy `public` one, the relay's operator issues keys. As the relay's user:

```sh
rackhand relay key create --name site-a --expires 2027-06-30 --priority high --max-endpoints 1
```

It prints a token signed by the relay's own key. `--name` and `--expires` (a date, valid through that day in UTC) are
required; `--priority` is `normal` (the default) or `high`; a key is bound to the first `--max-endpoints` endpoints that
use it (default 1). At capacity, high-priority keyed endpoints are admitted first, then normal keyed ones, then
unkeyed ones.

## Telling a hub about a relay

Add the relay's URL to `relays` in the hub's `/etc/rackhand/hub.toml`, in the order to try them, and restart the hub:

```toml
relays = ["https://relay.example.com"]
```

The hub uses its relays itself, puts them in the tickets of the install commands and invites it issues (so probes,
operators and devices find it through them), and uses them for tunnels to remote-mode probes. A ticket issued before
the change doesn't name the new relay.

**Relay lists.** On the Peers and relays page a hub can follow lists of public relays: HTTPS URLs returning TOML
`[[relay]]` entries (`url`, `name`, `region`, `operator`), at most 100 entries, fetched daily. Following lists is off
by default, and turning it on is an outside source (see [hardening.md](hardening.md)). Listed relays are tried after
the hub's own and are always treated as public.

## Not available yet

- A hub can't present a relay key yet: there is no place to put one. A `private` relay therefore refuses hubs (and
  everything that reaches a hub through it), so for now run your relay with `--mode public` and a `--rate` that suits
  your link.
- The setting for n0's public relays is stored but not used: a hub uses only its own relays and the relays from lists
  it follows.
