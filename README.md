# Rackhand

A self-hosted operations hub for homelabs, written in Rust.

Each site runs a Rackhand hub. A small probe on every VM and hypervisor node reports vitals (CPU, memory, storage,
services, containers) and security signals to its hub. The hub spots trouble, calls out to you, fixes routine problems
with runbooks, and hands the rest to an AI assistant through its MCP tools, under your approval. Hubs at different
sites find each other through hole punching, with relays as a fallback, and keep an eye on each other.

## Status

Rackhand is pre-release software. It is built from the design in
[docs/designs/0001-architecture/design.md](docs/designs/0001-architecture/design.md), its version stays `0.x`, and
there is no published release yet. The install commands in these pages name release URLs that work once the first
release is signed and published. Parts of the design are not built yet; each page says which.

## Quick start

1. Make a hub: run `install.sh --hub` on a Debian 12 or later machine with systemd, or `rackhand-lxc.sh` on a Proxmox
   host. See [docs/install.md](docs/install.md).
2. Open the dashboard address the installer printed, enter the setup code, and create the admin account with a second
   factor. Store the recovery code offline.
3. Add machines from the dashboard's Add page and run the one-time command it shows on each machine. See
   [docs/machines.md](docs/machines.md).
4. Optional: an operator host for the AI assistant ([docs/operators.md](docs/operators.md)) and a relay for sites behind
   NAT ([docs/relays.md](docs/relays.md)).
5. Before you rely on it, read [docs/hardening.md](docs/hardening.md) and [docs/recovery.md](docs/recovery.md), and work
   through [docs/lab-checklist.md](docs/lab-checklist.md).

Also: [docs/windows-checklist.md](docs/windows-checklist.md) (manual checks on Windows) and
[docs/maintainers/signing.md](docs/maintainers/signing.md) (how a release is signed).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
