# Rackhand

A self-hosted operations hub for homelabs, written in Rust.

Each site runs a Rackhand hub. A small agent on every VM and hypervisor node reports vitals (CPU, memory, storage,
services, containers) to its hub. The hub spots trouble and calls out to you, or to an AI assistant through its MCP
tools, so it can be fixed with stored playbooks. Hubs at different sites find each other through hole punching, with
relays as a fallback, and keep an eye on each other.

Status: in design. See `docs/designs/`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
