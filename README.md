# Rackhand

A self-hosted operations hub for homelabs, written in Rust.

Each site runs a Rackhand hub. A small probe on every VM and hypervisor node reports vitals (CPU, memory, storage,
services, containers) and security signals to its hub. The hub spots trouble, calls out to you, fixes routine problems
with runbooks, and hands the rest to an AI assistant through its MCP tools, under your approval. Hubs at different
sites find each other through hole punching, with relays as a fallback, and keep an eye on each other.

Status: in design. See `docs/designs/`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
