//! Which versions of probes, operators, relays and CLIs a hub accepts (design 5.2, 13): its own minor version and one
//! minor older, any patch. Anything else, or a version that doesn't parse, is refused with `0x12`.

use rackhand_release::binary::Version;

/// Whether a hub of version `hub` accepts a client that reports `client`.
pub fn accepts(hub: &str, client: &str) -> bool {
    let (Some(hub), Some(client)) = (Version::parse(hub), Version::parse(client)) else { return false };
    client.0 == hub.0 && (client.1 == hub.1 || client.1 + 1 == hub.1)
}

#[cfg(test)]
mod tests;
