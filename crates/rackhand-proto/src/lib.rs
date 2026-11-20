//! Wire messages, ALPN names and versions (design 7.2, Proto; 7.3).
//!
//! Every QUIC contract frames protobuf messages with a u32 big-endian length prefix ([`frame`]), at most 4 MB on the
//! wire; compressed payloads expand to at most 16 MB ([`zstd`]). Unknown enum values decode to their contract's
//! `Unsupported` value ([`known_or_unsupported`]).

pub mod alpn;
pub mod catalogue;
pub mod close;
pub mod frame;
pub mod helper;
pub mod mcp;
pub mod signed;
pub mod zstd;

/// The first byte of each unidirectional stream of `rackhand/probe/1` (7.3.2): which stream it is.
pub mod streams {
    /// Stream 1: live reports, one `Report` per frame.
    pub const LIVE: u8 = 1;
    /// Stream 2: replay batches, one `ReplayBatch` per frame.
    pub const REPLAY: u8 = 2;
}

#[allow(clippy::all, missing_debug_implementations)]
pub mod common {
    include!(concat!(env!("OUT_DIR"), "/rackhand.common.rs"));
}
#[allow(clippy::all, missing_debug_implementations)]
pub mod join {
    include!(concat!(env!("OUT_DIR"), "/rackhand.join.rs"));
}
#[allow(clippy::all, missing_debug_implementations)]
pub mod probe {
    include!(concat!(env!("OUT_DIR"), "/rackhand.probe.rs"));
}
#[allow(clippy::all, missing_debug_implementations)]
pub mod peer {
    include!(concat!(env!("OUT_DIR"), "/rackhand.peer.rs"));
}
#[allow(clippy::all, missing_debug_implementations)]
pub mod operator {
    include!(concat!(env!("OUT_DIR"), "/rackhand.operator.rs"));
}
#[allow(clippy::all, missing_debug_implementations)]
pub mod tunnel {
    include!(concat!(env!("OUT_DIR"), "/rackhand.tunnel.rs"));
}

/// Maps a decoded enum value to its variant, or to `unsupported` when this build doesn't know the value (7.3: unknown
/// enum values are answered with an `unsupported` error, never a crash).
pub fn known_or_unsupported<E: TryFrom<i32>>(value: i32, unsupported: E) -> E {
    E::try_from(value).unwrap_or(unsupported)
}

#[cfg(test)]
mod samples;

#[cfg(test)]
mod tests {
    mod enums;
    mod frame;
    mod golden;
    mod helper;
    mod signed;
    mod zstd;
}
