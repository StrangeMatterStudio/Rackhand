//! ALPN names. The ALPN carries the contract's major version (7.3).

pub const JOIN: &[u8] = b"rackhand/join/1";
pub const PROBE: &[u8] = b"rackhand/probe/1";
pub const PEER: &[u8] = b"rackhand/peer/1";
pub const OPERATOR: &[u8] = b"rackhand/operator/1";
pub const MCP: &[u8] = b"rackhand/mcp/1";
pub const TUNNEL: &[u8] = b"rackhand/tunnel/1";
pub const XFER: &[u8] = b"rackhand/xfer/1";

pub const ALL: &[&[u8]] = &[JOIN, PROBE, PEER, OPERATOR, MCP, TUNNEL, XFER];
