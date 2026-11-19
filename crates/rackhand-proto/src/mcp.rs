//! `rackhand/mcp/1` (7.3.6): newline-delimited JSON-RPC 2.0 whose first line authenticates the session.

use serde::{Deserialize, Serialize};

/// The first line of an MCP session: `{"auth": "<job token or device key>"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthLine {
    pub auth: String,
}
