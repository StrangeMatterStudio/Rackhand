//! The signed command list (7.3.7, D92): `commands.json` generated from the enabled runbooks and signed with the hub's
//! node key, as `run install-commands` takes it on standard input.

use ed25519_dalek::SigningKey;
use prost::Message;
use rackhand_runbook::runbook::Runbook;
use rackhand_runbook::templates::command_list;

/// The protobuf `SignedPayload` bytes of the command list for `runbooks`, version `version`, valid for `ttl_ms`.
pub fn signed_command_list(key: &SigningKey, runbooks: &[Runbook], version: u64, now_ms: i64, ttl_ms: i64) -> Vec<u8> {
    let body = serde_json::to_vec(&command_list(runbooks)).unwrap_or_default();
    rackhand_proto::signed::sign(key, "commands", version, now_ms, now_ms + ttl_ms, &body).encode_to_vec()
}
