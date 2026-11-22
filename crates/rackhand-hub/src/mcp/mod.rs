//! The hub's MCP server (7.3.6, `rackhand/mcp/1`): one bidirectional QUIC stream per session carrying
//! newline-delimited JSON-RPC 2.0 (MCP's stdio framing), with `{"auth": "<token>"}` as the first line. The hub speaks
//! the part of MCP it serves (initialize, ping, tools/list, tools/call) itself.
//!
//! Every tool call is checked against the caller's tools, limited to 60 a minute per token, and audited. Machine
//! output is returned inside `{"untrusted_output": ...}`.

pub mod auth;
mod gate;
pub mod keys;
mod tools_act;
pub use tools_act::EXEC_TIMEOUT;
mod tools_read;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use iroh::EndpointId;
use iroh::endpoint::Connection;
use rackhand_store::Db;
use rackhand_store::ids::now_ms;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::audit::Audit;
use auth::Caller;
use keys::Scope;

pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// Calls a token may make in a minute.
pub const CALLS_PER_MINUTE: usize = 60;
/// The longest line accepted (a call and its arguments).
const MAX_LINE: usize = 1 << 20;

/// A series request for `get_vitals`.
#[derive(Debug, Clone, PartialEq)]
pub struct SeriesQuery {
    pub machine_id: String,
    pub metric: String,
    pub labels: BTreeMap<String, String>,
    pub from_ms: i64,
    pub to_ms: i64,
    pub step_ms: Option<i64>,
}

/// What a machine's probe last reported about it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Facts {
    pub services: Vec<Value>,
    pub containers: Vec<Value>,
    pub updates: Vec<Value>,
}

/// Machine data owned by other systems (series from the time-series store, facts from the latest report); the
/// composition wires them in.
pub trait Observations: Send + Sync + std::fmt::Debug {
    fn series(&self, q: &SeriesQuery) -> Vec<(i64, f64)>;
    fn facts(&self, machine_id: &str) -> Facts;
}

/// A tool error as callers see it: one of 7.3.6's codes and a sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolError {
    pub code: &'static str,
    pub message: String,
    /// More for the caller, such as `needs_approval`'s `approval_id`.
    pub data: Option<Value>,
}

impl ToolError {
    pub fn new(code: &'static str, message: impl Into<String>) -> ToolError {
        ToolError { code, message: message.into(), data: None }
    }

    pub fn with(mut self, data: Value) -> ToolError {
        self.data = Some(data);
        self
    }

    pub fn invalid(message: impl Into<String>) -> ToolError {
        ToolError::new("invalid_args", message)
    }
}

/// Tools for every caller.
pub const READ_TOOLS: [&str; 12] = [
    "list_machines",
    "get_machine",
    "get_vitals",
    "list_incidents",
    "get_incident",
    "list_security_events",
    "get_connections",
    "list_runbooks",
    "get_runbook",
    "list_playbooks",
    "get_playbook",
    "get_approval",
];
/// Tools for `read_request` keys and jobs.
pub const REQUEST_TOOLS: [&str; 4] = ["run_diagnostic", "run_runbook", "propose_library_change", "add_incident_note"];
/// Tools for jobs only.
pub const JOB_TOOLS: [&str; 2] = ["exec", "finish_job"];

/// Whether the caller may use the tool at all (gating comes after, per call).
pub fn allowed(caller: &Caller, tool: &str) -> bool {
    let known = READ_TOOLS.contains(&tool) || REQUEST_TOOLS.contains(&tool) || JOB_TOOLS.contains(&tool);
    match caller {
        // The playbook's `tools`, checked on every call (7.3.6 Enforcement).
        Caller::Job { tools, .. } => known && tools.iter().any(|t| t == tool),
        Caller::Key { scope, .. } => {
            READ_TOOLS.contains(&tool) || (*scope == Scope::ReadRequest && REQUEST_TOOLS.contains(&tool))
        }
    }
}

struct Inner {
    db: Arc<Db>,
    audit: Audit,
    observations: Arc<dyn Observations>,
    actions: Option<crate::actions::Actions>,
    library: Option<crate::library::items::Library>,
    /// Call times per token, for the rate limit.
    calls: Mutex<HashMap<String, VecDeque<i64>>>,
}

#[derive(Clone)]
pub struct Mcp {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Mcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mcp")
    }
}

/// Reads one line of at most [`MAX_LINE`] bytes; `None` at the end of the stream or on a longer line.
async fn read_line<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Option<String> {
    let mut buf = Vec::new();
    loop {
        let chunk = reader.fill_buf().await.ok()?;
        if chunk.is_empty() {
            return None;
        }
        if let Some(n) = chunk.iter().position(|b| *b == b'\n') {
            buf.extend_from_slice(&chunk[..n]);
            reader.consume(n + 1);
            return String::from_utf8(buf).ok();
        }
        let len = chunk.len();
        buf.extend_from_slice(chunk);
        reader.consume(len);
        if buf.len() > MAX_LINE {
            return None;
        }
    }
}

async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, value: &Value) -> bool {
    let mut line = value.to_string();
    line.push('\n');
    writer.write_all(line.as_bytes()).await.is_ok() && writer.flush().await.is_ok()
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn tool_result(result: Result<Value, ToolError>) -> Value {
    match result {
        Ok(v) => {
            json!({ "content": [{ "type": "text", "text": v.to_string() }], "structuredContent": v, "isError": false })
        }
        Err(e) => {
            let mut v = json!({ "error": e.code, "message": e.message });
            if let (Some(Value::Object(extra)), Some(obj)) = (e.data, v.as_object_mut()) {
                obj.extend(extra);
            }
            json!({ "content": [{ "type": "text", "text": v.to_string() }], "structuredContent": v, "isError": true })
        }
    }
}

impl Mcp {
    pub fn new(db: Arc<Db>, audit: Audit, observations: Arc<dyn Observations>) -> Mcp {
        Mcp {
            inner: Arc::new(Inner {
                db,
                audit,
                observations,
                actions: None,
                library: None,
                calls: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Actions, for the tools that run something; before serving.
    pub fn with_actions(mut self, actions: crate::actions::Actions) -> Mcp {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.actions = Some(actions);
        }
        self
    }

    /// The Library, for `propose_library_change`; before serving.
    pub fn with_library(mut self, library: crate::library::items::Library) -> Mcp {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.library = Some(library);
        }
        self
    }

    /// The router handler for `rackhand/mcp/1`.
    pub fn handler(&self) -> rackhand_net::router::Handler {
        let mcp = self.clone();
        rackhand_net::router::handler(move |conn: Connection| {
            let mcp = mcp.clone();
            async move { mcp.serve(conn).await }
        })
    }

    /// Each bidirectional stream on the connection is one session.
    pub async fn serve(&self, conn: Connection) {
        let peer = conn.remote_id();
        while let Ok((send, recv)) = conn.accept_bi().await {
            let mcp = self.clone();
            tokio::spawn(async move { mcp.session(recv, send, peer).await });
        }
    }

    /// One session: the auth line, then requests until the stream ends.
    pub async fn session<R, W>(&self, reader: R, mut writer: W, peer: EndpointId)
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut reader = BufReader::new(reader);
        let token = read_line(&mut reader).await.and_then(|l| serde_json::from_str::<Value>(&l).ok()).and_then(|v| {
            v.as_object().filter(|o| o.len() == 1).and_then(|o| o.get("auth")?.as_str().map(str::to_string))
        });
        let first = token.as_deref().map_or(Err("unauthorized"), |t| auth::check(&self.inner.db, t, &peer, now_ms()));
        let refused = first.as_ref().err().copied();
        let (Some(token), None) = (token, refused) else {
            let code = refused.unwrap_or("unauthorized");
            let _ = write_line(&mut writer, &rpc_error(Value::Null, -32001, code)).await;
            let _ = writer.shutdown().await;
            return;
        };
        while let Some(line) = read_line(&mut reader).await {
            let Ok(msg) = serde_json::from_str::<Value>(&line) else {
                if !write_line(&mut writer, &rpc_error(Value::Null, -32700, "parse error")).await {
                    return;
                }
                continue;
            };
            // Notifications (no id) need no answer.
            let Some(id) = msg.get("id").cloned() else { continue };
            let method = msg["method"].as_str().unwrap_or("");
            // The caller is checked again on every request: a revoked key, a disabled user or a finished job stops
            // at once, and a changed role takes effect.
            let caller = match self.caller(&token, &peer) {
                Some(c) => c,
                None if token.starts_with(keys::JOB_PREFIX) && method == "tools/call" => {
                    let ended = ToolError::new("deadline_exceeded", "the job has ended or its token expired");
                    let reply = json!({ "jsonrpc": "2.0", "id": id, "result": tool_result(Err(ended)) });
                    if !write_line(&mut writer, &reply).await {
                        return;
                    }
                    continue;
                }
                None => {
                    let _ = write_line(&mut writer, &rpc_error(id, -32001, "unauthorized")).await;
                    let _ = writer.shutdown().await;
                    return;
                }
            };
            let reply = match method {
                "initialize" => json!({ "jsonrpc": "2.0", "id": id, "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": "rackhand", "version": env!("CARGO_PKG_VERSION") },
                }}),
                "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
                "tools/list" => json!({ "jsonrpc": "2.0", "id": id, "result": { "tools": self.tools(&caller) } }),
                "tools/call" => {
                    let name = msg["params"]["name"].as_str().unwrap_or("").to_string();
                    let args = msg["params"].get("arguments").cloned().unwrap_or_else(|| json!({}));
                    let result = self.call(&caller, &name, &args).await;
                    json!({ "jsonrpc": "2.0", "id": id, "result": tool_result(result) })
                }
                _ => rpc_error(id, -32601, "method not found"),
            };
            if !write_line(&mut writer, &reply).await {
                return;
            }
        }
    }

    fn caller(&self, token: &str, peer: &EndpointId) -> Option<Caller> {
        auth::authenticate(&self.inner.db, token, peer, now_ms())
    }

    fn tools(&self, caller: &Caller) -> Vec<Value> {
        let all = READ_TOOLS.iter().chain(REQUEST_TOOLS.iter()).chain(JOB_TOOLS.iter());
        all.filter(|t| allowed(caller, t)).map(|t| tools_read::describe(t)).collect()
    }

    /// Over the limit: more than 60 calls in the last minute for this token.
    fn rate_limited(&self, caller: &Caller, now: i64) -> bool {
        let Ok(mut calls) = self.inner.calls.lock() else { return true };
        let times = calls.entry(caller.actor()).or_default();
        while times.front().is_some_and(|t| now - *t >= 60_000) {
            times.pop_front();
        }
        if times.len() >= CALLS_PER_MINUTE {
            return true;
        }
        times.push_back(now);
        false
    }

    async fn call(&self, caller: &Caller, tool: &str, args: &Value) -> Result<Value, ToolError> {
        let now = now_ms();
        let result = if self.rate_limited(caller, now) {
            Err(ToolError::new("rate_limited", "over 60 calls a minute for this token"))
        } else if !allowed(caller, tool) {
            Err(ToolError::new("tool_not_allowed", format!("`{tool}` isn't available to this caller")))
        } else {
            self.dispatch(caller, tool, args, now).await
        };
        let data = match &result {
            Ok(_) => json!({ "tool": tool }),
            Err(e) => json!({ "tool": tool, "error": e.code }),
        };
        if let Err(e) = self.inner.audit.append(&caller.actor(), "mcp.call", Some(tool), &data.to_string()).await {
            tracing::error!(error = %e, "audit");
        }
        result
    }

    async fn dispatch(&self, caller: &Caller, tool: &str, args: &Value, now: i64) -> Result<Value, ToolError> {
        if READ_TOOLS.contains(&tool) {
            return tools_read::call(&self.inner.db, self.inner.observations.as_ref(), tool, args, now);
        }
        // Boxed: the act tools' futures are large, and a session serves many calls.
        Box::pin(self.act(caller, tool, args, now)).await
    }
}
