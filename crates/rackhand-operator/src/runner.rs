//! The runner interface (7.3.5): what runs an assistant job on the operator host. A runner gets the job without its token
//! and a command for the MCP bridge, the one way to the hub.

use std::process::Command;

use rackhand_proto::operator::{JobEventKind, Outcome};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// A job as the runner sees it: the offer without the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSpec {
    pub job_id: String,
    pub incident_id: String,
    pub playbook: String,
    pub playbook_rev: u64,
    pub brief_markdown: String,
    pub allowed_tools: Vec<String>,
    pub autonomy: u32,
    pub hosts: Vec<String>,
    pub deadline_ms: i64,
    pub max_turns: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub at_ms: i64,
    pub kind: JobEventKind,
    pub text: String,
}

/// How a run ended, and what to say about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Done {
    pub outcome: Outcome,
    pub summary: String,
}

#[derive(Debug)]
pub struct RunHandle {
    pub events: mpsc::Receiver<Event>,
    /// Cancelling it stops the run (SIGTERM, then a kill).
    pub cancel: CancellationToken,
    pub done: oneshot::Receiver<Done>,
}

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("{0}")]
    Start(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub name: String,
    pub version: String,
}

#[async_trait::async_trait]
pub trait Runner: Send + Sync {
    fn info(&self) -> Info;
    async fn start(&self, job: &JobSpec, mcp_bridge: Command) -> Result<RunHandle, RunnerError>;
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
