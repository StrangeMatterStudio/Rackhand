//! A scripted runner for the integration tests (`rackhand operator run --runner fake:<script.json>`, in lab builds): it plays a
//! list of steps through the real MCP bridge, so what it does reaches the hub exactly as a real assistant's calls do. A call
//! the hub answers with `needs_approval` waits for the approval to be decided, then repeats with its id: the order of changes
//! in a guided install is the script's order.
//!
//! ```json
//! [{"say": "Looking"}, {"call": "run_diagnostic", "args": {"machine": "web", "name": "mounts"}},
//!  {"call": "run_runbook", "args": {"name": "compose-restart", "target": "web", "params": {}, "reason": "restart"},
//!   "wait_approval": true}, {"finish": {"outcome": "resolved", "summary": "restarted"}}]
//! ```

use std::process::Command;
use std::time::Duration;

use rackhand_proto::operator::{JobEventKind, Outcome};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::runner::{Done, Event, Info, JobSpec, RunHandle, Runner, RunnerError, now_ms};

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Step {
    Say {
        say: String,
    },
    Call {
        call: String,
        #[serde(default)]
        args: Value,
        #[serde(default)]
        wait_approval: bool,
    },
    Finish {
        finish: Finish,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct Finish {
    pub outcome: String,
    #[serde(default)]
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct Fake {
    pub script: Vec<Step>,
    /// How often an approval's state is looked at.
    pub poll: Duration,
}

impl Fake {
    pub fn from_file(path: &std::path::Path) -> Result<Fake, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let script = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Fake { script, poll: Duration::from_millis(500) })
    }
}

struct Session {
    stdin: tokio::process::ChildStdin,
    stdout: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    next: u64,
}

impl Session {
    async fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.next += 1;
        let line = format!("{}\n", json!({ "jsonrpc": "2.0", "id": self.next, "method": method, "params": params }));
        self.stdin.write_all(line.as_bytes()).await.map_err(|e| e.to_string())?;
        loop {
            let answer = self.stdout.next_line().await.map_err(|e| e.to_string())?.ok_or("the bridge closed")?;
            let v: Value = serde_json::from_str(&answer).map_err(|e| e.to_string())?;
            if v["id"] == self.next {
                return Ok(v);
            }
        }
    }

    async fn notify(&mut self, method: &str) -> Result<(), String> {
        let line = format!("{}\n", json!({ "jsonrpc": "2.0", "method": method }));
        self.stdin.write_all(line.as_bytes()).await.map_err(|e| e.to_string())
    }

    /// A tool call: its structured result, and whether it was an error.
    async fn call(&mut self, tool: &str, args: &Value) -> Result<(Value, bool), String> {
        let reply = self.request("tools/call", json!({ "name": tool, "arguments": args })).await?;
        if let Some(e) = reply.get("error") {
            return Err(e.to_string());
        }
        let result = &reply["result"];
        Ok((result["structuredContent"].clone(), result["isError"] == true))
    }
}

fn cancelled() -> Done {
    Done { outcome: Outcome::Failed, summary: "the run was cancelled".into() }
}

async fn play(fake: Fake, bridge: Command, events: mpsc::Sender<Event>, stop: CancellationToken) -> Done {
    let say = |kind, text: String| {
        let events = events.clone();
        async move {
            let _ = events.send(Event { at_ms: now_ms(), kind, text }).await;
        }
    };
    let mut child = match tokio::process::Command::from(bridge)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Done { outcome: Outcome::Failed, summary: format!("the bridge didn't start: {e}") },
    };
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Done { outcome: Outcome::Failed, summary: "no bridge streams".into() };
    };
    let mut s = Session { stdin, stdout: BufReader::new(stdout).lines(), next: 0 };
    let fail = |why: String| Done { outcome: Outcome::Failed, summary: why };
    let hello = json!({ "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": { "name": "fake", "version": "0" } });
    if let Err(e) = s.request("initialize", hello).await {
        return fail(e);
    }
    if let Err(e) = s.notify("notifications/initialized").await {
        return fail(e);
    }
    let mut finished = None;
    for step in &fake.script {
        if stop.is_cancelled() {
            return cancelled();
        }
        match step {
            Step::Say { say: text } => say(JobEventKind::Message, text.clone()).await,
            Step::Finish { finish } => {
                let args = json!({ "outcome": finish.outcome, "summary": finish.summary });
                say(JobEventKind::ToolCall, format!("finish_job {args}")).await;
                match s.call("finish_job", &args).await {
                    Ok((v, false)) => say(JobEventKind::ToolResult, v.to_string()).await,
                    Ok((v, true)) => say(JobEventKind::Error, v.to_string()).await,
                    Err(e) => return fail(e),
                }
                finished = Some(match finish.outcome.as_str() {
                    "resolved" => Outcome::Resolved,
                    _ => Outcome::NeedsHuman,
                });
            }
            Step::Call { call, args, wait_approval } => {
                let mut args = args.clone();
                loop {
                    say(JobEventKind::ToolCall, format!("{call} {args}")).await;
                    let (v, error) = match s.call(call, &args).await {
                        Ok(r) => r,
                        Err(e) => return fail(e),
                    };
                    if !error {
                        say(JobEventKind::ToolResult, v.to_string()).await;
                        break;
                    }
                    say(JobEventKind::Error, v.to_string()).await;
                    let asked = v["approval_id"].as_str().filter(|_| v["error"] == "needs_approval" && *wait_approval);
                    let Some(id) = asked else { break };
                    // wait for a person, then ask again with the approval
                    let state = loop {
                        tokio::time::sleep(fake.poll).await;
                        if stop.is_cancelled() {
                            return cancelled();
                        }
                        let (a, _) = match s.call("get_approval", &json!({ "id": id })).await {
                            Ok(r) => r,
                            Err(e) => return fail(e),
                        };
                        match a["state"].as_str() {
                            Some("pending") | None => {}
                            Some(other) => break other.to_string(),
                        }
                    };
                    if state != "approved" {
                        say(JobEventKind::Message, format!("the approval was {state}")).await;
                        return Done { outcome: Outcome::NeedsHuman, summary: format!("the approval was {state}") };
                    }
                    args["approval_id"] = json!(id);
                }
            }
        }
    }
    let _ = child.start_kill();
    match finished {
        Some(outcome) => Done { outcome, summary: "the script finished the job".into() },
        None => Done { outcome: Outcome::NeedsHuman, summary: "the script ended without finishing the job".into() },
    }
}

#[async_trait::async_trait]
impl Runner for Fake {
    fn info(&self) -> Info {
        Info { name: "fake".into(), version: "0".into() }
    }

    async fn start(&self, _job: &JobSpec, mcp_bridge: Command) -> Result<RunHandle, RunnerError> {
        let (events, rx) = mpsc::channel(256);
        let (done_tx, done) = oneshot::channel();
        let cancel = CancellationToken::new();
        let (fake, stop) = (self.clone(), cancel.clone());
        tokio::spawn(async move {
            let done = tokio::select! {
                d = play(fake, mcp_bridge, events, stop.clone()) => d,
                () = stop.cancelled() => cancelled(),
            };
            let _ = done_tx.send(done);
        });
        Ok(RunHandle { events: rx, cancel, done })
    }
}
