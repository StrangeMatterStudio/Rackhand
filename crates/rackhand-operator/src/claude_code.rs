//! The Claude Code runner (7.3.5, spike S5): `claude -p` with the flags the spike found, so that a run has no built-in tools
//! and no MCP server but the bridge, from a configuration directory of its own. Its stream-json output becomes job events;
//! SIGTERM at the deadline ends `claude` and its bridge child, and a process that ignores it is killed after a grace.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use rackhand_proto::operator::{JobEventKind, Outcome};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::runner::{Done, Event, Info, JobSpec, RunHandle, Runner, RunnerError, now_ms};

/// How long a run has to end after SIGTERM before it is killed (S5: it ends within 5 s).
pub const GRACE: Duration = Duration::from_secs(5);

/// The text a job's tool calls and results are cut to in an event.
const EVENT_TEXT: usize = 8 * 1024;

#[derive(Debug, Clone)]
pub struct ClaudeCode {
    pub binary: PathBuf,
    /// Holds only the provider credential (and what the run writes itself).
    pub config_dir: PathBuf,
    /// One working directory per job goes here.
    pub work_root: PathBuf,
    pub grace: Duration,
}

impl ClaudeCode {
    pub fn new(binary: PathBuf, config_dir: PathBuf, work_root: PathBuf) -> ClaudeCode {
        ClaudeCode { binary, config_dir, work_root, grace: GRACE }
    }
}

/// The arguments of the run, exactly the vector the spike used, ending with the prompt.
pub fn args(job: &JobSpec, mcp_config: &Path) -> Vec<String> {
    let mut a: Vec<String> = ["-p", "--mcp-config"].map(String::from).into();
    a.push(mcp_config.display().to_string());
    a.extend(
        [
            "--strict-mcp-config",
            "--tools",
            "",
            "--allowedTools",
            "mcp__rackhand__*",
            "--output-format",
            "stream-json",
            "--verbose",
        ]
        .map(String::from),
    );
    a.extend(["--max-turns".to_string(), job.max_turns.to_string()]);
    a.extend(["--no-session-persistence", "--permission-mode", "dontAsk"].map(String::from));
    a.push(job.brief_markdown.clone());
    a
}

/// The MCP configuration: one server, the bridge.
pub fn mcp_config(bridge: &Command) -> String {
    let args: Vec<String> = bridge.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    serde_json::json!({
        "mcpServers": { "rackhand": { "command": bridge.get_program().to_string_lossy(), "args": args } }
    })
    .to_string()
}

fn cut(text: &str) -> String {
    if text.len() <= EVENT_TEXT {
        return text.to_string();
    }
    let mut end = EVENT_TEXT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... ({} bytes more)", &text[..end], text.len() - end)
}

/// What one line of stream-json says.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub events: Vec<(JobEventKind, String)>,
    /// The final `result` line: whether it failed, and its text.
    pub result: Option<(bool, String)>,
}

pub fn parse_line(line: &str) -> Parsed {
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return Parsed {
            events: vec![(JobEventKind::Error, cut(&format!("unreadable output: {line}")))],
            result: None,
        };
    };
    let mut out = Parsed::default();
    match v["type"].as_str() {
        Some("assistant") => {
            for block in v["message"]["content"].as_array().into_iter().flatten() {
                match block["type"].as_str() {
                    Some("text") => {
                        let text = block["text"].as_str().unwrap_or("");
                        if !text.trim().is_empty() {
                            out.events.push((JobEventKind::Message, cut(text)));
                        }
                    }
                    Some("tool_use") => {
                        let name = block["name"].as_str().unwrap_or("?");
                        let name = name.strip_prefix("mcp__rackhand__").unwrap_or(name);
                        out.events.push((JobEventKind::ToolCall, cut(&format!("{name} {}", block["input"]))));
                    }
                    _ => {}
                }
            }
        }
        Some("user") => {
            for block in v["message"]["content"].as_array().into_iter().flatten() {
                if block["type"] == "tool_result" {
                    let text = match &block["content"] {
                        Value::String(s) => s.clone(),
                        Value::Array(parts) => {
                            parts.iter().filter_map(|p| p["text"].as_str()).collect::<Vec<_>>().join("\n")
                        }
                        other => other.to_string(),
                    };
                    let kind = if block["is_error"] == true { JobEventKind::Error } else { JobEventKind::ToolResult };
                    out.events.push((kind, cut(&text)));
                }
            }
        }
        Some("result") => {
            let failed = v["is_error"] == true || v["subtype"].as_str().is_some_and(|s| s != "success");
            out.result = Some((failed, v["result"].as_str().unwrap_or("").to_string()));
        }
        _ => {}
    }
    out
}

#[cfg(target_os = "linux")]
fn signal_group(pid: u32, kill: bool) {
    use rustix::process::{Pid, Signal, kill_process_group};
    if let Some(pid) = i32::try_from(pid).ok().and_then(Pid::from_raw) {
        let _ = kill_process_group(pid, if kill { Signal::KILL } else { Signal::TERM });
    }
}

#[cfg(not(target_os = "linux"))]
fn signal_group(_pid: u32, _kill: bool) {}

/// Ends the run: SIGTERM to its process group (`claude` and its bridge), a kill if it is still there after `grace`.
async fn terminate(child: &mut tokio::process::Child, grace: Duration) {
    let Some(pid) = child.id() else { return };
    signal_group(pid, false);
    if tokio::time::timeout(grace, child.wait()).await.is_err() {
        signal_group(pid, true);
        let _ = child.wait().await;
    }
    // anything of the group that outlived `claude`
    signal_group(pid, true);
}

#[derive(Debug, PartialEq, Eq)]
enum Ended {
    Exited(bool),
    Cancelled,
    Deadline,
}

#[async_trait::async_trait]
impl Runner for ClaudeCode {
    fn info(&self) -> Info {
        let version = Command::new(&self.binary)
            .arg("--version")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().next().unwrap_or("").to_string())
            .unwrap_or_default();
        Info { name: "claude-code".into(), version }
    }

    async fn start(&self, job: &JobSpec, mcp_bridge: Command) -> Result<RunHandle, RunnerError> {
        let work = self.work_root.join(&job.job_id);
        let fail = |what: &str, e: std::io::Error| RunnerError::Start(format!("{what}: {e}"));
        std::fs::create_dir_all(&work).map_err(|e| fail(&work.display().to_string(), e))?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700)).map_err(|e| fail("work dir", e))?;
        }
        std::fs::create_dir_all(&self.config_dir).map_err(|e| fail("config dir", e))?;
        std::fs::write(work.join("brief.md"), &job.brief_markdown).map_err(|e| fail("brief", e))?;
        let config = work.join("mcp.json");
        std::fs::write(&config, mcp_config(&mcp_bridge)).map_err(|e| fail("mcp config", e))?;
        let mut cmd = tokio::process::Command::new(&self.binary);
        cmd.args(args(job, &config))
            .current_dir(&work)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", &work)
            .env("CLAUDE_CONFIG_DIR", &self.config_dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        let mut child = cmd.spawn().map_err(|e| fail(&self.binary.display().to_string(), e))?;
        let stdout = child.stdout.take().ok_or_else(|| RunnerError::Start("no standard output".into()))?;
        let stderr = child.stderr.take();
        let (events, rx) = mpsc::channel::<Event>(256);
        let (done_tx, done_rx) = oneshot::channel();
        let cancel = CancellationToken::new();
        let (job_id, deadline_ms, grace) = (job.job_id.clone(), job.deadline_ms, self.grace);
        let stop = cancel.clone();
        // standard output: stream-json to events, and the final result
        let reader = tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            let mut result = None;
            while let Ok(Some(line)) = lines.next_line().await {
                let parsed = parse_line(&line);
                if parsed.result.is_some() {
                    result = parsed.result;
                }
                for (kind, text) in parsed.events {
                    if events.send(Event { at_ms: now_ms(), kind, text }).await.is_err() {
                        break;
                    }
                }
            }
            result
        });
        let tail = tokio::spawn(async move {
            let mut text = String::new();
            if let Some(err) = stderr {
                let mut lines = BufReader::new(err).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    text = format!("{text}{line}\n");
                    if text.len() > 4096 {
                        text.drain(..text.len() - 4096);
                    }
                }
            }
            text
        });
        tokio::spawn(async move {
            let until = Duration::from_millis(u64::try_from(deadline_ms - now_ms()).unwrap_or(0));
            let ended = tokio::select! {
                status = child.wait() => Ended::Exited(status.is_ok_and(|s| s.success())),
                () = stop.cancelled() => { terminate(&mut child, grace).await; Ended::Cancelled }
                () = tokio::time::sleep(until) => { terminate(&mut child, grace).await; Ended::Deadline }
            };
            let result = reader.await.ok().flatten();
            let stderr = tail.await.unwrap_or_default();
            let done = match ended {
                Ended::Deadline => {
                    Done { outcome: Outcome::TimedOut, summary: "the deadline passed; the run was stopped".into() }
                }
                Ended::Cancelled => Done { outcome: Outcome::Failed, summary: "the run was cancelled".into() },
                Ended::Exited(true) if result.as_ref().is_some_and(|(failed, _)| !failed) => Done {
                    outcome: Outcome::NeedsHuman,
                    summary: format!(
                        "the assistant ended without a result: {}",
                        cut(&result.map(|r| r.1).unwrap_or_default())
                    ),
                },
                Ended::Exited(_) => Done {
                    outcome: Outcome::Failed,
                    summary: match result {
                        Some((_, text)) if !text.is_empty() => cut(&text),
                        _ => format!("claude ended with an error: {}", cut(stderr.trim())),
                    },
                },
            };
            tracing::info!(job = %job_id, outcome = ?done.outcome, "run ended");
            let _ = done_tx.send(done);
        });
        Ok(RunHandle { events: rx, cancel, done: done_rx })
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn spec(deadline_ms: i64) -> JobSpec {
        JobSpec {
            job_id: "01JOB00000000000000000000A".into(),
            incident_id: "01INC".into(),
            playbook: "patch-failure".into(),
            playbook_rev: 1,
            brief_markdown: "The mount /srv is missing.".into(),
            allowed_tools: vec!["run_diagnostic".into()],
            autonomy: 1,
            hosts: vec![],
            deadline_ms,
            max_turns: 60,
        }
    }

    #[test]
    fn command_line_matches_spike_flags() {
        let a = args(&spec(0), Path::new("/w/mcp.json"));
        // the vector spike S5 ran, with the brief as its prompt
        assert_eq!(
            a,
            [
                "-p",
                "--mcp-config",
                "/w/mcp.json",
                "--strict-mcp-config",
                "--tools",
                "",
                "--allowedTools",
                "mcp__rackhand__*",
                "--output-format",
                "stream-json",
                "--verbose",
                "--max-turns",
                "60",
                "--no-session-persistence",
                "--permission-mode",
                "dontAsk",
                "The mount /srv is missing.",
            ]
        );
        // one MCP server, the bridge, and nothing in its configuration but how to start it
        let mut bridge = Command::new("/usr/local/bin/rackhand");
        bridge.args(["operator", "mcp-bridge", "--hub", "ab", "--job", "01J"]);
        let config: Value = serde_json::from_str(&mcp_config(&bridge)).unwrap();
        let servers = config["mcpServers"].as_object().unwrap();
        assert_eq!(servers.keys().collect::<Vec<_>>(), ["rackhand"]);
        assert_eq!(servers["rackhand"]["command"], "/usr/local/bin/rackhand");
        assert_eq!(servers["rackhand"]["args"][1], "mcp-bridge");
    }

    #[test]
    fn stream_json_lines_map_to_job_events() {
        let lines = [
            r#"{"type":"system","subtype":"init","tools":["mcp__rackhand__run_diagnostic"]}"#,
            r#"{"type":"assistant","message":{"content":[{"type":"text","text":"Looking at the mounts."},{"type":"tool_use","id":"t1","name":"mcp__rackhand__run_diagnostic","input":{"machine":"web","name":"mounts"}}]}}"#,
            r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"/srv not mounted"}]}]}}"#,
            r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t2","content":"no such machine","is_error":true}]}}"#,
            r#"{"type":"rate_limit_event"}"#,
            r#"{"type":"result","subtype":"success","is_error":false,"result":"Done."}"#,
            "not json at all",
        ];
        let parsed: Vec<Parsed> = lines.iter().map(|l| parse_line(l)).collect();
        assert!(parsed[0].events.is_empty() && parsed[4].events.is_empty(), "system and rate limit lines say nothing");
        assert_eq!(parsed[1].events[0], (JobEventKind::Message, "Looking at the mounts.".to_string()));
        assert_eq!(
            parsed[1].events[1],
            (JobEventKind::ToolCall, r#"run_diagnostic {"machine":"web","name":"mounts"}"#.to_string())
        );
        assert_eq!(parsed[2].events, [(JobEventKind::ToolResult, "/srv not mounted".to_string())]);
        assert_eq!(parsed[3].events, [(JobEventKind::Error, "no such machine".to_string())]);
        assert_eq!(parsed[5].result, Some((false, "Done.".to_string())));
        assert_eq!(parsed[6].events[0].0, JobEventKind::Error, "output that isn't JSON is an error, not a crash");
        // a long result is cut, not dropped
        let long = format!(
            r#"{{"type":"user","message":{{"content":[{{"type":"tool_result","content":"{}"}}]}}}}"#,
            "x".repeat(20_000)
        );
        let cut = &parse_line(&long).events[0].1;
        assert!(cut.len() < 9_000 && cut.contains("bytes more"), "{}", cut.len());
    }

    fn stub(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("claude-stub");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rackhand-operator-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn alive(pid: &str) -> bool {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
            && !std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default().contains(") Z")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn killed_at_deadline_no_process_left() {
        let dir = temp("deadline");
        // a stand-in that ignores SIGTERM and starts a child of its own that does too
        let binary = stub(
            &dir,
            &format!(
                "trap '' TERM\n(trap '' TERM; echo $$ > {0}/child.pid; sleep 300) &\necho $$ > {0}/main.pid\nwhile true; do sleep 1; done",
                dir.display()
            ),
        );
        let mut runner = ClaudeCode::new(binary, dir.join("config"), dir.join("work"));
        runner.grace = Duration::from_millis(800);
        let bridge = Command::new("/bin/true");
        let started = std::time::Instant::now();
        let handle = runner.start(&spec(now_ms() + 700), bridge).await.unwrap();
        let done = handle.done.await.unwrap();
        assert_eq!(done.outcome, Outcome::TimedOut, "{done:?}");
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "stopped without waiting for the stand-in: {:?}",
            started.elapsed()
        );
        for file in ["main.pid", "child.pid"] {
            let pid = std::fs::read_to_string(dir.join(file)).unwrap().trim().to_string();
            // give the kernel a moment to reap
            for _ in 0..40 {
                if !alive(&pid) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(!alive(&pid), "{file}: process {pid} is still there");
        }
        // the run's own directory has its brief and its one-server config, and nothing of a token
        let config = std::fs::read_to_string(dir.join("work/01JOB00000000000000000000A/mcp.json")).unwrap();
        assert!(config.contains("mcpServers") && !config.contains("token"), "{config}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_run_that_ends_by_itself_reports_its_events_and_needs_a_person_when_nothing_finished_the_job() {
        let dir = temp("ends");
        let binary = stub(
            &dir,
            r#"echo '{"type":"assistant","message":{"content":[{"type":"text","text":"hello"}]}}'
echo '{"type":"result","subtype":"success","is_error":false,"result":"all done"}'"#,
        );
        let runner = ClaudeCode::new(binary, dir.join("config"), dir.join("work"));
        let mut handle = runner.start(&spec(now_ms() + 60_000), Command::new("/bin/true")).await.unwrap();
        let first = handle.events.recv().await.unwrap();
        assert_eq!((first.kind, first.text.as_str()), (JobEventKind::Message, "hello"));
        let done = handle.done.await.unwrap();
        assert_eq!(done.outcome, Outcome::NeedsHuman);
        assert!(done.summary.contains("all done"), "{done:?}");
        // one that fails says why
        let binary = stub(&dir, "echo oops >&2\nexit 3");
        let runner = ClaudeCode::new(binary, dir.join("config"), dir.join("work2"));
        let handle = runner.start(&spec(now_ms() + 60_000), Command::new("/bin/true")).await.unwrap();
        let done = handle.done.await.unwrap();
        assert_eq!(done.outcome, Outcome::Failed);
        assert!(done.summary.contains("oops"), "{done:?}");
    }
}
