//! The MCP bridge (7.3.5, 7.3.6): how a runner's MCP client reaches the hub, with the job token kept out of its reach.
//!
//! The runner starts `rackhand operator mcp-bridge` as its one MCP server (stdio). That process holds no token: it connects to
//! a socket the operator serves for this job and passes lines both ways. The operator's [`Broker`] on the other end of the
//! socket opens the hub's MCP stream, sends the `{"auth": <token>}` line, and forwards each request and its answer. While the
//! hub can't be reached, a tool call is answered with `hub_unreachable` and the next call tries again.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

/// The longest a request may wait for the hub's answer: an `exec` may run for 10 minutes.
const ANSWER_WAIT: Duration = Duration::from_secs(11 * 60);
/// The longest line either side sends.
const MAX_LINE: usize = 8 * 1024 * 1024;

pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}
pub type BoxStream = Box<dyn Stream>;

/// Opens a stream to the hub's `rackhand/mcp/1`.
#[async_trait::async_trait]
pub trait Dialer: Send + Sync {
    async fn dial(&self) -> Result<BoxStream, String>;
}

/// The command a runner starts as its MCP server. It carries where to connect, never a token.
pub fn bridge_command(exe: &Path, hub: &str, job: &str, dir: &Path) -> Command {
    let mut c = Command::new(exe);
    c.args(["operator", "mcp-bridge", "--hub", hub, "--job", job, "--dir"]).arg(dir);
    c
}

pub fn socket_path(sockets: &Path, job: &str) -> PathBuf {
    sockets.join(format!("{job}.sock"))
}

fn error_reply(request: &Value, why: &str) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    if request["method"] == "tools/call" {
        let body =
            json!({ "error": why, "message": "the hub can't be reached from this operator right now; try again" });
        json!({ "jsonrpc": "2.0", "id": id, "result": {
            "content": [{ "type": "text", "text": body.to_string() }], "structuredContent": body, "isError": true } })
    } else {
        json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32003, "message": why } })
    }
}

async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Option<String> {
    let mut line = String::new();
    let n = tokio::io::AsyncReadExt::take(&mut *reader, MAX_LINE as u64).read_line(&mut line).await.ok()?;
    if n == 0 || !line.ends_with('\n') {
        return None;
    }
    Some(line)
}

/// One bridge's session: lines from it to the hub, each request's answer back.
async fn proxy(conn: UnixStream, dialer: Arc<dyn Dialer>, token: String) {
    let (read, mut write) = conn.into_split();
    let mut from_bridge = BufReader::new(read);
    let mut hub: Option<(BufReader<tokio::io::ReadHalf<BoxStream>>, tokio::io::WriteHalf<BoxStream>)> = None;
    while let Some(line) = read_line(&mut from_bridge).await {
        let Ok(request) = serde_json::from_str::<Value>(&line) else { continue };
        let wants_answer = request.get("id").is_some();
        if hub.is_none() {
            let opened = async {
                let stream = dialer.dial().await?;
                let (r, mut w) = tokio::io::split(stream);
                let auth = format!("{}\n", json!({ "auth": token }));
                w.write_all(auth.as_bytes()).await.map_err(|e| e.to_string())?;
                Ok::<_, String>((BufReader::new(r), w))
            }
            .await;
            match opened {
                Ok(pair) => hub = Some(pair),
                Err(_) => {
                    if wants_answer {
                        let reply = format!("{}\n", error_reply(&request, "hub_unreachable"));
                        if write.write_all(reply.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                    continue;
                }
            }
        }
        let Some((hub_read, hub_write)) = hub.as_mut() else { continue };
        let sent = hub_write.write_all(line.as_bytes()).await.and(hub_write.flush().await).is_ok();
        let answer = if !sent {
            None
        } else if wants_answer {
            tokio::time::timeout(ANSWER_WAIT, read_line(hub_read)).await.ok().flatten()
        } else {
            continue;
        };
        match answer {
            Some(answer) => {
                if write.write_all(answer.as_bytes()).await.is_err() {
                    return;
                }
            }
            None => {
                hub = None;
                if wants_answer {
                    let reply = format!("{}\n", error_reply(&request, "hub_unreachable"));
                    if write.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// The operator's end for one job: a socket for the bridge, and the token that never leaves this process.
#[derive(Debug)]
pub struct Broker {
    path: PathBuf,
    task: JoinHandle<()>,
}

impl Broker {
    pub fn start(path: PathBuf, dialer: Arc<dyn Dialer>, token: String) -> std::io::Result<Broker> {
        use std::os::unix::fs::PermissionsExt;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let task = tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                tokio::spawn(proxy(conn, dialer.clone(), token.clone()));
            }
        });
        Ok(Broker { path, task })
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// `rackhand operator mcp-bridge`: the runner's stdio MCP server, passing lines between it and the operator's socket.
pub async fn bridge_main(socket: &Path) -> std::io::Result<()> {
    let conn = UnixStream::connect(socket).await?;
    let (mut read, mut write) = conn.into_split();
    let up = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let _ = tokio::io::copy(&mut stdin, &mut write).await;
        let _ = write.shutdown().await;
    });
    let mut stdout = tokio::io::stdout();
    let _ = tokio::io::copy(&mut read, &mut stdout).await;
    let _ = stdout.flush().await;
    up.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    use super::*;

    const TOKEN: &str = "rhjob_0123456789abcdef-SECRET";

    /// A hub that answers every request with its own method, and keeps what it was sent.
    struct FakeHub {
        up: Mutex<bool>,
        seen: Arc<Mutex<Vec<String>>>,
        /// Drops the stream after this many requests, once.
        drop_after: Mutex<Option<usize>>,
    }

    #[async_trait::async_trait]
    impl Dialer for FakeHub {
        async fn dial(&self) -> Result<BoxStream, String> {
            if !*self.up.lock().unwrap() {
                return Err("no route".into());
            }
            let (ours, theirs) = tokio::io::duplex(64 * 1024);
            let seen = self.seen.clone();
            let limit = self.drop_after.lock().unwrap().take();
            tokio::spawn(async move {
                let (r, mut w) = tokio::io::split(theirs);
                let mut lines = BufReader::new(r).lines();
                let mut n = 0;
                while let Ok(Some(line)) = lines.next_line().await {
                    seen.lock().unwrap().push(line.clone());
                    let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
                    if v.get("id").is_none() {
                        continue;
                    }
                    n += 1;
                    if limit.is_some_and(|l| n > l) {
                        return;
                    }
                    let reply = json!({ "jsonrpc": "2.0", "id": v["id"], "result": { "echo": v["method"] } });
                    let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                }
            });
            Ok(Box::new(ours))
        }
    }

    fn hub(up: bool) -> Arc<FakeHub> {
        Arc::new(FakeHub { up: Mutex::new(up), seen: Arc::default(), drop_after: Mutex::new(None) })
    }

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rackhand-bridge-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    async fn ask(conn: &mut BufReader<UnixStream>, request: Value) -> Value {
        conn.get_mut().write_all(format!("{request}\n").as_bytes()).await.unwrap();
        let mut line = String::new();
        conn.read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn token_not_in_runner_environment_or_args() {
        let sockets = dir("token");
        let fake = hub(true);
        let path = socket_path(&sockets, "01JOB");
        let _broker = Broker::start(path.clone(), fake.clone(), TOKEN.into()).unwrap();
        // what the runner is given to start: no token in the program, its arguments or its environment
        let cmd = bridge_command(Path::new("/usr/local/bin/rackhand"), "ab12", "01JOB", &sockets);
        let shown = format!("{:?} {:?}", cmd.get_program(), cmd.get_args().collect::<Vec<_>>());
        assert!(!shown.contains("SECRET") && !shown.contains("rhjob_"), "{shown}");
        assert_eq!(cmd.get_envs().count(), 0, "it adds nothing to the environment");
        // yet the hub is authenticated: the token goes only on the operator's side of the socket
        let mut conn = BufReader::new(UnixStream::connect(&path).await.unwrap());
        let reply = ask(&mut conn, json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" })).await;
        assert_eq!(reply["result"]["echo"], "initialize");
        let seen = fake.seen.lock().unwrap().clone();
        assert_eq!(seen[0], json!({ "auth": TOKEN }).to_string(), "{seen:?}");
        assert!(seen[1..].iter().all(|l| !l.contains("SECRET")), "{seen:?}");
        // the socket is the operator's alone
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&sockets).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreachable_hub_fails_tool_calls_and_the_next_one_tries_again() {
        let sockets = dir("unreachable");
        let fake = hub(false);
        let path = socket_path(&sockets, "01JOB");
        let _broker = Broker::start(path.clone(), fake.clone(), TOKEN.into()).unwrap();
        let mut conn = BufReader::new(UnixStream::connect(&path).await.unwrap());
        let call = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": { "name": "list_machines" } });
        let reply = ask(&mut conn, call.clone()).await;
        assert_eq!(reply["id"], 7);
        assert_eq!(reply["result"]["isError"], true);
        assert_eq!(reply["result"]["structuredContent"]["error"], "hub_unreachable");
        // another method gets a plain error
        let other = ask(&mut conn, json!({ "jsonrpc": "2.0", "id": 8, "method": "tools/list" })).await;
        assert_eq!(other["error"]["message"], "hub_unreachable");
        // the hub is back: the same session works again
        *fake.up.lock().unwrap() = true;
        let reply = ask(&mut conn, call.clone()).await;
        assert_eq!(reply["result"]["echo"], "tools/call");
        // and a stream the hub drops in the middle of a request fails that call only
        *fake.drop_after.lock().unwrap() = Some(1);
        *fake.up.lock().unwrap() = true;
        let mut second = BufReader::new(UnixStream::connect(&path).await.unwrap());
        assert_eq!(ask(&mut second, call.clone()).await["result"]["echo"], "tools/call");
        assert_eq!(ask(&mut second, call.clone()).await["result"]["structuredContent"]["error"], "hub_unreachable");
        assert_eq!(ask(&mut second, call).await["result"]["echo"], "tools/call", "a new stream after the drop");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn notifications_get_no_answer_and_the_socket_goes_with_the_broker() {
        let sockets = dir("notify");
        let fake = hub(true);
        let path = socket_path(&sockets, "01JOB");
        let broker = Broker::start(path.clone(), fake.clone(), TOKEN.into()).unwrap();
        let mut conn = BufReader::new(UnixStream::connect(&path).await.unwrap());
        conn.get_mut().write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await.unwrap();
        let reply = ask(&mut conn, json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" })).await;
        assert_eq!(reply["id"], 2, "the answer is the ping's, not an answer to the notification");
        drop(broker);
        assert!(!path.exists(), "the job's socket is removed when the job ends");
    }
}
