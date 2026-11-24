//! The commands (7.7.3): `login`, `status`, `connect`, `forward`, `send` and `mcp`.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use rackhand_net::close_code;
use rackhand_proto::close::CloseCode;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::config::{self, Dirs};
use crate::net::{dial, open_tunnel};

/// `connect <site>/<machine> <port>`: standard input and output are the tunnel, for SSH's `ProxyCommand`.
pub async fn connect(
    dirs: &Dirs,
    target: &str,
    port: u16,
    input: impl AsyncRead + Unpin,
    output: impl AsyncWrite + Unpin,
) -> Result<(), String> {
    let (site, machine) = config::machine(target)?;
    let link = dial(dirs, site, rackhand_proto::alpn::TUNNEL).await?;
    let (send, recv) = open_tunnel(&link.conn, machine, port, "connect").await?;
    splice(input, output, send, recv).await;
    link.conn.close(0u32.into(), b"done");
    Ok(())
}

/// Passes bytes between a local stream and a QUIC one until either side ends.
pub async fn splice(
    mut input: impl AsyncRead + Unpin,
    mut output: impl AsyncWrite + Unpin,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
) {
    let up = async {
        let _ = tokio::io::copy(&mut input, &mut send).await;
        let _ = send.finish();
    };
    let down = async {
        let _ = tokio::io::copy(&mut recv, &mut output).await;
        let _ = output.flush().await;
    };
    tokio::select! { _ = up => {}, _ = down => {} }
}

/// The listener `forward` uses: this computer's loopback only, so a forward isn't a way in for anyone else on its network.
pub async fn bind_loopback(port: u16) -> Result<TcpListener, String> {
    TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await.map_err(|e| format!("127.0.0.1:{port}: {e}"))
}

/// `forward <local-port> <site>/<machine>:<port>`: each connection to the local port is a tunnel to the machine.
pub async fn forward(dirs: &Dirs, local_port: u16, target: &str) -> Result<(), String> {
    let (place, port) = target.rsplit_once(':').ok_or("a forward is `<local-port> <site>/<machine>:<port>`")?;
    let port: u16 = port.parse().map_err(|_| format!("`{port}` isn't a port"))?;
    let (site, machine) = config::machine(place)?;
    let listener = bind_loopback(local_port).await?;
    let link = dial(dirs, site, rackhand_proto::alpn::TUNNEL).await?;
    eprintln!("forwarding 127.0.0.1:{} to {place}:{port}", listener.local_addr().map_err(|e| e.to_string())?.port());
    loop {
        let (tcp, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let conn = link.conn.clone();
        let machine = machine.to_string();
        tokio::spawn(async move {
            match open_tunnel(&conn, &machine, port, "forward").await {
                Ok((send, recv)) => {
                    let (read, write) = tcp.into_split();
                    splice(read, write, send, recv).await;
                }
                Err(e) => eprintln!("rackhand-cli: {e}"),
            }
        });
    }
}

/// `send <path> <site>/<machine>:<dest>`: a file to a machine, in checked chunks that resume where they stopped.
pub async fn send(dirs: &Dirs, path: &Path, target: &str, allow_relay: bool) -> Result<(), String> {
    let (place, dest) = target.split_once(':').ok_or("a send is `<path> <site>/<machine>:<destination>`")?;
    let (site, machine) = config::machine(place)?;
    let link = dial(dirs, site, rackhand_proto::alpn::XFER).await?;
    let now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64);
    rackhand_net::xfer::wait_for_direct(&link.conn, allow_relay, &now, &mut || {
        eprintln!("still waiting for a direct path to {site}; --allow-relay sends through a relay")
    })
    .await;
    let mut last = 0;
    let result = rackhand_net::xfer::send_file(&link.conn, machine.as_bytes(), dest, path, &mut |done, total| {
        let pct = (done * 100).checked_div(total).unwrap_or(100);
        if pct != last {
            last = pct;
            eprintln!("{pct}% ({done} of {total} chunks)");
        }
    })
    .await;
    link.conn.close(0u32.into(), b"done");
    result.map_err(|e| e.to_string())
}

/// `mcp --hub <site>`: a stdio MCP server whose other end is the hub's (7.3.6). The key is a personal MCP key from the
/// dashboard; the device key makes the hub accept the connection at all.
pub async fn mcp(
    dirs: &Dirs,
    site: &str,
    key: &str,
    input: impl AsyncRead + Unpin,
    output: impl AsyncWrite + Unpin,
) -> Result<(), String> {
    let link = dial(dirs, site, rackhand_proto::alpn::MCP).await?;
    let (mut send, recv) = link.conn.open_bi().await.map_err(|e| e.to_string())?;
    let auth = serde_line(key);
    send.write_all(auth.as_bytes()).await.map_err(|e| e.to_string())?;
    splice(input, output, send, recv).await;
    link.conn.close(0u32.into(), b"done");
    Ok(())
}

/// The first line of an MCP session: `{"auth": "<key>"}`.
fn serde_line(key: &str) -> String {
    let escaped: String =
        key.chars().flat_map(|c| if c == '"' || c == '\\' { vec!['\\', c] } else { vec![c] }).collect();
    format!("{{\"auth\": \"{escaped}\"}}\n")
}

/// `status`: each hub this device is enrolled to, who it is there, and whether the hub takes it now.
pub async fn status(dirs: &Dirs) -> Result<String, String> {
    let hubs = config::load(dirs);
    if hubs.is_empty() {
        return Ok("this device isn't enrolled to any hub: `rackhand-cli login <invite>`\n".into());
    }
    let mut out = String::new();
    for hub in hubs {
        let device = config::device_key(dirs, &hub.id)?.public();
        let state = match dial(dirs, &hub.site, rackhand_proto::alpn::MCP).await {
            Err(e) => format!("not reachable: {e}"),
            Ok(link) => {
                // a hub that doesn't know or no longer admits this device closes the connection with a code
                let closed = tokio::time::timeout(std::time::Duration::from_millis(1500), link.conn.closed()).await;
                let state = match closed {
                    Ok(reason) => match close_code(&reason) {
                        Some(CloseCode::Revoked) => "refused: this device was revoked on the hub".to_string(),
                        Some(CloseCode::UnknownPeer) => "refused: the hub doesn't know this device".to_string(),
                        _ => format!("closed by the hub: {reason}"),
                    },
                    Err(_) => "enrolled and reachable".to_string(),
                };
                link.conn.close(0u32.into(), b"done");
                state
            }
        };
        out.push_str(&format!(
            "{} (hub {}): user {}, device {}: {state}\n",
            hub.site,
            &hub.id[..12],
            hub.user,
            device.fmt_short()
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpStream;

    use super::*;

    #[tokio::test]
    async fn forward_binds_loopback_only() {
        let listener = bind_loopback(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.ip().is_loopback(), "{addr}");
        assert_eq!(addr.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
        // and what answers on it is this process: nothing is reachable by another address of this machine
        assert!(TcpStream::connect(addr).await.is_ok());
    }

    #[test]
    fn the_mcp_auth_line_is_json() {
        assert_eq!(serde_line("rhk_abc"), "{\"auth\": \"rhk_abc\"}\n");
        assert_eq!(serde_line("a\"b\\c"), "{\"auth\": \"a\\\"b\\\\c\"}\n");
    }
}
