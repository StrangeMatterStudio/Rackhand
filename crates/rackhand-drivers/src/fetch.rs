//! A bounded file download (the probe's update spool, 7.3.3): one GET, the body streamed into a writer and counted as it
//! arrives, so a server that lies about its length, or sends none, can't fill a disk. No redirect is followed. HTTPS takes
//! whatever certificate the server presents: what makes the file trustworthy is the release signature the caller checks
//! (and the helper checks again), not the connection, and the hub that serves releases has a self-signed certificate.

use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    #[error("the URL: {0}")]
    Url(String),
    /// No route, refused, or the TLS handshake failed: the machine can't reach the server (E65).
    #[error("can't reach the server: {0}")]
    Unreachable(String),
    #[error("the server answered {0}")]
    Status(u16),
    #[error("the download is over the {0} byte limit")]
    TooLarge(u64),
    #[error("no answer in {0} s")]
    Timeout(u64),
    #[error("writing the download: {0}")]
    Write(String),
}

async fn get<I, W>(io: I, host: &str, path: &str, limit: u64, out: &mut W) -> Result<u64, FetchError>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, http_body_util::Empty<Bytes>>(TokioIo::new(io))
        .await
        .map_err(|e| FetchError::Unreachable(e.to_string()))?;
    tokio::spawn(conn);
    let request = hyper::Request::get(path)
        .header(hyper::header::HOST, host)
        .header(hyper::header::USER_AGENT, concat!("rackhand-probe/", env!("CARGO_PKG_VERSION")))
        .body(http_body_util::Empty::new())
        .map_err(|e| FetchError::Url(e.to_string()))?;
    let mut response = sender.send_request(request).await.map_err(|e| FetchError::Unreachable(e.to_string()))?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(FetchError::Status(status));
    }
    let mut written = 0u64;
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(|e| FetchError::Unreachable(e.to_string()))?;
        let Some(data) = frame.data_ref() else { continue };
        written += data.len() as u64;
        if written > limit {
            return Err(FetchError::TooLarge(limit));
        }
        out.write_all(data).await.map_err(|e| FetchError::Write(e.to_string()))?;
    }
    out.flush().await.map_err(|e| FetchError::Write(e.to_string()))?;
    Ok(written)
}

/// Downloads `url` (`http://` or `https://`) into `out`, at most `limit` bytes, in at most `timeout` altogether. Returns the
/// number of bytes written.
pub async fn download<W: AsyncWrite + Unpin>(
    url: &str,
    limit: u64,
    timeout: Duration,
    out: &mut W,
) -> Result<u64, FetchError> {
    let parsed = url::Url::parse(url).map_err(|e| FetchError::Url(e.to_string()))?;
    let tls = match parsed.scheme() {
        "http" => false,
        "https" => true,
        other => return Err(FetchError::Url(format!("`{other}` isn't http or https"))),
    };
    let host = parsed.host_str().ok_or_else(|| FetchError::Url("no host".into()))?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(if tls { 443 } else { 80 });
    let mut path = parsed.path().to_string();
    if let Some(q) = parsed.query() {
        path = format!("{path}?{q}");
    }
    let host_header = parsed.port().map_or(host.clone(), |p| format!("{host}:{p}"));
    let run = async {
        let addr = crate::driver::resolve(&format!("{host}:{port}")).await.map_err(FetchError::Unreachable)?;
        let tcp =
            tokio::net::TcpStream::connect(addr).await.map_err(|e| FetchError::Unreachable(format!("{addr}: {e}")))?;
        if tls {
            let name =
                rustls::pki_types::ServerName::try_from(host.trim_start_matches('[').trim_end_matches(']').to_string())
                    .map_err(|e| FetchError::Url(e.to_string()))?;
            let stream = crate::pinned::accept_any_certificate()
                .connect(name, tcp)
                .await
                .map_err(|e| FetchError::Unreachable(format!("TLS: {e}")))?;
            get(stream, &host_header, &path, limit, out).await
        } else {
            get(tcp, &host_header, &path, limit, out).await
        }
    };
    match tokio::time::timeout(timeout, run).await {
        Ok(result) => result,
        Err(_) => Err(FetchError::Timeout(timeout.as_secs())),
    }
}

#[cfg(test)]
mod tests;
