use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

const SOON: Duration = Duration::from_secs(5);

/// Answers the first connection with `reply` (after reading the request), then closes it.
async fn serve(reply: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut seen = vec![0u8; 4096];
        let _ = socket.read(&mut seen).await;
        let _ = socket.write_all(&reply).await;
        let _ = socket.shutdown().await;
    });
    format!("http://127.0.0.1:{port}/release/rackhand-probe")
}

fn ok(body: &[u8]) -> Vec<u8> {
    let mut reply = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len()).into_bytes();
    reply.extend_from_slice(body);
    reply
}

#[tokio::test]
async fn a_file_is_written_as_it_arrives() {
    let url = serve(ok(b"a release")).await;
    let mut out = Vec::new();
    assert_eq!(download(&url, 1024, SOON, &mut out).await, Ok(9));
    assert_eq!(out, b"a release");
}

#[tokio::test]
async fn the_limit_is_counted_on_what_arrives_not_on_what_the_server_says() {
    // content-length says it fits; the body doesn't
    let mut lying = b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\n".to_vec();
    lying.extend_from_slice(&[7u8; 64]);
    let url = serve(lying).await;
    let mut out = Vec::new();
    let got = download(&url, 1024, SOON, &mut out).await;
    assert!(
        got.is_ok() || matches!(got, Err(FetchError::Unreachable(_))),
        "hyper stops at the length it was told: {got:?}"
    );
    assert!(out.len() <= 4);
    // chunked, with no length at all, over the limit
    let mut chunked = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n".to_vec();
    for _ in 0..8 {
        chunked.extend_from_slice(b"20\r\n");
        chunked.extend_from_slice(&[1u8; 32]);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let url = serve(chunked).await;
    let mut out = Vec::new();
    assert_eq!(download(&url, 100, SOON, &mut out).await, Err(FetchError::TooLarge(100)));
    assert!(out.len() <= 100, "nothing past the limit is written: {}", out.len());
}

#[tokio::test]
async fn a_status_other_than_200_is_an_error_and_a_redirect_is_not_followed() {
    let url = serve(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".to_vec()).await;
    assert_eq!(download(&url, 1024, SOON, &mut Vec::new()).await, Err(FetchError::Status(404)));
    let url = serve(b"HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:1/\r\ncontent-length: 0\r\n\r\n".to_vec()).await;
    assert_eq!(download(&url, 1024, SOON, &mut Vec::new()).await, Err(FetchError::Status(302)));
}

#[tokio::test]
async fn a_server_that_cannot_be_reached_or_never_answers_is_an_error_not_a_hang() {
    // a port nothing listens on
    let free = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let got = download(&format!("http://127.0.0.1:{free}/x"), 1024, SOON, &mut Vec::new()).await;
    assert!(matches!(got, Err(FetchError::Unreachable(_))), "{got:?}");
    // one that accepts and says nothing
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let got = download(&format!("http://127.0.0.1:{port}/x"), 1024, Duration::from_millis(300), &mut Vec::new()).await;
    assert_eq!(got, Err(FetchError::Timeout(0)));
    for bad in ["ftp://example.test/x", "not a url", "file:///etc/passwd", "http://"] {
        let got = download(bad, 1024, SOON, &mut Vec::new()).await;
        assert!(matches!(got, Err(FetchError::Url(_))), "{bad}: {got:?}");
    }
}

#[tokio::test]
async fn https_takes_the_self_signed_certificate_of_a_hub() {
    let (acceptor, _fingerprint) = crate::pinned::test_server();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let mut seen = vec![0u8; 4096];
        let _ = socket.read(&mut seen).await;
        let _ = socket.write_all(&ok(b"over tls")).await;
        let _ = socket.shutdown().await;
    });
    let mut out = Vec::new();
    assert_eq!(download(&format!("https://127.0.0.1:{port}/release/x"), 1024, SOON, &mut out).await, Ok(8));
    assert_eq!(out, b"over tls");
}
