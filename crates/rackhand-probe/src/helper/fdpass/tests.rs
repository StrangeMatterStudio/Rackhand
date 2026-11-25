use std::io::{Read, Write};
use std::os::fd::AsFd;

use super::{MAX_FDS, recv_line, send_line};

fn file_with(text: &str) -> std::fs::File {
    let path = std::env::temp_dir().join(format!("rackhand-fdpass-{}-{text}", std::process::id()));
    std::fs::File::create(&path).unwrap().write_all(text.as_bytes()).unwrap();
    let file = std::fs::File::open(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    file
}

#[tokio::test]
async fn descriptors_travel_with_the_line() {
    let (a, b) = tokio::net::UnixStream::pair().unwrap();
    let (one, two) = (file_with("conns"), file_with("execs"));
    send_line(&a, b"{\"kind\":\"ebpf_maps\"}\n", &[one.as_fd(), two.as_fd()]).await.unwrap();
    let (line, fds) = recv_line(&b, 1024).await.unwrap();
    assert_eq!(line, "{\"kind\":\"ebpf_maps\"}\n");
    let texts: Vec<String> = fds
        .into_iter()
        .map(|fd| {
            let mut s = String::new();
            std::fs::File::from(fd).read_to_string(&mut s).unwrap();
            s
        })
        .collect();
    assert_eq!(texts, ["conns", "execs"], "the same open files, in order");
}

#[tokio::test]
async fn a_line_without_descriptors_reads_the_same() {
    let (a, b) = tokio::net::UnixStream::pair().unwrap();
    send_line(&a, b"{\"kind\":\"pong\"}\n", &[]).await.unwrap();
    let (line, fds) = recv_line(&b, 1024).await.unwrap();
    assert_eq!((line.as_str(), fds.len()), ("{\"kind\":\"pong\"}\n", 0));
}

#[tokio::test]
async fn a_line_sent_in_pieces_is_put_together() {
    let (a, b) = tokio::net::UnixStream::pair().unwrap();
    let file = file_with("maps");
    send_line(&a, b"{\"kind\":", &[file.as_fd()]).await.unwrap();
    send_line(&a, b"\"x\"}\n", &[]).await.unwrap();
    let (line, fds) = recv_line(&b, 1024).await.unwrap();
    assert_eq!((line.as_str(), fds.len()), ("{\"kind\":\"x\"}\n", 1));
}

#[tokio::test]
async fn too_long_or_cut_short_is_an_error() {
    let (a, b) = tokio::net::UnixStream::pair().unwrap();
    send_line(&a, &[b'x'; 64], &[]).await.unwrap();
    assert!(recv_line(&b, 16).await.is_err(), "no newline within the limit");
    let (a, b) = tokio::net::UnixStream::pair().unwrap();
    send_line(&a, b"{\"kind\"", &[]).await.unwrap();
    drop(a);
    assert!(recv_line(&b, 1024).await.is_err(), "closed before the newline");
}

#[tokio::test]
async fn more_descriptors_than_expected_are_refused() {
    let (a, b) = tokio::net::UnixStream::pair().unwrap();
    let files: Vec<std::fs::File> = (0..MAX_FDS + 1).map(|i| file_with(&format!("f{i}"))).collect();
    let fds: Vec<_> = files.iter().map(|f| f.as_fd()).collect();
    assert!(send_line(&a, b"{}\n", &fds).await.is_err(), "the sender keeps to the limit too");
    send_line(&a, b"{}\n", &fds[..MAX_FDS]).await.unwrap();
    let (_, got) = recv_line(&b, 1024).await.unwrap();
    assert_eq!(got.len(), MAX_FDS);
}
