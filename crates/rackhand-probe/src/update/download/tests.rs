use std::path::PathBuf;
use std::time::Duration;

use rackhand_proto::common::SemVer;
use rackhand_proto::probe::UpdateAvailable;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

struct Spool(PathBuf);

impl Spool {
    fn new(name: &str) -> Spool {
        let dir = std::env::temp_dir().join(format!("rackhand-download-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Spool(dir)
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn offer(url: &str, body: &[u8], version: &str) -> UpdateAvailable {
    UpdateAvailable {
        version: Some(SemVer { version: version.into() }),
        url: url.into(),
        sha256: Sha256::digest(body).to_vec(),
        signature: b"a signature".to_vec(),
    }
}

async fn serve(body: Vec<u8>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { return };
            let body = body.clone();
            tokio::spawn(async move {
                let mut seen = vec![0u8; 4096];
                let _ = socket.read(&mut seen).await;
                let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&body).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    format!("http://127.0.0.1:{port}/release/rackhand-probe-x86_64-unknown-linux-musl")
}

#[tokio::test]
async fn a_release_is_downloaded_into_the_one_spool_file() {
    let spool = Spool::new("good");
    // an earlier download's leftovers and anything else in the directory are cleared first
    std::fs::create_dir_all(&spool.0).unwrap();
    std::fs::write(spool.0.join("probe"), b"old").unwrap();
    std::fs::write(spool.0.join("probe.partial"), b"half").unwrap();
    std::fs::write(spool.0.join("other"), b"x").unwrap();
    let url = serve(b"the new probe".to_vec()).await;
    let parsed = parse_offer(&offer(&url, b"the new probe", "0.1.1")).unwrap();
    fetch(&spool.0, &parsed, Duration::from_secs(5)).await.unwrap();
    assert_eq!(std::fs::read(spool.0.join("probe")).unwrap(), b"the new probe");
    let mut names: Vec<String> =
        std::fs::read_dir(&spool.0).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(names, ["probe"], "one file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&spool.0).unwrap().permissions().mode() & 0o777, 0o700);
    }
}

#[tokio::test]
async fn a_download_that_is_not_the_offered_hash_is_deleted() {
    let spool = Spool::new("hash");
    let url = serve(b"something else".to_vec()).await;
    let parsed = parse_offer(&offer(&url, b"the new probe", "0.1.1")).unwrap();
    let failure = fetch(&spool.0, &parsed, Duration::from_secs(5)).await.unwrap_err();
    assert!(matches!(failure, Failure::Refused(_)), "{failure:?}");
    assert!(std::fs::read_dir(&spool.0).unwrap().next().is_none(), "nothing is left in the spool");
}

#[tokio::test]
async fn unreachable_url_reports_info_and_keeps_version() {
    let spool = Spool::new("unreachable");
    // a port nothing listens on
    let free = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{free}/release/rackhand-probe-x86_64-unknown-linux-musl");
    let parsed = parse_offer(&offer(&url, b"x", "0.1.1")).unwrap();
    let failure = fetch(&spool.0, &parsed, Duration::from_secs(5)).await.unwrap_err();
    let Failure::Unreachable(why) = &failure else { panic!("{failure:?}") };
    let event = failure.event(parsed.version, 1_000);
    assert_eq!(event.kind, "update_unreachable", "info on the hub: the machine stays on its version (E65)");
    assert_eq!(event.at_ms, 1_000);
    assert_eq!(event.fields.get("version").map(String::as_str), Some("0.1.1"));
    assert!(event.fields.get("detail").is_some_and(|d| d.contains(why.as_str())));
    assert!(std::fs::read_dir(&spool.0).map(|mut d| d.next().is_none()).unwrap_or(true));
    // the hub's severity for that kind is info, and a refused release is a warning
    assert_eq!(Failure::Refused("x".into()).event(parsed.version, 1).kind, "update_refused");
}

#[test]
fn an_offer_is_read_strictly() {
    let good = offer("https://hub.test:8443/release/x", b"x", "0.2.0");
    assert!(parse_offer(&good).is_ok());
    let mut bad = good.clone();
    bad.sha256 = vec![1; 31];
    assert!(parse_offer(&bad).is_err(), "a SHA-256 is 32 bytes");
    let mut bad = good.clone();
    bad.version = Some(SemVer { version: "latest".into() });
    assert!(parse_offer(&bad).is_err());
    let mut bad = good.clone();
    bad.version = None;
    assert!(parse_offer(&bad).is_err());
    let mut bad = good.clone();
    bad.signature = Vec::new();
    assert!(parse_offer(&bad).is_err(), "no signature, no update");
    let mut bad = good;
    bad.signature = vec![b'a'; 4096];
    assert!(parse_offer(&bad).is_err(), "a signature file is a few hundred bytes");
}

#[test]
fn only_a_newer_version_than_the_running_one_is_tried() {
    let v = |t: &str| rackhand_release::binary::Version::parse(t).unwrap();
    assert!(worth_trying(v("0.1.0"), v("0.1.1")));
    assert!(worth_trying(v("0.1.9"), v("0.1.10")));
    assert!(!worth_trying(v("0.1.1"), v("0.1.1")));
    assert!(!worth_trying(v("0.2.0"), v("0.1.9")), "never a downgrade");
}

#[test]
fn the_helper_request_carries_no_url_or_path() {
    let parsed = parse_offer(&offer("https://hub.test:8443/release/x", b"x", "0.2.0")).unwrap();
    let line = serde_json::to_string(&parsed.request()).unwrap();
    assert!(!line.contains("hub.test") && !line.contains("/release"), "{line}");
    assert!(line.contains(r#""op":"apply_update""#), "{line}");
    assert!(line.contains(&format!("{:x}", Sha256::digest(b"x"))), "{line}");
}
