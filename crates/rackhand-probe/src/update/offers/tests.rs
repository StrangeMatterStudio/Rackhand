use std::sync::Mutex;
use std::time::Duration;

use rackhand_proto::common::SemVer;
use rackhand_proto::helper::{HelperRequest, HelperResponse};
use rackhand_proto::probe::UpdateAvailable;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

fn update(url: &str, body: &[u8], version: &str) -> UpdateAvailable {
    UpdateAvailable {
        version: Some(SemVer { version: version.into() }),
        url: url.into(),
        sha256: Sha256::digest(body).to_vec(),
        signature: b"a signature".to_vec(),
    }
}

async fn serve(body: &'static [u8]) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut seen = vec![0u8; 4096];
                let _ = socket.read(&mut seen).await;
                let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(body).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    format!("http://127.0.0.1:{port}/release/x")
}

fn spool(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rackhand-offers-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

const SOON: Duration = Duration::from_secs(5);
const MIN: i64 = 60_000;

#[test]
fn an_offer_is_tried_when_newer_and_not_again_too_soon() {
    let mut offers = Offers::default();
    let u = update("http://hub.test/x", b"x", "0.1.1");
    assert!(offers.accept(&u, "0.1.0", 0).is_some(), "newer");
    assert!(offers.accept(&u, "0.1.0", 5 * MIN).is_none(), "the same version again within ten minutes");
    assert!(offers.accept(&u, "0.1.0", 11 * MIN).is_some(), "and after");
    assert!(offers.accept(&u, "0.1.1", 30 * MIN).is_none(), "already running it");
    assert!(offers.accept(&update("http://hub.test/x", b"x", "0.1.0"), "0.1.1", 30 * MIN).is_none(), "never older");
    let other = update("http://hub.test/x", b"x", "0.1.2");
    assert!(offers.accept(&other, "0.1.1", 31 * MIN).is_some(), "a different version isn't held back by the first");
    let mut bad = update("http://hub.test/x", b"x", "0.1.9");
    bad.sha256 = vec![0; 3];
    assert!(offers.accept(&bad, "0.1.1", 40 * MIN).is_none());
    assert!(offers.accept(&u, "not a version", 50 * MIN).is_none(), "own version unreadable: nothing is tried");
}

#[tokio::test]
async fn a_good_download_is_handed_to_the_helper_as_hash_and_signature_only() {
    let url = serve(b"the new probe").await;
    let dir = spool("good");
    let offer = parse_offer(&update(&url, b"the new probe", "0.1.1")).unwrap();
    let asked = Mutex::new(Vec::new());
    let result = perform(&dir, &offer, SOON, |request| {
        asked.lock().unwrap().push(request);
        async { Ok(HelperResponse::UpdateStarted) }
    })
    .await;
    assert_eq!(result, Ok(()));
    let asked = asked.into_inner().unwrap();
    assert_eq!(asked, vec![offer.request()]);
    assert!(matches!(asked[0], HelperRequest::ApplyUpdate { .. }));
    assert_eq!(std::fs::read(dir.join("probe")).unwrap(), b"the new probe", "the helper reads it from the spool");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_refusal_by_the_helper_is_reported_with_its_reason() {
    let url = serve(b"the new probe").await;
    let dir = spool("refused");
    let offer = parse_offer(&update(&url, b"the new probe", "0.1.1")).unwrap();
    let result = perform(&dir, &offer, SOON, |_| async {
        Ok(HelperResponse::Error { code: "bad_signature".into(), message: "signed by a key that isn't pinned".into() })
    })
    .await;
    let Err(Failure::Refused(why)) = result else { panic!("{result:?}") };
    assert!(why.contains("bad_signature") && why.contains("isn't pinned"), "{why}");
    // a helper that can't be reached, or isn't there
    let result = perform(&dir, &offer, SOON, |_| async { Err("the helper didn't answer".to_string()) }).await;
    assert!(matches!(result, Err(Failure::Refused(ref w)) if w.contains("didn't answer")), "{result:?}");
    let result = perform(&dir, &offer, SOON, |_| async { Ok(HelperResponse::Pong { version: "0.1.0".into() }) }).await;
    assert!(matches!(result, Err(Failure::Refused(_))), "an answer that isn't one: {result:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn an_unreachable_url_never_reaches_the_helper() {
    let free = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let dir = spool("unreachable");
    let offer = parse_offer(&update(&format!("http://127.0.0.1:{free}/x"), b"x", "0.1.1")).unwrap();
    let asked = Mutex::new(0);
    let result = perform(&dir, &offer, SOON, |_| {
        *asked.lock().unwrap() += 1;
        async { Ok(HelperResponse::UpdateStarted) }
    })
    .await;
    assert!(matches!(result, Err(Failure::Unreachable(_))), "{result:?}");
    assert_eq!(asked.into_inner().unwrap(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}
