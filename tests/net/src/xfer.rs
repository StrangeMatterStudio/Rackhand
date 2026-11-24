//! A big transfer between two hubs behind NATs (AC29, E30): a sparse 5 GB file is cut at 60% and goes on from the last verified
//! chunk, and its BLAKE3 matches at the end. The receiver is the one that keeps a peer's backup, which verifies and resumes the
//! way a machine's does; the stream between two hubs to a machine is the integration tier's (`zfs_replicate_runbook...`).

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use rackhand_hub::audit::Audit;
use rackhand_hub::backup::peer::{DEST, PeerBackups, dir};
use rackhand_hub::peers::xfer::Xfer;
use rackhand_net::registry::MemoryRegistry;
use rackhand_net::xfer::{XferError, chunks, hash_file, send_file};
use rackhand_proto::alpn;
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use crate::holepunch::{hub_with, start_relay, via_relay};
use crate::topology::{A, B, FORWARDED_PORT, Lab, Nat, NsRuntime, RELAY};

/// What is sent: 5 GiB, unless the environment says otherwise.
fn size() -> u64 {
    std::env::var("RACKHAND_XFER_BYTES").ok().and_then(|v| v.parse().ok()).unwrap_or(5 << 30)
}

#[tokio::test(flavor = "multi_thread")]
async fn send_5gb_interrupted_at_60_percent_resumes_hash_matches() {
    crate::require_vm();
    let total_bytes = size();
    let root = std::path::PathBuf::from("/var/tmp").join(format!("rackhand-net-xfer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    // a sparse file that begins like a backup, which is what the receiver keeps
    let file = root.join("hub-1.rhbk");
    {
        let mut f = std::fs::File::create(&file).unwrap();
        f.write_all(b"RHBK1\n").unwrap();
        f.write_all(&[7u8; 4096]).unwrap();
        f.set_len(total_bytes).unwrap();
    }
    let _lab = Lab::new(Nat::Symmetric, Nat::FullCone);
    let (rt_relay, rt_a, rt_b) = (NsRuntime::new(RELAY), NsRuntime::new(A), NsRuntime::new(B));
    let relay = start_relay(&rt_relay, Some(1_000_000_000), rackhand_relay::admission::Mode::Public).await;
    let b = hub_with(&rt_b, 2, true, Some(FORWARDED_PORT), &[alpn::XFER]).await;
    let a = hub_with(&rt_a, 1, true, None, &[]).await;
    let (b_id, a_id) = (b.id(), a.id());
    let kept = root.join("receiver");
    let kept_for_b = kept.clone();
    rt_b.run(async move {
        std::fs::create_dir_all(&kept_for_b).unwrap();
        let db = Arc::new(Db::open(&kept_for_b.join("hub.db")).unwrap());
        let peer = Row::from([
            ("id", Value::Text("p1".into())),
            ("site", Value::Text("alpha".into())),
            ("endpoint_id", Value::Text(a_id.to_string())),
            ("backup_quota_bytes", Value::Integer(i64::MAX)),
            ("added_at", Value::Integer(1)),
        ]);
        db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("peers", peer)])).await.unwrap();
        let registry = Arc::new(MemoryRegistry::default());
        registry.allow(alpn::XFER, a_id);
        let audit = Audit::new(db.writer());
        let xfer = Xfer::new(Arc::new(PeerBackups::new(db, audit, dir(&kept_for_b))));
        tokio::spawn(rackhand_net::router::Router::new(b, registry).route(alpn::XFER, xfer.handler()).serve());
    })
    .await;
    let want = rt_a
        .run({
            let file = file.clone();
            async move { hash_file(&file).await.unwrap() }
        })
        .await;
    let total = chunks(total_bytes);
    let cut_at = total * 6 / 10;
    let (first_file, second_file) = (file.clone(), file.clone());
    let (started_second, interrupted) = rt_a
        .run(async move {
            let conn = a.connect(via_relay(b_id), alpn::XFER).await.expect("the hubs connect");
            rackhand_net::paths::wait_direct(&conn, Duration::from_secs(30))
                .await
                .expect("a direct path to the forwarded hub");
            let first = send_file(&conn, &[], DEST, &first_file, &mut |done, _| {
                if done == cut_at {
                    conn.close(1u32.into(), b"cut");
                }
            })
            .await;
            let conn = a.connect(via_relay(b_id), alpn::XFER).await.expect("the hubs connect again");
            rackhand_net::paths::wait_direct(&conn, Duration::from_secs(30)).await.expect("a direct path again");
            tokio::time::sleep(Duration::from_secs(1)).await;
            let mut started = None;
            let second = send_file(&conn, &[], DEST, &second_file, &mut |done, _| {
                started.get_or_insert(done);
            })
            .await;
            second.expect("the second attempt finishes");
            (started, first)
        })
        .await;
    assert!(matches!(interrupted, Err(XferError::Broken(_))), "the first attempt was cut: {interrupted:?}");
    let started = started_second.expect("progress");
    assert!(
        started >= cut_at - 1 && started < total,
        "it went on from the cut ({cut_at} of {total}), not from the start: {started}"
    );
    let kept_file = dir(&kept).join("alpha.rhbk");
    assert_eq!(std::fs::metadata(&kept_file).unwrap().len(), total_bytes, "all of it, and no more");
    let got = hash_file(&kept_file).await.unwrap();
    assert_eq!(got, want, "BLAKE3 matches at the end");
    rt_relay.run(async move { relay.shutdown().await }).await.expect("the relay stops");
    let _ = std::fs::remove_dir_all(&root);
}
