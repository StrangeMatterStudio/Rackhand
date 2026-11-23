//! Backups kept for peers (9, D58, 7.3.11): a hub sends its latest backup to each peer that gave it space, over
//! `rackhand/xfer/1`; the peer keeps one copy. The space is the peer's `backup_quota_bytes` for the sender (0, the default, is
//! none), so a hub that gave none refuses the offer before a byte is sent. The file is the encrypted backup as it is: the
//! hub holding it can't read it, and `export` hands it to an admin who copies it to the machine that restores it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use iroh::EndpointId;
use iroh::endpoint::Connection;
use rackhand_net::xfer::{self, CHUNK, XferError};
use rackhand_proto::tunnel::{XferKind, XferOffer};
use rackhand_store::Db;
use rusqlite::OptionalExtension;

use crate::actions::runner::BoxFuture;
use crate::audit::Audit;
use crate::peers::xfer::{Opener, Sink};

/// What a sender names as the destination of a backup.
pub const DEST: &str = "peer-backup";
const MAGIC: &[u8] = b"RHBK1\n";

/// Where the backups of peers are kept.
pub fn dir(data_dir: &Path) -> PathBuf {
    data_dir.join("peer-backups")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A peer's site name is a plain name (7.4.1), so it is safe in a file name.
fn plain_site(site: &str) -> bool {
    !site.is_empty()
        && site.len() <= 32
        && site.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// The receiving side: who may send a backup here, and where it is kept.
pub struct PeerBackups {
    db: Arc<Db>,
    audit: Audit,
    dir: PathBuf,
}

impl std::fmt::Debug for PeerBackups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeerBackups")
    }
}

impl PeerBackups {
    pub fn new(db: Arc<Db>, audit: Audit, dir: PathBuf) -> PeerBackups {
        PeerBackups { db, audit, dir }
    }

    /// The peer behind this endpoint, its site and the space it was given.
    fn peer(&self, caller: EndpointId) -> Option<(String, i64)> {
        self.db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT site, backup_quota_bytes FROM peers WHERE endpoint_id = ?1 AND revoked_at IS NULL",
                    [caller.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
            })
            .ok()
            .flatten()
    }

    fn judge(&self, caller: EndpointId, offer: &XferOffer) -> Result<String, String> {
        let (site, quota) = self.peer(caller).ok_or("not a linked peer of this hub")?;
        if offer.kind != XferKind::File as i32 || offer.dest != DEST || !plain_site(&site) {
            return Err("a peer may send its backup here and nothing else".into());
        }
        if quota <= 0 {
            return Err("this hub has given you no backup space".into());
        }
        if offer.size > quota as u64 {
            return Err(format!("the backup is larger than the {quota} bytes of space this hub gave you"));
        }
        Ok(site)
    }
}

impl Opener for PeerBackups {
    fn open<'a>(&'a self, caller: EndpointId, offer: &'a XferOffer) -> BoxFuture<'a, Result<Box<dyn Sink>, String>> {
        Box::pin(async move {
            let judged = self.judge(caller, offer);
            let who = self.peer(caller).map(|p| p.0).unwrap_or_else(|| caller.fmt_short().to_string());
            let data = serde_json::json!({ "size": offer.size, "result": judged.as_ref().map(|_| "accepted").unwrap_or_else(|e| e) });
            let _ = self.audit.append(&format!("peer:{who}"), "peer_backup.offered", None, &data.to_string()).await;
            let site = judged?;
            std::fs::create_dir_all(&self.dir).map_err(|e| format!("this hub can't keep it: {e}"))?;
            Ok(Box::new(BackupSink {
                partial: self
                    .dir
                    .join(format!("{site}.{}.partial", &hex(&offer.blake3)[..16.min(hex(&offer.blake3).len())])),
                dir: self.dir.clone(),
                site,
                hash: offer.blake3.clone(),
                audit: self.audit.clone(),
            }) as Box<dyn Sink>)
        })
    }
}

struct BackupSink {
    dir: PathBuf,
    site: String,
    partial: PathBuf,
    hash: Vec<u8>,
    audit: Audit,
}

impl BackupSink {
    /// The backup is a file of one peer's: other partial files of the site are an older attempt's.
    fn drop_other_partials(&self) {
        let prefix = format!("{}.", self.site);
        for entry in std::fs::read_dir(&self.dir).into_iter().flatten().flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path != self.partial && name.starts_with(&prefix) && name.ends_with(".partial") {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

impl Sink for BackupSink {
    fn resume(&mut self) -> BoxFuture<'_, Result<u64, String>> {
        Box::pin(async move {
            self.drop_other_partials();
            let size = std::fs::metadata(&self.partial).map(|m| m.len()).unwrap_or(0);
            // whole chunks only: a write cut in the middle of one is sent again
            let whole = size / CHUNK as u64;
            if size != whole * CHUNK as u64 {
                let file = std::fs::OpenOptions::new().write(true).open(&self.partial).map_err(|e| e.to_string())?;
                file.set_len(whole * CHUNK as u64).map_err(|e| e.to_string())?;
            }
            Ok(whole)
        })
    }

    fn write<'a>(&'a mut self, index: u64, data: &'a [u8]) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            use std::io::Write;
            if index == 0 && !data.starts_with(MAGIC) {
                return Err("that isn't a Rackhand backup".into());
            }
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.partial)
                .map_err(|e| format!("this hub can't keep it: {e}"))?;
            file.write_all(data).map_err(|e| format!("this hub can't keep it: {e}"))
        })
    }

    fn finish(self: Box<Self>) -> BoxFuture<'static, Result<(), String>> {
        Box::pin(async move {
            let partial = self.partial.clone();
            let hash = tokio::task::spawn_blocking(move || {
                let mut hasher = blake3::Hasher::new();
                hasher.update_reader(std::fs::File::open(&partial)?)?;
                Ok::<_, std::io::Error>(hasher.finalize())
            })
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
            if hash.as_bytes().as_slice() != self.hash.as_slice() {
                let _ = std::fs::remove_file(&self.partial);
                return Err("the backup doesn't match its hash".into());
            }
            // one copy: the newer backup replaces the one before it
            let kept = self.dir.join(format!("{}.rhbk", self.site));
            std::fs::rename(&self.partial, &kept).map_err(|e| e.to_string())?;
            let size = std::fs::metadata(&kept).map(|m| m.len()).unwrap_or(0);
            let _ = self
                .audit
                .append(&format!("peer:{}", self.site), "peer_backup.received", None, &format!("{{\"size\":{size}}}"))
                .await;
            Ok(())
        })
    }

    fn abandon(self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }
}

/// How sending the latest backup to one peer went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sent {
    Sent,
    /// This hub has no backup yet.
    NoBackup,
    /// The peer said no, and why (no space given, too large).
    Refused(String),
}

/// Sends the newest backup in `backups` to a peer over `conn`. Waits for a direct path first unless `allow_relay`; after 10
/// minutes on a relay `notice` is called once (an info event, `bulk_waiting_direct_path`).
pub async fn send_latest(
    conn: &Connection,
    backups: &Path,
    allow_relay: bool,
    now_ms: &(dyn Fn() -> i64 + Send + Sync),
    notice: &mut (dyn FnMut() + Send),
) -> Result<Sent, XferError> {
    let Some(latest) = crate::backup::list(backups).pop() else { return Ok(Sent::NoBackup) };
    xfer::wait_for_direct(conn, allow_relay, now_ms, notice).await;
    match xfer::send_file(conn, &[], DEST, &latest, &mut |_, _| {}).await {
        Ok(()) => Ok(Sent::Sent),
        Err(XferError::Refused(why)) => Ok(Sent::Refused(why)),
        Err(e) => Err(e),
    }
}

/// Sends the newest backup to every linked peer: each peer that gave this hub space keeps it. Peers are dialed by endpoint
/// id through `relays`. Returns how it went for each site.
pub async fn send_to_peers(
    endpoint: &iroh::Endpoint,
    db: &Db,
    audit: &Audit,
    relays: &[iroh::RelayUrl],
    backups: &Path,
    allow_relay: bool,
) -> Vec<(String, Result<Sent, XferError>)> {
    let peers: Vec<(String, String)> = db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT site, endpoint_id FROM peers WHERE revoked_at IS NULL ORDER BY site")?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<Vec<_>, _>>()
        })
        .unwrap_or_default();
    let mut out = Vec::new();
    for (site, id) in peers {
        let result = async {
            let id: EndpointId = id.parse().map_err(|_| XferError::Source("a peer's endpoint id isn't one".into()))?;
            let mut addr = iroh::EndpointAddr::new(id);
            for relay in relays {
                addr.addrs.insert(iroh::TransportAddr::Relay(relay.clone()));
            }
            let conn = endpoint
                .connect(addr, rackhand_proto::alpn::XFER)
                .await
                .map_err(|e| XferError::Broken(e.to_string()))?;
            let now = || rackhand_store::ids::now_ms();
            let mut notice = || {
                // the design's info event, `bulk_waiting_direct_path`: a hub-level one, so it is an audit entry
                let audit = audit.clone();
                let site = site.clone();
                tokio::spawn(async move {
                    let _ = audit.append("hub", "bulk_waiting_direct_path", Some(&site), "{\"what\":\"backup\"}").await;
                });
            };
            send_latest(&conn, backups, allow_relay, &now, &mut notice).await
        }
        .await;
        let outcome = match &result {
            Ok(Sent::Sent) => "sent".to_string(),
            Ok(Sent::NoBackup) => "no_backup".to_string(),
            Ok(Sent::Refused(why)) => format!("refused: {why}"),
            Err(e) => format!("failed: {e}"),
        };
        let _ = audit
            .append("hub", "peer_backup.sent", Some(&site), &serde_json::json!({ "result": outcome }).to_string())
            .await;
        out.push((site, result));
    }
    out
}

/// `rackhand hub peer-backup export <site> <file>`: the backup kept for a peer, copied to `to`, which `hub restore` takes.
pub fn export(dir: &Path, site: &str, to: &Path) -> Result<u64, String> {
    if !plain_site(site) {
        return Err(format!("`{site}` isn't a site name"));
    }
    let kept = dir.join(format!("{site}.rhbk"));
    let mut head = [0u8; 6];
    {
        use std::io::Read;
        let mut file = std::fs::File::open(&kept).map_err(|_| format!("no backup is kept for {site}"))?;
        file.read_exact(&mut head).map_err(|_| format!("the backup kept for {site} is cut short"))?;
    }
    if head != MAGIC {
        return Err(format!("the file kept for {site} isn't a Rackhand backup"));
    }
    let tmp = to.with_extension("exporting");
    let bytes = std::fs::copy(&kept, &tmp).map_err(|e| format!("{}: {e}", to.display()))?;
    std::fs::rename(&tmp, to).map_err(|e| format!("{}: {e}", to.display()))?;
    Ok(bytes)
}
