//! Hub backups (9, D58): `VACUUM INTO` a temporary file, zstd-compress it, add the node key, and encrypt with the master
//! key; 2 kept locally. `rackhand hub restore <file>` with the master key restores the database and the node key, so
//! probes stay pinned to the same hub (AC47).
//!
//! The file is `RHBK1\n` and then sealed chunks of at most 1 MiB, each `[u32 length][24-byte nonce][ciphertext]`. A
//! chunk's associated data names its index and whether it is the last, so a reordered or truncated file is refused.
//! The first chunk holds a JSON header with the node key.

use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::vault::master_key::{MasterKey, Sealed};

pub mod peer;

const MAGIC: &[u8] = b"RHBK1\n";
const CHUNK: usize = 1024 * 1024;
/// Local copies kept (D58).
pub const KEEP: usize = 2;

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("database: {0}")]
    Db(String),
    #[error("the file isn't a Rackhand backup")]
    NotABackup,
    #[error("the backup can't be opened with this master key, or it was changed or cut short")]
    Sealed,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Header {
    version: u32,
    created_at_ms: i64,
    node_key: String,
}

fn aad(index: u64, last: bool) -> String {
    format!("rackhand-backup-v1:{index}:{}", if last { "last" } else { "more" })
}

struct Sealer<W: Write> {
    out: W,
    key: MasterKey,
    index: u64,
    pending: Vec<u8>,
}

impl<W: Write> Sealer<W> {
    fn seal(&mut self, plain: &[u8], last: bool) -> Result<(), BackupError> {
        let sealed = self.key.seal(&aad(self.index, last), plain).map_err(|_| BackupError::Sealed)?;
        self.index += 1;
        let len = u32::try_from(sealed.ciphertext.len()).map_err(|_| BackupError::Sealed)?;
        self.out.write_all(&len.to_be_bytes())?;
        self.out.write_all(&sealed.nonce)?;
        self.out.write_all(&sealed.ciphertext)?;
        Ok(())
    }

    fn finish(mut self) -> Result<W, BackupError> {
        let rest = std::mem::take(&mut self.pending);
        self.seal(&rest, true)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

impl<W: Write> Write for Sealer<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.pending.extend_from_slice(buf);
        while self.pending.len() > CHUNK {
            let chunk: Vec<u8> = self.pending.drain(..CHUNK).collect();
            self.seal(&chunk, false).map_err(|e| std::io::Error::other(e.to_string()))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Reads the chunks back; `None` once the last chunk has been read.
struct Opener<R: Read> {
    input: R,
    key: MasterKey,
    index: u64,
    done: bool,
}

impl<R: Read> Opener<R> {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, BackupError> {
        if self.done {
            return Ok(None);
        }
        let mut len = [0u8; 4];
        self.input.read_exact(&mut len).map_err(|_| BackupError::Sealed)?;
        let len = u32::from_be_bytes(len) as usize;
        if len > CHUNK + 64 {
            return Err(BackupError::Sealed);
        }
        let mut nonce = [0u8; 24];
        self.input.read_exact(&mut nonce).map_err(|_| BackupError::Sealed)?;
        let mut ciphertext = vec![0u8; len];
        self.input.read_exact(&mut ciphertext).map_err(|_| BackupError::Sealed)?;
        let sealed = Sealed { nonce, ciphertext };
        for last in [false, true] {
            if let Ok(plain) = self.key.open(&aad(self.index, last), &sealed) {
                self.index += 1;
                self.done = last;
                return Ok(Some(plain.expose().to_vec()));
            }
        }
        Err(BackupError::Sealed)
    }
}

/// The plaintext after the header chunk, as a reader (for zstd).
struct Body<R: Read> {
    opener: Opener<R>,
    buf: Vec<u8>,
    pos: usize,
}

impl<R: Read> Read for Body<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pos == self.buf.len() {
            match self.opener.next_chunk().map_err(|e| std::io::Error::other(e.to_string()))? {
                Some(chunk) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                None => return Ok(0),
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn copy_key(key: &MasterKey) -> MasterKey {
    MasterKey::from_bytes(*key.bytes())
}

/// Takes a backup of the database at `db_path` into `dir` as `hub-<created_at_ms>.rhbk`; keeps the newest [`KEEP`].
/// `VACUUM INTO` runs on a connection of its own, which only reads the hub's database (WAL keeps the hub writing).
pub fn take(db_path: &Path, key: &MasterKey, node_key: &Path, dir: &Path, now_ms: i64) -> Result<PathBuf, BackupError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let snapshot = dir.join(format!(".snapshot-{now_ms}.db"));
    let _ = std::fs::remove_file(&snapshot);
    let target = snapshot.to_string_lossy().into_owned();
    let conn = rusqlite::Connection::open(db_path).map_err(|e| BackupError::Db(e.to_string()))?;
    conn.busy_timeout(std::time::Duration::from_secs(30)).map_err(|e| BackupError::Db(e.to_string()))?;
    conn.execute("VACUUM INTO ?1", [target.as_str()]).map_err(|e| BackupError::Db(e.to_string()))?;
    drop(conn);
    let result = seal_snapshot(&snapshot, key, node_key, dir, now_ms);
    let _ = std::fs::remove_file(&snapshot);
    let path = result?;
    prune(dir)?;
    Ok(path)
}

fn seal_snapshot(
    snapshot: &Path,
    key: &MasterKey,
    node_key: &Path,
    dir: &Path,
    now_ms: i64,
) -> Result<PathBuf, BackupError> {
    use base64::Engine;
    use std::os::unix::fs::OpenOptionsExt;
    let node = std::fs::read(node_key)?;
    let header =
        Header { version: 1, created_at_ms: now_ms, node_key: base64::engine::general_purpose::STANDARD.encode(node) };
    let path = dir.join(format!("hub-{now_ms}.rhbk"));
    let tmp = path.with_extension("tmp");
    let file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    let mut out = BufWriter::new(file);
    out.write_all(MAGIC)?;
    let mut sealer = Sealer { out, key: copy_key(key), index: 0, pending: Vec::new() };
    let header = serde_json::to_vec(&header).map_err(|e| BackupError::Db(e.to_string()))?;
    sealer.seal(&header, false)?;
    let mut encoder = zstd::stream::Encoder::new(sealer, 3)?;
    std::io::copy(&mut BufReader::new(std::fs::File::open(snapshot)?), &mut encoder)?;
    let sealer = encoder.finish()?;
    let mut out = sealer.finish()?;
    out.flush()?;
    out.get_ref().sync_all()?;
    drop(out);
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// The backups in `dir`, oldest first.
pub fn list(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<(i64, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let at = p.file_name()?.to_str()?.strip_prefix("hub-")?.strip_suffix(".rhbk")?.parse().ok()?;
            Some((at, p))
        })
        .collect();
    found.sort();
    found.into_iter().map(|(_, p)| p).collect()
}

fn prune(dir: &Path) -> Result<(), BackupError> {
    let all = list(dir);
    for old in all.iter().take(all.len().saturating_sub(KEEP)) {
        std::fs::remove_file(old)?;
    }
    Ok(())
}

/// Restores `file` into `db_path` and `node_key`, which must not exist yet (a new machine, or files moved aside).
pub fn restore(file: &Path, key: &MasterKey, db_path: &Path, node_key: &Path) -> Result<(), BackupError> {
    use base64::Engine;
    use std::os::unix::fs::OpenOptionsExt;
    let mut input = BufReader::new(std::fs::File::open(file)?);
    let mut magic = [0u8; 6];
    input.read_exact(&mut magic).map_err(|_| BackupError::NotABackup)?;
    if magic != MAGIC {
        return Err(BackupError::NotABackup);
    }
    let mut opener = Opener { input, key: copy_key(key), index: 0, done: false };
    let header = opener.next_chunk()?.ok_or(BackupError::Sealed)?;
    let header: Header = serde_json::from_slice(&header).map_err(|_| BackupError::NotABackup)?;
    let node =
        base64::engine::general_purpose::STANDARD.decode(header.node_key).map_err(|_| BackupError::NotABackup)?;
    let tmp = db_path.with_extension("restoring");
    {
        let mut decoder = zstd::stream::Decoder::new(Body { opener, buf: Vec::new(), pos: 0 })?;
        let mut out = BufWriter::new(std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?);
        if let Err(e) = std::io::copy(&mut decoder, &mut out) {
            let _ = std::fs::remove_file(&tmp);
            return Err(if e.to_string().contains("this master key") {
                BackupError::Sealed
            } else {
                BackupError::Io(e)
            });
        }
        out.flush()?;
    }
    if let Some(dir) = node_key.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(node_key)?.write_all(&node)?;
    std::fs::rename(&tmp, db_path)?;
    Ok(())
}

#[cfg(test)]
mod tests;
