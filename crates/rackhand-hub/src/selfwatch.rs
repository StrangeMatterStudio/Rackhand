//! Hub self-watch (10, E33): once a day the hub checks its database's integrity, its own binary against the signed
//! release manifest, its config files, and the audit chain. Every failure is critical.
//!
//! A database that fails `quick_check` can't be trusted with writes, so the hub stops writing: Ingest holds reports
//! (no acks, probes keep buffering), no job starts, and the critical alert goes straight to the notifiers instead of
//! through an incident (E33). The other checks raise critical events, which open incidents as usual.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::ingest::{Event, Ingest, Severity};
use crate::notify::Notify;

/// What one check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// `hub.db_corrupt`, `hub.binary_changed`, `hub.config_exposed`, `hub.audit_broken`, or `hub.no_manifest` (info).
    pub kind: &'static str,
    pub detail: String,
}

/// The database check, replaceable in tests.
pub type IntegrityCheck = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;

/// `PRAGMA quick_check` on a connection of its own.
pub fn quick_check(db_path: PathBuf) -> IntegrityCheck {
    Arc::new(move || {
        let c = rusqlite::Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| e.to_string())?;
        let mut s = c.prepare("PRAGMA quick_check").map_err(|e| e.to_string())?;
        let rows: Vec<String> = s.query_map([], |r| r.get(0)).map_err(|e| e.to_string())?.flatten().collect();
        if rows == ["ok"] { Ok(()) } else { Err(rows.join("; ")) }
    })
}

/// The signed release manifest (13): `{"version": "...", "files": {"<file name>": "<sha256 hex>"}}` and its `.minisig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub path: PathBuf,
    pub signature: PathBuf,
}

pub struct SelfWatch {
    pub ingest: Ingest,
    pub notify: Notify,
    pub db: Arc<rackhand_store::Db>,
    pub integrity: IntegrityCheck,
    /// The running binary, and the name it has in the manifest.
    pub exe: PathBuf,
    pub exe_name: String,
    pub manifest: Option<Manifest>,
    /// Files that must be root's and not writable by others: (path, mode at most).
    pub configs: Vec<(PathBuf, u32)>,
}

impl std::fmt::Debug for SelfWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelfWatch").field("exe", &self.exe).finish_non_exhaustive()
    }
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// The binary against the manifest; `Ok(None)` when they match.
pub fn binary_check(exe: &Path, exe_name: &str, manifest: &Manifest) -> Result<Option<Finding>, String> {
    let data = std::fs::read(&manifest.path).map_err(|e| format!("{}: {e}", manifest.path.display()))?;
    let sig =
        std::fs::read_to_string(&manifest.signature).map_err(|e| format!("{}: {e}", manifest.signature.display()))?;
    if let Err(e) = rackhand_release::verify(&data, &sig) {
        return Ok(Some(Finding { kind: "hub.binary_changed", detail: format!("the release manifest: {e}") }));
    }
    let doc: serde_json::Value = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
    let Some(expected) = doc["files"][exe_name].as_str() else {
        return Ok(Some(Finding {
            kind: "hub.binary_changed",
            detail: format!("{exe_name} isn't in the release manifest"),
        }));
    };
    let actual = sha256_file(exe).map_err(|e| e.to_string())?;
    Ok((actual != expected).then(|| Finding {
        kind: "hub.binary_changed",
        detail: format!("{} has SHA-256 {actual}; the release manifest says {expected}", exe.display()),
    }))
}

/// A config file that isn't root's, or that its group or others could change.
#[cfg(unix)]
pub fn config_check(path: &Path, max_mode: u32) -> Option<Finding> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).ok()?;
    let mode = meta.mode() & 0o777;
    let exposed = meta.uid() != 0 || mode & !max_mode != 0 || meta.file_type().is_symlink();
    exposed.then(|| Finding {
        kind: "hub.config_exposed",
        detail: format!(
            "{} is owner {} mode {mode:o}; it should be root's and at most {max_mode:o}",
            path.display(),
            meta.uid()
        ),
    })
}

impl SelfWatch {
    /// The day's checks; returns what they found.
    pub async fn daily(&self, now_ms: i64) -> Vec<Finding> {
        if let Err(detail) = (self.integrity)() {
            // E33: stop writing first, then alert from memory
            self.ingest.set_integrity_failed();
            let title = "The hub's database failed its integrity check";
            let text = format!(
                "{detail}. The hub stopped writing: probes keep their reports, no job starts. Restore the latest backup."
            );
            self.notify.send_critical(title, &text, now_ms).await;
            return vec![Finding { kind: "hub.db_corrupt", detail }];
        }
        let mut found = Vec::new();
        match &self.manifest {
            Some(m) => match binary_check(&self.exe, &self.exe_name, m) {
                Ok(Some(f)) => found.push(f),
                Ok(None) => {}
                Err(e) => found.push(Finding { kind: "hub.binary_changed", detail: e }),
            },
            None => found.push(Finding {
                kind: "hub.no_manifest",
                detail: "no release manifest to check the binary against".into(),
            }),
        }
        #[cfg(unix)]
        for (path, mode) in &self.configs {
            found.extend(config_check(path, *mode));
        }
        if let Err(e) = crate::audit::verify(self.db.readers()) {
            found.push(Finding { kind: "hub.audit_broken", detail: e.to_string() });
        }
        let events: Vec<Event> = found
            .iter()
            .map(|f| {
                let severity = if f.kind == "hub.no_manifest" { Severity::Info } else { Severity::Critical };
                Event::hub(f.kind, severity, serde_json::json!({ "detail": f.detail }))
            })
            .collect();
        if let Err(e) = self.ingest.raise_events(events).await {
            tracing::error!(error = %e, "self-watch events");
        }
        found
    }
}

#[cfg(test)]
mod tests;
