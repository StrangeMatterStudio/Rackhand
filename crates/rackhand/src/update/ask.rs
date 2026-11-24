//! The unprivileged side of an update (7.5.7): `rackhand self-update` (and the dashboard's Update for the hub). It checks the
//! release it is given against the pinned keys only to refuse early what the updater would refuse anyway, puts the release's
//! file, its signature and the signed manifest in the spool, and writes the request last, since the updater's path unit
//! starts on it. The hub also takes a backup and a copy of its database the guard can put back.
//!
//! When the hub starts again, what the updater answered and what the guard did are written to the audit log (the first
//! entries after a rollback) and kept beside them as `*.seen.json`, which the dashboard shows.

use std::path::Path;

use rackhand_release::binary::Version;
use rackhand_release::manifest;

use super::request::{Answer, RolledBack};
use super::{ANSWER, Component, MANIFEST, MANIFEST_SIG, PRE_UPDATE_DB, REQUEST, ROLLED_BACK, artifact};

/// What the hub keeps of an update once it has recorded it.
pub const ANSWER_SEEN: &str = "answer.seen.json";
pub const ROLLED_BACK_SEEN: &str = "rolled-back.seen.json";

fn copy(from: &Path, to: &Path) -> Result<(), String> {
    std::fs::copy(from, to).map(|_| ()).map_err(|e| format!("{}: {e}", from.display()))
}

/// Puts the release in `from` in `spool` with a request for it: the version, if it is newer than this one.
pub fn ask(
    from: &Path,
    spool: &Path,
    before_request: &dyn Fn(&Path) -> Result<(), String>,
    now_ms: i64,
) -> Result<Version, String> {
    let read = |name: &str| std::fs::read(from.join(name)).map_err(|e| format!("{}: {e}", from.join(name).display()));
    let bytes = read(MANIFEST)?;
    let sig = String::from_utf8(read(MANIFEST_SIG)?).map_err(|_| "the manifest's signature isn't text".to_string())?;
    let (_, m) = manifest::verify_signed(&bytes, &sig).map_err(|e| format!("the release's manifest: {e}"))?;
    let version = Version::parse(&m.version).ok_or("the release's version isn't x.y.z")?;
    let running = Version::parse(crate::VERSION).unwrap_or(Version(0, 0, 0));
    if version <= running {
        return Err(format!("{version} isn't newer than the running {running}"));
    }
    let file = artifact();
    if !m.artifacts.iter().any(|a| a.name == file) {
        return Err(format!("the release has no {file}"));
    }
    std::fs::create_dir_all(spool).map_err(|e| format!("{}: {e}", spool.display()))?;
    for stale in [REQUEST, ANSWER, ROLLED_BACK, PRE_UPDATE_DB] {
        let _ = std::fs::remove_file(spool.join(stale));
    }
    copy(&from.join(&file), &spool.join("rackhand"))?;
    copy(&from.join(format!("{file}.minisig")), &spool.join("rackhand.minisig"))?;
    copy(&from.join(MANIFEST), &spool.join(MANIFEST))?;
    copy(&from.join(MANIFEST_SIG), &spool.join(MANIFEST_SIG))?;
    before_request(spool)?;
    let request = serde_json::json!({ "version": version.to_string(), "requested_at_ms": now_ms });
    std::fs::write(spool.join(REQUEST), request.to_string()).map_err(|e| format!("the request: {e}"))?;
    Ok(version)
}

/// The hub's update: a backup, a copy of the database the guard can put back, then the request.
pub fn ask_hub(config: &crate::hub_cmd::HubConfig, from: &Path, now_ms: i64) -> Result<Version, String> {
    let spool = config.data_dir.join("update");
    let db = config.db_path();
    let prepare = |spool: &Path| -> Result<(), String> {
        crate::hub_cmd::backups::backup_now(config, now_ms)?;
        let copy = spool.join(PRE_UPDATE_DB);
        let c = rusqlite::Connection::open(&db).map_err(|e| format!("{}: {e}", db.display()))?;
        c.execute("VACUUM INTO ?1", [copy.to_string_lossy().as_ref()])
            .map_err(|e| format!("copying the database: {e}"))?;
        crate::hub_cmd::backups::keep_with_the_data(&config.data_dir, spool)
    };
    ask(from, &spool, &prepare, now_ms)
}

/// What the updater and the guard said since the hub last looked, as audit actions with their details; each file is renamed to
/// its `.seen` name once read, so it is recorded once.
pub fn outcomes(spool: &Path) -> Vec<(&'static str, serde_json::Value)> {
    let mut out = Vec::new();
    let take = |name: &str, seen: &str| -> Option<Vec<u8>> {
        let bytes = std::fs::read(spool.join(name)).ok()?;
        let _ = std::fs::rename(spool.join(name), spool.join(seen));
        Some(bytes)
    };
    if let Some(bytes) = take(ROLLED_BACK, ROLLED_BACK_SEEN) {
        if let Ok(r) = serde_json::from_slice::<RolledBack>(&bytes) {
            out.push(("hub.update_rolled_back", serde_json::to_value(r).unwrap_or_default()));
        }
    }
    if let Some(bytes) = take(ANSWER, ANSWER_SEEN) {
        if let Ok(a) = serde_json::from_slice::<Answer>(&bytes) {
            let action = if a.ok { "hub.update_started" } else { "hub.update_refused" };
            out.push((action, serde_json::to_value(a).unwrap_or_default()));
        }
    }
    out
}

/// The component of a `self-update` command line.
pub fn component_dir(component: Component) -> std::path::PathBuf {
    Path::new("/").join(component.state_dir()).join("update")
}

/// The newer release the hub holds in `release`, checked against the pinned keys.
pub fn available(release: &Path) -> Option<Version> {
    let bytes = std::fs::read(release.join(MANIFEST)).ok()?;
    let sig = std::fs::read_to_string(release.join(MANIFEST_SIG)).ok()?;
    let (_, m) = manifest::verify_signed(&bytes, &sig).ok()?;
    let version = Version::parse(&m.version)?;
    let running = Version::parse(crate::VERSION)?;
    (version > running && m.artifacts.iter().any(|a| a.name == artifact())).then_some(version)
}

/// What the dashboard says about the last update, from what the hub recorded.
pub fn last(spool: &Path) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(r) =
        std::fs::read(spool.join(ROLLED_BACK_SEEN)).ok().and_then(|b| serde_json::from_slice::<RolledBack>(&b).ok())
    {
        let minutes = ((r.window_to_ms - r.window_from_ms) as f64 / 60_000.0).ceil().max(1.0) as i64;
        let lost = if r.restored_database {
            format!(
                "the database from before the update was put back, and what the hub wrote in between ({minutes} {}) is gone",
                if minutes == 1 { "minute" } else { "minutes" }
            )
        } else {
            "the database was kept".to_string()
        };
        lines.push(format!("{} didn't come up and was rolled back to {}; {lost}.", r.to, r.from));
    }
    if let Some(a) = std::fs::read(spool.join(ANSWER_SEEN)).ok().and_then(|b| serde_json::from_slice::<Answer>(&b).ok())
    {
        let version = a.version.unwrap_or_else(|| "the release".into());
        if a.ok {
            lines.push(format!("The updater checked {version} and switched to it."));
        } else {
            lines.push(format!("The updater refused {version}: {} ({}).", a.message, a.code));
        }
    }
    lines
}
