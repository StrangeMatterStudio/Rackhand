//! `rackhand hub backup`, `rackhand hub restore`, and the nightly schedule (9, D58): a backup at 02:00 site time and the
//! self-watch at 02:30.

use std::path::{Path, PathBuf};

use rackhand_hub::backup;
use rackhand_hub::vault::master_key::MasterKey;
use rackhand_store::Db;

use super::HubConfig;

/// Where the hub keeps its local copies.
pub fn backups_dir(config: &HubConfig) -> PathBuf {
    config.data_dir.join("backups")
}

/// One backup now; the newest are kept, as many as the `[backups] kept` setting says (2 by default, 7.8.1).
pub fn backup_now(config: &HubConfig, now_ms: i64) -> Result<PathBuf, String> {
    let key = MasterKey::load(Some(&config.master_key))
        .map_err(|_| format!("the master key {} can't be read", config.master_key.display()))?;
    let dir = backups_dir(config);
    let file = backup::take(&config.db_path(), &key, &config.node_key, &dir, now_ms).map_err(|e| e.to_string())?;
    keep_with_the_data(&config.data_dir, &dir)?;
    Ok(file)
}

/// The backups belong to whoever owns the data directory: a backup the owner takes as root (`sudo rackhand hub
/// backup`) mustn't leave the directory to root, or the hub's own 02:00 backup can't write or prune there.
pub(crate) fn keep_with_the_data(data_dir: &Path, dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let owner = std::fs::metadata(data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;
    let (uid, gid) = (owner.uid(), owner.gid());
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut paths = vec![dir.to_path_buf()];
    paths.extend(entries.filter_map(|e| e.ok().map(|e| e.path())));
    for path in paths {
        let meta = std::fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if meta.uid() != uid || meta.gid() != gid {
            std::os::unix::fs::chown(&path, Some(uid), Some(gid)).map_err(|e| format!("{}: {e}", path.display()))?;
        }
    }
    Ok(())
}

/// Restores `file` onto a machine that has no hub yet: the database, the node key (so probes stay pinned), the master
/// key and a `hub.toml` with the default addresses. Refuses to overwrite a hub that is there.
pub fn restore(file: &Path, master_key: &Path, config_dir: &Path, data_dir: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    let config = HubConfig::defaults(config_dir, data_dir);
    for existing in [&config.master_key, &config.node_key, &config.db_path()] {
        if existing.exists() {
            return Err(format!("{} already exists; restore onto a machine without a hub", existing.display()));
        }
    }
    let key = MasterKey::load(Some(master_key))
        .map_err(|_| format!("the master key {} can't be read", master_key.display()))?;
    std::fs::create_dir_all(data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;
    std::fs::create_dir_all(config_dir).map_err(|e| format!("{}: {e}", config_dir.display()))?;
    backup::restore(file, &key, &config.db_path(), &config.node_key).map_err(|e| e.to_string())?;
    key.save(&config.master_key).map_err(|e| format!("{}: {e}", config.master_key.display()))?;
    let toml_path = config_dir.join("hub.toml");
    let text = toml::to_string(&config).map_err(|e| e.to_string())?;
    std::fs::write(&toml_path, text).map_err(|e| format!("{}: {e}", toml_path.display()))?;
    std::fs::set_permissions(&toml_path, std::fs::Permissions::from_mode(0o640)).map_err(|e| e.to_string())?;
    Ok(toml_path)
}

/// The minute of the day at the hub's own site (its time zone), if first run has named the site.
pub fn site_minute(db: &Db, now_ms: i64) -> Option<u32> {
    let tz: String =
        db.readers().with(|c| c.query_row("SELECT timezone FROM sites WHERE is_local = 1", [], |r| r.get(0))).ok()?;
    let zone = jiff::tz::TimeZone::get(&tz).ok()?;
    let at = jiff::Timestamp::from_millisecond(now_ms).ok()?.to_zoned(zone);
    Some(u32::from(at.hour() as u8) * 60 + u32::from(at.minute() as u8))
}

/// What the nightly schedule does in this minute of the site's day: the backup at 02:00, the self-watch at 02:30.
pub fn nightly(minute_of_day: u32) -> (bool, bool) {
    (minute_of_day == 2 * 60, minute_of_day == 2 * 60 + 30)
}
