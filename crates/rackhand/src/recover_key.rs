//! `rackhand hub recover-key` (E34): the master key back from the recovery code first run showed. The code is read
//! from standard input, so it is in no shell history or process list; the key is written only when it opens the
//! vault's secrets, and never over a key that is there.

use std::path::Path;
use std::sync::Arc;

use rackhand_hub::vault::Vault;
use rackhand_hub::vault::master_key::restore_from_recovery_code;
use rackhand_store::Db;

/// Writes the key the code stands for to `key_path`, once it has opened the vault's secrets in `db_path`; how many
/// secrets it opened.
pub fn recover(code: &str, key_path: &Path, db_path: &Path) -> Result<usize, String> {
    let key = restore_from_recovery_code(code.trim()).map_err(|_| "that isn't a recovery code".to_string())?;
    if key_path.exists() {
        return Err(format!("a master key is already at {}: move it away first", key_path.display()));
    }
    let mut opened = 0;
    if db_path.exists() {
        let db = Arc::new(Db::open(db_path).map_err(|e| format!("{}: {e}", db_path.display()))?);
        let names: Vec<String> = db
            .readers()
            .with(|c| {
                let mut s = c.prepare("SELECT name FROM secrets ORDER BY name")?;
                s.query_map([], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()
            })
            .map_err(|e| e.to_string())?;
        let check = restore_from_recovery_code(code.trim()).map_err(|_| "that isn't a recovery code".to_string())?;
        let vault = Vault::new(check, db);
        for name in &names {
            vault.get(name).map_err(|_| format!("the code doesn't open this hub's vault (secret {name})"))?;
            opened += 1;
        }
    }
    key.save(key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
    Ok(opened)
}

#[cfg(all(test, unix))]
mod tests;
