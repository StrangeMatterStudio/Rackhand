//! Opening the hub database: WAL mode, the baseline schema, and refusing a database newer than this binary (7.4.1, 13).

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

use crate::reader::ReadPool;
use crate::writer::StoreWriter;

/// The schema version this binary writes (`PRAGMA user_version`).
pub const SCHEMA_VERSION: i64 = 1;
const BASELINE: &str = include_str!("schema.sql");

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("database schema {found} is newer than this binary supports ({supported}); upgrade Rackhand")]
    DatabaseTooNew { found: i64, supported: i64 },
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

/// Applies the settings every connection uses.
pub(crate) fn configure(conn: &Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL;")
}

#[derive(Debug)]
pub struct Db {
    #[cfg_attr(not(test), allow(dead_code))]
    admin: Mutex<Connection>,
    writer: StoreWriter,
    readers: ReadPool,
}

impl Db {
    pub fn open(path: &Path) -> Result<Db, OpenError> {
        let conn = Connection::open(path)?;
        // Read the version before anything writes to the file.
        let found: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if found > SCHEMA_VERSION {
            return Err(OpenError::DatabaseTooNew { found, supported: SCHEMA_VERSION });
        }
        let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        debug_assert_eq!(mode, "wal");
        configure(&conn)?;
        if found == 0 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(BASELINE)?;
            tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
            tx.commit()?;
        }
        let writer = StoreWriter::spawn(path)?;
        let readers = ReadPool::open(path, 4)?;
        Ok(Db { admin: Mutex::new(conn), writer, readers })
    }

    pub fn writer(&self) -> StoreWriter {
        self.writer.clone()
    }

    pub fn readers(&self) -> &ReadPool {
        &self.readers
    }

    /// The connection used to open the database, for tests that inspect it.
    #[cfg(test)]
    pub fn connection(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.admin.lock().unwrap_or_else(|e| e.into_inner())
    }
}
