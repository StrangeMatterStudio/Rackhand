//! Opening the hub database: WAL mode, the baseline schema, and refusing a database newer than this binary (7.4.1, 13).

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

use crate::reader::ReadPool;
use crate::writer::StoreWriter;

/// The schema version this binary writes (`PRAGMA user_version`).
pub const SCHEMA_VERSION: i64 = 2;
const BASELINE: &str = include_str!("schema.sql");

/// A column added by an upgrade: table, column, declaration.
type Column = (&'static str, &'static str, &'static str);

/// Forward-only upgrades (13): each runs once, in order, for a database older than its version. `schema.sql` is always the
/// newest shape, so a new database skips them. Each step is safe to run twice.
const UPGRADES: &[(i64, &[Column])] = &[
    // 2: a linked hub's addresses and relays, so that a hub can dial a peer (7.3.4)
    (2, &[("peers", "addrs", "TEXT NOT NULL DEFAULT '[]'"), ("peers", "relays", "TEXT NOT NULL DEFAULT '[]'")]),
];

fn has_column(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt.query_map([], |r| r.get::<_, String>(1))?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(names.iter().any(|n| n == column))
}

fn upgrade(conn: &Connection, found: i64) -> rusqlite::Result<()> {
    for (version, columns) in UPGRADES.iter().filter(|(v, _)| *v > found) {
        let tx = conn.unchecked_transaction()?;
        for (table, column, decl) in *columns {
            if !has_column(&tx, table, column)? {
                tx.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))?;
            }
        }
        tx.execute_batch(&format!("PRAGMA user_version = {version}"))?;
        tx.commit()?;
    }
    Ok(())
}

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
        } else {
            upgrade(&conn, found)?;
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
