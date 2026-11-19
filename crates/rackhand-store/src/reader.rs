//! A pool of read-only connections (11: one writer, four readers). Readers see committed data (WAL).

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::{Connection, OpenFlags};

#[derive(Debug)]
pub struct ReadPool {
    conns: Vec<Mutex<Connection>>,
    next: AtomicUsize,
}

impl ReadPool {
    pub(crate) fn open(path: &Path, size: usize) -> rusqlite::Result<ReadPool> {
        let mut conns = Vec::with_capacity(size);
        for _ in 0..size {
            let conn = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_URI,
            )?;
            crate::db::configure(&conn)?;
            conn.execute_batch("PRAGMA query_only = ON")?;
            conns.push(Mutex::new(conn));
        }
        Ok(ReadPool { conns, next: AtomicUsize::new(0) })
    }

    pub fn size(&self) -> usize {
        self.conns.len()
    }

    /// Runs `f` on a free reader (or waits for the next one in turn).
    pub fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> rusqlite::Result<T> {
        for conn in &self.conns {
            if let Ok(guard) = conn.try_lock() {
                return f(&guard);
            }
        }
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.conns.len();
        let guard = self.conns[i].lock().unwrap_or_else(|e| e.into_inner());
        f(&guard)
    }
}
