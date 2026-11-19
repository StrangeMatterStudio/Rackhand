//! SQLite schema, writer task, read pool, time-series encoding, retention and rollups (design 7.2, Store).

pub mod audit;
pub mod db;
pub mod ids;
pub mod reader;
pub mod writer;

pub use db::{Db, OpenError, SCHEMA_VERSION};
pub use writer::{Row, RowWrite, StoreError, StoreWriter, WriteAck, WriteCmd};

#[cfg(test)]
mod tests {
    pub mod db;
    mod reader;
    mod writer;
}
