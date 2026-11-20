//! SQLite schema, writer task, read pool, time-series encoding, retention and rollups (design 7.2, Store).

pub mod audit;
pub mod db;
pub mod ids;
pub mod reader;
pub mod retention;
pub mod rollup;
pub mod series;
pub mod writer;

pub use db::{Db, OpenError, SCHEMA_VERSION};
pub use writer::{
    ConsumeToken, RegistryChange, Row, RowUpdate, RowWrite, StoreError, StoreWriter, TokenRefusal, WriteAck, WriteCmd,
};

#[cfg(test)]
mod tests {
    pub mod db;
    mod reader;
    mod retention;
    mod rollup;
    mod series {
        pub mod chunk;
        pub mod codec;
        mod query;
        mod step;
    }
    mod writer;
}
