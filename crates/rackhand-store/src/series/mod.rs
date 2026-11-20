//! Time-series chunks (7.4.1, D109): the chunk codec, per-metric steps, chunk rows and range queries.

mod bits;
pub mod chunk;
pub mod codec;
pub mod compact;
pub mod query;
pub mod step;

#[derive(Debug, thiserror::Error)]
pub enum SeriesError {
    #[error("points must be newer than the open chunk's last point ({last_ms})")]
    OutOfOrder { last_ms: i64 },
    #[error("columns don't match the timestamps or the open chunk")]
    Shape,
    #[error(transparent)]
    Codec(#[from] codec::CodecError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}
