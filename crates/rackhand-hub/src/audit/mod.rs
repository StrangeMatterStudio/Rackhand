//! Append-only hash-chained log (design 7.2, Audit; FR-26; 7.4.1). Rows go through the store writer, which chains
//! each one to the current head inside its transaction. Retention writes a checkpoint row holding the hash of the last
//! row it removes, so `verify` can still check the chain from the first remaining row.

mod chain;
mod verify;

pub use chain::Audit;
pub use verify::{VerifyError, VerifyReport, verify};

#[cfg(test)]
mod tests;
