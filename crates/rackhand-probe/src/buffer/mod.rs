//! The probe's report buffer, epochs and label table (design 7.3.2, 7.4.1, FR-3, D94).

pub mod epoch;
pub mod labels;
pub mod segments;

#[cfg(test)]
mod tests;
