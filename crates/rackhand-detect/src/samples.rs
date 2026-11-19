//! Samples at their corrected times (7.3.2).

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    pub at_ms: i64,
    pub value: f64,
}
