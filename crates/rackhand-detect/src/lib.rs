//! Pure rule evaluation: thresholds, forecasts, baselines, silence, connection scoring and event severity (design
//! 7.2, Detect). Depends on nothing of ours.

pub mod baseline;
pub mod counted;
pub mod forecast;
pub mod rules;
pub mod samples;
pub mod silence;
pub mod threshold;

#[cfg(test)]
mod tests {
    mod baseline;
    mod counted;
    mod forecast;
    mod silence;
    mod threshold;
}
