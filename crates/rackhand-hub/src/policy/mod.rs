//! Autonomy levels, risk, approvals, maintenance and quarantine rules (7.6.8, 7.7.2).

pub mod approvals;
pub mod decide;
pub mod exclusions;
pub mod exec_patterns;
pub mod quarantine;
pub mod risk;
pub mod store;

#[cfg(test)]
mod tests {
    mod approvals;
    mod decide;
    mod exclusions;
}
