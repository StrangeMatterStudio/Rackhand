//! Runbook and playbook parsing and validation, and command template generation (design 7.2,
//! Runbook model). Depends on nothing of ours.

pub mod check_cmd;
pub mod diagnostics;
pub mod error;
pub mod params;
pub mod playbook;
pub mod runbook;
pub mod templates;
mod validate;

pub use error::ModelError;

#[cfg(test)]
mod tests {
    mod check_cmd;
    mod params;
    mod playbook;
    pub(crate) mod runbook;
    mod templates;
}
