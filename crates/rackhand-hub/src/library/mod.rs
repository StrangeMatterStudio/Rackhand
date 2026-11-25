//! Runbook and playbook revisions, drafts, built-ins and the git mirror (7.2, Library), and the hub configuration
//! stored the same way.

pub mod config;
pub mod items;
pub mod mirror;
pub mod scan;

#[cfg(test)]
#[path = "settings_tests.rs"]
mod settings;
#[cfg(test)]
pub(crate) mod tests;
