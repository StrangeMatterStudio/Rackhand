//! The hub's systems (design 7.2). Each module owns its tables; see the dependency rules in 7.2.

pub mod actions;
pub mod assist;
pub mod audit;
#[cfg(unix)]
pub mod backup;
pub mod bus;
pub mod checks;
pub mod executor;
pub mod http;
pub mod incidents;
pub mod ingest;
pub mod intel;
pub mod library;
pub mod mcp;
pub mod notify;
pub mod peers;
pub mod policy;
pub mod query;
pub mod registry;
pub mod scheduler;
pub mod selfwatch;
pub mod ssh;
pub mod vault;
pub mod web;
