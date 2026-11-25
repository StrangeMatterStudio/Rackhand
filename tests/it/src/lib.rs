//! Integration tier (design 14): hub, probes and helpers in Docker containers. Run with `cargo xtask ci it`.

#[cfg(test)]
#[path = "bootstrap_it.rs"]
mod bootstrap_it;
#[cfg(test)]
mod callouts;
#[cfg(test)]
#[path = "checks_it.rs"]
mod checks;
#[cfg(test)]
mod drivers_it;
#[cfg(test)]
mod executor_it;
#[cfg(test)]
mod helper_it;
#[cfg(test)]
mod helper_scan;
#[cfg(test)]
mod install_it;
#[cfg(test)]
mod jobs;
#[cfg(test)]
mod mirror_it;
#[cfg(test)]
mod offline;
#[cfg(test)]
#[path = "operator_it.rs"]
mod operator_it;
#[cfg(test)]
mod patch_it;
#[cfg(test)]
mod probe_hub;
#[cfg(test)]
#[path = "quarantine_it.rs"]
mod quarantine;
#[cfg(test)]
#[path = "sampling_it.rs"]
mod sampling;
#[cfg(test)]
mod smoke;
#[cfg(test)]
mod ssh_it;
#[cfg(test)]
mod support;
#[cfg(test)]
#[path = "update_it.rs"]
mod update;
#[cfg(test)]
#[path = "updater_it.rs"]
mod updater_it;
#[cfg(test)]
mod wrapper;
